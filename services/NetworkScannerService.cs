namespace NetworkScanner.Services;

using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Net.Http;
using System.Collections.Concurrent;
using NetworkScanner.Models;

public class NetworkScannerService
{
    private readonly DatabaseService _dbService;

    public NetworkScannerService(DatabaseService? dbService = null)
    {
        _dbService = dbService ?? new DatabaseService();
        _ = _dbService.InitializeAsync();
    }
    private CancellationTokenSource? _cancellationTokenSource;
    public event EventHandler<ScanResult>? HostFound;
    public event EventHandler<string>? StatusChanged;
    public event EventHandler? ScanCompleted;

    private static readonly HttpClient _httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
    private static readonly ConcurrentDictionary<string, string?> _ouiCache = new();
    private static readonly SemaphoreSlim _vendorRateLimit = new SemaphoreSlim(1, 1);
    private static readonly System.Text.RegularExpressions.Regex _macRegex =
        new(@"^([0-9A-F]{2}-){5}[0-9A-F]{2}$", System.Text.RegularExpressions.RegexOptions.Compiled | System.Text.RegularExpressions.RegexOptions.IgnoreCase);

    private static string? NormalizeMacOrNull(string? mac)
    {
        if (string.IsNullOrWhiteSpace(mac)) return null;
        var normalized = mac.Trim().Replace(':', '-').ToUpperInvariant();
        if (!_macRegex.IsMatch(normalized)) return null;
        if (normalized == "00-00-00-00-00-00") return null;
        return normalized;
    }

    public bool IsScanning { get; private set; } = false;

    // ── Static Wrappers for Testing ──────────────────────────────────────────
    public static List<int> ParsePortsWrapper(string input) => ParsePorts(input);
    public static IEnumerable<string> ExpandRangeWrapper(string input) => ExpandRange(input);

    public async Task StartScanAsync(ScanOptions options)
    {
        IsScanning = true;
        _cancellationTokenSource = new CancellationTokenSource();
        var token = _cancellationTokenSource.Token;

        try
        {
            await Task.Run(async () =>
            {
                StatusChanged?.Invoke(this, "Building scan list...");
                var candidates = BuildCandidateList(options, out var explicitCount, out var augmentedCount, out bool usedAugmentation);

                if (usedAugmentation)
                    StatusChanged?.Invoke(this, $"Scan targets: explicit {explicitCount} + discovered {augmentedCount} = {candidates.Count}");
                else
                    StatusChanged?.Invoke(this, $"Scan targets: explicit {explicitCount} (no connection-table augmentation)");

                var macCache = options.LookupMAC ? BuildMacCache() : new Dictionary<string, string>(StringComparer.Ordinal);

                // Shuffle target candidates to randomize scanning order
                var shuffledCandidates = candidates.ToList();
                NetworkScanner.Core.NetworkScannerUtils.Shuffle(shuffledCandidates);

                var liveHosts = await PingAllAsync(shuffledCandidates, options, token);
                
                if (options.LookupMAC && liveHosts.Count > 0)
                {
                    await Task.Delay(800, token);
                    var postCache = BuildMacCache();
                    foreach (var kv in postCache) macCache[kv.Key] = kv.Value;
                }

                await ScanPortsAndReportAsync(liveHosts, options, macCache, token);
                ScanCompleted?.Invoke(this, EventArgs.Empty);
            }, token);
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { StatusChanged?.Invoke(this, $"Error: {ex.Message}"); }
        finally { IsScanning = false; }
    }

    private static Dictionary<string, string> BuildMacCache()
    {
        var cache = new Dictionary<string, string>(StringComparer.Ordinal);
        IPHelperAPI.SnapshotArpCache(cache);
        IPHelperAPI.MergeArpCommandOutput(cache);
        ParseNdpIntoCache(cache);
        return cache;
    }

    private static void ParseNdpIntoCache(Dictionary<string, string> cache)
    {
        try {
            var psi = new System.Diagnostics.ProcessStartInfo {
                FileName = "netsh", Arguments = "interface ipv6 show neighbors",
                RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true
            };
            using var proc = System.Diagnostics.Process.Start(psi);
            if (proc == null) return;
            var output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(3000);

            foreach (var line in output.Split('\n')) {
                var parts = line.Trim().Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 2) continue;
                if (!IPAddress.TryParse(parts[0], out var addr)) continue;
                var macField = parts[1].Replace(':', '-');
                string? mac = NormalizeMacOrNull(macField) ?? IPHelperAPI.ExtractMacFromEui64(parts[0]);
                if (mac != null) cache[parts[0]] = mac;
            }
        } catch { }
    }

    private HashSet<string> BuildCandidateList(ScanOptions options, out int explicitCount, out int augmentedCount, out bool usedAugmentation)
    {
        var explicitCandidates = new HashSet<string>(StringComparer.Ordinal);
        foreach (var range in options.IPRanges)
            foreach (var ip in ExpandRange(range)) explicitCandidates.Add(ip);

        explicitCount = explicitCandidates.Count;
        var candidates = new HashSet<string>(explicitCandidates, StringComparer.Ordinal);
        augmentedCount = 0;
        usedAugmentation = options.IPRanges.Any(r => (r ?? "").Trim().Contains('/'));

        if (usedAugmentation) {
            var subnet = ExtractSubnetFromRange(options.IPRanges.FirstOrDefault());
            foreach (var ip in IPHelperAPI.DiscoverDevicesFromConnectionTable(subnet)) {
                if (candidates.Add(ip)) augmentedCount++;
            }
        }
        return candidates;
    }

    private static IEnumerable<string> ExpandRange(string range)
    {
        if (string.IsNullOrWhiteSpace(range)) return Array.Empty<string>();
        var results = new List<string>();
        try {
            if (range.Contains('/')) {
                var parts = range.Split('/');
                if (IPAddress.TryParse(parts[0], out var baseAddr) && int.TryParse(parts[1], out int prefix)) {
                    if (baseAddr.AddressFamily == AddressFamily.InterNetwork) {
                        uint b = IpToUint(baseAddr), m = prefix == 0 ? 0 : ~((1u << (32 - prefix)) - 1);
                        for (uint i = (b & m) + 1; i < ((b & m) | ~m); i++) results.Add(UintToIp(i));
                    }
                }
            } else if (range.Contains('-')) {
                var parts = range.Split('-');
                if (IPAddress.TryParse(parts[0].Trim(), out var sAddr) && IPAddress.TryParse(parts[1].Trim(), out var eAddr)) {
                    uint s = IpToUint(sAddr), e = IpToUint(eAddr);
                    for (uint i = s; i <= e; i++) results.Add(UintToIp(i));
                }
            } else if (IPAddress.TryParse(range, out _)) results.Add(range);
        } catch { }
        return results;
    }

    private static uint IpToUint(IPAddress addr) {
        var b = addr.GetAddressBytes();
        return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
    }

    private static string UintToIp(uint ip) => $"{(ip >> 24) & 0xFF}.{(ip >> 16) & 0xFF}.{(ip >> 8) & 0xFF}.{ip & 0xFF}";

    private static string? ExtractSubnetFromRange(string? range) {
        if (string.IsNullOrEmpty(range)) return null;
        var parts = range.Split(new[] { '/', '-' }, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 0) return null;
        var octets = parts[0].Trim().Split('.');
        return octets.Length == 4 ? $"{octets[0]}.{octets[1]}.{octets[2]}" : null;
    }

    public static List<int> ParsePorts(string input)
    {
        var ports = new HashSet<int>();
        if (string.IsNullOrWhiteSpace(input)) return new();
        foreach (var item in input.Split(',')) {
            var t = item.Trim();
            if (t.Contains('-')) {
                var p = t.Split('-');
                if (p.Length == 2 && int.TryParse(p[0].Trim(), out int s) && int.TryParse(p[1].Trim(), out int e)) {
                    for (int i = s; i <= e; i++) if (i is >= 1 and <= 65535) ports.Add(i);
                }
            } else if (int.TryParse(t, out int port) && port is >= 1 and <= 65535) ports.Add(port);
        }
        return ports.OrderBy(p => p).ToList();
    }

    public void StopScan() => _cancellationTokenSource?.Cancel();

    private async Task<List<string>> PingAllAsync(IEnumerable<string> candidates, ScanOptions options, CancellationToken token)
    {
        try
        {
            StatusChanged?.Invoke(this, "Starting stateless ICMP host discovery...");
            return await PingAllStatelessAsync(candidates, options, token);
        }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.AccessDenied)
        {
            StatusChanged?.Invoke(this, "Raw socket access denied (requires Admin). Falling back to managed ping...");
            return await PingAllLegacyAsync(candidates, options, token);
        }
        catch (Exception ex)
        {
            StatusChanged?.Invoke(this, $"Stateless ICMP failed ({ex.Message}). Falling back to managed ping...");
            return await PingAllLegacyAsync(candidates, options, token);
        }
    }

    private async Task<List<string>> PingAllLegacyAsync(IEnumerable<string> candidates, ScanOptions options, CancellationToken token)
    {
        var liveHosts = new ConcurrentBag<string>();
        var sem = new SemaphoreSlim(50);
        var tasks = candidates.Select(async ip => {
            if (token.IsCancellationRequested) return;
            await sem.WaitAsync(token);
            try { if (await PingHostAsync(ip, options.PingTimeout, token)) liveHosts.Add(ip); }
            finally { sem.Release(); }
        });
        await Task.WhenAll(tasks);
        return liveHosts.ToList();
    }

    private async Task<bool> PingHostAsync(string ip, int timeout, CancellationToken token) {
        try {
            using var ping = new Ping();
            var reply = await ping.SendPingAsync(ip, timeout);
            return reply.Status == IPStatus.Success;
        } catch { return false; }
    }

    private async Task<List<string>> PingAllStatelessAsync(IEnumerable<string> candidates, ScanOptions options, CancellationToken token)
    {
        var ipv4Targets = new List<IPAddress>();
        var ipv6Targets = new List<IPAddress>();

        foreach (var ipStr in candidates)
        {
            if (IPAddress.TryParse(ipStr, out var addr))
            {
                if (addr.AddressFamily == AddressFamily.InterNetwork && options.ScanIPv4)
                    ipv4Targets.Add(addr);
                else if (addr.AddressFamily == AddressFamily.InterNetworkV6 && options.ScanIPv6)
                    ipv6Targets.Add(addr);
            }
        }

        var responsiveHosts = new ConcurrentBag<string>();
        var tasks = new List<Task>();

        if (ipv4Targets.Count > 0)
        {
            tasks.Add(RunStatelessPingV4Async(ipv4Targets, options.PingTimeout, responsiveHosts, token));
        }
        if (ipv6Targets.Count > 0)
        {
            tasks.Add(RunStatelessPingV6Async(ipv6Targets, options.PingTimeout, responsiveHosts, token));
        }

        await Task.WhenAll(tasks);
        return responsiveHosts.ToList();
    }

    private async Task RunStatelessPingV4Async(List<IPAddress> targets, int timeoutMs, ConcurrentBag<string> responsiveHosts, CancellationToken token)
    {
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Icmp);
        socket.Bind(new IPEndPoint(IPAddress.Any, 0));

        ushort scannerId = (ushort)(Environment.ProcessId & 0xFFFF);
        var seenResponses = new ConcurrentDictionary<string, bool>(StringComparer.Ordinal);

        var receiverTask = Task.Run(async () =>
        {
            var buffer = new byte[65536];
            EndPoint remoteEP = new IPEndPoint(IPAddress.Any, 0);

            while (!token.IsCancellationRequested)
            {
                try
                {
                    if (socket.Poll(10000, SelectMode.SelectRead))
                    {
                        var result = socket.ReceiveFrom(buffer, ref remoteEP);
                        if (result < 28) continue;

                        int ihl = (buffer[0] & 0x0F) * 4;
                        if (result < ihl + 8) continue;

                        int type = buffer[ihl + 0];
                        int code = buffer[ihl + 1];

                        if (type == 0 && code == 0) // Echo Reply
                        {
                            ushort replyId = BitConverter.ToUInt16(buffer, ihl + 4);
                            if (replyId == scannerId)
                            {
                                var responderIp = ((IPEndPoint)remoteEP).Address.ToString();
                                if (seenResponses.TryAdd(responderIp, true))
                                {
                                    responsiveHosts.Add(responderIp);
                                }
                            }
                        }
                    }
                    else
                    {
                        await Task.Delay(1, token);
                    }
                }
                catch (SocketException ex) when (ex.SocketErrorCode == SocketError.Interrupted || ex.SocketErrorCode == SocketError.OperationAborted)
                {
                    break;
                }
                catch (ObjectDisposedException)
                {
                    break;
                }
                catch (Exception) {}
            }
        }, token);

        var seq = (ushort)0;
        int count = 0;
        foreach (var target in targets)
        {
            if (token.IsCancellationRequested) break;

            var packet = new NetworkScanner.Core.IcmpPacket
            {
                Type = 8, // Echo Request
                Code = 0,
                Identifier = scannerId,
                Sequence = seq++,
                Data = new byte[32]
            };
            Random.Shared.NextBytes(packet.Data);

            var packetBytes = packet.Serialize();
            try
            {
                socket.SendTo(packetBytes, new IPEndPoint(target, 0));
            }
            catch {}

            count++;
            if (count % 10 == 0)
            {
                await Task.Delay(1, token);
            }
        }

        await Task.Delay(timeoutMs, token);
        try { socket.Close(); } catch {}
        await receiverTask;
    }

    private async Task RunStatelessPingV6Async(List<IPAddress> targets, int timeoutMs, ConcurrentBag<string> responsiveHosts, CancellationToken token)
    {
        using var socket = new Socket(AddressFamily.InterNetworkV6, SocketType.Raw, ProtocolType.IcmpV6);
        socket.Bind(new IPEndPoint(IPAddress.IPv6Any, 0));

        ushort scannerId = (ushort)(Environment.ProcessId & 0xFFFF);
        var seenResponses = new ConcurrentDictionary<string, bool>(StringComparer.Ordinal);

        var receiverTask = Task.Run(async () =>
        {
            var buffer = new byte[65536];
            EndPoint remoteEP = new IPEndPoint(IPAddress.IPv6Any, 0);

            while (!token.IsCancellationRequested)
            {
                try
                {
                    if (socket.Poll(10000, SelectMode.SelectRead))
                    {
                        var result = socket.ReceiveFrom(buffer, ref remoteEP);
                        if (result < 8) continue;

                        int type = buffer[0];
                        int code = buffer[1];

                        if (type == 129 && code == 0) // ICMPv6 Echo Reply
                        {
                            ushort replyId = BitConverter.ToUInt16(buffer, 4);
                            if (replyId == scannerId)
                            {
                                var responderIp = ((IPEndPoint)remoteEP).Address.ToString();
                                if (seenResponses.TryAdd(responderIp, true))
                                {
                                    responsiveHosts.Add(responderIp);
                                }
                            }
                        }
                    }
                    else
                    {
                        await Task.Delay(1, token);
                    }
                }
                catch (SocketException ex) when (ex.SocketErrorCode == SocketError.Interrupted || ex.SocketErrorCode == SocketError.OperationAborted)
                {
                    break;
                }
                catch (ObjectDisposedException)
                {
                    break;
                }
                catch (Exception) {}
            }
        }, token);

        var seq = (ushort)0;
        int count = 0;
        foreach (var target in targets)
        {
            if (token.IsCancellationRequested) break;

            var packet = new NetworkScanner.Core.IcmpPacket
            {
                Type = 128, // ICMPv6 Echo Request
                Code = 0,
                Identifier = scannerId,
                Sequence = seq++,
                Data = new byte[32]
            };
            Random.Shared.NextBytes(packet.Data);

            var packetBytes = packet.Serialize();
            try
            {
                socket.SendTo(packetBytes, new IPEndPoint(target, 0));
            }
            catch {}

            count++;
            if (count % 10 == 0)
            {
                await Task.Delay(1, token);
            }
        }

        await Task.Delay(timeoutMs, token);
        try { socket.Close(); } catch {}
        await receiverTask;
    }

    public static async Task<bool> ScanPortAsync(string ipAddress, int port, int timeoutMs, CancellationToken token) {
        if (!IPAddress.TryParse(ipAddress, out var address))
            return false;

        try {
            using var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(token);
            cts.CancelAfter(timeoutMs);

            await socket.ConnectAsync(address, port, cts.Token);
            return true;
        } catch { return false; }
    }

    private async Task ScanPortsAndReportAsync(List<string> hosts, ScanOptions opts, Dictionary<string, string> macs, CancellationToken token) {
        using var sem = new SemaphoreSlim(200);

        var tasks = hosts.Select(async ip => {
            if (token.IsCancellationRequested) return;

            var openPorts = new List<int>();
            if (opts.Ports != null && opts.Ports.Count > 0) {
                var portTasks = opts.Ports.Select(async port => {
                    if (token.IsCancellationRequested) return;
                    await sem.WaitAsync(token);
                    try {
                        if (await ScanPortAsync(ip, port, opts.PortTimeout, token)) {
                            lock (openPorts) {
                                openPorts.Add(port);
                            }
                        }
                    } finally {
                        sem.Release();
                    }
                });
                await Task.WhenAll(portTasks);
            }

            var res = new ScanResult { IPAddress = ip, IsResponsive = true };
            if (opts.LookupMAC && macs.TryGetValue(ip, out var mac)) res.MACAddress = mac;
            res.OpenPorts = openPorts.OrderBy(p => p).ToList();

            HostFound?.Invoke(this, res);
        });

        await Task.WhenAll(tasks);
    }

    public Task<bool> PingHostPublicAsync(string ip, int timeoutMs = 3000, CancellationToken token = default)
        => PingHostAsync(ip, timeoutMs, token);

    public static async Task<List<int>> ScanPortsForHostAsync(
        string ip,
        IEnumerable<int> ports,
        int portTimeoutMs,
        CancellationToken token,
        IProgress<int>? progress = null)
    {
        var openPorts = new List<int>();
        foreach (var port in ports.Distinct().OrderBy(p => p))
        {
            if (token.IsCancellationRequested) break;
            progress?.Report(port);
            if (await ScanPortAsync(ip, port, portTimeoutMs, token))
                openPorts.Add(port);
        }
        return openPorts;
    }
}
