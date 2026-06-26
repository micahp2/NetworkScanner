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

            await EnrichAndReportAsync(liveHosts, options, macCache, token);
            ScanCompleted?.Invoke(this, EventArgs.Empty);
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

    private Task EnrichAndReportAsync(List<string> hosts, ScanOptions opts, Dictionary<string, string> macs, CancellationToken token) {
        foreach (var ip in hosts) {
            if (token.IsCancellationRequested) break;
            var res = new ScanResult { IPAddress = ip, IsResponsive = true };
            if (opts.LookupMAC && macs.TryGetValue(ip, out var mac)) res.MACAddress = mac;
            HostFound?.Invoke(this, res);
        }
        return Task.CompletedTask;
    }
}
