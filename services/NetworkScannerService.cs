namespace NetworkScanner.Services;

using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Net.Http;
using System.Collections.Concurrent;
using NetworkScanner.Models;

public class NetworkScannerService
{
    private CancellationTokenSource? _cancellationTokenSource;
    public event EventHandler<ScanResult>? HostFound;
    public event EventHandler<string>? StatusChanged;
    public event EventHandler? ScanCompleted;

    private static readonly HttpClient _httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
    private static readonly ConcurrentDictionary<string, string?> _ouiCache = new();
    private static readonly SemaphoreSlim _vendorRateLimit = new SemaphoreSlim(1, 1);

    public bool IsScanning { get; private set; } = false;

    public async Task StartScanAsync(ScanOptions options)
    {
        IsScanning = true;
        _cancellationTokenSource = new CancellationTokenSource();
        var token = _cancellationTokenSource.Token;

        try
        {
            // Phase 1: Build full candidate IP list from the user's range + OS tables
            StatusChanged?.Invoke(this, "Building scan list...");
            var candidates = BuildCandidateList(options);

            // Phase 2: Pre-scan MAC snapshot (devices already in the OS cache)
            var macCache = options.LookupMAC
                ? BuildMacCache()
                : new Dictionary<string, string>(StringComparer.Ordinal);
            System.Diagnostics.Debug.WriteLine($"Pre-scan MAC cache: {macCache.Count} entries");

            // Phase 3: Ping all candidates at high concurrency.
            // Firing all pings simultaneously floods the subnet with ARP/NDP requests,
            // maximising the chance every device's MAC lands in the OS tables.
            StatusChanged?.Invoke(this, $"Scanning {candidates.Count} IPs...");
            var liveHosts = await PingAllAsync(candidates, options, token);
            StatusChanged?.Invoke(this, $"Found {liveHosts.Count} live hosts — resolving MACs...");

            if (options.LookupMAC && liveHosts.Count > 0)
            {
                // Phase 4: Settle delay — give the OS time to write all ARP/NDP replies
                await Task.Delay(800, token);

                // Phase 5: Post-ping MAC snapshot — now contains entries from the ping burst
                var postCache = BuildMacCache();
                System.Diagnostics.Debug.WriteLine($"Post-ping MAC cache: {postCache.Count} entries");
                foreach (var kv in postCache)
                    macCache[kv.Key] = kv.Value;

                System.Diagnostics.Debug.WriteLine($"Combined MAC cache: {macCache.Count} entries");
            }

            // Phase 6: Enrich and report
            StatusChanged?.Invoke(this, $"Enriching {liveHosts.Count} hosts...");
            await EnrichAndReportAsync(liveHosts, options, macCache, token);

            ScanCompleted?.Invoke(this, EventArgs.Empty);
        }
        catch (OperationCanceledException)
        {
            StatusChanged?.Invoke(this, "Scan cancelled");
            ScanCompleted?.Invoke(this, EventArgs.Empty);
        }
        catch (Exception ex)
        {
            StatusChanged?.Invoke(this, $"Error: {ex.Message}");
            ScanCompleted?.Invoke(this, EventArgs.Empty);
        }
        finally
        {
            IsScanning = false;
        }
    }

    /// <summary>
    /// Builds the most complete MAC cache possible from all available sources:
    ///   1. GetIpNetTable2 (modern IPv4 neighbor table)
    ///   2. GetIpNetTable  (legacy ARP cache)
    ///   3. netsh interface ipv4 show neighbors (catches Stale entries APIs miss)
    ///   4. netsh interface ipv6 show neighbors (NDP — works through Wi-Fi client isolation)
    ///      - Uses physical address field where available
    ///      - Extracts MAC via EUI-64 reversal for Unreachable/zero entries
    ///   5. arp -a fallback
    ///
    /// For IPv6 NDP entries, the IPv6 address itself IS the key (not IPv4 yet).
    /// The caller must still correlate IPv6 keys to IPv4 via the live host scan.
    /// All IPv4-keyed entries are immediately usable.
    /// </summary>
    private static Dictionary<string, string> BuildMacCache()
    {
        var cache = new Dictionary<string, string>(StringComparer.Ordinal);

        // IPv4 sources
        IPHelperAPI.SnapshotArpCache(cache);
        IPHelperAPI.MergeArpCommandOutput(cache);

        // IPv6 NDP source — adds entries keyed by IPv6 address
        // (these get correlated to IPv4 during enrichment via EUI-64 reversal)
        ParseNdpIntoCache(cache);

        return cache;
    }

    /// <summary>
    /// Parses the IPv6 NDP table and adds entries to the cache.
    /// For entries with a real MAC in the Physical Address field: stored as IPv6→MAC.
    /// For Unreachable/zero entries with EUI-64 IPv6 addresses: MAC extracted from the
    /// IPv6 address itself and stored as MAC→MAC (for later correlation).
    /// Also builds a reverse EUI-64 MAC→IPv6 index for cross-referencing.
    /// </summary>
    private static void ParseNdpIntoCache(Dictionary<string, string> cache)
    {
        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo
            {
                FileName = "netsh",
                Arguments = "interface ipv6 show neighbors",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            using var proc = System.Diagnostics.Process.Start(psi);
            if (proc == null) return;
            var output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(3000);

            foreach (var line in output.Split('\n'))
            {
                var parts = line.Trim().Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 2) continue;
                var ipStr = parts[0];

                if (!IPAddress.TryParse(ipStr, out var addr)) continue;
                if (addr.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6) continue;
                if (ipStr.StartsWith("ff", StringComparison.OrdinalIgnoreCase)) continue; // multicast

                var macField = parts[1].Replace(':', '-');
                bool validMac = System.Text.RegularExpressions.Regex.IsMatch(
                    macField, @"^([0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2}$")
                    && !macField.Equals("00-00-00-00-00-00", StringComparison.OrdinalIgnoreCase)
                    && !macField.StartsWith("33-33", StringComparison.OrdinalIgnoreCase);

                string? mac = validMac ? macField.ToUpper() : IPHelperAPI.ExtractMacFromEui64(ipStr);
                if (mac == null) continue;

                // Store IPv6→MAC so enrichment can look up by IPv6 address
                if (!cache.ContainsKey(ipStr))
                    cache[ipStr] = mac;

                // Also store a "ndp_mac:XX-XX-XX-XX-XX-XX" sentinel so we know
                // this MAC exists in NDP even without a confirmed IPv4 address yet
                var macKey = $"ndp_mac:{mac}";
                if (!cache.ContainsKey(macKey))
                    cache[macKey] = mac;
            }
        }
        catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"ParseNdpIntoCache: {ex.Message}"); }
    }

    private HashSet<string> BuildCandidateList(ScanOptions options)
    {
        var candidates = new HashSet<string>(StringComparer.Ordinal);
        foreach (var range in options.IPRanges)
            foreach (var ip in ExpandRange(range))
                candidates.Add(ip);

        var subnet = ExtractSubnetFromRange(options.IPRanges.FirstOrDefault());
        foreach (var ip in IPHelperAPI.DiscoverDevicesFromConnectionTable(subnet))
            candidates.Add(ip);

        System.Diagnostics.Debug.WriteLine($"Candidate list: {candidates.Count} IPs");
        return candidates;
    }

    private static IEnumerable<string> ExpandRange(string range)
    {
        if (string.IsNullOrWhiteSpace(range)) return Array.Empty<string>();
        range = range.Trim();
        var results = new List<string>();
        try
        {
            if (range.Contains('/'))
            {
                var parts = range.Split('/');
                if (parts.Length == 2 &&
                    IPAddress.TryParse(parts[0], out var baseAddr) &&
                    int.TryParse(parts[1], out int prefix) &&
                    prefix >= 0 && prefix <= 32)
                {
                    uint baseInt   = IpToUint(baseAddr);
                    uint mask      = prefix == 0 ? 0u : ~((1u << (32 - prefix)) - 1);
                    uint network   = baseInt & mask;
                    uint broadcast = network | ~mask;
                    for (uint i = network + 1; i < broadcast; i++)
                        results.Add(UintToIp(i));
                }
                return results;
            }

            if (range.Contains('-'))
            {
                var parts = range.Split('-');
                if (parts.Length == 2)
                {
                    if (IPAddress.TryParse(parts[0].Trim(), out _) &&
                        int.TryParse(parts[1].Trim(), out int endOctet))
                    {
                        var octets = parts[0].Trim().Split('.');
                        if (octets.Length == 4 && int.TryParse(octets[3], out int startOctet))
                        {
                            string prefix3 = $"{octets[0]}.{octets[1]}.{octets[2]}";
                            for (int i = startOctet; i <= endOctet && i <= 254; i++)
                                results.Add($"{prefix3}.{i}");
                        }
                        return results;
                    }
                    if (IPAddress.TryParse(parts[0].Trim(), out var start2) &&
                        IPAddress.TryParse(parts[1].Trim(), out var end2))
                    {
                        uint s = IpToUint(start2), e = IpToUint(end2);
                        for (uint i = s; i <= e; i++)
                            results.Add(UintToIp(i));
                        return results;
                    }
                }
            }

            if (IPAddress.TryParse(range, out _))
                results.Add(range);
        }
        catch { }
        return results;
    }

    private static uint IpToUint(IPAddress addr)
    {
        var b = addr.GetAddressBytes();
        return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
    }

    private static string UintToIp(uint ip)
        => $"{(ip >> 24) & 0xFF}.{(ip >> 16) & 0xFF}.{(ip >> 8) & 0xFF}.{ip & 0xFF}";

    private string? ExtractSubnetFromRange(string? range)
    {
        if (string.IsNullOrEmpty(range)) return null;
        try
        {
            var parts = range.Split(new[] { '/', '-' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length == 0) return null;
            var octets = parts[0].Split('.');
            if (octets.Length != 4) return null;
            return $"{octets[0]}.{octets[1]}.{octets[2]}";
        }
        catch { return null; }
    }

    public void StopScan() => _cancellationTokenSource?.Cancel();

    private async Task<List<string>> PingAllAsync(
        HashSet<string> candidates, ScanOptions options, CancellationToken token)
    {
        var liveHosts = new ConcurrentBag<string>();
        var semaphore = new SemaphoreSlim(50);
        var tasks = new List<Task>();
        int probed = 0;

        foreach (var ip in candidates)
        {
            if (token.IsCancellationRequested) break;
            bool isIPv6 = ip.Contains(':');
            if (isIPv6 && !options.ScanIPv6) continue;
            if (!isIPv6 && !options.ScanIPv4) continue;

            await semaphore.WaitAsync(token);
            var capturedIp = ip;
            tasks.Add(Task.Run(async () =>
            {
                try
                {
                    if (await PingHostAsync(capturedIp, options.PingTimeout, token))
                        liveHosts.Add(capturedIp);
                }
                finally { semaphore.Release(); }
            }, token));

            if (++probed % 50 == 0)
                StatusChanged?.Invoke(this, $"Probing {probed}/{candidates.Count}...");
        }

        await Task.WhenAll(tasks);
        return liveHosts.ToList();
    }

    private async Task EnrichAndReportAsync(
        List<string> liveHosts,
        ScanOptions options,
        Dictionary<string, string> macCache,
        CancellationToken token)
    {
        // Build MAC → IPv6 reverse index from NDP cache entries (stored as IPv6→MAC).
        // Where a device has both a ULA (fdd0::/fd..) and a link-local (fe80::),
        // prefer the ULA since it's a stable, routable address worth displaying.
        var macToIPv6 = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var kv in macCache)
        {
            var key = kv.Key;
            bool isIPv6Entry = key.StartsWith("fe80:", StringComparison.OrdinalIgnoreCase) ||
                               key.StartsWith("fd",    StringComparison.OrdinalIgnoreCase);
            if (!isIPv6Entry) continue;

            var mac = kv.Value;
            bool isULA = key.StartsWith("fd", StringComparison.OrdinalIgnoreCase) &&
                        !key.StartsWith("fe80:", StringComparison.OrdinalIgnoreCase);

            if (!macToIPv6.ContainsKey(mac))
            {
                macToIPv6[mac] = key;
            }
            else if (isULA)
            {
                // Upgrade from link-local to ULA if we find a better address
                macToIPv6[mac] = key;
            }
        }
        System.Diagnostics.Debug.WriteLine($"MAC→IPv6 reverse index: {macToIPv6.Count} entries");

        var semaphore = new SemaphoreSlim(10);
        var tasks = new List<Task>();

        foreach (var ip in liveHosts)
        {
            if (token.IsCancellationRequested) break;
            await semaphore.WaitAsync(token);
            var capturedIp = ip;

            tasks.Add(Task.Run(async () =>
            {
                try
                {
                    var result = new ScanResult
                    {
                        IPAddress = capturedIp,
                        IPVersion = capturedIp.Contains(':') ? "IPv6" : "IPv4",
                        IsResponsive = true
                    };

                    if (options.ResolveDNS)
                        result.Hostname = await ResolveHostnameAsync(capturedIp, token);

                    if (options.LookupMAC && result.IPVersion == "IPv4")
                    {
                        result.MACAddress = ResolveMACForHost(capturedIp, macCache);

                        // Populate IPv6 address by looking up the MAC in our NDP reverse index
                        if (result.MACAddress != null && macToIPv6.TryGetValue(result.MACAddress, out var ipv6))
                        {
                            // Prefer the global ULA (fdd0::) address over link-local (fe80::)
                            // since ULA is more meaningful to display
                            result.IPv6Address = ipv6;
                            System.Diagnostics.Debug.WriteLine($"IPv6 found for {capturedIp}: {ipv6}");
                        }

                        if (options.LookupVendor && result.MACAddress != null)
                            result.Vendor = await LookupVendorAsync(result.MACAddress, token);
                    }

                    result.OpenPorts = await ScanPortsAsync(
                        capturedIp, options.Ports, options.PortTimeout, token);

                    HostFound?.Invoke(this, result);
                }
                finally { semaphore.Release(); }
            }, token));
        }

        await Task.WhenAll(tasks);
    }

    /// <summary>
    /// Resolves the MAC for a given IPv4 address using all available sources in order:
    ///   1. IPv4 ARP cache (direct lookup)
    ///   2. EUI-64 correlation: construct the expected fe80:: and fdd0:: link-local
    ///      IPv6 addresses for this host and check if NDP has them. Since we stored
    ///      IPv6→MAC in the cache during BuildMacCache(), we just need to construct
    ///      the possible IPv6 addresses. But without knowing the MAC first this is
    ///      circular — so instead we scan ALL NDP IPv6 entries and check if any
    ///      EUI-64-extracted MAC is in the cache as "ndp_mac:XX-XX-XX-XX-XX-XX",
    ///      then try SendARP to confirm the mapping.
    ///   3. SendARP active probe
    /// </summary>
    private static string? ResolveMACForHost(string ipv4, Dictionary<string, string> macCache)
    {
        // 1. Direct IPv4 cache hit (ARP/netsh)
        if (macCache.TryGetValue(ipv4, out var mac) && mac != null)
        {
            System.Diagnostics.Debug.WriteLine($"Cache hit (IPv4): {ipv4} → {mac}");
            return mac;
        }

        // 2. SendARP active probe
        mac = IPHelperAPI.ProbeViaSendARP(ipv4);
        if (mac != null)
        {
            System.Diagnostics.Debug.WriteLine($"SendARP hit: {ipv4} → {mac}");
            return mac;
        }

        // 3. Re-check cache after SendARP (it may have updated the OS table)
        mac = IPHelperAPI.GetMACFromCacheOnly(ipv4);
        if (mac != null)
        {
            System.Diagnostics.Debug.WriteLine($"Cache hit (post-SendARP): {ipv4} → {mac}");
            return mac;
        }

        System.Diagnostics.Debug.WriteLine($"No MAC found: {ipv4}");
        return null;
    }

    private async Task<bool> PingHostAsync(string ipAddress, int timeout, CancellationToken token)
    {
        if (await ICMPPingAsync(ipAddress, timeout, token)) return true;

        // Run TCP fallback probes in parallel; each manages its own timeout independently
        // so cancelling one doesn't throw through the outer scan token.
        var fallbackPorts = new[] { 80, 443, 22, 8080, 3306, 445, 139, 5353, 67, 68 };
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(token);
        var tasks = fallbackPorts
            .Select(p => TCPPingAsync(ipAddress, p, timeout / 2, cts.Token))
            .ToList();

        while (tasks.Count > 0)
        {
            var done = await Task.WhenAny(tasks);
            tasks.Remove(done);
            try
            {
                if (await done) { cts.Cancel(); return true; }
            }
            catch { /* swallow any stragglers */ }
        }
        return false;
    }

    private async Task<bool> ICMPPingAsync(string ipAddress, int timeout, CancellationToken token)
    {
        try
        {
            using var ping = new Ping();
            var reply = await ping.SendPingAsync(ipAddress, timeout);
            return reply.Status == IPStatus.Success;
        }
        catch { return false; }
    }

    private async Task<bool> TCPPingAsync(string ipAddress, int port, int timeout, CancellationToken token)
    {
        // Use a fresh independent CTS for the per-connection timeout so that
        // cancelling it (on timeout) does NOT propagate as OperationCanceledException
        // up through the caller's token — that would flood the VS output window.
        using var cts = new CancellationTokenSource(timeout);
        try
        {
            using var client = new TcpClient();
            await client.ConnectAsync(ipAddress, port, cts.Token);
            return true;
        }
        catch (OperationCanceledException) { return false; } // timeout — not an error
        catch (Exception) { return false; }
    }

    private async Task<string?> ResolveHostnameAsync(string ipAddress, CancellationToken token)
    {
        try
        {
            var entry = await Dns.GetHostEntryAsync(ipAddress);
            return entry.HostName;
        }
        catch { return null; }
    }

    private async Task<string?> LookupVendorAsync(string macAddress, CancellationToken token)
    {
        if (string.IsNullOrEmpty(macAddress)) return null;
        try
        {
            var normalized = macAddress.Replace("-", ":");
            if (normalized.Length < 8) return null;
            var oui = normalized.Substring(0, 8).ToUpper();

            if (_ouiCache.TryGetValue(oui, out var cached)) return cached;

            await _vendorRateLimit.WaitAsync(token);
            try
            {
                if (_ouiCache.TryGetValue(oui, out cached)) return cached;

                var url = $"https://api.macvendors.com/{oui.Replace(":", "-")}";
                var response = await _httpClient.GetAsync(url, token);

                string? vendor = null;
                if (response.IsSuccessStatusCode)
                {
                    var content = await response.Content.ReadAsStringAsync(token);
                    vendor = string.IsNullOrWhiteSpace(content) ? null : content.Trim();
                }
                else if (response.StatusCode == System.Net.HttpStatusCode.TooManyRequests)
                {
                    System.Diagnostics.Debug.WriteLine($"OUI rate limit: {oui}");
                    await Task.Delay(1000, token);
                }

                _ouiCache[oui] = vendor;
                await Task.Delay(1100, token);
                return vendor;
            }
            finally { _vendorRateLimit.Release(); }
        }
        catch (OperationCanceledException) { return null; }
        catch { return null; }
    }

    private async Task<List<int>> ScanPortsAsync(
        string ipAddress, List<int> ports, int timeout, CancellationToken token)
    {
        var openPorts = new ConcurrentBag<int>();
        await Task.WhenAll(ports.Select(port => Task.Run(async () =>
        {
            if (await TCPPingAsync(ipAddress, port, timeout, token))
                openPorts.Add(port);
        }, token)));
        return openPorts.OrderBy(p => p).ToList();
    }
}
