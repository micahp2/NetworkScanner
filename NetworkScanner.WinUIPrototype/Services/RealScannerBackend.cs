using NetworkScanner.Core;
using NetworkScanner.Models;
using NetworkScanner.Services;
using NetworkScanner.WinUIPrototype.Models;

namespace NetworkScanner.WinUIPrototype.Services;

public sealed class RealScannerBackend : IScannerBackend
{
    public string Name => "Real";

    public async Task<IReadOnlyList<ScanResultRow>> ScanAsync(
        string ipRanges,
        string ports,
        bool scanIPv4,
        bool scanIPv6,
        CancellationToken token,
        Action<ScanResultRow>? onHostFound = null,
        Action<string>? onStatus = null)
    {
        var options = BuildOptions(ipRanges, ports, scanIPv4, scanIPv6);
        var service = new NetworkScannerService();

        var rows = new List<ScanResultRow>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var gate = new object();

        void StatusHandler(object? _, string status)
        {
            onStatus?.Invoke(status);
        }

        void HostHandler(object? _, ScanResult result)
        {
            var row = Map(result);
            lock (gate)
            {
                var key = string.IsNullOrWhiteSpace(row.IPAddress) ? Guid.NewGuid().ToString("N") : row.IPAddress;
                if (!seen.Add(key)) return;
                rows.Add(row);
            }

            onHostFound?.Invoke(row);
        }

        service.StatusChanged += StatusHandler;
        service.HostFound += HostHandler;

        using var reg = token.Register(() => service.StopScan());

        try
        {
            await service.StartScanAsync(options);
        }
        finally
        {
            service.StatusChanged -= StatusHandler;
            service.HostFound -= HostHandler;
        }

        return rows
            .OrderBy(r => IPv4SortKey(r.IPAddress))
            .ThenBy(r => r.IPAddress, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    public async Task<IReadOnlyList<int>> ScanPortsForHostAsync(
        string ip,
        string ports,
        int portTimeoutMs,
        CancellationToken token,
        IProgress<int>? progress = null,
        IProgress<int>? openPortProgress = null)
    {
        var parsed = NetworkScannerUtils.ParsePorts(ports);
        if (parsed.Count == 0)
            parsed = new List<int> { 22, 80, 443 };

        return await NetworkScannerService.ScanPortsForHostAsync(ip, parsed, portTimeoutMs, token, progress, openPortProgress != null ? openPortProgress.Report : null);
    }

    private static ScanOptions BuildOptions(string ipRanges, string ports, bool scanIPv4, bool scanIPv6)
    {
        var ranges = (ipRanges ?? string.Empty)
            .Split(new[] { ',', ';', '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries)
            .Select(x => x.Trim())
            .Where(x => x.Length > 0)
            .ToList();

        var parsedPorts = ParsePorts(ports);

        return new ScanOptions
        {
            IPRanges = ranges.Count > 0 ? ranges : new List<string> { "192.168.1.0/24" },
            Ports = parsedPorts.Count > 0 ? parsedPorts : new List<int> { 22, 53, 80, 443, 3306, 8080, 8443 },
            ScanIPv4 = scanIPv4,
            ScanIPv6 = scanIPv6,
            ResolveDNS = true,
            LookupMAC = true,
            LookupVendor = true,
            PingTimeout = 3000,
            PortTimeout = 1500
        };
    }


    private static List<int> ParsePorts(string input)
    {
        var ports = new HashSet<int>();
        if (string.IsNullOrWhiteSpace(input))
        {
            return new List<int>();
        }

        foreach (var item in input.Split(','))
        {
            var t = item.Trim();
            if (t.Length == 0) continue;

            if (t.Contains('-'))
            {
                var p = t.Split('-');
                if (p.Length == 2 && int.TryParse(p[0].Trim(), out var s) && int.TryParse(p[1].Trim(), out var e))
                {
                    if (e < s) (s, e) = (e, s);
                    for (var i = s; i <= e; i++)
                    {
                        if (i is >= 1 and <= 65535) ports.Add(i);
                    }
                }
            }
            else if (int.TryParse(t, out var port) && port is >= 1 and <= 65535)
            {
                ports.Add(port);
            }
        }

        return ports.OrderBy(p => p).ToList();
    }

    private static ScanResultRow Map(ScanResult r)
    {
        return new ScanResultRow
        {
            IsOnline = r.IsOnline || r.IsResponsive,
            IsCached = r.IsCached,
            CustomName = r.CustomName ?? string.Empty,
            FirstSeen = r.FirstSeen.HasValue ? new DateTimeOffset(r.FirstSeen.Value) : null,
            LastSeen = r.LastSeen.HasValue ? new DateTimeOffset(r.LastSeen.Value) : null,
            IPAddress = r.IPAddress ?? string.Empty,
            Hostname = r.Hostname ?? string.Empty,
            MACAddress = r.MACAddress ?? string.Empty,
            Vendor = r.Vendor ?? string.Empty,
            OpenPorts = r.OpenPortsString ?? string.Empty,
            IPv6Address = r.IPv6Address ?? string.Empty
        };
    }

    private static long IPv4SortKey(string ip)
    {
        if (System.Net.IPAddress.TryParse(ip, out var p) && p.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            var b = p.GetAddressBytes();
            return ((long)b[0] << 24) | ((long)b[1] << 16) | ((long)b[2] << 8) | b[3];
        }

        return long.MaxValue;
    }
}