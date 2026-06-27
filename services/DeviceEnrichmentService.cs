using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;
using NetworkScanner.Core;
using NetworkScanner.Models;

namespace NetworkScanner.Services;

public sealed class DeviceEnrichmentService
{
    private readonly DatabaseService _db;
    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(4) };

    public DeviceEnrichmentService(DatabaseService db) => _db = db;

    public async Task<string?> ResolveHostnameAsync(string ip, CancellationToken token = default)
    {
        try
        {
            var entry = await Dns.GetHostEntryAsync(ip, token);
            return entry.HostName;
        }
        catch
        {
            return null;
        }
    }

    public async Task<string?> LookupVendorAsync(string? mac, CancellationToken token = default)
    {
        var normalized = DeviceIdentityHelper.NormalizeMac(mac);
        if (normalized is null || normalized.Length < 8) return null;

        var prefix = normalized[..8];
        var cached = await _db.GetCachedVendorAsync(prefix);
        if (!string.IsNullOrWhiteSpace(cached)) return cached;

        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(token);
            cts.CancelAfter(TimeSpan.FromSeconds(5));
            var url = $"https://api.macvendors.com/{normalized.Replace("-", ":")}";
            var vendor = await _http.GetStringAsync(url, cts.Token);
            if (!string.IsNullOrWhiteSpace(vendor))
            {
                await _db.CacheVendorAsync(prefix, vendor.Trim());
                return vendor.Trim();
            }
        }
        catch { }

        return null;
    }

    public string GuessOsHeuristic(IEnumerable<int> openPorts, string? vendor)
    {
        var ports = openPorts.ToHashSet();
        var v = vendor ?? string.Empty;

        if (ports.Contains(445) && ports.Contains(3389)) return "Windows";
        if (ports.Contains(445) && ports.Contains(135)) return "Windows";
        if (v.Contains("Apple", StringComparison.OrdinalIgnoreCase)) return "Apple device";
        if (ports.Contains(22) && ports.Contains(631)) return "Linux/Unix";
        if (ports.Contains(22) && !ports.Contains(445)) return "Linux/Unix";
        if (ports.Contains(9100) || ports.Contains(515)) return "Printer OS";
        if (ports.Contains(5000) || ports.Contains(5001)) return "NAS (likely Linux)";
        return string.Empty;
    }

    public async Task<(string? hint, string? source)> ProbeOsBannerAsync(string ip, IEnumerable<int> openPorts, CancellationToken token = default)
    {
        var ports = openPorts.ToHashSet();

        if (ports.Contains(22))
        {
            var ssh = await ReadTcpBannerAsync(ip, 22, token);
            if (!string.IsNullOrWhiteSpace(ssh))
                return (ParseSshBanner(ssh), "ssh-banner");
        }

        foreach (var port in new[] { 443, 80, 8080, 8443 }.Where(ports.Contains))
        {
            var header = await ReadHttpServerHeaderAsync(ip, port, token);
            if (!string.IsNullOrWhiteSpace(header))
                return (header, "http-server");
        }

        return (null, null);
    }

    public async Task<(string? hostname, string? vendor)> RefreshMetadataAsync(
        string ip, string? mac, bool resolveDns, bool lookupVendor, CancellationToken token = default)
    {
        string? hostname = null;
        string? vendor = null;

        if (resolveDns)
            hostname = await ResolveHostnameAsync(ip, token);

        if (lookupVendor)
            vendor = await LookupVendorAsync(mac, token);

        return (hostname, vendor);
    }

    public static string GetServiceName(int port) => port switch
    {
        21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        80 => "HTTP",
        110 => "POP3",
        135 => "RPC",
        139 => "NetBIOS",
        143 => "IMAP",
        443 => "HTTPS",
        445 => "SMB",
        3306 => "MySQL",
        3389 => "RDP",
        5000 => "UPnP",
        5432 => "PostgreSQL",
        5900 => "VNC",
        8080 => "HTTP-Alt",
        8443 => "HTTPS-Alt",
        9100 => "Print",
        _ => "TCP"
    };

    private static async Task<string?> ReadTcpBannerAsync(string ip, int port, CancellationToken token)
    {
        try
        {
            using var client = new TcpClient();
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(token);
            cts.CancelAfter(3000);
            await client.ConnectAsync(ip, port, cts.Token);
            client.ReceiveTimeout = 3000;
            using var stream = client.GetStream();
            var buffer = new byte[512];
            var read = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), cts.Token);
            return read > 0 ? Encoding.UTF8.GetString(buffer, 0, read).Trim() : null;
        }
        catch
        {
            return null;
        }
    }

    private async Task<string?> ReadHttpServerHeaderAsync(string ip, int port, CancellationToken token)
    {
        try
        {
            var scheme = port is 443 or 8443 ? "https" : "http";
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(token);
            cts.CancelAfter(4000);
            using var req = new HttpRequestMessage(HttpMethod.Head, $"{scheme}://{ip}:{port}/");
            using var resp = await _http.SendAsync(req, cts.Token);
            if (resp.Headers.TryGetValues("Server", out var values))
                return values.FirstOrDefault();
        }
        catch { }

        return null;
    }

    private static string ParseSshBanner(string banner)
    {
        var line = banner.Split('\n', '\r')[0].Trim();
        if (line.StartsWith("SSH-", StringComparison.OrdinalIgnoreCase))
            return line;
        return banner.Length > 80 ? banner[..80] : banner;
    }
}
