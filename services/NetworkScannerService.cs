namespace NetworkScanner.Services;

using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Net.Http;
using NetworkScanner.Models;

public class NetworkScannerService
{
    private CancellationTokenSource? _cancellationTokenSource;
    public event EventHandler<ScanResult>? HostFound;
    public event EventHandler<string>? StatusChanged;
    public event EventHandler? ScanCompleted;

    public bool IsScanning { get; private set; } = false;

    public async Task StartScanAsync(ScanOptions options)
    {
        IsScanning = true;
        _cancellationTokenSource = new CancellationTokenSource();
        var token = _cancellationTokenSource.Token;

        try
        {
            // Phase 1: Discover devices via kernel connection table
            // Extract subnet from first IP range (e.g., "192.168.2.0/24" -> "192.168.2")
            string? subnet = ExtractSubnetFromRange(options.IPRanges.FirstOrDefault());
            
            StatusChanged?.Invoke(this, $"Scanning subnet {subnet}...");
            var discoveredDevices = await Task.Run(() => IPHelperAPI.DiscoverDevicesFromConnectionTable(subnet), token);

            // Phase 2: Scan discovered devices
            StatusChanged?.Invoke(this, "Scanning for active devices...");
            await ScanDiscoveredIPsAsync(discoveredDevices, options, token);

            ScanCompleted?.Invoke(this, EventArgs.Empty);
        }
        catch (OperationCanceledException)
        {
            StatusChanged?.Invoke(this, "Scan cancelled");
        }
        catch (Exception ex)
        {
            StatusChanged?.Invoke(this, $"Error: {ex.Message}");
        }
        finally
        {
            IsScanning = false;
        }
    }

    private string? ExtractSubnetFromRange(string? range)
    {
        if (string.IsNullOrEmpty(range)) return null;

        try
        {
            // Handle both "192.168.2.0/24" and "192.168.2.1-254" formats
            var parts = range.Split(new[] { '/', '-' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length == 0) return null;

            var ip = parts[0];
            var octets = ip.Split('.');
            if (octets.Length != 4) return null;

            // Return first three octets (e.g., "192.168.2")
            return $"{octets[0]}.{octets[1]}.{octets[2]}";
        }
        catch
        {
            return null;
        }
    }

    public void StopScan()
    {
        _cancellationTokenSource?.Cancel();
    }

    private async Task ScanDiscoveredIPsAsync(HashSet<string> ips, ScanOptions options, CancellationToken token)
    {
        var tasks = new List<Task>();
        var semaphore = new SemaphoreSlim(10);

        foreach (var ip in ips)
        {
            if (token.IsCancellationRequested) break;

            await semaphore.WaitAsync(token);
            tasks.Add(Task.Run(async () =>
            {
                try
                {
                    var result = await ScanHostAsync(ip, options, token);
                    if (result != null && result.IsResponsive)
                    {
                        HostFound?.Invoke(this, result);
                    }
                }
                finally
                {
                    semaphore.Release();
                }
            }, token));
        }

        await Task.WhenAll(tasks);
    }

    private async Task<ScanResult?> ScanHostAsync(string ipAddress, ScanOptions options, CancellationToken token)
    {
        if (!await PingHostAsync(ipAddress, options.PingTimeout, token))
            return null;

        var result = new ScanResult
        {
            IPAddress = ipAddress,
            IPVersion = ipAddress.Contains(":") ? "IPv6" : "IPv4",
            IsResponsive = true
        };

        if (options.ResolveDNS)
        {
            result.Hostname = await ResolveHostnameAsync(ipAddress, token);
        }

        if (options.LookupMAC && result.IPVersion == "IPv4")
        {
            result.MACAddress = GetMACAddress(ipAddress);

            if (options.LookupVendor && result.MACAddress != null)
            {
                result.Vendor = await LookupVendorAsync(result.MACAddress, token);
            }
        }

        result.OpenPorts = await ScanPortsAsync(ipAddress, options.Ports, options.PortTimeout, token);

        return result;
    }

    private async Task<bool> PingHostAsync(string ipAddress, int timeout, CancellationToken token)
    {
        if (await ICMPPingAsync(ipAddress, timeout, token))
            return true;

        foreach (var port in new[] { 80, 443, 22, 8080, 3306, 445, 139, 5353, 67, 68 })
        {
            if (await TCPPingAsync(ipAddress, port, timeout / 2, token))
                return true;
        }

        return false;
    }

    private async Task<bool> ICMPPingAsync(string ipAddress, int timeout, CancellationToken token)
    {
        try
        {
            using (var ping = new Ping())
            {
                var result = await ping.SendPingAsync(ipAddress, timeout);
                return result.Status == IPStatus.Success;
            }
        }
        catch
        {
            return false;
        }
    }

    private async Task<bool> TCPPingAsync(string ipAddress, int port, int timeout, CancellationToken token)
    {
        try
        {
            using (var client = new TcpClient())
            {
                var task = client.ConnectAsync(ipAddress, port);
                var completedTask = await Task.WhenAny(task, Task.Delay(timeout, token));
                return completedTask == task && client.Connected;
            }
        }
        catch
        {
            return false;
        }
    }

    private async Task<string?> ResolveHostnameAsync(string ipAddress, CancellationToken token)
    {
        try
        {
            var hostEntry = await Dns.GetHostEntryAsync(ipAddress);
            return hostEntry.HostName;
        }
        catch
        {
            return null;
        }
    }

    private string? GetMACAddress(string ipAddress)
    {
        // Use IPHelperAPI with ARP probing for more complete MAC lookup
        return IPHelperAPI.ProbeAndGetMACAddress(ipAddress);
    }

    private async Task<string?> LookupVendorAsync(string macAddress, CancellationToken token)
    {
        if (string.IsNullOrEmpty(macAddress)) return null;
        
        try
        {
            var oui = macAddress.Replace("-", ":").Substring(0, 8).ToUpper();
            using (var client = new HttpClient { Timeout = TimeSpan.FromSeconds(2) })
            {
                var url = $"https://api.macvendors.com/{oui.Replace(":", "-")}";
                var response = await client.GetStringAsync(url);
                return response.Trim();
            }
        }
        catch
        {
            return null;
        }
    }

    private async Task<List<int>> ScanPortsAsync(string ipAddress, List<int> ports, int timeout, CancellationToken token)
    {
        var openPorts = new List<int>();
        var tasks = new List<Task>();

        foreach (var port in ports)
        {
            tasks.Add(Task.Run(async () =>
            {
                if (await TCPPingAsync(ipAddress, port, timeout, token))
                {
                    lock (openPorts)
                    {
                        openPorts.Add(port);
                    }
                }
            }, token));
        }

        await Task.WhenAll(tasks);
        return openPorts.OrderBy(p => p).ToList();
    }

}
