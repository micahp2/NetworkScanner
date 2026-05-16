using NetworkScanner.WinUIPrototype.Models;

namespace NetworkScanner.WinUIPrototype.Services;

public sealed class MockScannerBackend : IScannerBackend
{
    private readonly Random _random = new();

    public string Name => "Mock";

    public async Task<IReadOnlyList<ScanResultRow>> ScanAsync(
        string ipRanges,
        string ports,
        bool scanIPv4,
        bool scanIPv6,
        CancellationToken token,
        Action<ScanResultRow>? onHostFound = null,
        Action<string>? onStatus = null)
    {
        var now = DateTimeOffset.Now;
        var set = new List<ScanResultRow>();

        for (var i = 20; i < 32; i++)
        {
            token.ThrowIfCancellationRequested();
            await Task.Delay(_random.Next(40, 110), token);

            var row = new ScanResultRow
            {
                IsOnline = true,
                IsCached = false,
                CustomName = i % 2 == 0 ? $"Desk-{i}" : string.Empty,
                FirstSeen = now.AddMinutes(-_random.Next(3, 240)),
                LastSeen = now,
                IPAddress = $"192.168.1.{i}",
                Hostname = $"host-{i}",
                MACAddress = $"A4-5E-60-1F-2A-{i:X2}",
                Vendor = i % 3 == 0 ? "Ubiquiti Inc" : "Intel Corporate",
                OpenPorts = i % 2 == 0 ? "22, 80, 443" : "80",
                IPv6Address = i % 4 == 0 ? $"fd00::a45e:60ff:fe1f:{i:X2}" : string.Empty
            };

            set.Add(row);
            onHostFound?.Invoke(row);
            onStatus?.Invoke($"Scanning... {set.Count} active host(s) discovered");
        }

        return set;
    }
}
