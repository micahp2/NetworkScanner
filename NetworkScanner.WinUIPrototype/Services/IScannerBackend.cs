using NetworkScanner.WinUIPrototype.Models;

namespace NetworkScanner.WinUIPrototype.Services;

public interface IScannerBackend
{
    string Name { get; }

    Task<IReadOnlyList<ScanResultRow>> ScanAsync(
        string ipRanges,
        string ports,
        bool scanIPv4,
        bool scanIPv6,
        CancellationToken token,
        Action<ScanResultRow>? onHostFound = null,
        Action<string>? onStatus = null);

    Task<IReadOnlyList<int>> ScanPortsForHostAsync(
        string ip,
        string ports,
        int portTimeoutMs,
        CancellationToken token,
        IProgress<int>? progress = null);
}
