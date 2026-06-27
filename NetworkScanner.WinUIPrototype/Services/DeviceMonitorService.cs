using NetworkScanner.Services;

namespace NetworkScanner.WinUIPrototype.Services;

public sealed class DeviceMonitorService : IDisposable
{
    private readonly NetworkScannerService _scanner = new();
    private CancellationTokenSource? _cts;
    private readonly Queue<long> _recentLatencies = new();
    private const int MaxSamples = 20;

    public bool IsMonitoring { get; private set; }
    public string? TargetIp { get; private set; }
    public bool IsUp { get; private set; }
    public long LastLatencyMs { get; private set; }
    public double AverageLatencyMs { get; private set; }
    public double PacketLossPercent { get; private set; }

    public event Action? StatsUpdated;

    public void Start(string ip, int intervalMs = 3000)
    {
        Stop();
        TargetIp = ip;
        _cts = new CancellationTokenSource();
        IsMonitoring = true;
        _ = RunLoopAsync(ip, intervalMs, _cts.Token);
    }

    public void Stop()
    {
        _cts?.Cancel();
        _cts?.Dispose();
        _cts = null;
        IsMonitoring = false;
    }

    private async Task RunLoopAsync(string ip, int intervalMs, CancellationToken token)
    {
        int attempts = 0;
        int failures = 0;

        while (!token.IsCancellationRequested)
        {
            attempts++;
            var sw = System.Diagnostics.Stopwatch.StartNew();
            var ok = await _scanner.PingHostPublicAsync(ip, 3000, token);
            sw.Stop();

            if (ok)
            {
                IsUp = true;
                LastLatencyMs = sw.ElapsedMilliseconds;
                _recentLatencies.Enqueue(LastLatencyMs);
                while (_recentLatencies.Count > MaxSamples)
                    _recentLatencies.Dequeue();
                AverageLatencyMs = _recentLatencies.Count > 0 ? _recentLatencies.Average() : LastLatencyMs;
            }
            else
            {
                IsUp = false;
                failures++;
            }

            PacketLossPercent = attempts > 0 ? (failures * 100.0 / attempts) : 0;
            StatsUpdated?.Invoke();

            try
            {
                await Task.Delay(intervalMs, token);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }

    public void Dispose() => Stop();
}
