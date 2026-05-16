namespace NetworkScanner.WinUIPrototype.Services;

public static class ScannerBackendFactory
{
    // Set NS_WINUI_BACKEND=mock to force demo mode.
    // Default is real scanning backend for parity work.
    public static IScannerBackend Create()
    {
        var mode = (Environment.GetEnvironmentVariable("NS_WINUI_BACKEND") ?? "real")
            .Trim()
            .ToLowerInvariant();

        return mode switch
        {
            "mock" => new MockScannerBackend(),
            _ => new RealScannerBackend()
        };
    }
}
