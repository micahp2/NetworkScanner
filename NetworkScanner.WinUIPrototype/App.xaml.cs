using System;
using System.Diagnostics;
using System.IO;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using NetworkScanner.WinUIPrototype.ViewModels;

namespace NetworkScanner.WinUIPrototype;

public partial class App : Application
{
    // ── Sounds ───────────────────────────────────────────────────────────────
    [System.Runtime.InteropServices.DllImport("winmm.dll", SetLastError = true)]
    private static extern bool PlaySound(string? pszSound, IntPtr hmod, uint fdwSound);

    private const uint SND_ALIAS     = 0x00010000;
    private const uint SND_ASYNC     = 0x00000001;
    private const uint SND_NODEFAULT = 0x00000002;

    public static void PlayScanComplete() =>
        PlaySound("Notification.Default", IntPtr.Zero, SND_ALIAS | SND_ASYNC | SND_NODEFAULT);

    public static void PlayScanStopped() =>
        PlaySound("SystemHand", IntPtr.Zero, SND_ALIAS | SND_ASYNC | SND_NODEFAULT);

    private Window? _window;
    public Window? MainWindow => _window;

    public ScannerViewModel ScannerViewModel { get; } = new();

    public App()
    {
        // Safe to initialize app-level resources (App.xaml). We still avoid page/window XAML.
        InitializeComponent();
        UnhandledException += App_UnhandledException;
    }

    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        try
        {
            WriteCrashLog("OnLaunched.Start", new Exception("Launching app"));

            var navDiag = Environment.GetEnvironmentVariable("NS_NAV_DIAG");
            if (string.Equals(navDiag, "1", StringComparison.OrdinalIgnoreCase))
            {
                _window = new NavDiagWindow();
                WriteCrashLog("OnLaunched.NavDiagWindowCreated", new Exception("NavDiagWindow created"));
            }
            else
            {
                _window = new MainWindow();
                WriteCrashLog("OnLaunched.MainWindowCreated", new Exception("MainWindow created"));
            }

            _window.Activate();
            WriteCrashLog("OnLaunched.Activated", new Exception("Window activated"));
        }
        catch (Exception ex)
        {
            WriteCrashLog("OnLaunched.Exception", ex);

            // Final fallback so startup errors are visible instead of silent exit.
            var fallback = new Window
            {
                Content = new ScrollViewer
                {
                    Content = new TextBlock
                    {
                        Text = "Startup fallback window.\n\n" + ex,
                        TextWrapping = TextWrapping.Wrap,
                        Margin = new Thickness(16)
                    }
                }
            };

            fallback.Activate();
            _window = fallback;
        }
    }

    private void App_UnhandledException(object sender, Microsoft.UI.Xaml.UnhandledExceptionEventArgs e)
    {
        WriteCrashLog("UnhandledException", e.Exception);
    }

    private static void WriteCrashLog(string stage, Exception ex)
    {
        var message = $"[{DateTime.Now:O}] {stage}\n{ex}\n\n";

        try
        {
            var localDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "NetworkScanner.WinUIPrototype");
            Directory.CreateDirectory(localDir);
            File.AppendAllText(Path.Combine(localDir, "startup-crash.log"), message);
        }
        catch
        {
            // ignore local log failures
        }

        try
        {
            var exeDir = AppContext.BaseDirectory;
            File.AppendAllText(Path.Combine(exeDir, "startup-crash.log"), message);
        }
        catch
        {
            // ignore exe-dir log failures
        }

        try
        {
            Debug.WriteLine(message);
        }
        catch
        {
            // ignore debug output failures
        }
    }
}
