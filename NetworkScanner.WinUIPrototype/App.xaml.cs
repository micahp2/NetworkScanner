using System;
using System.IO;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using NetworkScanner.WinUIPrototype.ViewModels;

namespace NetworkScanner.WinUIPrototype;

public partial class App : Application
{
    private Window? _window;

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
            _window = new MainWindow();
            _window.Activate();
        }
        catch (Exception ex)
        {
            WriteCrashLog("OnLaunched", ex);

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
        try
        {
            var dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "NetworkScanner.WinUIPrototype");
            Directory.CreateDirectory(dir);
            var path = Path.Combine(dir, "startup-crash.log");
            File.AppendAllText(path, $"[{DateTime.Now:O}] {stage}\n{ex}\n\n");
        }
        catch
        {
            // ignore log failures
        }
    }
}
