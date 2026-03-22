namespace NetworkScanner;

using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Media;
using Microsoft.Win32;

public partial class App : Application
{
    // ── DWM dark title bar ───────────────────────────────────────────────────
    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr,
        ref int attrValue, int attrSize);

    private const int DWMWA_USE_IMMERSIVE_DARK_MODE_BEFORE_20H1 = 19;
    private const int DWMWA_USE_IMMERSIVE_DARK_MODE             = 20;

    // ── Sounds ───────────────────────────────────────────────────────────────
    [DllImport("winmm.dll", SetLastError = true)]
    private static extern bool PlaySound(string? pszSound, IntPtr hmod, uint fdwSound);

    private const uint SND_ALIAS  = 0x00010000;
    private const uint SND_ASYNC  = 0x00000001;
    private const uint SND_NODEFAULT = 0x00000002;

    public static void PlayScanComplete() =>
        PlaySound("Notification.Default", IntPtr.Zero, SND_ALIAS | SND_ASYNC | SND_NODEFAULT);

    public static void PlayScanStopped() =>
        PlaySound("SystemHand", IntPtr.Zero, SND_ALIAS | SND_ASYNC | SND_NODEFAULT);

    // ── Startup ──────────────────────────────────────────────────────────────
    protected override void OnStartup(StartupEventArgs e)
    {
        ApplyTheme();
        base.OnStartup(e);

        if (GetWindowsDarkMode() && MainWindow != null)
            HookDarkTitleBar(MainWindow);
    }

    private static void HookDarkTitleBar(Window window)
    {
        // ContentRendered fires after the window is first painted — the earliest
        // point where DWM attributes reliably take effect on the title bar.
        void Apply()
        {
            try
            {
                var hwnd = new System.Windows.Interop.WindowInteropHelper(window).Handle;
                if (hwnd == IntPtr.Zero) return;
                int dark = 1;
                DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, ref dark, sizeof(int));
                DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE_BEFORE_20H1, ref dark, sizeof(int));
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"DWM: {ex.Message}");
            }
        }

        window.SourceInitialized += (_, _) => Apply();
        window.ContentRendered   += (_, _) => Apply();
    }

    // ── Theme ─────────────────────────────────────────────────────────────────
    private void ApplyTheme()
    {
        try
        {
            bool dark = GetWindowsDarkMode();
            System.Diagnostics.Debug.WriteLine($"Dark mode: {dark}");

            if (dark)
            {
                // All values must be set so DynamicResource consumers update correctly
                Set("BackgroundBrush",       0x1E, 0x1E, 0x1E);
                Set("PanelBrush",            0x2D, 0x2D, 0x30);
                Set("BorderBrush",           0x3C, 0x3C, 0x3C);
                Set("TextBrush",             0xF0, 0xF0, 0xF0);
                Set("GridBackgroundBrush",   0x1E, 0x1E, 0x1E);
                Set("GridTextBrush",         0xF0, 0xF0, 0xF0);
                Set("GridAlternatingBrush",  0x2D, 0x2D, 0x30);
                Set("GridHeaderBrush",       0x3C, 0x3C, 0x3C);
                Set("InputBackgroundBrush",  0x32, 0x32, 0x32);
                Set("InputTextBrush",        0xF0, 0xF0, 0xF0);
                Set("HeaderTextBrush",       0xC8, 0xC8, 0xC8);
                Set("ButtonBackgroundBrush", 0x3C, 0x3C, 0x3C);
                Set("ButtonTextBrush",       0xF0, 0xF0, 0xF0);
                Set("ScrollTrackBrush",      0x1A, 0x1A, 0x1A);
                Set("ScrollThumbBrush",      0x50, 0x50, 0x50);
                Set("ScrollThumbHoverBrush", 0x78, 0x78, 0x78);
            }
            else
            {
                Set("BackgroundBrush",       0xFF, 0xFF, 0xFF);
                Set("PanelBrush",            0xF5, 0xF5, 0xF5);
                Set("BorderBrush",           0xDD, 0xDD, 0xDD);
                Set("TextBrush",             0x1A, 0x1A, 0x1A);
                Set("GridBackgroundBrush",   0xFF, 0xFF, 0xFF);
                Set("GridTextBrush",         0x1A, 0x1A, 0x1A);
                Set("GridAlternatingBrush",  0xF7, 0xF7, 0xF7);
                Set("GridHeaderBrush",       0xEB, 0xEB, 0xEB);
                Set("InputBackgroundBrush",  0xFF, 0xFF, 0xFF);
                Set("InputTextBrush",        0x1A, 0x1A, 0x1A);
                Set("HeaderTextBrush",       0x66, 0x66, 0x66);
                Set("ButtonBackgroundBrush", 0xE4, 0xE4, 0xE4);
                Set("ButtonTextBrush",       0x1A, 0x1A, 0x1A);
                Set("ScrollTrackBrush",      0xF0, 0xF0, 0xF0);
                Set("ScrollThumbBrush",      0xBB, 0xBB, 0xBB);
                Set("ScrollThumbHoverBrush", 0x88, 0x88, 0x88);
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"ApplyTheme: {ex.Message}");
        }
    }

    private void Set(string key, byte r, byte g, byte b) =>
        Resources[key] = new SolidColorBrush(Color.FromRgb(r, g, b));

    private static bool GetWindowsDarkMode()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
            if (key?.GetValue("AppsUseLightTheme") is int v)
                return v == 0;
        }
        catch { }
        return false;
    }
}
