namespace NetworkScanner;

using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;
using Microsoft.Win32;

public partial class App : Application
{
    // ── DWM P/Invoke ─────────────────────────────────────────────────────────
    [DllImport("dwmapi.dll", PreserveSig = true)]
    private static extern int DwmSetWindowAttribute(
        IntPtr hwnd, int attr, ref bool attrValue, int attrSize);

    [DllImport("dwmapi.dll", PreserveSig = true)]
    private static extern int DwmSetWindowAttribute(
        IntPtr hwnd, int attr, ref int attrValue, int attrSize);

    private const int DWMWA_USE_IMMERSIVE_DARK_MODE_BEFORE_20H1 = 19;
    private const int DWMWA_USE_IMMERSIVE_DARK_MODE             = 20;
    private const int DWMWA_CAPTION_COLOR                       = 35;
    private const int DWMWA_TEXT_COLOR                          = 36;

    // ── Sounds ───────────────────────────────────────────────────────────────
    [DllImport("winmm.dll", SetLastError = true)]
    private static extern bool PlaySound(string? pszSound, IntPtr hmod, uint fdwSound);

    private const uint SND_ALIAS     = 0x00010000;
    private const uint SND_ASYNC     = 0x00000001;
    private const uint SND_NODEFAULT = 0x00000002;

    public static void PlayScanComplete() =>
        PlaySound("Notification.Default", IntPtr.Zero, SND_ALIAS | SND_ASYNC | SND_NODEFAULT);

    public static void PlayScanStopped() =>
        PlaySound("SystemHand", IntPtr.Zero, SND_ALIAS | SND_ASYNC | SND_NODEFAULT);

    // WM_SETTINGCHANGE with lParam="ImmersiveColorSet" = theme toggled
    private const int WM_SETTINGCHANGE = 0x001A;

    // ── Startup ──────────────────────────────────────────────────────────────
    protected override void OnStartup(StartupEventArgs e)
    {
        ApplyTheme(GetWindowsDarkMode());

        // Must subscribe to Activated BEFORE base.OnStartup because base.OnStartup
        // processes StartupUri synchronously — SourceInitialized / ContentRendered
        // fire and complete inside that call, before it returns.
        Activated += OnFirstActivated;
        base.OnStartup(e);
    }

    private void OnFirstActivated(object? sender, EventArgs e)
    {
        Activated -= OnFirstActivated;
        if (MainWindow == null) return;

        var hwnd = new WindowInteropHelper(MainWindow).EnsureHandle();

        // Apply DWM attributes now that we have a valid, visible HWND
        ApplyTitleBar(hwnd, GetWindowsDarkMode());

        // Install the WndProc hook for live theme changes.
        // HwndSource.FromHwnd works here because the HWND is already live.
        var source = HwndSource.FromHwnd(hwnd);
        if (source != null)
            source.AddHook(ThemeWndProc);
        else
            System.Diagnostics.Debug.WriteLine("HwndSource.FromHwnd returned null");
    }

    // ── WndProc — catches WM_SETTINGCHANGE ───────────────────────────────────
    private IntPtr ThemeWndProc(IntPtr hwnd, int msg, IntPtr wParam,
                                IntPtr lParam, ref bool handled)
    {
        if (msg != WM_SETTINGCHANGE) return IntPtr.Zero;

        var param = Marshal.PtrToStringAuto(lParam);
        System.Diagnostics.Debug.WriteLine($"WM_SETTINGCHANGE: '{param}'");

        if (param == "ImmersiveColorSet")
        {
            bool dark = GetWindowsDarkMode();
            System.Diagnostics.Debug.WriteLine($"Theme switch → dark={dark}");

            // ApplyTheme swaps all DynamicResource brushes — the UI updates instantly
            ApplyTheme(dark);

            // Re-apply DWM title bar to match the new theme
            ApplyTitleBar(hwnd, dark);
        }

        return IntPtr.Zero;
    }

    // ── DWM title bar ─────────────────────────────────────────────────────────
    private static void ApplyTitleBar(IntPtr hwnd, bool dark)
    {
        if (hwnd == IntPtr.Zero) return;
        try
        {
            bool flag = dark;
            int r20 = DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE,
                ref flag, Marshal.SizeOf(flag));
            int r19 = DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE_BEFORE_20H1,
                ref flag, Marshal.SizeOf(flag));
            System.Diagnostics.Debug.WriteLine($"ApplyTitleBar dark={dark} attr20={r20} attr19={r19}");

            if (dark)
            {
                // RGB(45,45,48) → BGR 0x00302D2D
                int capBgr  = 0x00302D2D;
                int textBgr = 0x00F0F0F0;
                DwmSetWindowAttribute(hwnd, DWMWA_CAPTION_COLOR, ref capBgr,  sizeof(int));
                DwmSetWindowAttribute(hwnd, DWMWA_TEXT_COLOR,    ref textBgr, sizeof(int));
            }
            else
            {
                // 0xFFFFFFFF = DWMWA_COLOR_DEFAULT — let DWM use the system colour
                int def = unchecked((int)0xFFFFFFFF);
                DwmSetWindowAttribute(hwnd, DWMWA_CAPTION_COLOR, ref def, sizeof(int));
                DwmSetWindowAttribute(hwnd, DWMWA_TEXT_COLOR,    ref def, sizeof(int));
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"ApplyTitleBar error: {ex.Message}");
        }
    }

    // ── Theme brushes ─────────────────────────────────────────────────────────
    private void ApplyTheme(bool dark)
    {
        try
        {
            if (dark)
            {
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
