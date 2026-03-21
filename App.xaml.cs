namespace NetworkScanner;

using System.Windows;
using System.Windows.Media;
using Microsoft.Win32;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        // Apply theme before window loads
        ApplyTheme();
        base.OnStartup(e);
    }

    private void ApplyTheme()
    {
        try
        {
            var isDarkMode = GetWindowsDarkMode();
            System.Diagnostics.Debug.WriteLine($"Dark mode detected: {isDarkMode}");
            
            if (isDarkMode)
            {
                System.Diagnostics.Debug.WriteLine("Applying dark theme");
                Resources["BackgroundBrush"] = new SolidColorBrush(Color.FromRgb(30, 30, 30));
                Resources["PanelBrush"] = new SolidColorBrush(Color.FromRgb(45, 45, 48));
                Resources["BorderBrush"] = new SolidColorBrush(Color.FromRgb(60, 60, 60));
                Resources["TextBrush"] = new SolidColorBrush(Color.FromRgb(240, 240, 240));
                Resources["GridBackgroundBrush"] = new SolidColorBrush(Color.FromRgb(30, 30, 30));
                Resources["GridTextBrush"] = new SolidColorBrush(Color.FromRgb(240, 240, 240));
                Resources["GridAlternatingBrush"] = new SolidColorBrush(Color.FromRgb(45, 45, 48));
                Resources["GridHeaderBrush"] = new SolidColorBrush(Color.FromRgb(60, 60, 60));
                Resources["InputBackgroundBrush"] = new SolidColorBrush(Color.FromRgb(50, 50, 50));
                Resources["InputTextBrush"] = new SolidColorBrush(Color.FromRgb(240, 240, 240));
                Resources["HeaderTextBrush"] = new SolidColorBrush(Color.FromRgb(200, 200, 200));
                Resources["ButtonBackgroundBrush"] = new SolidColorBrush(Color.FromRgb(60, 60, 60));
                Resources["ButtonTextBrush"] = new SolidColorBrush(Color.FromRgb(240, 240, 240));
            }
            else
            {
                System.Diagnostics.Debug.WriteLine("Using light theme");
                Resources["BackgroundBrush"] = new SolidColorBrush(Color.FromRgb(255, 255, 255));
                Resources["PanelBrush"] = new SolidColorBrush(Color.FromRgb(245, 245, 245));
                Resources["BorderBrush"] = new SolidColorBrush(Color.FromRgb(224, 224, 224));
                Resources["TextBrush"] = new SolidColorBrush(Color.FromRgb(0, 0, 0));
                Resources["GridBackgroundBrush"] = new SolidColorBrush(Color.FromRgb(255, 255, 255));
                Resources["GridTextBrush"] = new SolidColorBrush(Color.FromRgb(0, 0, 0));
                Resources["GridAlternatingBrush"] = new SolidColorBrush(Color.FromRgb(245, 245, 245));
                Resources["GridHeaderBrush"] = new SolidColorBrush(Color.FromRgb(224, 224, 224));
                Resources["InputBackgroundBrush"] = new SolidColorBrush(Color.FromRgb(255, 255, 255));
                Resources["InputTextBrush"] = new SolidColorBrush(Color.FromRgb(0, 0, 0));
                Resources["HeaderTextBrush"] = new SolidColorBrush(Color.FromRgb(0, 0, 0));
                Resources["ButtonBackgroundBrush"] = new SolidColorBrush(Color.FromRgb(224, 224, 224));
                Resources["ButtonTextBrush"] = new SolidColorBrush(Color.FromRgb(0, 0, 0));
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"Error applying theme: {ex.Message}");
        }
    }

    private bool GetWindowsDarkMode()
    {
        try
        {
            var regKey = Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize", 
                writable: false);
            
            if (regKey == null)
                return false;

            var value = regKey.GetValue("AppsUseLightTheme");
            regKey.Close();

            System.Diagnostics.Debug.WriteLine($"AppsUseLightTheme value: {value}");

            // 0 = Dark mode, 1 = Light mode
            return value != null && value is int lightTheme && lightTheme == 0;
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"Registry read error: {ex.Message}");
            return false;
        }
    }
}
