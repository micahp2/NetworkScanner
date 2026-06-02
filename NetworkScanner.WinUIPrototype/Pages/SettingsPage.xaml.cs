using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Data;
using NetworkScanner.WinUIPrototype.ViewModels;

namespace NetworkScanner.WinUIPrototype.Pages;

public sealed partial class SettingsPage : Page
{
    public SettingsPage()
    {
        // Ultra-safe compatibility page: avoid controls that have been unstable
        // on this machine (e.g., NumberBox/ToggleSwitch) and keep everything
        // code-built (no XAML parsing).
        var vm = ((App)Application.Current).ScannerViewModel;
        DataContext = vm;

        var root = new ScrollViewer();
        var panel = new StackPanel
        {
            Margin = new Thickness(16),
            Spacing = 10
        };

        panel.Children.Add(new TextBlock { Text = "Settings & Scan Options (prototype)", FontSize = 22 });
        panel.Children.Add(new TextBlock
        {
            Text = "Compatibility mode active for this machine.",
            Opacity = 0.8,
            TextWrapping = TextWrapping.Wrap
        });

        panel.Children.Add(new TextBlock { Text = "Scan Options", FontSize = 18, Margin = new Thickness(0, 8, 0, 0) });
        panel.Children.Add(MakeCheck("Resolve DNS", "ResolveDns"));
        panel.Children.Add(MakeCheck("Lookup MAC", "LookupMac"));
        panel.Children.Add(MakeCheck("Lookup Vendor", "LookupVendor"));
        panel.Children.Add(MakeCheck("Scan IPv4", "ScanIPv4"));
        panel.Children.Add(MakeCheck("Scan IPv6", "ScanIPv6"));

        panel.Children.Add(new TextBlock { Text = "Timeouts", FontSize = 18, Margin = new Thickness(0, 8, 0, 0) });
        panel.Children.Add(MakeTextSetting("Ping Timeout (ms)", "PingTimeoutMs"));
        panel.Children.Add(MakeTextSetting("Port Timeout (ms)", "PortTimeoutMs"));

        panel.Children.Add(new TextBlock { Text = "Appearance", FontSize = 18, Margin = new Thickness(0, 8, 0, 0) });
        panel.Children.Add(MakeTextSetting("Theme", "AppThemeMode"));

        panel.Children.Add(new TextBlock { Text = "Sound Events", FontSize = 18, Margin = new Thickness(0, 8, 0, 0) });
        panel.Children.Add(new CheckBox { Content = "Play scan complete sound (mock)", IsChecked = true });
        panel.Children.Add(new CheckBox { Content = "Play scan stopped sound (mock)", IsChecked = true });

        panel.Children.Add(new TextBlock { Text = "Persistence", FontSize = 18, Margin = new Thickness(0, 8, 0, 0) });
        panel.Children.Add(new CheckBox { Content = "Persist column layout (mock)", IsChecked = true });
        panel.Children.Add(new CheckBox { Content = "Persist known devices (mock)", IsChecked = true });
        panel.Children.Add(new CheckBox { Content = "Persist OUI vendor cache (mock)", IsChecked = true });

        root.Content = panel;
        Content = root;
    }

    private static CheckBox MakeCheck(string label, string bindingPath)
    {
        var cb = new CheckBox { Content = label };
        cb.SetBinding(CheckBox.IsCheckedProperty, new Binding
        {
            Path = new PropertyPath(bindingPath),
            Mode = BindingMode.TwoWay
        });
        return cb;
    }

    private static UIElement MakeTextSetting(string label, string bindingPath)
    {
        var row = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8 };
        row.Children.Add(new TextBlock { Text = label, Width = 160, VerticalAlignment = VerticalAlignment.Center });

        var tb = new TextBox { Width = 220 };
        tb.SetBinding(TextBox.TextProperty, new Binding
        {
            Path = new PropertyPath(bindingPath),
            Mode = BindingMode.TwoWay
        });

        row.Children.Add(tb);
        return row;
    }
}
