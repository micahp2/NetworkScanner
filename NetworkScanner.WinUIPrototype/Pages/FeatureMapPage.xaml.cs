using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace NetworkScanner.WinUIPrototype.Pages;

public sealed partial class FeatureMapPage : Page
{
    public FeatureMapPage()
    {
        // Intentionally avoid InitializeComponent() to bypass local XAML parse failures.
        var panel = new StackPanel
        {
            Margin = new Thickness(16),
            Spacing = 10
        };

        panel.Children.Add(new TextBlock
        {
            Text = "Feature Map",
            FontSize = 22
        });

        panel.Children.Add(new TextBlock
        {
            Text = "This prototype exposes the same major capabilities as the WPF app, with mocked interaction flows.",
            TextWrapping = TextWrapping.Wrap,
            Opacity = 0.85
        });

        panel.Children.Add(new TextBlock
        {
            Text = "- Scanner: IP/ports input, scan/stop, clear/export, result list, find, column toggles, context actions\n"
                 + "- Settings: DNS/MAC/vendor/IPv4/IPv6 toggles, timeouts, theme, sounds, persistence\n"
                 + "- Mock data/behavior: realistic rows, status updates, action logging\n"
                 + "- Compatibility mode: core shell and pages built in C# to avoid local XAML parser crashes",
            TextWrapping = TextWrapping.Wrap
        });

        panel.Children.Add(new TextBlock
        {
            Text = "Detailed mapping doc: docs/WINUI_PROTOTYPE_FEATURE_MAP.md",
            TextWrapping = TextWrapping.Wrap,
            Opacity = 0.8
        });

        Content = new ScrollViewer { Content = panel };
    }
}
