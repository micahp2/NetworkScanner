using Microsoft.UI.Text;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace NetworkScanner.WinUIPrototype.Pages;

public sealed class HelpPage : Page
{
    public HelpPage()
    {
        var panel = new StackPanel
        {
            Margin = new Thickness(16),
            Spacing = 10
        };

        panel.Children.Add(new TextBlock
        {
            Text = "Help",
            FontSize = 24,
            FontWeight = FontWeights.SemiBold
        });

        panel.Children.Add(new TextBlock
        {
            Text = "Help content, quick-start, and troubleshooting guidance will live here.",
            TextWrapping = TextWrapping.Wrap,
            Opacity = 0.8
        });

        Content = panel;
    }
}
