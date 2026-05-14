using Microsoft.UI.Text;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace NetworkScanner.WinUIPrototype.Pages;

public sealed class AboutPage : Page
{
    public AboutPage()
    {
        var panel = new StackPanel
        {
            Margin = new Thickness(16),
            Spacing = 10
        };

        panel.Children.Add(new TextBlock
        {
            Text = "About",
            FontSize = 24,
            FontWeight = FontWeights.SemiBold
        });

        panel.Children.Add(new TextBlock
        {
            Text = "Network Scanner WinUI 3 Prototype\nCompatibility mode enabled for local XAML stability.",
            TextWrapping = TextWrapping.Wrap,
            Opacity = 0.8
        });

        Content = panel;
    }
}
