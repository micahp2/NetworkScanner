using Microsoft.UI.Text;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace NetworkScanner.WinUIPrototype.Pages;

public sealed class DetailsPage : Page
{
    public DetailsPage()
    {
        var panel = new StackPanel
        {
            Margin = new Thickness(16),
            Spacing = 10
        };

        panel.Children.Add(new TextBlock
        {
            Text = "Details",
            FontSize = 24,
            FontWeight = FontWeights.SemiBold
        });

        panel.Children.Add(new TextBlock
        {
            Text = "Selected device details and expanded metadata will be shown here.",
            TextWrapping = TextWrapping.Wrap,
            Opacity = 0.8
        });

        Content = panel;
    }
}
