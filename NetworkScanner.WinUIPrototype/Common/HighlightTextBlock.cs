using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Documents;
using Microsoft.UI.Xaml.Media;

namespace NetworkScanner.WinUIPrototype.Common;

public sealed class HighlightTextBlock : UserControl
{
    private readonly TextBlock _textBlock;

    public static readonly DependencyProperty FullTextProperty = DependencyProperty.Register(
        nameof(FullText), typeof(string), typeof(HighlightTextBlock),
        new PropertyMetadata(string.Empty, OnHighlightInputChanged));

    public static readonly DependencyProperty HighlightTextProperty = DependencyProperty.Register(
        nameof(HighlightText), typeof(string), typeof(HighlightTextBlock),
        new PropertyMetadata(string.Empty, OnHighlightInputChanged));

    public static readonly DependencyProperty UseStrongHighlightProperty = DependencyProperty.Register(
        nameof(UseStrongHighlight), typeof(bool), typeof(HighlightTextBlock),
        new PropertyMetadata(false, OnHighlightInputChanged));

    public HighlightTextBlock()
    {
        _textBlock = new TextBlock { TextTrimming = TextTrimming.CharacterEllipsis };
        Content = _textBlock;
    }

    public string FullText
    {
        get => (string)GetValue(FullTextProperty);
        set => SetValue(FullTextProperty, value);
    }

    public string HighlightText
    {
        get => (string)GetValue(HighlightTextProperty);
        set => SetValue(HighlightTextProperty, value);
    }

    public bool UseStrongHighlight
    {
        get => (bool)GetValue(UseStrongHighlightProperty);
        set => SetValue(UseStrongHighlightProperty, value);
    }

    private static void OnHighlightInputChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        ((HighlightTextBlock)d).RebuildInlines();
    }

    private void RebuildInlines()
    {
        _textBlock.Inlines.Clear();

        var text = FullText ?? string.Empty;
        var query = HighlightText ?? string.Empty;

        if (string.IsNullOrEmpty(text))
        {
            _textBlock.Inlines.Add(new Run { Text = string.Empty });
            return;
        }

        if (string.IsNullOrWhiteSpace(query))
        {
            _textBlock.Inlines.Add(new Run { Text = text });
            return;
        }

        var idx = 0;
        while (idx < text.Length)
        {
            var hit = text.IndexOf(query, idx, StringComparison.OrdinalIgnoreCase);
            if (hit < 0)
            {
                _textBlock.Inlines.Add(new Run { Text = text[idx..] });
                break;
            }

            if (hit > idx)
            {
                _textBlock.Inlines.Add(new Run { Text = text[idx..hit] });
            }

            var matchText = text.Substring(hit, query.Length);
            var run = new Run
            {
                Text = matchText,
                Foreground = UseStrongHighlight
                    ? new SolidColorBrush(ColorHelper.FromArgb(0xFF, 0x9B, 0xC3, 0xFF))
                    : new SolidColorBrush(ColorHelper.FromArgb(0xFF, 0x7A, 0xAC, 0xFF)),
                FontWeight = Microsoft.UI.Text.FontWeights.SemiBold
            };
            _textBlock.Inlines.Add(run);

            idx = hit + query.Length;
        }
    }
}
