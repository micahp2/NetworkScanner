using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Documents;
using Microsoft.UI.Xaml.Media;

namespace NetworkScanner.WinUIPrototype.Common;

public sealed class HighlightTextBlock : UserControl
{
    private readonly TextBlock _textBlock;

    private static readonly SolidColorBrush NormalHighlightFg = new(ColorHelper.FromArgb(0xFF, 0x7A, 0xAC, 0xFF));
    private static readonly SolidColorBrush StrongHighlightFg = new(ColorHelper.FromArgb(0xFF, 0x9B, 0xC3, 0xFF));

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
        var block = (HighlightTextBlock)d;
        ApplyHighlight(block._textBlock, block.FullText, block.HighlightText, block.UseStrongHighlight);
    }

    public static void ApplyHighlight(TextBlock textBlock, string? fullText, string? query, bool useStrongHighlight)
    {
        textBlock.Inlines.Clear();

        var text = fullText ?? string.Empty;
        if (string.IsNullOrEmpty(text))
        {
            return;
        }

        if (string.IsNullOrWhiteSpace(query))
        {
            textBlock.Inlines.Add(new Run { Text = text });
            return;
        }

        var highlightBrush = useStrongHighlight ? StrongHighlightFg : NormalHighlightFg;
        var idx = 0;
        while (idx < text.Length)
        {
            var hit = text.IndexOf(query, idx, StringComparison.OrdinalIgnoreCase);
            if (hit < 0)
            {
                textBlock.Inlines.Add(new Run { Text = text[idx..] });
                break;
            }

            if (hit > idx)
            {
                textBlock.Inlines.Add(new Run { Text = text[idx..hit] });
            }

            textBlock.Inlines.Add(new Run
            {
                Text = text.Substring(hit, query.Length),
                Foreground = highlightBrush,
                FontWeight = Microsoft.UI.Text.FontWeights.SemiBold
            });

            idx = hit + query.Length;
        }
    }
}
