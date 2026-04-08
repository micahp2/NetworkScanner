from pathlib import Path
path = Path('MainWindow.xaml')
text = path.read_text(encoding='utf-8')
brushes = [
    'BackgroundBrush','PanelBrush','BorderBrush','TextBrush','GridBackgroundBrush',
    'GridTextBrush','GridAlternatingBrush','GridHeaderBrush','InputBackgroundBrush',
    'InputTextBrush','HeaderTextBrush','ButtonBackgroundBrush','ButtonTextBrush',
    'ScrollTrackBrush','ScrollThumbBrush','ScrollThumbHoverBrush'
]
for key in brushes:
    text = text.replace(f"{{StaticResource {key}}}", f"{{DynamicResource {key}}}")
path.write_text(text, encoding='utf-8')
