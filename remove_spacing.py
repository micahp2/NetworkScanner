from pathlib import Path
path = Path('MainWindow.xaml')
text = path.read_text(encoding='utf-8')
if 'Spacing="12"' not in text:
    print('pattern not found')
else:
    text = text.replace('Spacing="12"', '', 1)
    path.write_text(text, encoding='utf-8')
