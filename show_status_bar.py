from pathlib import Path
text = Path('MainWindow.xaml').read_text(encoding='utf-8')
start = text.index('<!-- Left: scan status message')
end = text.index('<!-- Right: version number as a clickable link to the repo -->')
print(text[start:end])
