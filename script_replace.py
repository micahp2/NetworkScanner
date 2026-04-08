from pathlib import Path
text=Path('MainWindow.xaml').read_text(encoding='utf-8')
old='                <StackPanel Grid.Column="0" Orientation="Horizontal" VerticalAlignment="Center" Spacing="12">'
new='                <StackPanel Grid.Column="0" Orientation="Horizontal" VerticalAlignment="Center">'
if old not in text:
    raise SystemExit('pattern not found')
Path('MainWindow.xaml').write_text(text.replace(old,new,1),encoding='utf-8')
