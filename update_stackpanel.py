from pathlib import Path
path=Path('MainWindow.xaml')
text=path.read_text(encoding='utf-8')
old="                <!-- Left: scan status message -->\n                <TextBlock x:Name=\"StatusText\" Grid.Column=\"0\"\n                           Text=\"Ready\" FontSize=\"11\"\n                           Foreground=\"{StaticResource TextBrush}\"\n                           VerticalAlignment=\"Center\" />\n\n                <!-- Right: version number as a clickable link to the repo -->\n"
new="                <!-- Left: scan status message -->\n                <StackPanel Grid.Column=\"0\" Orientation=\"Horizontal\" VerticalAlignment=\"Center\" Margin=\"0,0,12,0\">\n                    <TextBlock x:Name=\"StatusText\"\n                               Text=\"Ready\" FontSize=\"11\"\n                               Foreground=\"{StaticResource TextBrush}\"\n                               VerticalAlignment=\"Center\" />\n                    <TextBlock x:Name=\"ThemeIndicator\"\n                               Text=\"Theme: Light\" FontSize=\"10\"\n                               Foreground=\"{StaticResource HeaderTextBrush}\"\n                               VerticalAlignment=\"Center\"\n                               Margin=\"10,0,0,0\" />\n                </StackPanel>\n\n                <!-- Right: version number as a clickable link to the repo -->\n"
if old not in text:
    raise SystemExit('target block not found')
path.write_text(text.replace(old,new,1),encoding='utf-8')
