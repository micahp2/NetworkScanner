from pathlib import Path
path = Path('MainWindow.xaml.cs')
text = path.read_text(encoding='utf-8')
needle_fields = "    private readonly NetworkScannerService _scannerService;\r\n    private readonly ObservableCollection<ScanResult> _results;\r\n    private readonly HashSet<string> _resultIPIndex = new();\r\n\r\n    // Search state"
if needle_fields not in text:
    raise SystemExit('field block not found')
replacement_fields = "    private readonly NetworkScannerService _scannerService;\r\n    private readonly ObservableCollection<ScanResult> _results;\r\n    private readonly HashSet<string> _resultIPIndex = new();\r\n    private readonly EventHandler<bool> _themeChangedHandler;\r\n\r\n    // Search state"
text = text.replace(needle_fields, replacement_fields, 1)
needle_input = "        InputBindings.Add(new KeyBinding(\r\n            new RelayCommand(_ => OpenFindPopup()),\r\n            new KeyGesture(Key.F, ModifierKeys.Control)));\r\n\r\n        // Build context menu"
if needle_input not in text:
    raise SystemExit('input block not found')
replacement_input = "        InputBindings.Add(new KeyBinding(\r\n            new RelayCommand(_ => OpenFindPopup()),\r\n            new KeyGesture(Key.F, ModifierKeys.Control)));\r\n\r\n        _themeChangedHandler = (_, _) => UpdateThemeIndicator();\r\n        UpdateThemeIndicator();\r\n        App.ThemeChanged += _themeChangedHandler;\r\n\r\n        // Build context menu"
text = text.replace(needle_input, replacement_input, 1)
clear_block = "    private void ClearSearch()\r\n    {\r\n        _searchTerm = \"\";\r\n        foreach (var r in _results) { r.IsSearchMatch = false; r.SearchTerm = \"\"; }\r\n        _searchMatches.Clear();\r\n        _searchIndex  = -1;\r\n        SearchStatus.Text = \"\";\r\n    }\r\n\r\n    // ── Sorting"
if clear_block not in text:
    raise SystemExit('clear block not found')
new_clear = "    private void ClearSearch()\r\n    {\r\n        _searchTerm = \"\";\r\n        foreach (var r in _results) { r.IsSearchMatch = false; r.SearchTerm = \"\"; }\r\n        _searchMatches.Clear();\r\n        _searchIndex  = -1;\r\n        SearchStatus.Text = \"\";\r\n    }\r\n\r\n    private void UpdateThemeIndicator()\r\n    {\r\n        if (ThemeIndicator != null)\r\n        {\r\n            ThemeIndicator.Text = App.IsDarkMode ? \"Theme: Dark\" : \"Theme: Light\";\r\n        }\r\n    }\r\n\r\n    protected override void OnClosed(EventArgs e)\r\n    {\r\n        App.ThemeChanged -= _themeChangedHandler;\r\n        base.OnClosed(e);\r\n    }\r\n\r\n    // ── Sorting"
text = text.replace(clear_block, new_clear, 1)
path.write_text(text)
PY