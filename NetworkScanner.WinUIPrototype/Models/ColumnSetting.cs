using NetworkScanner.WinUIPrototype.Common;

namespace NetworkScanner.WinUIPrototype.Models;

public class ColumnSetting : ObservableObject
{
    private bool _isVisible = true;

    public string Key { get; init; } = string.Empty;
    public string Header { get; init; } = string.Empty;

    public bool IsVisible
    {
        get => _isVisible;
        set => SetProperty(ref _isVisible, value);
    }
}
