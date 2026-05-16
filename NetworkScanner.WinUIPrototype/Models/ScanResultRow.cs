using Microsoft.UI;
using Microsoft.UI.Xaml.Media;
using NetworkScanner.WinUIPrototype.Common;

namespace NetworkScanner.WinUIPrototype.Models;

public class ScanResultRow : ObservableObject
{
    private bool _isOnline;
    private bool _isCached;
    private bool _isSearchMatch;
    private bool _isCurrentSearchHit;
    private string _searchQuery = string.Empty;
    private string _sortedColumn = string.Empty;

    private string _customName = string.Empty;
    private DateTimeOffset? _firstSeen;
    private DateTimeOffset? _lastSeen;
    private string _ipAddress = string.Empty;
    private string _hostname = string.Empty;
    private string _macAddress = string.Empty;
    private string _vendor = string.Empty;
    private string _openPorts = string.Empty;
    private string _ipv6Address = string.Empty;

    public bool IsOnline
    {
        get => _isOnline;
        set
        {
            if (SetProperty(ref _isOnline, value))
            {
                RaisePropertyChanged(nameof(StateBrush));
            }
        }
    }

    public bool IsCached
    {
        get => _isCached;
        set
        {
            if (SetProperty(ref _isCached, value))
            {
                RaisePropertyChanged(nameof(StateLabel));
                RaisePropertyChanged(nameof(StateBrush));
            }
        }
    }

    public bool IsSearchMatch
    {
        get => _isSearchMatch;
        set => SetProperty(ref _isSearchMatch, value);
    }

    public bool IsCurrentSearchHit
    {
        get => _isCurrentSearchHit;
        set => SetProperty(ref _isCurrentSearchHit, value);
    }

    public string SearchQuery
    {
        get => _searchQuery;
        set => SetProperty(ref _searchQuery, value);
    }

    public string CustomName { get => _customName; set => SetProperty(ref _customName, value); }
    public DateTimeOffset? FirstSeen { get => _firstSeen; set => SetProperty(ref _firstSeen, value); }
    public DateTimeOffset? LastSeen { get => _lastSeen; set => SetProperty(ref _lastSeen, value); }
    public string IPAddress { get => _ipAddress; set => SetProperty(ref _ipAddress, value); }
    public string Hostname { get => _hostname; set => SetProperty(ref _hostname, value); }
    public string MACAddress { get => _macAddress; set => SetProperty(ref _macAddress, value); }
    public string Vendor { get => _vendor; set => SetProperty(ref _vendor, value); }
    public string OpenPorts { get => _openPorts; set => SetProperty(ref _openPorts, value); }
    public string IPv6Address { get => _ipv6Address; set => SetProperty(ref _ipv6Address, value); }

    public string StateLabel => IsCached ? "Cached" : (IsOnline ? "Live" : "Offline");

    public SolidColorBrush StateBrush
    {
        get
        {
            if (IsCached)
                return new SolidColorBrush(ColorHelper.FromArgb(0xFF, 0xE1, 0xB8, 0x54)); // cached/amber

            if (!IsOnline)
                return new SolidColorBrush(ColorHelper.FromArgb(0xFF, 0xE0, 0x5A, 0x5A)); // offline

            return new SolidColorBrush(ColorHelper.FromArgb(0xFF, 0x39, 0xD3, 0x53)); // live/green
        }
    }

    public SolidColorBrush HostnameCellBrush => CellBrush("Hostname");
    public SolidColorBrush IPAddressCellBrush => CellBrush("IPAddress");
    public SolidColorBrush MACAddressCellBrush => CellBrush("MACAddress");
    public SolidColorBrush StatusCellBrush => CellBrush("StateLabel");
    public SolidColorBrush FirstSeenCellBrush => CellBrush("FirstSeen");
    public SolidColorBrush LastSeenCellBrush => CellBrush("LastSeen");
    public SolidColorBrush VendorCellBrush => CellBrush("Vendor");
    public SolidColorBrush OpenPortsCellBrush => CellBrush("OpenPorts");

    public void SetSortedColumn(string key)
    {
        _sortedColumn = key ?? string.Empty;
        RaisePropertyChanged(nameof(HostnameCellBrush));
        RaisePropertyChanged(nameof(IPAddressCellBrush));
        RaisePropertyChanged(nameof(MACAddressCellBrush));
        RaisePropertyChanged(nameof(StatusCellBrush));
        RaisePropertyChanged(nameof(FirstSeenCellBrush));
        RaisePropertyChanged(nameof(LastSeenCellBrush));
        RaisePropertyChanged(nameof(VendorCellBrush));
        RaisePropertyChanged(nameof(OpenPortsCellBrush));
    }

    private SolidColorBrush CellBrush(string key)
    {
        return string.Equals(_sortedColumn, key, StringComparison.OrdinalIgnoreCase)
            ? new SolidColorBrush(ColorHelper.FromArgb(0x1C, 0x4A, 0x8D, 0xF7))
            : new SolidColorBrush(ColorHelper.FromArgb(0x00, 0x00, 0x00, 0x00));
    }
}