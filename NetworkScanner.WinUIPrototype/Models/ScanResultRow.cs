using Microsoft.UI;
using Microsoft.UI.Xaml.Media;
using NetworkScanner.WinUIPrototype.Common;

namespace NetworkScanner.WinUIPrototype.Models;

public class ScanResultRow : ObservableObject
{
    private static readonly SolidColorBrush TransparentBrush = new(ColorHelper.FromArgb(0x00, 0x00, 0x00, 0x00));
    private static readonly SolidColorBrush SearchMatchBrush = new(ColorHelper.FromArgb(0x22, 0x2E, 0x7D, 0xFF));
    private static readonly SolidColorBrush SearchCurrentBrush = new(ColorHelper.FromArgb(0x66, 0x2E, 0x7D, 0xFF));
    private static readonly SolidColorBrush SearchMatchBorderBrush = new(ColorHelper.FromArgb(0x44, 0x8C, 0xA8, 0xFF));
    private static readonly SolidColorBrush SearchCurrentBorderBrush = new(ColorHelper.FromArgb(0xCC, 0x8C, 0xA8, 0xFF));

    private bool _isOnline;
    private bool _isCached;
    private bool _isSearchMatch;
    private bool _isCurrentSearchHit;
    private bool _isSelectedRow;
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
        set
        {
            if (SetProperty(ref _isSearchMatch, value))
            {
                RaiseSearchRowChromeChanged();
            }
        }
    }

    public bool IsCurrentSearchHit
    {
        get => _isCurrentSearchHit;
        set
        {
            if (SetProperty(ref _isCurrentSearchHit, value))
            {
                RaiseSearchRowChromeChanged();
            }
        }
    }

    public string SearchQuery
    {
        get => _searchQuery;
        set => SetProperty(ref _searchQuery, value);
    }

    public void SetSelectedRow(bool selected)
    {
        if (SetProperty(ref _isSelectedRow, selected))
        {
            RaiseSearchRowChromeChanged();
        }
    }

    public SolidColorBrush SearchRowBackground
    {
        get
        {
            if (_isSelectedRow || IsCurrentSearchHit)
            {
                return SearchCurrentBrush;
            }

            if (IsSearchMatch)
            {
                return SearchMatchBrush;
            }

            return TransparentBrush;
        }
    }

    public SolidColorBrush SearchRowBorderBrush
    {
        get
        {
            if (_isSelectedRow || IsCurrentSearchHit)
            {
                return SearchCurrentBorderBrush;
            }

            if (IsSearchMatch)
            {
                return SearchMatchBorderBrush;
            }

            return TransparentBrush;
        }
    }

    public string CustomName { get => _customName; set => SetProperty(ref _customName, value); }

    public DateTimeOffset? FirstSeen
    {
        get => _firstSeen;
        set
        {
            if (SetProperty(ref _firstSeen, value))
            {
                RaisePropertyChanged(nameof(FirstSeenText));
            }
        }
    }

    public DateTimeOffset? LastSeen
    {
        get => _lastSeen;
        set
        {
            if (SetProperty(ref _lastSeen, value))
            {
                RaisePropertyChanged(nameof(LastSeenText));
            }
        }
    }

    public string FirstSeenText => FirstSeen?.ToString("yyyy-MM-dd HH:mm") ?? string.Empty;
    public string LastSeenText => LastSeen?.ToString("yyyy-MM-dd HH:mm") ?? string.Empty;

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
    public SolidColorBrush CustomNameCellBrush => CellBrush("CustomName");
    public SolidColorBrush IPv6AddressCellBrush => CellBrush("IPv6Address");

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
        RaisePropertyChanged(nameof(CustomNameCellBrush));
        RaisePropertyChanged(nameof(IPv6AddressCellBrush));
    }

    private void RaiseSearchRowChromeChanged()
    {
        RaisePropertyChanged(nameof(SearchRowBackground));
        RaisePropertyChanged(nameof(SearchRowBorderBrush));
    }

    private SolidColorBrush CellBrush(string key)
    {
        return string.Equals(_sortedColumn, key, StringComparison.OrdinalIgnoreCase)
            ? new SolidColorBrush(ColorHelper.FromArgb(0x1C, 0x4A, 0x8D, 0xF7))
            : new SolidColorBrush(ColorHelper.FromArgb(0x00, 0x00, 0x00, 0x00));
    }
}
