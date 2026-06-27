using Microsoft.UI;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using NetworkScanner.Core;
using NetworkScanner.Services;
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
    private readonly HashSet<int> _livePorts = new();
    private readonly HashSet<int> _cachedPorts = new();
    private string _ipv6Address = string.Empty;
    private string _operatingSystem = string.Empty;
    private string _osHint = string.Empty;
    private string _osHintSource = string.Empty;
    private string _deviceIconKey = "Generic";
    private string _notes = string.Empty;
    private List<string> _tags = new();
    private readonly Dictionary<int, DevicePortActionConfig> _portActions = new();

    public bool IsOnline
    {
        get => _isOnline;
        set
        {
            if (SetProperty(ref _isOnline, value))
            {
                RaisePropertyChanged(nameof(StateLabel));
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

    public string CustomName
    {
        get => _customName;
        set
        {
            if (SetProperty(ref _customName, value))
                RaisePropertyChanged(nameof(DisplayName));
            RaisePropertyChanged(nameof(ListLabel));
        }
    }

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
    public string Hostname { get => _hostname; set { if (SetProperty(ref _hostname, value)) { RaisePropertyChanged(nameof(DisplayName)); RaisePropertyChanged(nameof(ListLabel)); } } }
    public string MACAddress { get => _macAddress; set => SetProperty(ref _macAddress, value); }
    public string Vendor { get => _vendor; set => SetProperty(ref _vendor, value); }
    public string OpenPorts
    {
        get => _openPorts;
        set
        {
            if (!SetProperty(ref _openPorts, value))
                return;

            if (_livePorts.Count == 0 && _cachedPorts.Count == 0)
                InferPortProvenanceFromOpenPorts();
        }
    }
    public string IPv6Address { get => _ipv6Address; set => SetProperty(ref _ipv6Address, value); }

    public string OperatingSystem { get => _operatingSystem; set => SetProperty(ref _operatingSystem, value); }
    public string OsHint { get => _osHint; set { if (SetProperty(ref _osHint, value)) RaisePropertyChanged(nameof(OsDisplayText)); } }
    public string OsHintSource { get => _osHintSource; set => SetProperty(ref _osHintSource, value); }
    public string DeviceIconKey { get => _deviceIconKey; set { if (SetProperty(ref _deviceIconKey, value)) { RaisePropertyChanged(nameof(ListLabel)); RaisePropertyChanged(nameof(DeviceIconSymbol)); } } }

    public Symbol DeviceIconSymbol => DeviceIconHelper.GetSymbol(DeviceIconKey);
    public string Notes { get => _notes; set => SetProperty(ref _notes, value); }

    public IReadOnlyList<string> Tags => _tags;

    public string DisplayName =>
        !string.IsNullOrWhiteSpace(CustomName) ? CustomName :
        !string.IsNullOrWhiteSpace(Hostname) ? Hostname :
        IPAddress;

    public string ListLabel =>
        DeviceIconKey is not "Generic" and not "" && !DeviceIconHelper.IsHexGlyphKey(DeviceIconKey)
            ? $"[{DeviceIconKey}] {DisplayName}"
            : DisplayName;

    public string OsDisplayText =>
        !string.IsNullOrWhiteSpace(OperatingSystem) ? OperatingSystem :
        !string.IsNullOrWhiteSpace(OsHint) ? OsHint :
        "Unknown";

    public bool CanPersistMetadata => DeviceIdentityHelper.IsValidMac(MACAddress);

    public IReadOnlyList<DevicePortDisplayItem> GetKnownPortDisplayItems()
    {
        return _livePorts.Union(_cachedPorts)
            .OrderBy(p => p)
            .Select(p =>
            {
                var action = GetPortAction(p);
                return new DevicePortDisplayItem
                {
                    Port = p,
                    ServiceName = DeviceEnrichmentService.GetServiceName(p),
                    Source = _livePorts.Contains(p) switch
                    {
                        true when _cachedPorts.Contains(p) => DevicePortSource.Both,
                        true => DevicePortSource.Live,
                        _ => DevicePortSource.Cached
                    },
                    ActionKind = action.Kind,
                    ActionLabel = action.Kind == DevicePortActionKind.Auto
                        ? string.Empty
                        : DevicePortActionHelper.GetShortLabel(action.Kind)
                };
            })
            .ToList();
    }

    public DevicePortActionConfig GetPortAction(int port) =>
        _portActions.TryGetValue(port, out var config) ? config.Clone() : DevicePortActionConfig.Auto;

    public void SetPortAction(int port, DevicePortActionConfig config)
    {
        if (config.IsDefault)
            _portActions.Remove(port);
        else
            _portActions[port] = config.Clone();
    }

    public void ClearPortActions() => _portActions.Clear();

    public string PortActionsJson => DevicePortActionHelper.Serialize(_portActions);

    public void SetPortActionsFromJson(string? json)
    {
        _portActions.Clear();
        foreach (var (port, config) in DevicePortActionHelper.Deserialize(json))
            _portActions[port] = config;
    }

    public void SetLivePortsFromScan(string portsText)
    {
        _livePorts.Clear();
        foreach (var port in ParsePorts(portsText))
            _livePorts.Add(port);
        SyncOpenPortsString();
    }

    public void SetCachedPortsFromDb(string portsText)
    {
        foreach (var port in ParsePorts(portsText))
            _cachedPorts.Add(port);
        SyncOpenPortsString();
    }

    public void MergeLivePorts(IEnumerable<int> ports)
    {
        foreach (var port in ports)
            _livePorts.Add(port);
        SyncOpenPortsString();
    }

    public void RetireLivePortsToCached()
    {
        foreach (var port in _livePorts)
            _cachedPorts.Add(port);
        _livePorts.Clear();
        SyncOpenPortsString();
    }

    public void MarkReachableLive()
    {
        IsCached = false;
        IsOnline = true;
        LastSeen = DateTimeOffset.Now;
    }

    private void InferPortProvenanceFromOpenPorts()
    {
        var ports = ParsePorts(_openPorts);
        if (!ports.Any())
            return;

        if (IsOnline && !IsCached)
        {
            _livePorts.Clear();
            foreach (var port in ports)
                _livePorts.Add(port);
        }
        else
        {
            foreach (var port in ports)
                _cachedPorts.Add(port);
        }
    }

    private void SyncOpenPortsString()
    {
        _openPorts = string.Join(", ", _livePorts.Union(_cachedPorts).OrderBy(p => p));
        RaisePropertyChanged(nameof(OpenPorts));
    }

    private static IEnumerable<int> ParsePorts(string portsText) => DeviceActions.ParseOpenPorts(portsText);

    public void SetTags(IEnumerable<string> tags)
    {
        _tags = tags.Where(t => !string.IsNullOrWhiteSpace(t)).Select(t => t.Trim()).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        RaisePropertyChanged(nameof(Tags));
        RaisePropertyChanged(nameof(TagsDisplay));
    }

    public string TagsDisplay => string.Join(", ", _tags);

    public void AddTag(string tag)
    {
        if (string.IsNullOrWhiteSpace(tag)) return;
        var t = tag.Trim();
        if (_tags.Contains(t, StringComparer.OrdinalIgnoreCase)) return;
        _tags.Add(t);
        RaisePropertyChanged(nameof(Tags));
        RaisePropertyChanged(nameof(TagsDisplay));
    }

    public void RemoveTag(string tag)
    {
        _tags.RemoveAll(x => string.Equals(x, tag, StringComparison.OrdinalIgnoreCase));
        RaisePropertyChanged(nameof(Tags));
        RaisePropertyChanged(nameof(TagsDisplay));
    }

    public string StateLabel =>
        IsOnline ? "Live" :
        IsCached ? "Cached" :
        "Offline";

    public SolidColorBrush StateBrush
    {
        get
        {
            if (IsOnline)
                return new SolidColorBrush(ColorHelper.FromArgb(0xFF, 0x39, 0xD3, 0x53)); // live/green

            if (IsCached)
                return new SolidColorBrush(ColorHelper.FromArgb(0xFF, 0xE1, 0xB8, 0x54)); // cached/amber

            return new SolidColorBrush(ColorHelper.FromArgb(0xFF, 0xE0, 0x5A, 0x5A)); // offline
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
