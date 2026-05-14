using System.Collections.ObjectModel;
using System.Text;
using NetworkScanner.WinUIPrototype.Common;
using NetworkScanner.WinUIPrototype.Models;

namespace NetworkScanner.WinUIPrototype.ViewModels;

public class ScannerViewModel : ObservableObject
{
    private readonly Random _random = new();
    private CancellationTokenSource? _scanCts;

    private string _ipRanges = "192.168.1.0/24";
    private string _ports = "80";
    private string _statusText = "Ready";
    private string _searchText = string.Empty;
    private string _scanButtonText = "Scan";
    private bool _isScanning;
    private bool _isSearching;
    private bool _showFindPanel;
    private string _mockActionLog = "No action yet.";
    private string _appThemeMode = "Use system theme";
    private ScanResultRow? _selectedResult;
    private string _sortColumn = "IPAddress";
    private bool _sortAscending = true;

    public ScannerViewModel()
    {
        Results = new ObservableCollection<ScanResultRow>();
        ColumnSettings = new ObservableCollection<ColumnSetting>
        {
            new() { Key = "Online", Header = "Online" },
            new() { Key = "State", Header = "State" },
            new() { Key = "CustomName", Header = "Custom Name" },
            new() { Key = "FirstSeen", Header = "First Seen" },
            new() { Key = "LastSeen", Header = "Last Seen" },
            new() { Key = "IPAddress", Header = "IP Address" },
            new() { Key = "Hostname", Header = "Hostname" },
            new() { Key = "MACAddress", Header = "MAC Address" },
            new() { Key = "Vendor", Header = "Vendor" },
            new() { Key = "OpenPorts", Header = "Open Ports" },
            new() { Key = "IPv6Address", Header = "IPv6 Address" }
        };

        StartStopScanCommand = new RelayCommand(async () => await StartStopScanAsync());
        ClearCommand = new RelayCommand(ClearResults);
        ExportCommand = new RelayCommand(ExportMock);
        ToggleFindCommand = new RelayCommand(ToggleSearchState);
        FindNextCommand = new RelayCommand(FindNext);
        FindPreviousCommand = new RelayCommand(FindPrevious);

        CopyFieldCommand = new RelayCommand(p => LogMockAction($"Copy: {p}"));
        BrowsePortCommand = new RelayCommand(p => LogMockAction($"Browse: {p}"));
        ShellCommand = new RelayCommand(p => LogMockAction($"Shell: {p}"));

        LoadMockCachedDevices();
        ApplySortColumnHighlights();
        RefreshStatus();
    }

    public ObservableCollection<ScanResultRow> Results { get; }
    public ObservableCollection<ColumnSetting> ColumnSettings { get; }

    public RelayCommand StartStopScanCommand { get; }
    public RelayCommand ClearCommand { get; }
    public RelayCommand ExportCommand { get; }
    public RelayCommand ToggleFindCommand { get; }
    public RelayCommand FindNextCommand { get; }
    public RelayCommand FindPreviousCommand { get; }
    public RelayCommand CopyFieldCommand { get; }
    public RelayCommand BrowsePortCommand { get; }
    public RelayCommand ShellCommand { get; }

    public string IPRanges
    {
        get => _ipRanges;
        set => SetProperty(ref _ipRanges, value);
    }

    public string Ports
    {
        get => _ports;
        set => SetProperty(ref _ports, value);
    }

    public string StatusText
    {
        get => _statusText;
        set => SetProperty(ref _statusText, value);
    }

    public string SearchText
    {
        get => _searchText;
        set
        {
            if (SetProperty(ref _searchText, value))
            {
                CurrentSearchIndex = -1;
                SelectedResult = null;
                ApplySearchHighlights();
                RaisePropertyChanged(nameof(SearchStatusText));
                RaisePropertyChanged(nameof(SearchMatchCount));
                RaisePropertyChanged(nameof(CanNavigateSearch));
            }
        }
    }

    public bool ShowFindPanel
    {
        get => _showFindPanel;
        set => SetProperty(ref _showFindPanel, value);
    }

    public bool IsSearching
    {
        get => _isSearching;
        set
        {
            if (SetProperty(ref _isSearching, value))
            {
                RaisePropertyChanged(nameof(SearchButtonText));
                RaisePropertyChanged(nameof(SearchStatusText));
                RaisePropertyChanged(nameof(SearchMatchCount));
                RaisePropertyChanged(nameof(CanNavigateSearch));
            }
        }
    }

    public string SearchButtonText => IsSearching ? "Cancel" : "Search";

    public string ScanButtonText
    {
        get => _scanButtonText;
        set => SetProperty(ref _scanButtonText, value);
    }

    public bool IsScanning
    {
        get => _isScanning;
        set => SetProperty(ref _isScanning, value);
    }

    public string MockActionLog
    {
        get => _mockActionLog;
        set => SetProperty(ref _mockActionLog, value);
    }

    public string AppThemeMode
    {
        get => _appThemeMode;
        set => SetProperty(ref _appThemeMode, value);
    }

    public ScanResultRow? SelectedResult
    {
        get => _selectedResult;
        set => SetProperty(ref _selectedResult, value);
    }

    public bool ResolveDns { get; set; } = true;
    public bool LookupMac { get; set; } = true;
    public bool LookupVendor { get; set; } = true;
    public bool ScanIPv4 { get; set; } = true;
    public bool ScanIPv6 { get; set; }
    public int PingTimeoutMs { get; set; } = 3000;
    public int PortTimeoutMs { get; set; } = 1500;

    public int CurrentSearchIndex { get; private set; } = -1;
    public int SearchNavigationVersion { get; private set; }

    public string SearchStatusText
    {
        get
        {
            var matches = MatchingRows().ToList();
            if (string.IsNullOrWhiteSpace(SearchText)) return string.Empty;
            if (matches.Count == 0) return "No matches";
            if (CurrentSearchIndex < 0) return $"{matches.Count} matches";
            return $"{CurrentSearchIndex + 1} / {matches.Count}";
        }
    }

    public int SearchMatchCount => MatchingRows().Count();

    public bool CanNavigateSearch => SearchMatchCount > 1;

    private async Task StartStopScanAsync()
    {
        if (IsScanning)
        {
            _scanCts?.Cancel();
            IsScanning = false;
            ScanButtonText = "Scan";
            StatusText = "Scan stopped (mock).";
            return;
        }

        IsScanning = true;
        ScanButtonText = "Stop";
        _scanCts = new CancellationTokenSource();

        try
        {
            var token = _scanCts.Token;
            var hosts = BuildMockTargetList();
            var freshCount = 0;

            StatusText = $"Building scan list... {hosts.Count} targets";
            await Task.Delay(300, token);

            foreach (var host in hosts)
            {
                token.ThrowIfCancellationRequested();
                await Task.Delay(_random.Next(70, 190), token);

                Results.Insert(0, host);
                ApplySortColumnHighlights();
                ApplySearchHighlights();
                freshCount++;
                RefreshStatus();
            }

            StatusText = $"Scan complete - {freshCount} live host(s) (mock)";
            LogMockAction("Scan complete sound event (mock).\nVendor lookup, DNS, MAC, and port scan were simulated.");
        }
        catch (OperationCanceledException)
        {
            StatusText = "Scan cancelled (mock).";
        }
        finally
        {
            IsScanning = false;
            ScanButtonText = "Scan";
        }
    }

    private List<ScanResultRow> BuildMockTargetList()
    {
        var set = new List<ScanResultRow>();
        var now = DateTimeOffset.Now;

        for (var i = 20; i < 32; i++)
        {
            set.Add(new ScanResultRow
            {
                IsOnline = true,
                IsCached = false,
                CustomName = i % 2 == 0 ? $"Desk-{i}" : string.Empty,
                FirstSeen = now.AddMinutes(-_random.Next(3, 240)),
                LastSeen = now,
                IPAddress = $"192.168.1.{i}",
                Hostname = $"host-{i}",
                MACAddress = $"A4-5E-60-1F-2A-{i:X2}",
                Vendor = i % 3 == 0 ? "Ubiquiti Inc" : "Intel Corporate",
                OpenPorts = i % 2 == 0 ? "22, 80, 443" : "80",
                IPv6Address = i % 4 == 0 ? $"fd00::a45e:60ff:fe1f:{i:X2}" : string.Empty
            });
        }

        return set;
    }

    private void ClearResults()
    {
        Results.Clear();
        CurrentSearchIndex = -1;
        ApplySortColumnHighlights();
        ApplySearchHighlights();
        RefreshStatus();
        StatusText = "Ready";
    }

    private void ExportMock()
    {
        var csv = new StringBuilder();
        csv.AppendLine("IP Address,Hostname,MAC Address,Vendor,Open Ports,IPv6 Address");
        foreach (var row in Results)
        {
            csv.AppendLine($"\"{row.IPAddress}\",\"{row.Hostname}\",\"{row.MACAddress}\",\"{row.Vendor}\",\"{row.OpenPorts}\",\"{row.IPv6Address}\"");
        }

        LogMockAction($"Exported {Results.Count} row(s) to CSV (mock).\nPreview length: {csv.Length} chars.");
    }

    private void ToggleSearchState()
    {
        if (IsSearching)
        {
            IsSearching = false;
            ShowFindPanel = false;
            SearchText = string.Empty;
            CurrentSearchIndex = -1;
            ApplySearchHighlights();
            RaisePropertyChanged(nameof(SearchStatusText));
            return;
        }

        IsSearching = true;
        ShowFindPanel = true;
        CurrentSearchIndex = -1;
        ApplySearchHighlights();
        RaisePropertyChanged(nameof(SearchStatusText));
    }

    private void FindNext()
    {
        var matches = MatchingRows().ToList();
        if (matches.Count == 0)
        {
            CurrentSearchIndex = -1;
            SelectedResult = null;
            ApplySearchHighlights();
            RaisePropertyChanged(nameof(SearchStatusText));
            return;
        }

        CurrentSearchIndex = (CurrentSearchIndex + 1) % matches.Count;
        SelectedResult = matches[CurrentSearchIndex];
        SearchNavigationVersion++;
        RaisePropertyChanged(nameof(SearchNavigationVersion));
        ApplySearchHighlights();
        LogMockAction($"Find next: {matches[CurrentSearchIndex].IPAddress}");
        RaisePropertyChanged(nameof(SearchStatusText));
    }

    private void FindPrevious()
    {
        var matches = MatchingRows().ToList();
        if (matches.Count == 0)
        {
            CurrentSearchIndex = -1;
            SelectedResult = null;
            ApplySearchHighlights();
            RaisePropertyChanged(nameof(SearchStatusText));
            return;
        }

        CurrentSearchIndex = (CurrentSearchIndex - 1 + matches.Count) % matches.Count;
        SelectedResult = matches[CurrentSearchIndex];
        SearchNavigationVersion++;
        RaisePropertyChanged(nameof(SearchNavigationVersion));
        ApplySearchHighlights();
        LogMockAction($"Find previous: {matches[CurrentSearchIndex].IPAddress}");
        RaisePropertyChanged(nameof(SearchStatusText));
    }

    private IEnumerable<ScanResultRow> MatchingRows()
    {
        if (string.IsNullOrWhiteSpace(SearchText))
        {
            return Enumerable.Empty<ScanResultRow>();
        }

        return Results.Where(r =>
            r.IPAddress.Contains(SearchText, StringComparison.OrdinalIgnoreCase) ||
            r.Hostname.Contains(SearchText, StringComparison.OrdinalIgnoreCase) ||
            r.MACAddress.Contains(SearchText, StringComparison.OrdinalIgnoreCase) ||
            r.Vendor.Contains(SearchText, StringComparison.OrdinalIgnoreCase) ||
            r.OpenPorts.Contains(SearchText, StringComparison.OrdinalIgnoreCase) ||
            r.IPv6Address.Contains(SearchText, StringComparison.OrdinalIgnoreCase) ||
            r.CustomName.Contains(SearchText, StringComparison.OrdinalIgnoreCase));
    }

    private void ApplySearchHighlights()
    {
        foreach (var row in Results)
        {
            row.IsSearchMatch = false;
            row.IsCurrentSearchHit = false;
            row.SearchQuery = SearchText;
        }

        var matches = MatchingRows().ToList();
        for (var i = 0; i < matches.Count; i++)
        {
            var row = matches[i];
            row.IsSearchMatch = true;
            row.IsCurrentSearchHit = i == CurrentSearchIndex;
        }

        RaisePropertyChanged(nameof(SearchStatusText));
        RaisePropertyChanged(nameof(SearchMatchCount));
        RaisePropertyChanged(nameof(CanNavigateSearch));
    }

    private void ApplySortColumnHighlights()
    {
        foreach (var row in Results)
        {
            row.SetSortedColumn(_sortColumn);
        }
    }

    private void LoadMockCachedDevices()
    {
        var now = DateTimeOffset.Now;

        Results.Add(new ScanResultRow
        {
            IsOnline = true,
            IsCached = true,
            CustomName = "NAS",
            FirstSeen = now.AddDays(-20),
            LastSeen = now.AddHours(-8),
            IPAddress = "192.168.1.10",
            Hostname = "nas-main",
            MACAddress = "B8-27-EB-55-12-99",
            Vendor = "Raspberry Pi Foundation",
            OpenPorts = "22, 445",
            IPv6Address = "fd00::b827:ebff:fe55:1299"
        });

        Results.Add(new ScanResultRow
        {
            IsOnline = false,
            IsCached = true,
            CustomName = "Printer",
            FirstSeen = now.AddDays(-11),
            LastSeen = now.AddHours(-28),
            IPAddress = "192.168.1.40",
            Hostname = "hp-laserjet",
            MACAddress = "D0-37-45-A1-18-CC",
            Vendor = "HP Inc.",
            OpenPorts = "80, 9100",
            IPv6Address = string.Empty
        });
    }

    private void RefreshStatus()
    {
        var live = Results.Count(r => !r.IsCached);
        var cached = Results.Count(r => r.IsCached);
        StatusText = $"Live: {live} | Cached: {cached} | Total: {Results.Count}";
    }

    private void LogMockAction(string message)
    {
        MockActionLog = $"{DateTime.Now:HH:mm:ss}  {message}";
    }

    public bool IsColumnVisible(string key)
        => ColumnSettings.FirstOrDefault(c => c.Key == key)?.IsVisible ?? true;

    public string CurrentSortColumn => _sortColumn;
    public bool IsSortAscending => _sortAscending;

    public void SortBy(string columnKey)
    {
        if (string.IsNullOrWhiteSpace(columnKey)) return;

        if (string.Equals(_sortColumn, columnKey, StringComparison.OrdinalIgnoreCase))
        {
            _sortAscending = !_sortAscending;
        }
        else
        {
            _sortColumn = columnKey;
            _sortAscending = true;
        }

        RaisePropertyChanged(nameof(CurrentSortColumn));
        RaisePropertyChanged(nameof(IsSortAscending));

        IEnumerable<ScanResultRow> ordered = columnKey switch
        {
            "Hostname" => _sortAscending ? Results.OrderBy(r => r.Hostname) : Results.OrderByDescending(r => r.Hostname),
            "IPAddress" => _sortAscending ? Results.OrderBy(r => r.IPAddress) : Results.OrderByDescending(r => r.IPAddress),
            "MACAddress" => _sortAscending ? Results.OrderBy(r => r.MACAddress) : Results.OrderByDescending(r => r.MACAddress),
            "StateLabel" => _sortAscending ? Results.OrderBy(r => r.StateLabel) : Results.OrderByDescending(r => r.StateLabel),
            "Vendor" => _sortAscending ? Results.OrderBy(r => r.Vendor) : Results.OrderByDescending(r => r.Vendor),
            "OpenPorts" => _sortAscending ? Results.OrderBy(r => r.OpenPorts) : Results.OrderByDescending(r => r.OpenPorts),
            _ => _sortAscending ? Results.OrderBy(r => r.IPAddress) : Results.OrderByDescending(r => r.IPAddress)
        };

        var snapshot = ordered.ToList();
        Results.Clear();
        foreach (var row in snapshot)
        {
            Results.Add(row);
        }

        ApplySortColumnHighlights();
        ApplySearchHighlights();
    }
}

