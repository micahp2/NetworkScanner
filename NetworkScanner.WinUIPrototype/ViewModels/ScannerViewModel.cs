using System.Collections.ObjectModel;
using System.Linq;
using System.Text;
using NetworkScanner.WinUIPrototype.Common;
using NetworkScanner.WinUIPrototype.Models;
using NetworkScanner.WinUIPrototype.Services;
using NetworkScanner.Services;
using NetworkScanner.Models;
using Microsoft.UI.Dispatching;
using System.Net;
using System.Net.Sockets;

namespace NetworkScanner.WinUIPrototype.ViewModels;

public enum ScanLifecycleState
{
    Idle,
    Scanning,
    Cancelling,
    Completed,
    Cancelled,
    Faulted
}

public class ScannerViewModel : ObservableObject
{
    private readonly Random _random = new();
    private readonly ObservableCollection<string> _scanStateTransitions = new();
    private readonly IScannerBackend _backend;
    private readonly DispatcherQueue? _dispatcherQueue;
    private readonly DatabaseService _dbService;
    private readonly HashSet<string> _resultIPIndex = new(StringComparer.OrdinalIgnoreCase);
    private CancellationTokenSource? _scanCts;

    private string _ipRanges = string.Empty;
    private string _ports = "80";
    private string _statusText = "Ready";
    private string _searchText = string.Empty;
    private string _scanButtonText = "Scan";
    private bool _isScanning;
    private ScanLifecycleState _scanState = ScanLifecycleState.Idle;
    private bool _isSearching;
    private bool _showFindPanel;
    private string _mockActionLog = "No action yet.";
    private string _appThemeMode = "Use system theme";
    private ScanResultRow? _selectedResult;
    private string _sortColumn = "IPAddress";
    private bool _sortAscending = true;
    private string _lastBackendStatus = "Ready";

    public ScannerViewModel()
    {
        _backend = ScannerBackendFactory.Create();
        _dispatcherQueue = DispatcherQueue.GetForCurrentThread();
        PopulateNetworkRanges();
        _dbService = new DatabaseService();
        _ = _dbService.InitializeAsync();
        Results = new ObservableCollection<ScanResultRow>();
        ScanStateTransitions = new ReadOnlyObservableCollection<string>(_scanStateTransitions);
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

        if (string.Equals(_backend.Name, "Mock", StringComparison.OrdinalIgnoreCase))
        {
            LoadMockCachedDevices();
        }
        else
        {
            _ = LoadCachedDevicesAsync();
        }
        ApplySortColumnHighlights();
        RefreshStatus();
    }

    public ObservableCollection<string> DetectedRanges { get; } = new();
    public ObservableCollection<ScanResultRow> Results { get; }
    public ObservableCollection<ColumnSetting> ColumnSettings { get; }
    public ReadOnlyObservableCollection<string> ScanStateTransitions { get; }

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

    public ScanLifecycleState ScanState
    {
        get => _scanState;
        private set => SetProperty(ref _scanState, value);
    }
    public bool IsScanning
    {
        get => _isScanning;
        set
        {
            if (SetProperty(ref _isScanning, value))
            {
                RaisePropertyChanged(nameof(ScanActivityLabel));
            }
        }
    }

    public string ScanActivityLabel => IsScanning ? "Scanning" : "Stopped";

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

    private bool _periodicScanEnabled;
    private int _periodicScanIntervalMinutes = 5;
    private CancellationTokenSource? _periodicCts;

    public bool PeriodicScanEnabled
    {
        get => _periodicScanEnabled;
        set
        {
            if (SetProperty(ref _periodicScanEnabled, value))
            {
                OnPeriodicScanEnabledChanged();
            }
        }
    }

    public int PeriodicScanIntervalMinutes
    {
        get => _periodicScanIntervalMinutes;
        set => SetProperty(ref _periodicScanIntervalMinutes, value);
    }

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
    public bool CanNavigateSearch => MatchingRows().Any();

    private void PopulateNetworkRanges()
    {
        var ranges = new List<string>();
        try
        {
            var nics = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces();
            foreach (var nic in nics)
            {
                if (nic.OperationalStatus != System.Net.NetworkInformation.OperationalStatus.Up) continue;
                if (nic.NetworkInterfaceType == System.Net.NetworkInformation.NetworkInterfaceType.Loopback) continue;

                var ipProps = nic.GetIPProperties();
                foreach (var uni in ipProps.UnicastAddresses)
                {
                    if (uni.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    {
                        var ip = uni.Address;
                        var mask = uni.IPv4Mask;
                        if (mask == null) continue;

                        var ipBytes = ip.GetAddressBytes();
                        var maskBytes = mask.GetAddressBytes();
                        if (ipBytes.Length != 4 || maskBytes.Length != 4) continue;

                        if (ipBytes[0] == 169 && ipBytes[1] == 254) continue;
                        if (ipBytes[0] == 127) continue;

                        var subnetBytes = new byte[4];
                        for (int i = 0; i < 4; i++)
                        {
                            subnetBytes[i] = (byte)(ipBytes[i] & maskBytes[i]);
                        }

                        int cidr = 0;
                        foreach (var b in maskBytes)
                        {
                            int temp = b;
                            while (temp > 0)
                            {
                                if ((temp & 1) == 1) cidr++;
                                temp >>= 1;
                            }
                        }

                        var subnetIp = new IPAddress(subnetBytes);
                        ranges.Add($"{subnetIp}/{cidr}");
                    }
                    else if (uni.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                    {
                        var ip = uni.Address;
                        if (ip.IsIPv6LinkLocal || ip.IsIPv6Multicast || ip.IsIPv6SiteLocal) continue;

                        var ipv6Bytes = ip.GetAddressBytes();
                        if (ipv6Bytes.Length == 16)
                        {
                            var prefixBytes = new byte[16];
                            Array.Copy(ipv6Bytes, prefixBytes, 8);
                            var prefixIp = new IPAddress(prefixBytes);
                            ranges.Add($"{prefixIp}/64");
                        }
                    }
                }
            }
        }
        catch
        {
            // fallback
        }

        ranges.Add("fe80::/112");

        var sortedRanges = ranges
            .Distinct()
            .OrderBy(r => r.Contains(':'))
            .ThenBy(r => r)
            .ToList();

        DetectedRanges.Clear();
        foreach (var r in sortedRanges)
        {
            DetectedRanges.Add(r);
        }

        var firstIpv4 = sortedRanges.FirstOrDefault(r => !r.Contains(':'));
        if (firstIpv4 != null)
        {
            IPRanges = firstIpv4;
        }
        else if (sortedRanges.Count > 0)
        {
            IPRanges = sortedRanges[0];
        }
    }

    private async Task StartStopScanAsync()
    {
        if (ScanState == ScanLifecycleState.Cancelling)
        {
            return;
        }

        if (ScanState == ScanLifecycleState.Scanning || IsScanning || _periodicCts != null)
        {
            TransitionLifecycle(ScanLifecycleState.Cancelling, "Stopping scan...");
            
            bool wasCountingDown = _periodicCts != null;

            _scanCts?.Cancel();
            _periodicCts?.Cancel();
            _periodicCts = null;
            TransitionLifecycle(ScanLifecycleState.Idle, "Ready");

            if (wasCountingDown)
            {
                App.PlayScanStopped();
            }

            return;
        }

        _periodicCts?.Cancel();
        _periodicCts = null;

        _scanCts?.Dispose();
        _scanCts = new CancellationTokenSource();

        try
        {
            var token = _scanCts.Token;

            RunOnUi(() =>
            {
                foreach (var r in Results)
                {
                    r.IsOnline = false;
                    r.IsCached = true;
                }
                UpdateStatusWithCounts("Building scan list...");
            });

            TransitionLifecycle(ScanLifecycleState.Scanning, $"Scanning with {_backend.Name} backend...");

            var hosts = await _backend.ScanAsync(
                IPRanges,
                Ports,
                ScanIPv4,
                ScanIPv6,
                token,
                onHostFound: row => RunOnUi(() =>
                {
                    var existing = Results.FirstOrDefault(r => string.Equals(r.IPAddress, row.IPAddress, StringComparison.OrdinalIgnoreCase));
                    var now = DateTimeOffset.Now;

                    ScanResultRow persistTarget;

                    if (existing is null)
                    {
                        row.IsOnline = true;
                        row.IsCached = false;
                        row.FirstSeen ??= now;
                        row.LastSeen ??= now;
                        Results.Add(row);
                        _resultIPIndex.Add(row.IPAddress);
                        persistTarget = row;
                    }
                    else
                    {
                        existing.IsOnline = true;
                        existing.IsCached = false;
                        existing.LastSeen = now;
                        existing.FirstSeen ??= row.FirstSeen ?? now;

                        if (!string.IsNullOrWhiteSpace(row.Hostname)) existing.Hostname = row.Hostname;
                        if (!string.IsNullOrWhiteSpace(row.MACAddress)) existing.MACAddress = row.MACAddress;
                        if (!string.IsNullOrWhiteSpace(row.Vendor)) existing.Vendor = row.Vendor;
                        if (!string.IsNullOrWhiteSpace(row.IPv6Address)) existing.IPv6Address = row.IPv6Address;
                        if (!string.IsNullOrWhiteSpace(row.OpenPorts)) existing.OpenPorts = row.OpenPorts;
                        if (!string.IsNullOrWhiteSpace(row.CustomName)) existing.CustomName = row.CustomName;
                        persistTarget = existing;
                    }

                    _ = PersistDeviceAsync(persistTarget);

                    ApplySortColumnHighlights();
                    ApplySearchHighlights();
                    UpdateStatusWithCounts();
                }),
                onStatus: status => RunOnUi(() =>
                {
                    _lastBackendStatus = status;
                    UpdateStatusWithCounts(status);
                }));

            token.ThrowIfCancellationRequested();

            RunOnUi(() =>
            {
                ApplySortColumnHighlights();
                ApplySearchHighlights();
                TransitionLifecycle(ScanLifecycleState.Completed, $"Scan complete - {Results.Count} active host(s)");

                App.PlayScanComplete();
                
                if (PeriodicScanEnabled)
                {
                    _ = StartPeriodicCountdownAsync();
                }
                else
                {
                    UpdateStatusWithCounts($"Scan complete - {Results.Count} active host(s)");
                }
            });

            LogMockAction($"Scan completed via {_backend.Name} backend.");
        }
        catch (OperationCanceledException)
        {
            RunOnUi(() =>
            {
                TransitionLifecycle(ScanLifecycleState.Cancelled, "Scan cancelled.");
                UpdateStatusWithCounts("Scan cancelled");
                App.PlayScanStopped();
            });
        }
        catch (Exception ex)
        {
            RunOnUi(() =>
            {
                TransitionLifecycle(ScanLifecycleState.Faulted, $"Scan failed: {ex.Message}");
                UpdateStatusWithCounts($"Error: {ex.Message}");
                App.PlayScanStopped();
            });
        }
        finally
        {
            _scanCts?.Dispose();
            _scanCts = null;
            if (ScanState == ScanLifecycleState.Scanning || ScanState == ScanLifecycleState.Cancelling)
            {
                RunOnUi(() => TransitionLifecycle(ScanLifecycleState.Idle, StatusText));
            }
            else
            {
                IsScanning = false;
                ScanButtonText = PeriodicScanEnabled && _periodicCts != null ? "Stop" : "Scan";
            }
        }
    }

    private async Task StartPeriodicCountdownAsync()
    {
        _periodicCts?.Cancel();
        _periodicCts = new CancellationTokenSource();
        var token = _periodicCts.Token;

        try
        {
            RunOnUi(() =>
            {
                ScanButtonText = "Stop";
            });

            int remainingSeconds = _periodicScanIntervalMinutes * 60;
            while (remainingSeconds > 0)
            {
                token.ThrowIfCancellationRequested();

                int minutes = remainingSeconds / 60;
                int seconds = remainingSeconds % 60;

                RunOnUi(() =>
                {
                    var live = Results.Count(r => !r.IsCached);
                    var cached = Results.Count(r => r.IsCached);
                    var total = Results.Count;
                    StatusText = $"Next scan in {minutes:D2}:{seconds:D2} | Live: {live} | Cached: {cached} | Total: {total}";
                });

                await Task.Delay(1000, token);
                remainingSeconds--;
            }

            token.ThrowIfCancellationRequested();

            RunOnUi(async () =>
            {
                _periodicCts = null;
                await StartStopScanAsync();
            });
        }
        catch (OperationCanceledException)
        {
            RunOnUi(() =>
            {
                ScanButtonText = "Scan";
            });
        }
    }

    private void OnPeriodicScanEnabledChanged()
    {
        if (!_periodicScanEnabled)
        {
            _periodicCts?.Cancel();
            _periodicCts = null;
            ScanButtonText = "Scan";
            UpdateStatusWithCounts();
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

        LogMockAction($"Exported {Results.Count} row(s) to CSV.\nPreview length: {csv.Length} chars.");
    }


    private void TransitionLifecycle(ScanLifecycleState nextState, string? statusText = null)
    {
        ScanState = nextState;

        switch (nextState)
        {
            case ScanLifecycleState.Scanning:
                IsScanning = true;
                ScanButtonText = "Stop";
                break;
            case ScanLifecycleState.Cancelling:
                IsScanning = true;
                ScanButtonText = "Stopping...";
                break;
            default:
                IsScanning = false;
                ScanButtonText = PeriodicScanEnabled && _periodicCts != null ? "Stop" : "Scan";
                break;
        }

        if (!string.IsNullOrWhiteSpace(statusText))
        {
            StatusText = statusText;
        }

        System.Diagnostics.Debug.WriteLine($"[{DateTime.Now:HH:mm:ss}] ScanState -> {nextState} | {StatusText}");
    }

    private void RunOnUi(Action action)
    {
        if (_dispatcherQueue is null || _dispatcherQueue.HasThreadAccess)
        {
            action();
            return;
        }

        _dispatcherQueue.TryEnqueue(() => action());
    }

    private void UpdateStatusWithCounts(string? phase = null)
    {
        if (!string.IsNullOrWhiteSpace(phase))
        {
            _lastBackendStatus = phase;
        }

        var live = Results.Count(r => !r.IsCached);
        var cached = Results.Count(r => r.IsCached);
        var total = Results.Count;

        var prefix = string.IsNullOrWhiteSpace(_lastBackendStatus) ? "Ready" : _lastBackendStatus;
        StatusText = $"{prefix} | Live: {live} | Cached: {cached} | Total: {total}";
    }

    private static long IPv4SortKey(string ip)
    {
        if (IPAddress.TryParse(ip, out var p) && p.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = p.GetAddressBytes();
            return ((long)b[0] << 24) | ((long)b[1] << 16) | ((long)b[2] << 8) | b[3];
        }

        return long.MaxValue;
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

    private async Task LoadCachedDevicesAsync()
    {
        try
        {
            var devices = await _dbService.GetAllDevicesAsync();

            RunOnUi(() =>
            {
                foreach (var d in devices)
                {
                    if (string.IsNullOrWhiteSpace(d.IPAddress))
                        continue;

                    if (!_resultIPIndex.Add(d.IPAddress))
                        continue;

                    Results.Add(new ScanResultRow
                    {
                        IsOnline = false,
                        IsCached = true,
                        CustomName = d.CustomName ?? string.Empty,
                        FirstSeen = d.FirstSeen.HasValue ? new DateTimeOffset(d.FirstSeen.Value) : null,
                        LastSeen = d.LastSeen.HasValue ? new DateTimeOffset(d.LastSeen.Value) : null,
                        IPAddress = d.IPAddress ?? string.Empty,
                        Hostname = d.Hostname ?? string.Empty,
                        MACAddress = d.MACAddress ?? string.Empty,
                        Vendor = d.Vendor ?? string.Empty,
                        OpenPorts = d.OpenPortsString ?? string.Empty,
                        IPv6Address = d.IPv6Address ?? string.Empty
                    });
                }

                ApplySortColumnHighlights();
                ApplySearchHighlights();
                UpdateStatusWithCounts("Ready");
            });
        }
        catch
        {
            // non-fatal cache load
        }
    }

    private async Task PersistDeviceAsync(ScanResultRow row)
    {
        try
        {
            var model = new ScanResult
            {
                IPAddress = row.IPAddress,
                Hostname = string.IsNullOrWhiteSpace(row.Hostname) ? null : row.Hostname,
                MACAddress = string.IsNullOrWhiteSpace(row.MACAddress) ? null : row.MACAddress,
                Vendor = string.IsNullOrWhiteSpace(row.Vendor) ? null : row.Vendor,
                IPv6Address = string.IsNullOrWhiteSpace(row.IPv6Address) ? null : row.IPv6Address,
                OpenPorts = ParseOpenPorts(row.OpenPorts),
                CustomName = string.IsNullOrWhiteSpace(row.CustomName) ? null : row.CustomName,
                FirstSeen = row.FirstSeen?.DateTime,
                LastSeen = row.LastSeen?.DateTime,
                IsOnline = row.IsOnline,
                IsCached = row.IsCached,
                IsResponsive = row.IsOnline,
                ScanTime = DateTime.Now
            };

            await _dbService.UpsertDeviceAsync(model);
        }
        catch
        {
            // non-fatal persistence failure
        }
    }

    private static List<int> ParseOpenPorts(string portsText)
    {
        if (string.IsNullOrWhiteSpace(portsText))
            return new List<int>();

        return portsText
            .Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries)
            .Select(x => int.TryParse(x.Trim(), out var p) ? p : -1)
            .Where(p => p is >= 1 and <= 65535)
            .Distinct()
            .OrderBy(p => p)
            .ToList();
    }

    private void SetScanUiState(bool isScanning, string? statusText = null)
    {
        IsScanning = isScanning;
        ScanButtonText = isScanning ? "Stop" : "Scan";

        if (!string.IsNullOrWhiteSpace(statusText))
        {
            StatusText = statusText;
        }
    }

    private void LogScanTransition(string message)
    {
        if (_scanStateTransitions.Count >= 100)
        {
            _scanStateTransitions.RemoveAt(_scanStateTransitions.Count - 1);
        }

        _scanStateTransitions.Insert(0, message);
        MockActionLog = string.Join(Environment.NewLine, _scanStateTransitions.Take(10));
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
            "IPAddress" => _sortAscending ? Results.OrderBy(r => IPv4SortKey(r.IPAddress)).ThenBy(r => r.IPAddress, StringComparer.OrdinalIgnoreCase) : Results.OrderByDescending(r => IPv4SortKey(r.IPAddress)).ThenByDescending(r => r.IPAddress, StringComparer.OrdinalIgnoreCase),
            "MACAddress" => _sortAscending ? Results.OrderBy(r => r.MACAddress) : Results.OrderByDescending(r => r.MACAddress),
            "StateLabel" => _sortAscending ? Results.OrderBy(r => r.StateLabel) : Results.OrderByDescending(r => r.StateLabel),
            "Vendor" => _sortAscending ? Results.OrderBy(r => r.Vendor) : Results.OrderByDescending(r => r.Vendor),
            "FirstSeen" => _sortAscending ? Results.OrderBy(r => r.FirstSeen) : Results.OrderByDescending(r => r.FirstSeen),
            "LastSeen" => _sortAscending ? Results.OrderBy(r => r.LastSeen) : Results.OrderByDescending(r => r.LastSeen),
            "OpenPorts" => _sortAscending ? Results.OrderBy(r => r.OpenPorts) : Results.OrderByDescending(r => r.OpenPorts),
            "CustomName" => _sortAscending ? Results.OrderBy(r => r.CustomName) : Results.OrderByDescending(r => r.CustomName),
            "IPv6Address" => _sortAscending ? Results.OrderBy(r => r.IPv6Address) : Results.OrderByDescending(r => r.IPv6Address),
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
