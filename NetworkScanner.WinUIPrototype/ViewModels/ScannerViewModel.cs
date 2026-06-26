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
    public event Func<object, SaveFileEventArgs, Task>? SaveFileRequested;

    private readonly Random _random = new();
    private readonly ObservableCollection<string> _scanStateTransitions = new();
    private readonly IScannerBackend _backend;
    private readonly DispatcherQueue? _dispatcherQueue;
    private readonly DatabaseService _dbService;
    private readonly HashSet<string> _resultIPIndex = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<ScanResultRow> _allResults = new();
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
    private readonly List<ScanResultRow> _searchMatches = new();
    private DispatcherQueueTimer? _searchHighlightTimer;
    private const int SearchHighlightDebounceMs = 150;

    private readonly string _settingsPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "NetworkScanner",
        "scope-settings-winui.json"
    );

    public ScannerViewModel()
    {
        _backend = ScannerBackendFactory.Create();
        _dispatcherQueue = DispatcherQueue.GetForCurrentThread();
        if (_dispatcherQueue is not null)
        {
            _searchHighlightTimer = _dispatcherQueue.CreateTimer();
            _searchHighlightTimer.Interval = TimeSpan.FromMilliseconds(SearchHighlightDebounceMs);
            _searchHighlightTimer.IsRepeating = false;
            _searchHighlightTimer.Tick += (_, _) => ApplySearchHighlights();
        }

        PopulateNetworkRanges();
        LoadSettings();
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
        ExportCommand = new RelayCommand(async () => await ExportCsvAsync());
        ToggleFindCommand = new RelayCommand(ToggleSearchState);
        FindNextCommand = new RelayCommand(FindNext);
        FindPreviousCommand = new RelayCommand(FindPrevious);

        CopyFieldCommand = new RelayCommand(ExecuteCopyField);
        BrowsePortCommand = new RelayCommand(ExecuteBrowsePort);
        ShellCommand = new RelayCommand(ExecuteShell);

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

        PropertyChanged += (s, e) =>
        {
            if (e.PropertyName is nameof(IPRanges) or nameof(Ports) or nameof(ScanIPv6) or nameof(ShowOffline) or nameof(ShowCached) or nameof(PeriodicScanEnabled) or nameof(PeriodicScanIntervalMinutes))
            {
                SaveSettings();
            }
            if (e.PropertyName is nameof(ShowOffline) or nameof(ShowCached))
            {
                RunOnUi(RefreshFilteredResults);
            }
        };
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
                ScheduleSearchHighlights();
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
        set
        {
            if (ReferenceEquals(_selectedResult, value)) return;

            var previous = _selectedResult;
            if (SetProperty(ref _selectedResult, value))
            {
                previous?.SetSelectedRow(false);
                _selectedResult?.SetSelectedRow(true);
            }
        }
    }

    public bool ResolveDns { get; set; } = true;
    public bool LookupMac { get; set; } = true;
    public bool LookupVendor { get; set; } = true;
    public bool ScanIPv4 { get; set; } = true;
    public bool ScanIPv6 { get; set; }
    public int PingTimeoutMs { get; set; } = 3000;
    public int PortTimeoutMs { get; set; } = 1500;

    private bool _showOffline = true;
    private bool _showCached = true;

    public bool ShowOffline
    {
        get => _showOffline;
        set => SetProperty(ref _showOffline, value);
    }

    public bool ShowCached
    {
        get => _showCached;
        set => SetProperty(ref _showCached, value);
    }

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
    public int SearchHighlightVersion { get; private set; }

    public string SearchStatusText
    {
        get
        {
            if (string.IsNullOrWhiteSpace(SearchText)) return string.Empty;
            if (_searchMatches.Count == 0) return "No matches";
            if (CurrentSearchIndex < 0) return $"{_searchMatches.Count} matches";
            return $"{CurrentSearchIndex + 1} / {_searchMatches.Count}";
        }
    }

    public int SearchMatchCount => _searchMatches.Count;
    public bool CanNavigateSearch => _searchMatches.Count > 0;

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
                foreach (var r in _allResults)
                {
                    r.IsOnline = false;
                    r.IsCached = true;
                }
                RefreshFilteredResults();
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
                    var existing = _allResults.FirstOrDefault(r => string.Equals(r.IPAddress, row.IPAddress, StringComparison.OrdinalIgnoreCase));
                    var now = DateTimeOffset.Now;

                    ScanResultRow persistTarget;

                    if (existing is null)
                    {
                        row.IsOnline = true;
                        row.IsCached = false;
                        row.FirstSeen ??= now;
                        row.LastSeen ??= now;
                        row.SetSortedColumn(_sortColumn);
                        _allResults.Add(row);
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

                    RefreshFilteredResults();
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
        _allResults.Clear();
        Results.Clear();
        CurrentSearchIndex = -1;
        ApplySortColumnHighlights();
        ApplySearchHighlights();
        RefreshStatus();
        StatusText = "Ready";
    }

    private async Task ExportCsvAsync()
    {
        if (Results.Count == 0)
        {
            LogMockAction("No results to export.");
            return;
        }

        var csv = new StringBuilder();
        csv.AppendLine("IP Address,Hostname,MAC Address,Vendor,Open Ports,IPv6 Address,Custom Name,First Seen,Last Seen,Status");
        foreach (var row in Results)
        {
            csv.AppendLine($"\"{row.IPAddress}\",\"{row.Hostname}\",\"{row.MACAddress}\",\"{row.Vendor}\",\"{row.OpenPorts}\",\"{row.IPv6Address}\",\"{row.CustomName}\",\"{row.FirstSeen}\",\"{row.LastSeen}\",\"{row.StateLabel}\"");
        }

        var defaultName = $"NetworkScan_{DateTime.Now:yyyyMMdd_HHmmss}.csv";
        var args = new SaveFileEventArgs(defaultName, ".csv", csv.ToString());
        
        if (SaveFileRequested != null)
        {
            await SaveFileRequested.Invoke(this, args);
        }

        if (args.ResultFilePath != null)
        {
            LogMockAction($"Exported {Results.Count} row(s) to CSV: {args.ResultFilePath}");
        }
        else
        {
            LogMockAction("CSV export cancelled.");
        }
    }

    private void ExecuteBrowsePort(object? parameter)
    {
        if (parameter is not string paramStr) return;

        string? url = null;
        if (paramStr.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || 
            paramStr.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            url = paramStr;
        }
        else if (SelectedResult != null)
        {
            var match = System.Text.RegularExpressions.Regex.Match(paramStr, @"(\d+)");
            if (match.Success && int.TryParse(match.Value, out var port))
            {
                var scheme = paramStr.Contains("https", StringComparison.OrdinalIgnoreCase) || port is 443 or 8443 or 9443 ? "https" : "http";
                url = $"{scheme}://{SelectedResult.IPAddress}:{port}";
            }
        }

        if (!string.IsNullOrEmpty(url))
        {
            try
            {
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(url) { UseShellExecute = true });
                LogMockAction($"Browsed to {url}");
            }
            catch (Exception ex)
            {
                LogMockAction($"Error browsing to {url}: {ex.Message}");
            }
        }
    }

    private void ExecuteShell(object? parameter)
    {
        if (SelectedResult == null) return;

        var paramStr = parameter as string ?? "";
        var ip = SelectedResult.IPAddress;

        if (paramStr.Contains("RDP", StringComparison.OrdinalIgnoreCase) || paramStr.Contains("3389"))
        {
            try
            {
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("mstsc", $"/v:{ip}") { UseShellExecute = true });
                LogMockAction($"Launched RDP to {ip}");
            }
            catch (Exception ex)
            {
                LogMockAction($"Error launching RDP: {ex.Message}");
            }
        }
        else
        {
            string? protocol = null;
            int port = 0;

            if (paramStr.Contains("SSH", StringComparison.OrdinalIgnoreCase) || paramStr.Contains("22"))
            {
                protocol = "ssh";
                port = 22;
            }
            else
            {
                var match = System.Text.RegularExpressions.Regex.Match(paramStr, @"(\d+)");
                if (match.Success)
                {
                    int.TryParse(match.Value, out port);
                }
            }

            try
            {
                string cmd = protocol switch
                {
                    "ssh" => $"ssh {ip}",
                    _     => port > 0 ? $"# {ip}:{port}" : $"# {ip}",
                };

                if (TryLaunch("wt.exe", $"new-tab -- powershell -NoExit -Command \"{cmd}\""))
                {
                    LogMockAction($"Launched WT session: {cmd}");
                    return;
                }
                if (TryLaunch("powershell.exe", $"-NoExit -Command \"{cmd}\""))
                {
                    LogMockAction($"Launched PowerShell session: {cmd}");
                    return;
                }
                if (TryLaunch("cmd.exe", $"/k echo {cmd}"))
                {
                    LogMockAction($"Launched CMD session: {cmd}");
                    return;
                }
            }
            catch (Exception ex)
            {
                LogMockAction($"Error launching shell: {ex.Message}");
            }
        }
    }

    private static bool TryLaunch(string exe, string args)
    {
        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(exe, args) { UseShellExecute = true });
            return true;
        }
        catch { return false; }
    }

    private void ExecuteCopyField(object? parameter)
    {
        if (SelectedResult == null || parameter is not string fieldName) return;

        string? val = fieldName.ToLowerInvariant() switch
        {
            "ip" or "ip address" => SelectedResult.IPAddress,
            "hostname" => SelectedResult.Hostname,
            "mac" or "mac address" => SelectedResult.MACAddress,
            "vendor" => SelectedResult.Vendor,
            "open ports" => SelectedResult.OpenPorts,
            "ipv6" or "ipv6 address" => SelectedResult.IPv6Address,
            "custom name" => SelectedResult.CustomName,
            _ => null
        };

        if (!string.IsNullOrEmpty(val))
        {
            try
            {
                var package = new Windows.ApplicationModel.DataTransfer.DataPackage();
                package.SetText(val);
                Windows.ApplicationModel.DataTransfer.Clipboard.SetContent(package);
                Windows.ApplicationModel.DataTransfer.Clipboard.Flush();
                LogMockAction($"Copied {fieldName}: {val}");
            }
            catch (Exception ex)
            {
                LogMockAction($"Failed to copy to clipboard: {ex.Message}");
            }
        }
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

        var live = _allResults.Count(r => !r.IsCached);
        var cached = _allResults.Count(r => r.IsCached);
        var total = _allResults.Count;

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
        _searchHighlightTimer?.Stop();

        if (IsSearching)
        {
            IsSearching = false;
            ShowFindPanel = false;
            SearchText = string.Empty;
            CurrentSearchIndex = -1;
            return;
        }

        IsSearching = true;
        ShowFindPanel = true;
        CurrentSearchIndex = -1;
        ApplySearchHighlights();
    }

    private void FindNext()
    {
        if (_searchMatches.Count == 0)
        {
            CurrentSearchIndex = -1;
            SelectedResult = null;
            ApplySearchHighlights();
            return;
        }

        CurrentSearchIndex = (CurrentSearchIndex + 1) % _searchMatches.Count;
        SelectedResult = _searchMatches[CurrentSearchIndex];
        UpdateSearchNavigationHighlight();
        SearchNavigationVersion++;
        RaisePropertyChanged(nameof(SearchNavigationVersion));
        LogMockAction($"Find next: {_searchMatches[CurrentSearchIndex].IPAddress}");
    }

    private void FindPrevious()
    {
        if (_searchMatches.Count == 0)
        {
            CurrentSearchIndex = -1;
            SelectedResult = null;
            ApplySearchHighlights();
            return;
        }

        CurrentSearchIndex = (CurrentSearchIndex - 1 + _searchMatches.Count) % _searchMatches.Count;
        SelectedResult = _searchMatches[CurrentSearchIndex];
        UpdateSearchNavigationHighlight();
        SearchNavigationVersion++;
        RaisePropertyChanged(nameof(SearchNavigationVersion));
        LogMockAction($"Find previous: {_searchMatches[CurrentSearchIndex].IPAddress}");
    }

    private void ScheduleSearchHighlights()
    {
        if (string.IsNullOrWhiteSpace(SearchText))
        {
            _searchHighlightTimer?.Stop();
            ApplySearchHighlights();
            return;
        }

        if (_searchHighlightTimer is null)
        {
            ApplySearchHighlights();
            return;
        }

        _searchHighlightTimer.Stop();
        _searchHighlightTimer.Start();
    }

    private void ApplySearchHighlights()
    {
        var term = SearchText.Trim();
        _searchMatches.Clear();

        if (string.IsNullOrEmpty(term))
        {
            foreach (var row in Results)
            {
                ClearRowSearchState(row);
            }

            NotifySearchStatusChanged();
            return;
        }

        foreach (var row in Results)
        {
            if (RowMatchesTerm(row, term))
            {
                _searchMatches.Add(row);
            }
        }

        var matchSet = new HashSet<ScanResultRow>(_searchMatches);
        foreach (var row in Results)
        {
            if (matchSet.Contains(row))
            {
                row.IsSearchMatch = true;
                row.SearchQuery = term;
            }
            else
            {
                row.IsSearchMatch = false;
                row.SearchQuery = string.Empty;
            }

            row.IsCurrentSearchHit = CurrentSearchIndex >= 0
                && CurrentSearchIndex < _searchMatches.Count
                && ReferenceEquals(_searchMatches[CurrentSearchIndex], row);
        }

        NotifySearchStatusChanged();
    }

    private void UpdateSearchNavigationHighlight()
    {
        for (var i = 0; i < _searchMatches.Count; i++)
        {
            _searchMatches[i].IsCurrentSearchHit = i == CurrentSearchIndex;
        }

        NotifySearchStatusChanged();
    }

    private static void ClearRowSearchState(ScanResultRow row)
    {
        row.IsSearchMatch = false;
        row.IsCurrentSearchHit = false;
        row.SearchQuery = string.Empty;
    }

    private static bool RowMatchesTerm(ScanResultRow row, string term)
    {
        var comparison = StringComparison.OrdinalIgnoreCase;
        return row.IPAddress.Contains(term, comparison) ||
               row.Hostname.Contains(term, comparison) ||
               row.MACAddress.Contains(term, comparison) ||
               row.Vendor.Contains(term, comparison) ||
               row.OpenPorts.Contains(term, comparison) ||
               row.IPv6Address.Contains(term, comparison) ||
               row.CustomName.Contains(term, comparison);
    }

    private void NotifySearchStatusChanged()
    {
        SearchHighlightVersion++;
        RaisePropertyChanged(nameof(SearchHighlightVersion));
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

        _allResults.Add(new ScanResultRow
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

        _allResults.Add(new ScanResultRow
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

        RefreshFilteredResults();
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

                    _allResults.Add(new ScanResultRow
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

                RefreshFilteredResults();
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
        var live = _allResults.Count(r => !r.IsCached);
        var cached = _allResults.Count(r => r.IsCached);
        StatusText = $"Live: {live} | Cached: {cached} | Total: {_allResults.Count}";
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

        RefreshFilteredResults();
    }

    private void RefreshFilteredResults()
    {
        var filtered = _allResults.Where(r =>
        {
            if (!NetworkScanner.Core.NetworkScannerUtils.IsIpInRanges(r.IPAddress, IPRanges)) return false;
            if (r.IsCached) return ShowCached;
            if (!r.IsOnline) return ShowOffline;
            return true;
        });

        // Apply active sorting dynamically
        IEnumerable<ScanResultRow> ordered = _sortColumn switch
        {
            "Hostname" => _sortAscending ? filtered.OrderBy(r => r.Hostname) : filtered.OrderByDescending(r => r.Hostname),
            "IPAddress" => _sortAscending ? filtered.OrderBy(r => IPv4SortKey(r.IPAddress)).ThenBy(r => r.IPAddress, StringComparer.OrdinalIgnoreCase) : filtered.OrderByDescending(r => IPv4SortKey(r.IPAddress)).ThenByDescending(r => r.IPAddress, StringComparer.OrdinalIgnoreCase),
            "MACAddress" => _sortAscending ? filtered.OrderBy(r => r.MACAddress) : filtered.OrderByDescending(r => r.MACAddress),
            "StateLabel" => _sortAscending ? filtered.OrderBy(r => r.StateLabel) : filtered.OrderByDescending(r => r.StateLabel),
            "Vendor" => _sortAscending ? filtered.OrderBy(r => r.Vendor) : filtered.OrderByDescending(r => r.Vendor),
            "FirstSeen" => _sortAscending ? filtered.OrderBy(r => r.FirstSeen) : filtered.OrderByDescending(r => r.FirstSeen),
            "LastSeen" => _sortAscending ? filtered.OrderBy(r => r.LastSeen) : filtered.OrderByDescending(r => r.LastSeen),
            "OpenPorts" => _sortAscending ? filtered.OrderBy(r => r.OpenPorts) : filtered.OrderByDescending(r => r.OpenPorts),
            "CustomName" => _sortAscending ? filtered.OrderBy(r => r.CustomName) : filtered.OrderByDescending(r => r.CustomName),
            "IPv6Address" => _sortAscending ? filtered.OrderBy(r => r.IPv6Address) : filtered.OrderByDescending(r => r.IPv6Address),
            _ => _sortAscending ? filtered.OrderBy(r => r.IPAddress) : filtered.OrderByDescending(r => r.IPAddress)
        };

        var selected = SelectedResult;

        Results.Clear();
        foreach (var item in ordered)
        {
            Results.Add(item);
        }

        if (selected != null && Results.Contains(selected))
        {
            SelectedResult = selected;
        }
        else
        {
            SelectedResult = null;
        }

        ApplySortColumnHighlights();
        ApplySearchHighlights();
        UpdateStatusWithCounts();
    }

    private void SaveSettings()
    {
        try
        {
            var settings = new ScannerScopeSettings
            {
                IPRanges = IPRanges,
                Ports = Ports,
                ScanIPv6 = ScanIPv6,
                ShowOffline = ShowOffline,
                ShowCached = ShowCached,
                PeriodicScanEnabled = PeriodicScanEnabled,
                PeriodicScanIntervalMinutes = PeriodicScanIntervalMinutes
            };

            var dir = Path.GetDirectoryName(_settingsPath);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
            {
                Directory.CreateDirectory(dir);
            }

            var json = System.Text.Json.JsonSerializer.Serialize(settings);
            File.WriteAllText(_settingsPath, json);
        }
        catch
        {
            // ignore
        }
    }

    private void LoadSettings()
    {
        try
        {
            if (File.Exists(_settingsPath))
            {
                var json = File.ReadAllText(_settingsPath);
                var settings = System.Text.Json.JsonSerializer.Deserialize<ScannerScopeSettings>(json);
                if (settings != null)
                {
                    IPRanges = settings.IPRanges;
                    Ports = settings.Ports;
                    ScanIPv6 = settings.ScanIPv6;
                    ShowOffline = settings.ShowOffline;
                    ShowCached = settings.ShowCached;
                    PeriodicScanEnabled = settings.PeriodicScanEnabled;
                    PeriodicScanIntervalMinutes = settings.PeriodicScanIntervalMinutes;
                }
            }
        }
        catch
        {
            // ignore
        }
    }
}

public class ScannerScopeSettings
{
    public string IPRanges { get; set; } = string.Empty;
    public string Ports { get; set; } = "80";
    public bool ScanIPv6 { get; set; }
    public bool ShowOffline { get; set; }
    public bool ShowCached { get; set; } = true;
    public bool PeriodicScanEnabled { get; set; }
    public int PeriodicScanIntervalMinutes { get; set; } = 5;
}

public class SaveFileEventArgs : EventArgs
{
    public string DefaultFileName { get; }
    public string FileExtension { get; }
    public string Content { get; }
    public string? ResultFilePath { get; set; }

    public SaveFileEventArgs(string defaultFileName, string fileExtension, string content)
    {
        DefaultFileName = defaultFileName;
        FileExtension = fileExtension;
        Content = content;
    }
}




