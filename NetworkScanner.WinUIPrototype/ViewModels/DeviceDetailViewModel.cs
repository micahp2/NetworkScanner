using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml.Media;
using NetworkScanner.Core;
using NetworkScanner.Models;
using NetworkScanner.Services;
using NetworkScanner.WinUIPrototype.Common;
using NetworkScanner.WinUIPrototype.Models;
using NetworkScanner.WinUIPrototype.Services;

namespace NetworkScanner.WinUIPrototype.ViewModels;

public sealed class DeviceDetailViewModel : ObservableObject, IDisposable
{
    private readonly ScannerViewModel _scanner;
    private readonly DeviceMonitorService _monitor = new();
    private readonly DeviceEnrichmentService _enrichment;
    private readonly List<ScanResultRow> _selectedDevices = new();
    private CancellationTokenSource? _portScanCts;
    private DispatcherQueueTimer? _persistTimer;
    private ScanResultRow? _selectedDeviceSubscription;

    private bool _monitorEnabled = true;
    private bool _isPortScanning;
    private string _portScanStatus = string.Empty;
    private string _deepScanPorts = "22,80,443,8080-8090";
    private DeviceEditSnapshot? _editSnapshot;
    private int? _selectedPort;

    private bool _monitorPingIsUp;
    private string _monitorPingStatusLabel = "—";
    private string _monitorLastLatency = "—";
    private string _monitorAverageLatency = "—";
    private string _monitorPacketLoss = "—";
    private string _deviceScanStateLabel = "—";

    private static readonly SolidColorBrush MonitorOnlineBrush = Bg(0xFF, 0x39, 0xD3, 0x53);
    private static readonly SolidColorBrush MonitorOfflineBrush = Bg(0xFF, 0xE0, 0x5A, 0x5A);
    private static readonly SolidColorBrush NeutralBrush = Bg(0xFF, 0x8D, 0x96, 0xA4);
    private static readonly SolidColorBrush CachedBrush = Bg(0xFF, 0xE1, 0xB8, 0x54);
    private static readonly SolidColorBrush LiveBrush = Bg(0xFF, 0x39, 0xD3, 0x53);
    private static readonly SolidColorBrush OfflineBrush = Bg(0xFF, 0xE0, 0x5A, 0x5A);

    public event Action? DeviceMetadataChanged;

    public DeviceDetailViewModel(ScannerViewModel scanner)
    {
        _scanner = scanner;
        _enrichment = new DeviceEnrichmentService(scanner.Database);
        _scanner.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName is nameof(ScannerViewModel.SelectedResult))
            {
                if (_selectedDevices.Count == 0 && SelectedDevice is not null)
                    SetSelectedDevices(new[] { SelectedDevice }, SelectedDevice);
                OnSelectedDeviceChanged();
                RaisePropertyChanged(nameof(SelectedDevice));
                RaisePropertyChanged(nameof(HasSelection));
                RaisePropertyChanged(nameof(PersistWarning));
                RaisePropertyChanged(nameof(HeroTitle));
                RaisePropertyChanged(nameof(HeroSubtitle));
            }
            else if (e.PropertyName is nameof(ScannerViewModel.DeepInfoListVersion))
            {
                PruneSelectionToVisibleDevices();
            }
        };
        _monitor.StatsUpdated += UpdateMonitorDisplay;

        PrevDeviceCommand = new RelayCommand(() => _scanner.SelectPreviousDevice());
        NextDeviceCommand = new RelayCommand(() => _scanner.SelectNextDevice());
        ScanPortsCommand = new RelayCommand(async () => await ScanPortsAsync());
        DetectOsCommand = new RelayCommand(async () => await DetectOsAsync());
        RefreshMetadataCommand = new RelayCommand(async () => await RefreshMetadataAsync());
        CopyProfileCommand = new RelayCommand(() =>
        {
            if (SelectedDevice is not null) DeviceActions.CopyDeviceProfile(SelectedDevice);
        });
        RevertChangesCommand = new RelayCommand(async () => await RevertChangesAsync(), () => HasPendingChanges);
        ClearAllMetadataCommand = new RelayCommand(async () => await ClearAllUserMetadataAsync(), () => HasSelection);
        ClearOsHintCommand = new RelayCommand(async () => await ClearOsHintAsync(), () => HasSelection && SelectedDevice is { OsHint: { Length: > 0 } });
        ApplyMetadataCommand = new RelayCommand(async () => await ApplyMetadataDialogRequestedAsync(), () => CanApplyMetadataToOthers);
    }

    public event Func<Task<DeviceMetadataApplyOptions?>>? ApplyMetadataDialogRequested;

    public ScannerViewModel Scanner => _scanner;

    public ScanResultRow? SelectedDevice => _scanner.SelectedResult;

    public IReadOnlyList<ScanResultRow> SelectedDevices => _selectedDevices;

    public int SelectedDeviceCount => _selectedDevices.Count;

    public bool IsMultiSelect => _selectedDevices.Count > 1;

    public bool HasSelection => SelectedDevice is not null;

    public bool CanApplyMetadataToOthers => SelectedDevice is not null && _selectedDevices.Count > 1;

    public string SelectionSummary => _selectedDevices.Count switch
    {
        0 => "No device selected",
        1 => SelectedDevice?.DisplayName ?? "1 device",
        _ => $"{_selectedDevices.Count} devices selected"
    };

    public string HeroTitle => IsMultiSelect
        ? SelectedDevice?.DisplayName ?? SelectionSummary
        : SelectedDevice?.DisplayName ?? "Deep Info";

    public string HeroSubtitle => IsMultiSelect
        ? $"{_selectedDevices.Count - 1} more selected — edits apply to all"
        : SelectedDevice?.IPAddress ?? string.Empty;

    public string MultiEditHint => IsMultiSelect
        ? $"Edits apply to all {_selectedDevices.Count} selected devices."
        : string.Empty;

    public bool HasPendingChanges =>
        SelectedDevice is not null && _editSnapshot is not null && !_editSnapshot.Matches(SelectedDevice);

    public string PendingChangesSummary =>
        HasPendingChanges
            ? IsMultiSelect ? "You have unsaved edits on the selected devices." : "You have unsaved edits on this device."
            : string.Empty;

    public string? PersistWarning =>
        SelectedDevice is { CanPersistMetadata: false }
            ? IsMultiSelect
                ? "One or more selected devices lack a MAC — edits on those devices won't persist until MAC lookup is enabled."
                : "MAC unknown — edits won't persist until this device is scanned with MAC lookup enabled."
            : null;

    public bool MonitorEnabled
    {
        get => _monitorEnabled;
        set
        {
            if (SetProperty(ref _monitorEnabled, value))
            {
                if (value) StartMonitorForSelection();
                else _monitor.Stop();
                UpdateMonitorDisplay();
            }
        }
    }

    public bool MonitorPingIsUp
    {
        get => _monitorPingIsUp;
        private set => SetProperty(ref _monitorPingIsUp, value);
    }

    public string MonitorPingStatusLabel
    {
        get => _monitorPingStatusLabel;
        private set => SetProperty(ref _monitorPingStatusLabel, value);
    }

    public SolidColorBrush MonitorPingStatusBrush =>
        !MonitorEnabled ? NeutralBrush : MonitorPingIsUp ? MonitorOnlineBrush : MonitorOfflineBrush;

    public string MonitorLastLatency
    {
        get => _monitorLastLatency;
        private set => SetProperty(ref _monitorLastLatency, value);
    }

    public string MonitorAverageLatency
    {
        get => _monitorAverageLatency;
        private set => SetProperty(ref _monitorAverageLatency, value);
    }

    public string MonitorPacketLoss
    {
        get => _monitorPacketLoss;
        private set => SetProperty(ref _monitorPacketLoss, value);
    }

    public string DeviceScanStateLabel
    {
        get => _deviceScanStateLabel;
        private set => SetProperty(ref _deviceScanStateLabel, value);
    }

    public SolidColorBrush DeviceScanStateBrush
    {
        get
        {
            if (SelectedDevice is null) return NeutralBrush;
            if (SelectedDevice.IsOnline) return LiveBrush;
            if (SelectedDevice.IsCached) return CachedBrush;
            return OfflineBrush;
        }
    }

    public bool IsPortScanning
    {
        get => _isPortScanning;
        private set => SetProperty(ref _isPortScanning, value);
    }

    public string PortScanStatus
    {
        get => _portScanStatus;
        private set => SetProperty(ref _portScanStatus, value);
    }

    public string DeepScanPorts
    {
        get => _deepScanPorts;
        set => SetProperty(ref _deepScanPorts, value);
    }

    public IEnumerable<string> TagSuggestions => _scanner.GetAllTags();

    public IReadOnlyList<DevicePortDisplayItem> KnownPorts { get; private set; } = Array.Empty<DevicePortDisplayItem>();

    public string KnownPortsSummary { get; private set; } = "No ports recorded";

    public bool HasKnownPorts => KnownPorts.Count > 0;

    public int? SelectedPort => _selectedPort;

    public bool HasSelectedPort => _selectedPort is not null;

    public void SelectPort(int? port)
    {
        if (_selectedPort == port)
            return;
        _selectedPort = port;
        RaisePropertyChanged(nameof(SelectedPort));
        RaisePropertyChanged(nameof(HasSelectedPort));
    }

    public DevicePortActionConfig GetEditingPortAction()
    {
        if (SelectedDevice is null || _selectedPort is null)
            return DevicePortActionConfig.Auto;
        return SelectedDevice.GetPortAction(_selectedPort.Value);
    }

    public async Task SavePortActionAsync(int port, DevicePortActionConfig config)
    {
        if (SelectedDevice is null)
            return;

        SelectedDevice.SetPortAction(port, config);
        await _scanner.UpdateUserMetadataAsync(SelectedDevice, new UserDeviceMetadata
        {
            UpdatePortActions = true,
            PortActionsJson = SelectedDevice.PortActionsJson
        });
        RefreshKnownPorts();
    }

    public async Task ResetPortActionAsync(int port) =>
        await SavePortActionAsync(port, DevicePortActionConfig.Auto);

    public void RunPortAction(int port)
    {
        if (SelectedDevice is null)
            return;
        DevicePortActionHelper.Execute(SelectedDevice, port, SelectedDevice.GetPortAction(port));
    }

    public void RefreshKnownPorts()
    {
        KnownPorts = SelectedDevice?.GetKnownPortDisplayItems() ?? Array.Empty<DevicePortDisplayItem>();
        var live = KnownPorts.Count(p => p.Source is DevicePortSource.Live or DevicePortSource.Both);
        var cached = KnownPorts.Count(p => p.Source is DevicePortSource.Cached or DevicePortSource.Both);
        KnownPortsSummary = KnownPorts.Count switch
        {
            0 => "No ports recorded",
            1 => $"1 port · {live} live · {cached} cached",
            _ => $"{KnownPorts.Count} ports · {live} live · {cached} cached"
        };
        RaisePropertyChanged(nameof(KnownPorts));
        RaisePropertyChanged(nameof(KnownPortsSummary));
        RaisePropertyChanged(nameof(HasKnownPorts));
        RaisePropertyChanged(nameof(HasSelectedPort));
    }

    public RelayCommand PrevDeviceCommand { get; }
    public RelayCommand NextDeviceCommand { get; }
    public RelayCommand ScanPortsCommand { get; }
    public RelayCommand DetectOsCommand { get; }
    public RelayCommand RefreshMetadataCommand { get; }
    public RelayCommand CopyProfileCommand { get; }
    public RelayCommand RevertChangesCommand { get; }
    public RelayCommand ClearAllMetadataCommand { get; }
    public RelayCommand ClearOsHintCommand { get; }
    public RelayCommand ApplyMetadataCommand { get; }

    public void SetSelectedDevices(IReadOnlyList<ScanResultRow> devices, ScanResultRow? primary)
    {
        _selectedDevices.Clear();
        foreach (var device in devices.Distinct())
            _selectedDevices.Add(device);

        var nextPrimary = primary ?? _selectedDevices.FirstOrDefault();
        if (!ReferenceEquals(_scanner.SelectedResult, nextPrimary))
            _scanner.SelectedResult = nextPrimary;

        RaiseSelectionPropertiesChanged();
    }

    public void SetPrimaryDevice(ScanResultRow row)
    {
        if (!_selectedDevices.Contains(row))
            SetSelectedDevices(new[] { row }, row);
        else if (!ReferenceEquals(_scanner.SelectedResult, row))
            _scanner.SelectedResult = row;
    }

    public void PruneSelectionToVisibleDevices()
    {
        var visible = new HashSet<ScanResultRow>(_scanner.DeepInfoDevices);
        var pruned = _selectedDevices.Where(visible.Contains).ToList();
        if (pruned.Count == 0)
        {
            SetSelectedDevices(Array.Empty<ScanResultRow>(), null);
            return;
        }

        if (pruned.Count == _selectedDevices.Count &&
            (SelectedDevice is null || visible.Contains(SelectedDevice)))
            return;

        var primary = SelectedDevice is not null && visible.Contains(SelectedDevice)
            ? SelectedDevice
            : pruned[0];
        SetSelectedDevices(pruned, primary);
    }

    public void NotifyMetadataEdited()
    {
        RaisePropertyChanged(nameof(HasPendingChanges));
        RaisePropertyChanged(nameof(PendingChangesSummary));
        RevertChangesCommand.NotifyCanExecuteChanged();
        ClearOsHintCommand.NotifyCanExecuteChanged();
        ApplyMetadataCommand.NotifyCanExecuteChanged();
        DeviceMetadataChanged?.Invoke();
    }

    public void SelectDevice(ScanResultRow row) => SetSelectedDevices(new[] { row }, row);

    public void SchedulePersistUserFields(ScanResultRow row)
    {
        NotifyMetadataEdited();
        _persistTimer?.Stop();
        _persistTimer = DispatcherQueue.GetForCurrentThread()?.CreateTimer();
        if (_persistTimer is null) return;
        _persistTimer.Interval = TimeSpan.FromMilliseconds(500);
        _persistTimer.IsRepeating = false;
        _persistTimer.Tick += async (_, _) => await PersistUserFieldsAsync(row);
        _persistTimer.Start();
    }

    public async Task PersistUserFieldsAsync(ScanResultRow row)
    {
        var targets = GetPersistTargets(row);
        if (IsMultiSelect && ReferenceEquals(row, SelectedDevice))
        {
            foreach (var target in targets)
            {
                if (!ReferenceEquals(target, SelectedDevice))
                    DeviceMetadataApplier.CopyUserFields(SelectedDevice!, target);
            }
        }

        foreach (var target in targets)
            await PersistSingleUserFieldsAsync(target);

        NotifyMetadataEdited();
    }

    public async Task ApplyMetadataFromPrimaryAsync(DeviceMetadataApplyOptions options)
    {
        if (SelectedDevice is null || _selectedDevices.Count < 2)
            return;

        var source = DeviceEditSnapshot.FromRow(SelectedDevice);
        var targets = _selectedDevices.Where(d => !ReferenceEquals(d, SelectedDevice)).ToList();
        if (targets.Count == 0)
            targets = _selectedDevices.ToList();

        foreach (var target in targets)
        {
            DeviceMetadataApplier.Apply(source, target, options);
            await _scanner.UpdateUserMetadataAsync(target, DeviceMetadataApplier.BuildPersistPatch(target, options));
        }

        if (ReferenceEquals(targets.LastOrDefault(), SelectedDevice) || targets.All(t => !ReferenceEquals(t, SelectedDevice)))
            CaptureEditSnapshot(SelectedDevice);

        NotifyMetadataEdited();
        DeviceMetadataChanged?.Invoke();
    }

    public async Task RevertChangesAsync()
    {
        if (SelectedDevice is null || _editSnapshot is null) return;

        var targets = GetPersistTargets(SelectedDevice);
        foreach (var target in targets)
        {
            _editSnapshot.ApplyTo(target);
            await _scanner.UpdateUserMetadataAsync(target, new UserDeviceMetadata
            {
                UpdateCustomName = true,
                CustomName = string.IsNullOrWhiteSpace(target.CustomName) ? null : target.CustomName,
                UpdateOperatingSystem = true,
                OperatingSystem = string.IsNullOrWhiteSpace(target.OperatingSystem) ? null : target.OperatingSystem,
                UpdateDeviceIconKey = true,
                DeviceIconKey = target.DeviceIconKey,
                UpdateTags = true,
                TagsJson = DeviceIdentityHelper.SerializeTags(target.Tags),
                UpdateNotes = true,
                Notes = string.IsNullOrWhiteSpace(target.Notes) ? null : target.Notes,
                UpdateOsHint = true,
                OsHint = string.IsNullOrWhiteSpace(target.OsHint) ? null : target.OsHint,
                UpdateOsHintSource = true,
                OsHintSource = string.IsNullOrWhiteSpace(target.OsHintSource) ? null : target.OsHintSource
            });
        }

        NotifyMetadataEdited();
    }

    public async Task ClearAllUserMetadataAsync()
    {
        if (SelectedDevice is null) return;

        foreach (var row in GetPersistTargets(SelectedDevice))
        {
            row.CustomName = string.Empty;
            row.OperatingSystem = string.Empty;
            row.Notes = string.Empty;
            row.DeviceIconKey = "Generic";
            row.SetTags(Array.Empty<string>());
            row.OsHint = string.Empty;
            row.OsHintSource = string.Empty;
            row.ClearPortActions();

            await _scanner.UpdateUserMetadataAsync(row, new UserDeviceMetadata
            {
                UpdateCustomName = true,
                CustomName = null,
                UpdateOperatingSystem = true,
                OperatingSystem = null,
                UpdateDeviceIconKey = true,
                DeviceIconKey = "Generic",
                UpdateTags = true,
                TagsJson = "[]",
                UpdateNotes = true,
                Notes = null,
                UpdateOsHint = true,
                OsHint = null,
                UpdateOsHintSource = true,
                OsHintSource = null,
                UpdatePortActions = true,
                PortActionsJson = "{}"
            });
        }

        SelectPort(null);
        CaptureEditSnapshot(SelectedDevice);
        NotifyMetadataEdited();
    }

    public async Task ClearOsHintAsync()
    {
        if (SelectedDevice is null) return;

        foreach (var row in GetPersistTargets(SelectedDevice))
        {
            row.OsHint = string.Empty;
            row.OsHintSource = string.Empty;
            await _scanner.UpdateUserMetadataAsync(row, new UserDeviceMetadata
            {
                UpdateOsHint = true,
                OsHint = null,
                UpdateOsHintSource = true,
                OsHintSource = null
            });
        }

        NotifyMetadataEdited();
    }

    private void CaptureEditSnapshot(ScanResultRow row)
    {
        _editSnapshot = DeviceEditSnapshot.FromRow(row);
        NotifyMetadataEdited();
    }

    public async Task SetIconAsync(ScanResultRow row, string iconKey)
    {
        foreach (var target in GetPersistTargets(row))
        {
            target.DeviceIconKey = iconKey;
            await _scanner.UpdateUserMetadataAsync(target, new UserDeviceMetadata
            {
                UpdateDeviceIconKey = true,
                DeviceIconKey = iconKey
            });
        }

        NotifyMetadataEdited();
    }

    public async Task AddTagAsync(ScanResultRow row, string tag)
    {
        foreach (var target in GetPersistTargets(row))
        {
            target.AddTag(tag);
            await PersistSingleUserFieldsAsync(target);
        }

        NotifyMetadataEdited();
    }

    public async Task RemoveTagAsync(ScanResultRow row, string tag)
    {
        foreach (var target in GetPersistTargets(row))
        {
            target.RemoveTag(tag);
            await PersistSingleUserFieldsAsync(target);
        }

        NotifyMetadataEdited();
    }

    private IEnumerable<ScanResultRow> GetPersistTargets(ScanResultRow row) =>
        IsMultiSelect && ReferenceEquals(row, SelectedDevice) ? _selectedDevices.ToList() : new[] { row };

    private async Task PersistSingleUserFieldsAsync(ScanResultRow row)
    {
        await _scanner.UpdateUserMetadataAsync(row, new UserDeviceMetadata
        {
            UpdateCustomName = true,
            CustomName = string.IsNullOrWhiteSpace(row.CustomName) ? null : row.CustomName,
            UpdateOperatingSystem = true,
            OperatingSystem = string.IsNullOrWhiteSpace(row.OperatingSystem) ? null : row.OperatingSystem,
            UpdateDeviceIconKey = true,
            DeviceIconKey = row.DeviceIconKey,
            UpdateTags = true,
            TagsJson = DeviceIdentityHelper.SerializeTags(row.Tags),
            UpdateNotes = true,
            Notes = string.IsNullOrWhiteSpace(row.Notes) ? null : row.Notes
        });
    }

    private void OnSelectedDeviceChanged()
    {
        UnsubscribeSelectedDevice();
        _monitor.Stop();
        SelectPort(null);
        UpdateMonitorDisplay();
        UpdateDeviceScanState();
        RefreshKnownPorts();

        if (SelectedDevice is not null)
        {
            SubscribeSelectedDevice(SelectedDevice);
            CaptureEditSnapshot(SelectedDevice);
        }
        else
        {
            _editSnapshot = null;
            NotifyMetadataEdited();
        }

        if (MonitorEnabled && SelectedDevice is not null && !string.IsNullOrWhiteSpace(SelectedDevice.IPAddress))
            StartMonitorForSelection();
    }

    private void SubscribeSelectedDevice(ScanResultRow row)
    {
        _selectedDeviceSubscription = row;
        row.PropertyChanged += OnSelectedDevicePropertyChanged;
    }

    private void UnsubscribeSelectedDevice()
    {
        if (_selectedDeviceSubscription is null) return;
        _selectedDeviceSubscription.PropertyChanged -= OnSelectedDevicePropertyChanged;
        _selectedDeviceSubscription = null;
    }

    private void OnSelectedDevicePropertyChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        if (e.PropertyName is nameof(ScanResultRow.IsOnline) or nameof(ScanResultRow.IsCached) or nameof(ScanResultRow.StateLabel))
            UpdateDeviceScanState();
    }

    private void UpdateDeviceScanState()
    {
        DeviceScanStateLabel = SelectedDevice?.StateLabel ?? "—";
        RaisePropertyChanged(nameof(DeviceScanStateBrush));
    }

    private void UpdateMonitorDisplay()
    {
        if (!MonitorEnabled)
        {
            MonitorPingIsUp = false;
            MonitorPingStatusLabel = "Paused";
            MonitorLastLatency = "—";
            MonitorAverageLatency = "—";
            MonitorPacketLoss = "—";
        }
        else if (!_monitor.IsMonitoring)
        {
            MonitorPingIsUp = false;
            MonitorPingStatusLabel = "—";
            MonitorLastLatency = "—";
            MonitorAverageLatency = "—";
            MonitorPacketLoss = "—";
        }
        else if (_monitor.IsUp)
        {
            MonitorPingIsUp = true;
            MonitorPingStatusLabel = "Online";
            MonitorLastLatency = $"{_monitor.LastLatencyMs,4} ms";
            MonitorAverageLatency = $"{_monitor.AverageLatencyMs,4:F0} ms";
            MonitorPacketLoss = $"{_monitor.PacketLossPercent,3:F0} %";

            if (SelectedDevice is not null && (!SelectedDevice.IsOnline || SelectedDevice.IsCached))
            {
                SelectedDevice.MarkReachableLive();
                _scanner.RefreshScopeFilters();
            }
        }
        else
        {
            MonitorPingIsUp = false;
            MonitorPingStatusLabel = "Offline";
            MonitorLastLatency = "—";
            MonitorAverageLatency = "—";
            MonitorPacketLoss = $"{_monitor.PacketLossPercent,3:F0} %";
        }

        RaisePropertyChanged(nameof(MonitorPingStatusBrush));
    }

    private void RaiseSelectionPropertiesChanged()
    {
        RaisePropertyChanged(nameof(SelectedDevices));
        RaisePropertyChanged(nameof(SelectedDeviceCount));
        RaisePropertyChanged(nameof(IsMultiSelect));
        RaisePropertyChanged(nameof(CanApplyMetadataToOthers));
        RaisePropertyChanged(nameof(SelectionSummary));
        RaisePropertyChanged(nameof(HeroTitle));
        RaisePropertyChanged(nameof(HeroSubtitle));
        RaisePropertyChanged(nameof(MultiEditHint));
        RaisePropertyChanged(nameof(PersistWarning));
        ApplyMetadataCommand.NotifyCanExecuteChanged();
    }

    private async Task ApplyMetadataDialogRequestedAsync()
    {
        if (ApplyMetadataDialogRequested is null) return;
        var options = await ApplyMetadataDialogRequested.Invoke();
        if (options is not null)
            await ApplyMetadataFromPrimaryAsync(options);
    }

    private void StartMonitorForSelection()
    {
        if (SelectedDevice is null || string.IsNullOrWhiteSpace(SelectedDevice.IPAddress)) return;
        _monitor.Start(SelectedDevice.IPAddress);
    }

    private async Task ScanPortsAsync()
    {
        if (SelectedDevice is null) return;

        _portScanCts?.Cancel();
        _portScanCts = new CancellationTokenSource();
        IsPortScanning = true;
        PortScanStatus = "Scanning...";

        try
        {
            var progress = new Progress<int>(p => PortScanStatus = $"Checking port {p}...");
            var open = await _scanner.Backend.ScanPortsForHostAsync(
                SelectedDevice.IPAddress,
                DeepScanPorts,
                _scanner.PortTimeoutMs,
                _portScanCts.Token,
                progress);

            var merged = DeviceActions.ParseOpenPorts(SelectedDevice.OpenPorts);
            merged.AddRange(open);
            SelectedDevice.MergeLivePorts(open);
            SelectedDevice.MarkReachableLive();
            PortScanStatus = $"Found {open.Count} open port(s)";
            await _scanner.PersistDevicePublicAsync(SelectedDevice);
            _scanner.RefreshScopeFilters();
            RefreshKnownPorts();
            DeviceMetadataChanged?.Invoke();
        }
        catch (OperationCanceledException)
        {
            PortScanStatus = "Cancelled";
        }
        catch (Exception ex)
        {
            PortScanStatus = ex.Message;
        }
        finally
        {
            IsPortScanning = false;
        }
    }

    private async Task DetectOsAsync()
    {
        if (SelectedDevice is null) return;
        var ports = DeviceActions.ParseOpenPorts(SelectedDevice.OpenPorts);
        var heuristic = _enrichment.GuessOsHeuristic(ports, SelectedDevice.Vendor);
        var (banner, source) = await _enrichment.ProbeOsBannerAsync(SelectedDevice.IPAddress, ports);

        var hint = !string.IsNullOrWhiteSpace(banner) ? banner : heuristic;
        if (string.IsNullOrWhiteSpace(hint)) hint = "Unknown";

        SelectedDevice.OsHint = hint;
        SelectedDevice.OsHintSource = !string.IsNullOrWhiteSpace(banner) ? source : "heuristic";

        await _scanner.UpdateUserMetadataAsync(SelectedDevice, new UserDeviceMetadata
        {
            UpdateOsHint = true,
            OsHint = SelectedDevice.OsHint,
            UpdateOsHintSource = true,
            OsHintSource = SelectedDevice.OsHintSource
        });
    }

    private async Task RefreshMetadataAsync()
    {
        if (SelectedDevice is null) return;
        var (hostname, vendor) = await _enrichment.RefreshMetadataAsync(
            SelectedDevice.IPAddress,
            SelectedDevice.MACAddress,
            resolveDns: _scanner.ResolveDns,
            lookupVendor: _scanner.LookupVendor);

        if (!string.IsNullOrWhiteSpace(hostname)) SelectedDevice.Hostname = hostname;
        if (!string.IsNullOrWhiteSpace(vendor)) SelectedDevice.Vendor = vendor;
        await _scanner.PersistDevicePublicAsync(SelectedDevice);
    }

    public void Dispose()
    {
        UnsubscribeSelectedDevice();
        _monitor.Dispose();
        _portScanCts?.Cancel();
        _portScanCts?.Dispose();
    }

    private static SolidColorBrush Bg(byte a, byte r, byte g, byte b) =>
        new(Microsoft.UI.ColorHelper.FromArgb(a, r, g, b));
}
