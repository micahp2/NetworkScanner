using Microsoft.UI.Dispatching;
using Microsoft.UI;
using Microsoft.UI.Text;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Data;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using NetworkScanner.Services;
using NetworkScanner.WinUIPrototype.Common;
using NetworkScanner.WinUIPrototype.Models;
using NetworkScanner.WinUIPrototype.ViewModels;

namespace NetworkScanner.WinUIPrototype.Pages;

public sealed class DetailsPage : Page
{
    private readonly DeviceDetailViewModel _vm;
    private readonly ListView _deviceList;
    private ScanResultRow? _lastClickedDevice;
    private readonly StackPanel _detailFields;
    private readonly StackPanel _actionsPanel;
    private readonly StackPanel _tagsPanel;
    private readonly Viewbox _heroIconView;
    private readonly Button _heroIconButton;
    private readonly Flyout _iconPickerFlyout;
    private ScrollViewer _iconPickerScroll = null!;
    private Grid _iconPickerGrid = null!;
    private ProgressRing _iconPickerProgress = null!;
    private TextBlock _iconPickerStatus = null!;
    private readonly VariableSizedWrapGrid _knownPortsPanel;
    private readonly TextBlock _knownPortsSummary;
    private readonly TextBlock _knownPortsEmpty;
    private readonly StackPanel _portActionPanel;
    private readonly TextBlock _portActionTitle;
    private readonly ComboBox _portActionKindCombo;
    private readonly TextBox _portActionCustomBox;
    private int? _selectedPort;
    private bool _portActionUiUpdating;
    private bool _isRefreshingKnownPorts;
    private readonly ColumnDefinition _leftColumn;
    private readonly ColumnDefinition _rightColumn;

    private double _leftWidth = 240;
    private double _rightWidth = 360;
    private bool _isResizingPane;
    private int _resizeTarget;
    private double _resizeStartX;
    private double _resizeStartWidth;
    private bool _iconPickerGridReady;
    private Task<IReadOnlyList<string>>? _glyphLoadTask;

    private const int IconPickerColumns = 10;
    private const int IconPickerButtonSize = 40;
    private const double IconPickerGridWidth = IconPickerColumns * IconPickerButtonSize;
    private const double IconPickerHostWidth = IconPickerGridWidth + 32;
    private const int IconPickerBatchSize = 80;
    private static readonly FontFamily FluentIconFont = new("Segoe Fluent Icons");

    public DetailsPage()
    {
        _vm = new DeviceDetailViewModel(((App)Application.Current).ScannerViewModel);
        DataContext = _vm;
        Unloaded += (_, _) => _vm.Dispose();
        _vm.DeviceMetadataChanged += OnDeviceMetadataChanged;
        _vm.ApplyMetadataDialogRequested += ShowApplyMetadataDialogAsync;

        var root = new Grid { Background = Bg(0xFF, 0x0E, 0x0F, 0x11) };
        _leftColumn = new ColumnDefinition { Width = new GridLength(_leftWidth) };
        _rightColumn = new ColumnDefinition { Width = new GridLength(_rightWidth) };
        root.ColumnDefinitions.Add(_leftColumn);
        root.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(6) });
        root.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        root.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(6) });
        root.ColumnDefinitions.Add(_rightColumn);

        // Left pane — scrollable device list (filtered by global search bar)
        var left = Card(new Thickness(8, 8, 2, 8));
        var leftGrid = new Grid();
        leftGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        leftGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });

        var leftHeader = new StackPanel { Spacing = 2 };
        leftHeader.Children.Add(new TextBlock { Text = "Devices", FontSize = 16, FontWeight = FontWeights.SemiBold });
        leftHeader.Children.Add(new TextBlock { Text = "Use the search bar above to filter", Opacity = 0.55, FontSize = 12 });
        leftHeader.Children.Add(new TextBlock { Text = "Ctrl+click to select multiple", Opacity = 0.45, FontSize = 11 });
        var selectionSummary = new TextBlock { Opacity = 0.7, FontSize = 12, TextWrapping = TextWrapping.Wrap };
        selectionSummary.SetBinding(TextBlock.TextProperty, new Binding { Path = new PropertyPath("SelectionSummary") });
        leftHeader.Children.Add(selectionSummary);
        Grid.SetRow(leftHeader, 0);
        leftGrid.Children.Add(leftHeader);

        _deviceList = new ListView
        {
            SelectionMode = ListViewSelectionMode.Extended,
            IsItemClickEnabled = true,
            DisplayMemberPath = "ListLabel",
            Margin = new Thickness(0, 8, 0, 0),
            VerticalAlignment = VerticalAlignment.Stretch
        };
        _deviceList.SetBinding(ItemsControl.ItemsSourceProperty, new Binding { Path = new PropertyPath("Scanner.DeepInfoDevices") });
        _deviceList.SelectionChanged += OnDeviceListSelectionChanged;
        _deviceList.ItemClick += (_, e) =>
        {
            if (e.ClickedItem is ScanResultRow row)
            {
                _lastClickedDevice = row;
                _vm.SetPrimaryDevice(row);
            }
        };
        Grid.SetRow(_deviceList, 1);
        leftGrid.Children.Add(_deviceList);
        left.Child = leftGrid;
        Grid.SetColumn(left, 0);
        root.Children.Add(left);

        root.Children.Add(CreatePaneSplitter(1, resizeLeft: true));
        root.Children.Add(CreatePaneSplitter(3, resizeLeft: false));

        // Center pane
        var centerScroll = new ScrollViewer { VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Margin = new Thickness(2, 8, 2, 8) };
        var center = new StackPanel { Spacing = 12, Padding = new Thickness(20, 16, 20, 20) };

        center.Children.Add(new TextBlock { Text = "Deep Info", FontSize = 20, FontWeight = FontWeights.SemiBold });

        var heroRow = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 14, VerticalAlignment = VerticalAlignment.Center };
        _heroIconView = DeviceIconHelper.CreateIconView("Generic", 40);
        _heroIconButton = new Button
        {
            Width = 72,
            Height = 72,
            Padding = new Thickness(0),
            HorizontalAlignment = HorizontalAlignment.Left,
            Content = _heroIconView
        };
        ToolTipService.SetToolTip(_heroIconButton, "Change device icon");
        _iconPickerFlyout = BuildIconPickerFlyout();
        _heroIconButton.Flyout = _iconPickerFlyout;
        heroRow.Children.Add(_heroIconButton);

        var heroText = new StackPanel { VerticalAlignment = VerticalAlignment.Center, Spacing = 2 };
        var heroName = new TextBlock { FontSize = 18, FontWeight = FontWeights.SemiBold, TextWrapping = TextWrapping.Wrap };
        heroName.SetBinding(TextBlock.TextProperty, new Binding { Path = new PropertyPath("HeroTitle") });
        var heroIp = new TextBlock { Opacity = 0.75, TextWrapping = TextWrapping.Wrap };
        heroIp.SetBinding(TextBlock.TextProperty, new Binding { Path = new PropertyPath("HeroSubtitle") });
        var changeIconHint = new TextBlock { Text = "Click icon to change", Opacity = 0.55, FontSize = 12 };
        heroText.Children.Add(heroName);
        heroText.Children.Add(heroIp);
        heroText.Children.Add(changeIconHint);
        heroRow.Children.Add(heroText);
        center.Children.Add(heroRow);

        var multiHint = new TextBlock { Foreground = Bg(0xFF, 0x8C, 0xA8, 0xFF), TextWrapping = TextWrapping.Wrap };
        multiHint.SetBinding(TextBlock.TextProperty, new Binding { Path = new PropertyPath("MultiEditHint") });
        multiHint.SetBinding(UIElement.VisibilityProperty, new Binding
        {
            Path = new PropertyPath("IsMultiSelect"),
            Converter = new BoolToVisibilityConverter()
        });
        center.Children.Add(multiHint);

        var navRow = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8 };
        var prevBtn = new Button { Content = "← Prev" };
        prevBtn.SetBinding(Button.CommandProperty, new Binding { Path = new PropertyPath("PrevDeviceCommand") });
        var nextBtn = new Button { Content = "Next →" };
        nextBtn.SetBinding(Button.CommandProperty, new Binding { Path = new PropertyPath("NextDeviceCommand") });
        navRow.Children.Add(prevBtn);
        navRow.Children.Add(nextBtn);
        center.Children.Add(navRow);

        var pending = new TextBlock { Foreground = Bg(0xFF, 0x8C, 0xA8, 0xFF), TextWrapping = TextWrapping.Wrap };
        pending.SetBinding(TextBlock.TextProperty, new Binding { Path = new PropertyPath("PendingChangesSummary") });
        center.Children.Add(pending);

        var warn = new TextBlock { Foreground = Bg(0xFF, 0xE1, 0xB8, 0x54), TextWrapping = TextWrapping.Wrap };
        warn.SetBinding(TextBlock.TextProperty, new Binding { Path = new PropertyPath("PersistWarning") });
        center.Children.Add(warn);

        var editActions = new StackPanel { Spacing = 8 };
        var editRow1 = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8 };
        var revertBtn = new Button { Content = "Revert Changes" };
        revertBtn.SetBinding(Button.CommandProperty, new Binding { Path = new PropertyPath("RevertChangesCommand") });
        var clearBtn = new Button { Content = "Clear All Metadata" };
        clearBtn.SetBinding(Button.CommandProperty, new Binding { Path = new PropertyPath("ClearAllMetadataCommand") });
        var clearOsBtn = new Button { Content = "Clear OS Detected" };
        clearOsBtn.SetBinding(Button.CommandProperty, new Binding { Path = new PropertyPath("ClearOsHintCommand") });
        editRow1.Children.Add(revertBtn);
        editRow1.Children.Add(clearBtn);
        editRow1.Children.Add(clearOsBtn);
        editActions.Children.Add(editRow1);

        var applyMetaBtn = new Button { Content = "Apply Metadata to Selected…", HorizontalAlignment = HorizontalAlignment.Left };
        applyMetaBtn.SetBinding(Button.CommandProperty, new Binding { Path = new PropertyPath("ApplyMetadataCommand") });
        editActions.Children.Add(applyMetaBtn);
        center.Children.Add(editActions);

        center.Children.Add(new TextBlock { Text = "Device tools", FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 4, 0, 0) });
        var deviceTools = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8 };
        var detectOs = new Button { Content = "Detect OS" };
        detectOs.SetBinding(Button.CommandProperty, new Binding { Path = new PropertyPath("DetectOsCommand") });
        var refresh = new Button { Content = "Refresh Metadata" };
        refresh.SetBinding(Button.CommandProperty, new Binding { Path = new PropertyPath("RefreshMetadataCommand") });
        var copyProfile = new Button { Content = "Copy Profile" };
        copyProfile.Click += async (_, _) =>
        {
            if (_vm.SelectedDevice is not null)
            {
                DeviceActions.CopyDeviceProfile(_vm.SelectedDevice);
                copyProfile.Content = "Copied!";
                await Task.Delay(1500);
                copyProfile.Content = "Copy Profile";
            }
        };
        deviceTools.Children.Add(detectOs);
        deviceTools.Children.Add(refresh);
        deviceTools.Children.Add(copyProfile);
        center.Children.Add(deviceTools);

        _detailFields = new StackPanel { Spacing = 10 };
        BuildDetailFields();
        center.Children.Add(_detailFields);
        centerScroll.Content = center;
        Grid.SetColumn(centerScroll, 2);
        root.Children.Add(centerScroll);

        // Right pane
        var rightScroll = new ScrollViewer { VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Margin = new Thickness(2, 8, 8, 8) };
        var right = new StackPanel { Spacing = 10, Padding = new Thickness(16, 12, 16, 20) };

        right.Children.Add(CreateLiveStatusHeader());
        var statusCard = Card(new Thickness(0));
        statusCard.Child = BuildLiveStatusPanel();
        right.Children.Add(statusCard);

        right.Children.Add(SectionTitle("Known Ports"));
        var knownPortsCard = Card(new Thickness(0));
        var knownPortsInner = new StackPanel { Spacing = 8, Padding = new Thickness(12) };
        _knownPortsSummary = new TextBlock { Opacity = 0.7, FontSize = 12 };
        _knownPortsSummary.SetBinding(TextBlock.TextProperty, new Binding { Path = new PropertyPath("KnownPortsSummary") });
        knownPortsInner.Children.Add(_knownPortsSummary);
        knownPortsInner.Children.Add(CreatePortLegend());

        _knownPortsEmpty = new TextBlock
        {
            Text = "No ports recorded for this device yet.",
            Opacity = 0.55,
            TextWrapping = TextWrapping.Wrap
        };
        _knownPortsEmpty.SetBinding(UIElement.VisibilityProperty, new Binding
        {
            Path = new PropertyPath("HasKnownPorts"),
            Converter = new BoolToVisibilityConverter(),
            ConverterParameter = "Invert"
        });

        _knownPortsPanel = new VariableSizedWrapGrid { Orientation = Orientation.Horizontal, ItemWidth = double.NaN, ItemHeight = double.NaN };

        knownPortsInner.Children.Add(_knownPortsEmpty);
        knownPortsInner.Children.Add(_knownPortsPanel);

        _portActionPanel = new StackPanel { Spacing = 8, Visibility = Visibility.Collapsed, Margin = new Thickness(0, 4, 0, 0) };
        _portActionTitle = new TextBlock { FontWeight = FontWeights.SemiBold, FontSize = 12, TextWrapping = TextWrapping.Wrap };
        _portActionKindCombo = new ComboBox { HorizontalAlignment = HorizontalAlignment.Stretch };
        foreach (var kind in DevicePortActionHelper.SelectableKinds)
        {
            _portActionKindCombo.Items.Add(new ComboBoxItem
            {
                Content = DevicePortActionHelper.GetKindDisplayName(kind),
                Tag = kind
            });
        }
        _portActionKindCombo.SelectionChanged += async (_, _) => await OnPortActionKindChangedAsync();

        _portActionCustomBox = new TextBox
        {
            PlaceholderText = "Custom URL or app command — use {ip} and {port}",
            Visibility = Visibility.Collapsed
        };
        _portActionCustomBox.LostFocus += async (_, _) => await SavePortActionFromUiAsync();

        var portActionButtons = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8 };
        var runPortBtn = new Button { Content = "Run" };
        runPortBtn.Click += (_, _) => RunSelectedPortAction();
        var resetPortBtn = new Button { Content = "Reset to Auto" };
        resetPortBtn.Click += async (_, _) => await ResetSelectedPortActionAsync();
        portActionButtons.Children.Add(runPortBtn);
        portActionButtons.Children.Add(resetPortBtn);

        _portActionPanel.Children.Add(_portActionTitle);
        _portActionPanel.Children.Add(new TextBlock
        {
            Text = "Choose how to open this port on this device. Settings are saved per device.",
            Opacity = 0.65,
            FontSize = 11,
            TextWrapping = TextWrapping.Wrap
        });
        _portActionPanel.Children.Add(_portActionKindCombo);
        _portActionPanel.Children.Add(_portActionCustomBox);
        _portActionPanel.Children.Add(portActionButtons);
        knownPortsInner.Children.Add(_portActionPanel);

        knownPortsCard.Child = knownPortsInner;
        right.Children.Add(knownPortsCard);

        right.Children.Add(SectionTitle("Port Scan"));
        var portCard = Card(new Thickness(0));
        var portInner = new StackPanel { Spacing = 8, Padding = new Thickness(12) };
        var portBox = new TextBox { PlaceholderText = "22,80,443,8080-8090" };
        portBox.SetBinding(TextBox.TextProperty, new Binding { Path = new PropertyPath("DeepScanPorts"), Mode = BindingMode.TwoWay });
        portInner.Children.Add(portBox);
        var scanBtn = new Button { Content = "Scan Ports" };
        scanBtn.SetBinding(Button.CommandProperty, new Binding { Path = new PropertyPath("ScanPortsCommand") });
        scanBtn.SetBinding(Control.IsEnabledProperty, new Binding { Path = new PropertyPath("CanStartPortScan") });

        var cancelBtn = new Button { Content = "Cancel" };
        cancelBtn.SetBinding(Button.CommandProperty, new Binding { Path = new PropertyPath("CancelPortScanCommand") });
        cancelBtn.SetBinding(Control.IsEnabledProperty, new Binding { Path = new PropertyPath("IsPortScanning") });

        var btnPanel = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8 };
        btnPanel.Children.Add(scanBtn);
        btnPanel.Children.Add(cancelBtn);
        portInner.Children.Add(btnPanel);

        var portStatus = new TextBlock { Opacity = 0.8 };
        portStatus.SetBinding(TextBlock.TextProperty, new Binding { Path = new PropertyPath("PortScanStatus") });
        portInner.Children.Add(portStatus);
        portCard.Child = portInner;
        right.Children.Add(portCard);

        right.Children.Add(SectionTitle("Quick Actions"));
        _actionsPanel = new StackPanel { Spacing = 6 };
        right.Children.Add(_actionsPanel);

        right.Children.Add(SectionTitle("Tags"));
        _tagsPanel = new StackPanel { Spacing = 6 };
        right.Children.Add(_tagsPanel);
        var tagBox = new TextBox { PlaceholderText = "Add tag, press Enter..." };
        tagBox.KeyDown += async (_, e) =>
        {
            if (e.Key == Windows.System.VirtualKey.Enter && _vm.SelectedDevice is not null && !string.IsNullOrWhiteSpace(tagBox.Text))
            {
                await _vm.AddTagAsync(_vm.SelectedDevice, tagBox.Text.Trim());
                tagBox.Text = string.Empty;
                RefreshTags();
            }
        };
        right.Children.Add(tagBox);

        rightScroll.Content = right;
        Grid.SetColumn(rightScroll, 4);
        root.Children.Add(rightScroll);

        Content = root;
        _glyphLoadTask = DeviceIconHelper.GetFluentGlyphsAsync();
        Loaded += (_, _) =>
        {
            RefreshActions();
            RefreshTags();
            RefreshHeroIcon();
            RefreshKnownPortsPanel();
            WireSelection();
        };
        _vm.Scanner.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName is nameof(ScannerViewModel.SelectedResult))
            {
                if (_vm.Scanner.SelectedResult is not null &&
                    (_deviceList.SelectedItems.Count == 0 || !_deviceList.SelectedItems.Contains(_vm.Scanner.SelectedResult)))
                {
                    SyncListSelection(new[] { _vm.Scanner.SelectedResult }, _vm.Scanner.SelectedResult);
                }

                ClearPortSelection();
                RefreshActions();
                RefreshTags();
                RefreshHeroIcon();
                RefreshKnownPortsPanel();
            }
            else if (e.PropertyName is nameof(ScannerViewModel.DeepInfoListVersion))
            {
                SyncListSelectionToDeepInfoDevices();
            }
        };
        _vm.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(DeviceDetailViewModel.KnownPorts))
            {
                DispatcherQueue.TryEnqueue(() => RefreshKnownPortsPanel());
            }
        };
    }

    private void SyncListSelectionToDeepInfoDevices()
    {
        var visible = _vm.Scanner.DeepInfoDevices.ToList();
        var current = _deviceList.SelectedItems.Cast<ScanResultRow>().Where(r => visible.Contains(r)).ToList();
        if (current.Count == 0)
        {
            if (visible.Count > 0)
                SyncListSelection(new[] { visible[0] }, visible[0]);
            else
                SyncListSelection(Array.Empty<ScanResultRow>(), null);
            return;
        }

        if (current.Count == _deviceList.SelectedItems.Count)
            return;

        var primary = _lastClickedDevice is not null && current.Contains(_lastClickedDevice)
            ? _lastClickedDevice
            : current[^1];
        SyncListSelection(current, primary);
    }

    private void OnDeviceListSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        var selected = _deviceList.SelectedItems.Cast<ScanResultRow>().ToList();
        if (selected.Count == 0)
        {
            _vm.SetSelectedDevices(Array.Empty<ScanResultRow>(), null);
            return;
        }

        var primary = _lastClickedDevice is not null && selected.Contains(_lastClickedDevice)
            ? _lastClickedDevice
            : selected[^1];
        _vm.SetSelectedDevices(selected, primary);
    }

    private void SyncListSelection(IReadOnlyList<ScanResultRow> rows, ScanResultRow? primary)
    {
        _deviceList.SelectionChanged -= OnDeviceListSelectionChanged;
        _deviceList.SelectedItems.Clear();
        foreach (var row in rows)
            _deviceList.SelectedItems.Add(row);
        _lastClickedDevice = primary ?? rows.FirstOrDefault();
        _deviceList.SelectionChanged += OnDeviceListSelectionChanged;
        _vm.SetSelectedDevices(rows, _lastClickedDevice);
    }

    private UIElement BuildLiveStatusPanel()
    {
        var panel = new StackPanel { Spacing = 10, Padding = new Thickness(12) };

        panel.Children.Add(new TextBlock
        {
            Text = "Device scan state",
            FontWeight = FontWeights.SemiBold,
            FontSize = 12,
            Opacity = 0.8
        });
        panel.Children.Add(CreateStatusBadgeRow("State", "DeviceScanStateLabel", "DeviceScanStateBrush"));

        panel.Children.Add(new TextBlock
        {
            Text = "Ping monitor",
            FontWeight = FontWeights.SemiBold,
            FontSize = 12,
            Opacity = 0.8,
            Margin = new Thickness(0, 4, 0, 0)
        });
        panel.Children.Add(CreateStatusBadgeRow("Ping", "MonitorPingStatusLabel", "MonitorPingStatusBrush"));
        panel.Children.Add(CreateMetricRow("Last latency", "MonitorLastLatency"));
        panel.Children.Add(CreateMetricRow("Average", "MonitorAverageLatency"));
        panel.Children.Add(CreateMetricRow("Packet loss", "MonitorPacketLoss"));

        return panel;
    }

    private UIElement CreateLiveStatusHeader()
    {
        var header = new Grid { Margin = new Thickness(0, 8, 0, 0) };
        header.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        header.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

        var title = new TextBlock
        {
            Text = "Live Status",
            FontWeight = FontWeights.SemiBold,
            VerticalAlignment = VerticalAlignment.Center
        };

        var monitorToggle = new ToggleSwitch
        {
            OnContent = "On",
            OffContent = "Off",
            VerticalAlignment = VerticalAlignment.Center
        };
        monitorToggle.SetBinding(ToggleSwitch.IsOnProperty, new Binding
        {
            Path = new PropertyPath("MonitorEnabled"),
            Mode = BindingMode.TwoWay
        });

        Grid.SetColumn(title, 0);
        Grid.SetColumn(monitorToggle, 1);
        header.Children.Add(title);
        header.Children.Add(monitorToggle);
        return header;
    }

    private static Grid CreateMetricRow(string label, string bindingPath)
    {
        var grid = new Grid();
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(96) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

        var labelBlock = new TextBlock { Text = label, Opacity = 0.7, FontSize = 12, VerticalAlignment = VerticalAlignment.Center };
        var valueBlock = new TextBlock
        {
            HorizontalAlignment = HorizontalAlignment.Right,
            VerticalAlignment = VerticalAlignment.Center,
            FontFamily = new FontFamily("Consolas")
        };
        valueBlock.SetBinding(TextBlock.TextProperty, new Binding { Path = new PropertyPath(bindingPath) });

        Grid.SetColumn(labelBlock, 0);
        Grid.SetColumn(valueBlock, 1);
        grid.Children.Add(labelBlock);
        grid.Children.Add(valueBlock);
        return grid;
    }

    private static Grid CreateStatusBadgeRow(string leftLabel, string labelPath, string brushPath)
    {
        var grid = new Grid();
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(96) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

        var labelBlock = new TextBlock { Text = leftLabel, Opacity = 0.7, FontSize = 12, VerticalAlignment = VerticalAlignment.Center };
        var badge = new Border
        {
            HorizontalAlignment = HorizontalAlignment.Right,
            MinWidth = 88,
            Padding = new Thickness(10, 4, 10, 4),
            CornerRadius = new CornerRadius(4)
        };
        var badgeText = new TextBlock
        {
            HorizontalAlignment = HorizontalAlignment.Center,
            FontWeight = FontWeights.SemiBold,
            FontSize = 12,
            Foreground = new SolidColorBrush(Microsoft.UI.Colors.White)
        };
        badgeText.SetBinding(TextBlock.TextProperty, new Binding { Path = new PropertyPath(labelPath) });
        badge.SetBinding(Border.BackgroundProperty, new Binding { Path = new PropertyPath(brushPath) });
        badge.Child = badgeText;

        Grid.SetColumn(labelBlock, 0);
        Grid.SetColumn(badge, 1);
        grid.Children.Add(labelBlock);
        grid.Children.Add(badge);
        return grid;
    }

    private async Task<DeviceMetadataApplyOptions?> ShowApplyMetadataDialogAsync()
    {
        if (_vm.SelectedDevice is null || _vm.SelectedDeviceCount < 2)
            return null;

        var targetCount = _vm.SelectedDevices.Count(d => !ReferenceEquals(d, _vm.SelectedDevice));
        if (targetCount == 0)
            targetCount = _vm.SelectedDeviceCount - 1;

        var applyCustomName = new CheckBox { Content = "Custom name", IsChecked = true };
        var applyIcon = new CheckBox { Content = "Icon", IsChecked = true };
        var applyOs = new CheckBox { Content = "Operating system", IsChecked = true };
        var applyTags = new CheckBox { Content = "Tags", IsChecked = true };
        var applyNotes = new CheckBox { Content = "Notes", IsChecked = true };
        var applyOsHint = new CheckBox { Content = "OS detected", IsChecked = false };
        var fillMissing = new ToggleSwitch
        {
            Header = "Only fill empty fields",
            IsOn = true,
            OnContent = "Missing only",
            OffContent = "Overwrite selected"
        };

        var content = new StackPanel { Spacing = 10, MinWidth = 360 };
        content.Children.Add(new TextBlock
        {
            Text = $"Copy metadata from {_vm.SelectedDevice.DisplayName} to {targetCount} other selected device(s).",
            TextWrapping = TextWrapping.Wrap
        });
        content.Children.Add(new TextBlock { Text = "Fields to apply", FontWeight = FontWeights.SemiBold, FontSize = 12 });
        content.Children.Add(applyCustomName);
        content.Children.Add(applyIcon);
        content.Children.Add(applyOs);
        content.Children.Add(applyTags);
        content.Children.Add(applyNotes);
        content.Children.Add(applyOsHint);
        content.Children.Add(fillMissing);

        var dialog = new ContentDialog
        {
            Title = "Apply metadata",
            Content = content,
            PrimaryButtonText = "Apply",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Primary,
            XamlRoot = XamlRoot
        };

        var result = await dialog.ShowAsync();
        if (result != ContentDialogResult.Primary)
            return null;

        return new DeviceMetadataApplyOptions
        {
            ApplyCustomName = applyCustomName.IsChecked == true,
            ApplyOperatingSystem = applyOs.IsChecked == true,
            ApplyDeviceIconKey = applyIcon.IsChecked == true,
            ApplyTags = applyTags.IsChecked == true,
            ApplyNotes = applyNotes.IsChecked == true,
            ApplyOsHint = applyOsHint.IsChecked == true,
            FillMissingOnly = fillMissing.IsOn
        };
    }

    private Flyout BuildIconPickerFlyout()
    {
        var flyout = new Flyout { Placement = FlyoutPlacementMode.Bottom };
        var panel = new StackPanel { Spacing = 8, Padding = new Thickness(12), MinWidth = IconPickerHostWidth + 24 };

        var header = new StackPanel { Spacing = 2 };
        header.Children.Add(new TextBlock { Text = "Choose an icon", FontWeight = FontWeights.SemiBold });
        _iconPickerStatus = new TextBlock
        {
            Text = "All Segoe Fluent Icons",
            Opacity = 0.55,
            FontSize = 12
        };
        header.Children.Add(_iconPickerStatus);
        panel.Children.Add(header);

        var host = new Grid { Height = 420, Width = IconPickerHostWidth };

        _iconPickerGrid = new Grid { Width = IconPickerGridWidth, HorizontalAlignment = HorizontalAlignment.Left };
        _iconPickerScroll = new ScrollViewer
        {
            Width = IconPickerHostWidth,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled,
            Content = _iconPickerGrid,
            Visibility = Visibility.Collapsed
        };

        _iconPickerProgress = new ProgressRing
        {
            Width = 36,
            Height = 36,
            IsActive = true,
            HorizontalAlignment = HorizontalAlignment.Center,
            VerticalAlignment = VerticalAlignment.Center
        };

        host.Children.Add(_iconPickerScroll);
        host.Children.Add(_iconPickerProgress);
        panel.Children.Add(host);

        flyout.Opening += (_, _) => _ = EnsureIconPickerGridAsync();
        flyout.Content = panel;
        return flyout;
    }

    private async Task EnsureIconPickerGridAsync()
    {
        if (_iconPickerGridReady)
            return;

        _iconPickerProgress.Visibility = Visibility.Visible;
        _iconPickerProgress.IsActive = true;
        _iconPickerScroll.Visibility = Visibility.Collapsed;
        _iconPickerStatus.Text = "Loading icons…";

        try
        {
            var hexKeys = await (_glyphLoadTask ?? DeviceIconHelper.GetFluentGlyphsAsync()).ConfigureAwait(true);
            await PopulateIconPickerGridAsync(hexKeys);
            _iconPickerScroll.Visibility = Visibility.Visible;
            _iconPickerProgress.Visibility = Visibility.Collapsed;
            _iconPickerProgress.IsActive = false;
            _iconPickerStatus.Text = $"{hexKeys.Count:N0} Segoe Fluent Icons";
            _iconPickerGridReady = true;
        }
        catch
        {
            _iconPickerStatus.Text = "Unable to load icons";
            _iconPickerProgress.Visibility = Visibility.Collapsed;
            _iconPickerProgress.IsActive = false;
        }
    }

    private async Task PopulateIconPickerGridAsync(IReadOnlyList<string> hexKeys)
    {
        _iconPickerGrid.Children.Clear();
        _iconPickerGrid.RowDefinitions.Clear();
        _iconPickerGrid.ColumnDefinitions.Clear();

        for (var c = 0; c < IconPickerColumns; c++)
            _iconPickerGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(IconPickerButtonSize) });

        var rowCount = (hexKeys.Count + IconPickerColumns - 1) / IconPickerColumns;
        for (var r = 0; r < rowCount; r++)
            _iconPickerGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        var row = 0;
        var col = 0;
        for (var i = 0; i < hexKeys.Count; i++)
        {
            var btn = CreateIconPickerButton(hexKeys[i]);
            Grid.SetRow(btn, row);
            Grid.SetColumn(btn, col);
            _iconPickerGrid.Children.Add(btn);

            col++;
            if (col >= IconPickerColumns)
            {
                col = 0;
                row++;
            }

            if (i > 0 && i % IconPickerBatchSize == 0)
                await YieldUiAsync();
        }
    }

    private Task YieldUiAsync()
    {
        var tcs = new TaskCompletionSource();
        DispatcherQueue.TryEnqueue(DispatcherQueuePriority.Low, () => tcs.SetResult());
        return tcs.Task;
    }

    private Button CreateIconPickerButton(string hexKey)
    {
        var btn = new Button
        {
            Width = IconPickerButtonSize,
            Height = IconPickerButtonSize,
            MinWidth = 0,
            MaxWidth = IconPickerButtonSize,
            Padding = new Thickness(0),
            Margin = new Thickness(0),
            Tag = hexKey,
            Content = new FontIcon
            {
                Glyph = HexKeyToGlyph(hexKey),
                FontSize = 16
            }
        };
        ToolTipService.SetToolTip(btn, $"U+{hexKey}");
        btn.Click += IconPickerButtonClick;
        return btn;
    }

    private static string HexKeyToGlyph(string hexKey) =>
        char.ConvertFromUtf32(Convert.ToInt32(hexKey, 16));

    private async void IconPickerButtonClick(object sender, RoutedEventArgs e)
    {
        if (sender is not Button btn || btn.Tag is not string hexKey || _vm.SelectedDevice is null)
            return;

        await _vm.SetIconAsync(_vm.SelectedDevice, hexKey);
        RefreshHeroIcon();
        _iconPickerFlyout.Hide();
    }

    private Border CreatePaneSplitter(int column, bool resizeLeft)
    {
        var grip = new Border
        {
            Width = 6,
            Background = Bg(0x00, 0x00, 0x00, 0x00),
            HorizontalAlignment = HorizontalAlignment.Stretch
        };
        var line = new Border
        {
            Width = 2,
            HorizontalAlignment = HorizontalAlignment.Center,
            Background = Bg(0x55, 0x8D, 0x96, 0xA4)
        };
        grip.Child = line;

        grip.PointerEntered += (_, _) => line.Background = Bg(0xBB, 0xA6, 0xB4, 0xFF);
        grip.PointerExited += (_, _) =>
        {
            if (!_isResizingPane) line.Background = Bg(0x55, 0x8D, 0x96, 0xA4);
        };

        grip.PointerPressed += (s, e) =>
        {
            _isResizingPane = true;
            _resizeTarget = resizeLeft ? 0 : 1;
            _resizeStartX = e.GetCurrentPoint(grip).Position.X;
            _resizeStartWidth = resizeLeft ? _leftWidth : _rightWidth;
            grip.CapturePointer(e.Pointer);
            e.Handled = true;
        };

        grip.PointerMoved += (s, e) =>
        {
            if (!_isResizingPane) return;
            var delta = e.GetCurrentPoint(grip).Position.X - _resizeStartX;
            if (_resizeTarget == 0)
            {
                _leftWidth = Math.Clamp(_resizeStartWidth + delta, 180, 480);
                _leftColumn.Width = new GridLength(_leftWidth);
            }
            else
            {
                _rightWidth = Math.Clamp(_resizeStartWidth - delta, 300, 560);
                _rightColumn.Width = new GridLength(_rightWidth);
            }
            e.Handled = true;
        };

        grip.PointerReleased += (s, e) =>
        {
            _isResizingPane = false;
            grip.ReleasePointerCapture(e.Pointer);
            e.Handled = true;
        };

        grip.PointerCanceled += (s, e) =>
        {
            _isResizingPane = false;
            grip.ReleasePointerCapture(e.Pointer);
        };

        Grid.SetColumn(grip, column);
        return grip;
    }

    private void OnDeviceMetadataChanged()
    {
        RefreshTags();
        RefreshHeroIcon();
        RefreshKnownPortsPanel();
    }

    private void RefreshHeroIcon()
    {
        var key = _vm.SelectedDevice?.DeviceIconKey;
        if (string.IsNullOrWhiteSpace(key))
            key = "Generic";
        _heroIconView.Child = DeviceIconHelper.CreateIconElement(key);
    }

    private void WireSelection()
    {
        if (_vm.Scanner.SelectedResult is not null)
        {
            SyncListSelection(new[] { _vm.Scanner.SelectedResult }, _vm.Scanner.SelectedResult);
            return;
        }

        if (_vm.Scanner.DeepInfoDevices.Count > 0)
            SyncListSelection(new[] { _vm.Scanner.DeepInfoDevices[0] }, _vm.Scanner.DeepInfoDevices[0]);
    }

    private void BuildDetailFields()
    {
        _detailFields.Children.Add(WrapEditable("Custom Name", "CustomName", v =>
            ApplyEditableField(r => r.CustomName = v, v)));

        _detailFields.Children.Add(ReadOnlyField("Hostname", "Scanner.SelectedResult.Hostname"));
        _detailFields.Children.Add(ReadOnlyField("IP Address", "Scanner.SelectedResult.IPAddress"));
        _detailFields.Children.Add(ReadOnlyField("MAC Address", "Scanner.SelectedResult.MACAddress"));
        _detailFields.Children.Add(ReadOnlyField("Vendor", "Scanner.SelectedResult.Vendor"));
        _detailFields.Children.Add(ReadOnlyField("IPv6", "Scanner.SelectedResult.IPv6Address"));
        _detailFields.Children.Add(ReadOnlyField("First Seen", "Scanner.SelectedResult.FirstSeenText"));
        _detailFields.Children.Add(ReadOnlyField("Last Seen", "Scanner.SelectedResult.LastSeenText"));

        _detailFields.Children.Add(WrapEditable("Operating System", "OperatingSystem", v =>
            ApplyEditableField(r => r.OperatingSystem = v, v)));

        _detailFields.Children.Add(ReadOnlyField("OS Detected", "Scanner.SelectedResult.OsHint"));

        _detailFields.Children.Add(WrapEditable("Notes", "Notes", v =>
            ApplyEditableField(r => r.Notes = v, v), multiline: true));
    }

    private void RefreshKnownPortsPanel()
    {
        if (_isRefreshingKnownPorts) return;
        _isRefreshingKnownPorts = true;
        try
        {
            _knownPortsPanel.Children.Clear();
            _knownPortsEmpty.Visibility = _vm.HasKnownPorts ? Visibility.Collapsed : Visibility.Visible;

            if (!_vm.HasKnownPorts)
            {
                ClearPortSelection();
                return;
            }

            if (_selectedPort is int selected && _vm.KnownPorts.All(p => p.Port != selected))
                ClearPortSelection();

            foreach (var port in _vm.KnownPorts)
            {
                _knownPortsPanel.Children.Add(CreatePortChip(port));
            }

            if (_selectedPort is int current)
                UpdatePortActionPanel(current);
        }
        finally
        {
            _isRefreshingKnownPorts = false;
        }
    }

    private Border CreatePortChip(DevicePortDisplayItem port)
    {
        var chip = BuildPortChipVisual(port, port.Port == _selectedPort);
        chip.PointerPressed += (_, e) =>
        {
            SelectPort(port.Port);
            e.Handled = true;
        };
        return chip;
    }

    private void SelectPort(int port)
    {
        if (_selectedPort == port)
        {
            ClearPortSelection();
            RefreshKnownPortsPanel();
            return;
        }

        _selectedPort = port;
        _vm.SelectPort(port);
        UpdatePortActionPanel(port);
        RefreshKnownPortsPanel();
    }

    private void ClearPortSelection()
    {
        _selectedPort = null;
        _vm.SelectPort(null);
        _portActionPanel.Visibility = Visibility.Collapsed;
    }

    private void UpdatePortActionPanel(int port)
    {
        var item = _vm.KnownPorts.FirstOrDefault(p => p.Port == port);
        var service = string.IsNullOrWhiteSpace(item?.ServiceName) ? string.Empty : $" · {item.ServiceName}";
        _portActionTitle.Text = $"Port :{port}{service}";
        _portActionPanel.Visibility = Visibility.Visible;

        _portActionUiUpdating = true;
        var config = _vm.GetEditingPortAction();
        SelectPortActionKind(config.Kind);
        _portActionCustomBox.Text = config.CustomTarget ?? string.Empty;
        _portActionCustomBox.Visibility = NeedsCustomTarget(config.Kind)
            ? Visibility.Visible
            : Visibility.Collapsed;
        _portActionUiUpdating = false;
    }

    private void SelectPortActionKind(DevicePortActionKind kind)
    {
        for (var i = 0; i < _portActionKindCombo.Items.Count; i++)
        {
            if (_portActionKindCombo.Items[i] is ComboBoxItem item &&
                item.Tag is DevicePortActionKind itemKind &&
                itemKind == kind)
            {
                _portActionKindCombo.SelectedIndex = i;
                return;
            }
        }
    }

    private static bool NeedsCustomTarget(DevicePortActionKind kind) =>
        kind is DevicePortActionKind.CustomUrl or DevicePortActionKind.CustomApp;

    private DevicePortActionKind GetSelectedPortActionKind()
    {
        if (_portActionKindCombo.SelectedItem is ComboBoxItem item && item.Tag is DevicePortActionKind kind)
            return kind;
        return DevicePortActionKind.Auto;
    }

    private async Task OnPortActionKindChangedAsync()
    {
        if (_portActionUiUpdating || _selectedPort is null)
            return;

        var kind = GetSelectedPortActionKind();
        _portActionCustomBox.Visibility = NeedsCustomTarget(kind) ? Visibility.Visible : Visibility.Collapsed;
        await SavePortActionFromUiAsync();
    }

    private async Task SavePortActionFromUiAsync()
    {
        if (_portActionUiUpdating || _selectedPort is null)
            return;

        var kind = GetSelectedPortActionKind();
        var config = new DevicePortActionConfig
        {
            Kind = kind,
            CustomTarget = NeedsCustomTarget(kind) ? _portActionCustomBox.Text : null
        };
        await _vm.SavePortActionAsync(_selectedPort.Value, config);
        RefreshKnownPortsPanel();
    }

    private async Task ResetSelectedPortActionAsync()
    {
        if (_selectedPort is null)
            return;

        await _vm.ResetPortActionAsync(_selectedPort.Value);
        UpdatePortActionPanel(_selectedPort.Value);
        RefreshKnownPortsPanel();
    }

    private void RunSelectedPortAction()
    {
        if (_selectedPort is null)
            return;

        try
        {
            _vm.RunPortAction(_selectedPort.Value);
        }
        catch (Exception ex)
        {
            _ = ShowPortActionErrorAsync(ex.Message);
        }
    }

    private async Task ShowPortActionErrorAsync(string message)
    {
        var dialog = new ContentDialog
        {
            Title = "Port action",
            Content = message,
            CloseButtonText = "OK",
            XamlRoot = XamlRoot
        };
        await dialog.ShowAsync();
    }

    private static UIElement CreatePortLegend()
    {
        var legend = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 12, Opacity = 0.75 };
        legend.Children.Add(LegendItem(Bg(0xFF, 0x39, 0xD3, 0x53), "Live"));
        legend.Children.Add(LegendItem(Bg(0xFF, 0xE1, 0xB8, 0x54), "Cached"));
        legend.Children.Add(LegendItem(Bg(0xFF, 0x8C, 0xA8, 0xFF), "Both"));
        return legend;
    }

    private static StackPanel LegendItem(SolidColorBrush brush, string label)
    {
        var item = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 6 };
        item.Children.Add(new Border
        {
            Width = 8,
            Height = 8,
            CornerRadius = new CornerRadius(4),
            Background = brush,
            VerticalAlignment = VerticalAlignment.Center
        });
        item.Children.Add(new TextBlock { Text = label, FontSize = 11, VerticalAlignment = VerticalAlignment.Center });
        return item;
    }

    private static Border BuildPortChipVisual(DevicePortDisplayItem port, bool isSelected)
    {
        var sourceBrush = port.Source switch
        {
            DevicePortSource.Live => Bg(0xFF, 0x39, 0xD3, 0x53),
            DevicePortSource.Cached => Bg(0xFF, 0xE1, 0xB8, 0x54),
            _ => Bg(0xFF, 0x8C, 0xA8, 0xFF)
        };

        var accent = new Border
        {
            Width = 3,
            MinHeight = 28,
            Background = sourceBrush,
            VerticalAlignment = VerticalAlignment.Stretch
        };

        var text = new StackPanel { Spacing = 1, VerticalAlignment = VerticalAlignment.Center };
        text.Children.Add(new TextBlock
        {
            Text = $":{port.Port}",
            FontWeight = FontWeights.SemiBold,
            FontSize = 13
        });
        if (!string.IsNullOrWhiteSpace(port.ServiceName))
        {
            text.Children.Add(new TextBlock
            {
                Text = port.ServiceName,
                FontSize = 10,
                Opacity = 0.75,
                TextTrimming = TextTrimming.CharacterEllipsis,
                MaxWidth = 58
            });
        }
        if (!string.IsNullOrWhiteSpace(port.ActionLabel))
        {
            text.Children.Add(new TextBlock
            {
                Text = port.ActionLabel,
                FontSize = 9,
                Foreground = Bg(0xFF, 0x8C, 0xA8, 0xFF),
                TextTrimming = TextTrimming.CharacterEllipsis,
                MaxWidth = 58
            });
        }

        var inner = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8 };
        inner.Children.Add(accent);
        inner.Children.Add(text);

        var chip = new Border
        {
            Width = 82,
            MinHeight = 44,
            Margin = new Thickness(0, 0, 6, 6),
            Padding = new Thickness(8, 6, 8, 6),
            CornerRadius = new CornerRadius(6),
            Background = isSelected ? Bg(0xFF, 0x24, 0x28, 0x36) : Bg(0xFF, 0x1A, 0x1B, 0x1F),
            BorderBrush = isSelected ? Bg(0xFF, 0x8C, 0xA8, 0xFF) : Bg(0xFF, 0x2E, 0x30, 0x36),
            BorderThickness = new Thickness(isSelected ? 2 : 1),
            Child = inner
        };
        ToolTipService.SetToolTip(chip, port.TooltipText + (isSelected ? " · selected" : " · click to configure"));
        return chip;
    }

    private void ApplyEditableField(Action<ScanResultRow> apply, string value)
    {
        if (_vm.SelectedDevice is null) return;
        apply(_vm.SelectedDevice);
        if (_vm.IsMultiSelect)
        {
            foreach (var row in _vm.SelectedDevices)
            {
                if (!ReferenceEquals(row, _vm.SelectedDevice))
                    apply(row);
            }
        }
        _vm.SchedulePersistUserFields(_vm.SelectedDevice);
    }

    private void RefreshActions()
    {
        _actionsPanel.Children.Clear();
        var row = _vm.SelectedDevice;
        if (row is null) return;

        _actionsPanel.Children.Add(ActionButton("Copy IP", () => DeviceActions.CopyField(row, "IP Address")));
        _actionsPanel.Children.Add(ActionButton("Copy MAC", () => DeviceActions.CopyField(row, "MAC Address")));
    }

    private void RefreshTags()
    {
        _tagsPanel.Children.Clear();
        if (_vm.SelectedDevice is null) return;

        const int tagsPerRow = 3;
        StackPanel? row = null;
        var col = 0;
        foreach (var tag in _vm.SelectedDevice.Tags)
        {
            if (col == 0)
            {
                row = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 6, Margin = new Thickness(0, 0, 0, 6) };
                _tagsPanel.Children.Add(row);
            }

            var t = tag;
            var chip = new Button { Content = $"{t} ×", Padding = new Thickness(8, 4, 8, 4) };
            chip.Click += async (_, _) => { await _vm.RemoveTagAsync(_vm.SelectedDevice!, t); RefreshTags(); };
            row!.Children.Add(chip);
            col = (col + 1) % tagsPerRow;
        }
    }

    private static Button ActionButton(string label, Action action)
    {
        var btn = new Button { Content = label, HorizontalAlignment = HorizontalAlignment.Stretch };
        btn.Click += (_, _) => action();
        return btn;
    }

    private static TextBlock SectionTitle(string text) =>
        new() { Text = text, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 8, 0, 0) };

    private static Border Card(Thickness margin) => new()
    {
        Background = Bg(0xFF, 0x15, 0x15, 0x17),
        BorderBrush = Bg(0xFF, 0x2A, 0x2A, 0x2F),
        BorderThickness = new Thickness(1),
        CornerRadius = new CornerRadius(8),
        Margin = margin,
        Padding = new Thickness(10)
    };

    private static StackPanel ReadOnlyField(string label, string bindingPath)
    {
        var panel = new StackPanel { Spacing = 2 };
        panel.Children.Add(new TextBlock { Text = label, Opacity = 0.7, FontSize = 12 });
        var val = new TextBlock();
        val.SetBinding(TextBlock.TextProperty, new Binding { Path = new PropertyPath(bindingPath) });
        panel.Children.Add(val);
        return panel;
    }

    private static StackPanel WrapEditable(string label, string prop, Action<string> onChanged, bool multiline = false)
    {
        var panel = new StackPanel { Spacing = 2 };
        panel.Children.Add(new TextBlock { Text = label, Opacity = 0.7, FontSize = 12 });
        var box = new TextBox { AcceptsReturn = multiline, TextWrapping = multiline ? TextWrapping.Wrap : TextWrapping.NoWrap };
        box.SetBinding(TextBox.TextProperty, new Binding
        {
            Path = new PropertyPath($"Scanner.SelectedResult.{prop}"),
            Mode = BindingMode.TwoWay
        });
        box.LostFocus += (_, _) => onChanged(box.Text);
        panel.Children.Add(box);
        return panel;
    }

    private static SolidColorBrush Bg(byte a, byte r, byte g, byte b) =>
        new(ColorHelper.FromArgb(a, r, g, b));
}
