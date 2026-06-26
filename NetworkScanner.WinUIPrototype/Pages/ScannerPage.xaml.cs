using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Text.Json;
using Microsoft.UI;
using Microsoft.UI.Text;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Data;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Documents;
using Microsoft.UI.Xaml.Input;
using Windows.Foundation;
using NetworkScanner.WinUIPrototype.ViewModels;
using NetworkScanner.WinUIPrototype.Models;

namespace NetworkScanner.WinUIPrototype.Pages;

public sealed partial class ScannerPage : Page
{
    public ScannerViewModel ViewModel { get; }

    private readonly StackPanel _searchInfoStrip;
    private readonly Style _darkTextBoxStyle;
    private readonly SymbolIcon _scanActionSymbol = null!;
    private readonly Dictionary<string, Button> _sortHeaderButtons = new();
    private readonly Dictionary<string, FontIcon> _sortHeaderIcons = new();
    private readonly Dictionary<string, Border> _sortHeaderHighlights = new();
    private readonly double[] _columnWidths = { 170, 130, 170, 90, 150, 150, 170, 130, 150, 220 };
    private readonly List<ColumnDefinition> _headerColumns = new();
    private ListView _resultsList = null!;
    private TextBlock _scopeSummary = null!;
    private Grid _tableGrid = null!;
    private Grid _headerGrid = null!;

    private readonly List<string> _columnOrder = new()
    {
        "Hostname", "IPAddress", "MACAddress", "StateLabel", "FirstSeen", "LastSeen", "Vendor", "OpenPorts", "CustomName", "IPv6Address"
    };

    private bool _isDraggingColumn;
    private string? _draggingColumnKey;
    private Point _pointerPressStartPos;
    private readonly TranslateTransform _dragTranslation = new();

    private readonly string _columnLayoutPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "NetworkScanner",
        "column-layout-winui.json"
    );

    private sealed class WinUIColumnLayoutItem
    {
        public string Key { get; set; } = "";
        public double Width { get; set; }
    }

    private bool _isResizingColumn;
    private int _resizingColumnIndex = -1;
    private double _resizeStartX;
    private double _resizeStartWidth;

    public ScannerPage()
    {
        LoadColumnLayoutOrDefault();
        ViewModel = ((App)Application.Current).ScannerViewModel;
        DataContext = ViewModel;

        _darkTextBoxStyle = BuildDarkTextBoxStyle();

        // Root with fixed bottom status bar
        var root = new Grid();
        root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) }); // content
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // bottom status

        var content = new Grid();
        content.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });   // view title
        content.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });   // controls row
        content.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) }); // table

        // View title at top (below app search bar)
        var viewTitleCard = Card(new Thickness(0, 0, 0, 8));
        viewTitleCard.Background = Brush(0xFF, 0x16, 0x16, 0x18);
        var titleGrid = new Grid();
        titleGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        titleGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto }); // scope summary
        titleGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto }); // scope button
        titleGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto }); // scan button
        titleGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto }); // divider
        titleGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto }); // overflow

        titleGrid.Children.Add(new TextBlock
        {
            Text = "Live Scan",
            FontSize = 20,
            FontWeight = FontWeights.SemiBold,
            VerticalAlignment = VerticalAlignment.Center
        });

        _scopeSummary = new TextBlock
        {
            Opacity = 0.86,
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(0),
            TextTrimming = TextTrimming.CharacterEllipsis,
            MaxWidth = 260,
            Foreground = Brush(0xFF, 0xC4, 0xC8, 0xD0)
        };
        // Binding intentionally omitted; summary text is composed from range + ports below.
        var scopeSummaryChip = new Border
        {
            Background = Brush(0x55, 0x3B, 0x3F, 0x47),
            BorderBrush = Brush(0x99, 0x4A, 0x4F, 0x58),
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(12),
            Padding = new Thickness(10, 4, 10, 4),
            Margin = new Thickness(0, 0, 12, 0),
            VerticalAlignment = VerticalAlignment.Center,
            Child = _scopeSummary
        };
        Grid.SetColumn(scopeSummaryChip, 1);
        titleGrid.Children.Add(scopeSummaryChip);

        RefreshScopeSummaryText();

        var scopeBtn = new Button
        {
            MinWidth = 96,
            Margin = new Thickness(0, 0, 8, 0),
            UseSystemFocusVisuals = false,
            Content = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                Spacing = 6,
                Children =
                {
                    new SymbolIcon(Symbol.World),
                    new TextBlock { Text = "Scope", VerticalAlignment = VerticalAlignment.Center }
                }
            }
        };
        scopeBtn.Resources["ButtonBorderBrushFocused"] = Brush(0x88, 0x4A, 0x8D, 0xF7);
        scopeBtn.Resources["ButtonBackgroundFocused"] = Brush(0x33, 0x4A, 0x8D, 0xF7);

        var scopeFlyoutPanel = new StackPanel { Spacing = 8, Width = 360 };

        var scopeRangeLabel = new TextBlock { Text = "IP Address Range", Opacity = 0.85 };
        var scopeRangeBox = new ComboBox
        {
            HorizontalAlignment = HorizontalAlignment.Stretch,
            IsEditable = true,
            Background = Brush(0xFF, 0x11, 0x12, 0x14),
            Foreground = Brush(0xFF, 0xF2, 0xF2, 0xF4),
            RequestedTheme = ElementTheme.Dark
        };
        scopeRangeBox.Resources["ComboBoxBackground"] = Brush(0xFF, 0x11, 0x12, 0x14);
        scopeRangeBox.Resources["ComboBoxBackgroundPointerOver"] = Brush(0xFF, 0x16, 0x18, 0x1D);
        scopeRangeBox.Resources["ComboBoxBackgroundFocused"] = Brush(0xFF, 0x16, 0x18, 0x1D);
        scopeRangeBox.Resources["ComboBoxForeground"] = Brush(0xFF, 0xF2, 0xF2, 0xF4);
        scopeRangeBox.Resources["ComboBoxForegroundFocused"] = Brush(0xFF, 0xF2, 0xF2, 0xF4);
        scopeRangeBox.Resources["ComboBoxBorderBrush"] = Brush(0xFF, 0x2A, 0x2A, 0x2F);
        scopeRangeBox.Resources["ComboBoxBorderBrushFocused"] = Brush(0xFF, 0x4A, 0x8D, 0xF7);

        scopeRangeBox.ItemsSource = ViewModel.DetectedRanges;
        scopeRangeBox.SetBinding(ComboBox.TextProperty, new Binding { Path = new PropertyPath("IPRanges"), Mode = BindingMode.TwoWay, UpdateSourceTrigger = UpdateSourceTrigger.PropertyChanged });

        var scopeSubnetLabel = new TextBlock { Text = "Subnet Mask", Opacity = 0.85 };
        var scopeSubnetBox = new TextBox { Text = "255.255.255.0", Style = _darkTextBoxStyle };
        ConfigureDarkTextBox(scopeSubnetBox);

        var scopePortsLabel = new TextBlock { Text = "Ports", Opacity = 0.85 };
        var scopePortsBox = new TextBox { Style = _darkTextBoxStyle };
        ConfigureDarkTextBox(scopePortsBox);
        scopePortsBox.SetBinding(TextBox.TextProperty, new Binding { Path = new PropertyPath("Ports"), Mode = BindingMode.TwoWay, UpdateSourceTrigger = UpdateSourceTrigger.PropertyChanged });

        var scanIPv6Switch = new ToggleSwitch
        {
            Header = "Scan IPv6 Addresses",
            Margin = new Thickness(0, 4, 0, 0),
            Foreground = Brush(0xFF, 0xF2, 0xF2, 0xF4)
        };
        scanIPv6Switch.SetBinding(ToggleSwitch.IsOnProperty, new Binding { Path = new PropertyPath("ScanIPv6"), Mode = BindingMode.TwoWay });

        var showOfflineSwitch = new ToggleSwitch
        {
            Header = "Show Offline Devices",
            Margin = new Thickness(0, 4, 0, 0),
            Foreground = Brush(0xFF, 0xF2, 0xF2, 0xF4)
        };
        showOfflineSwitch.SetBinding(ToggleSwitch.IsOnProperty, new Binding { Path = new PropertyPath("ShowOffline"), Mode = BindingMode.TwoWay });

        var showCachedSwitch = new ToggleSwitch
        {
            Header = "Show Cached Devices",
            Margin = new Thickness(0, 4, 0, 4),
            Foreground = Brush(0xFF, 0xF2, 0xF2, 0xF4)
        };
        showCachedSwitch.SetBinding(ToggleSwitch.IsOnProperty, new Binding { Path = new PropertyPath("ShowCached"), Mode = BindingMode.TwoWay });

        var periodicScanSwitch = new ToggleSwitch
        {
            Header = "Periodic Rescan",
            Margin = new Thickness(0, 4, 0, 0),
            Foreground = Brush(0xFF, 0xF2, 0xF2, 0xF4)
        };
        periodicScanSwitch.SetBinding(ToggleSwitch.IsOnProperty, new Binding { Path = new PropertyPath("PeriodicScanEnabled"), Mode = BindingMode.TwoWay });

        var periodicIntervalLabel = new TextBlock { Text = "Interval", Opacity = 0.85, Margin = new Thickness(0, 4, 0, 2) };
        var periodicIntervalBox = new ComboBox
        {
            HorizontalAlignment = HorizontalAlignment.Stretch,
            Background = Brush(0xFF, 0x11, 0x12, 0x14),
            Foreground = Brush(0xFF, 0xF2, 0xF2, 0xF4),
            RequestedTheme = ElementTheme.Dark,
            Margin = new Thickness(0, 0, 0, 4)
        };
        periodicIntervalBox.Resources["ComboBoxBackground"] = Brush(0xFF, 0x11, 0x12, 0x14);
        periodicIntervalBox.Resources["ComboBoxBackgroundPointerOver"] = Brush(0xFF, 0x16, 0x18, 0x1D);
        periodicIntervalBox.Resources["ComboBoxBackgroundFocused"] = Brush(0xFF, 0x16, 0x18, 0x1D);
        periodicIntervalBox.Resources["ComboBoxForeground"] = Brush(0xFF, 0xF2, 0xF2, 0xF4);
        periodicIntervalBox.Resources["ComboBoxForegroundFocused"] = Brush(0xFF, 0xF2, 0xF2, 0xF4);
        periodicIntervalBox.Resources["ComboBoxBorderBrush"] = Brush(0xFF, 0x2A, 0x2A, 0x2F);
        periodicIntervalBox.Resources["ComboBoxBorderBrushFocused"] = Brush(0xFF, 0x4A, 0x8D, 0xF7);

        periodicIntervalBox.Items.Add(new ComboBoxItem { Content = "1 min", Tag = 1 });
        periodicIntervalBox.Items.Add(new ComboBoxItem { Content = "5 min", Tag = 5 });
        periodicIntervalBox.Items.Add(new ComboBoxItem { Content = "10 min", Tag = 10 });
        periodicIntervalBox.Items.Add(new ComboBoxItem { Content = "30 min", Tag = 30 });
        periodicIntervalBox.Items.Add(new ComboBoxItem { Content = "60 min", Tag = 60 });
        
        periodicIntervalBox.SelectedIndex = 1;
        periodicIntervalBox.SetBinding(Control.IsEnabledProperty, new Binding { Path = new PropertyPath("PeriodicScanEnabled") });
        periodicIntervalBox.SelectionChanged += (s, e) =>
        {
            if (periodicIntervalBox.SelectedItem is ComboBoxItem item && item.Tag is int mins)
            {
                ViewModel.PeriodicScanIntervalMinutes = mins;
            }
        };

        var scopeHint = new TextBlock
        {
            Text = "Tip: Scope values drive this prototype's mock scan behavior.",
            Opacity = 0.7,
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 4, 0, 0)
        };

        var scopeActions = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right,
            Spacing = 8,
            Margin = new Thickness(0, 6, 0, 0)
        };

        var resetScopeBtn = new Button { Content = "Reset", MinWidth = 80 };
        resetScopeBtn.Click += (_, _) =>
        {
            scopeRangeBox.Text = "192.168.1.0/24";
            scopeSubnetBox.Text = "255.255.255.0";
            scopePortsBox.Text = "80";
            scanIPv6Switch.IsOn = false;
            showOfflineSwitch.IsOn = true;
            showCachedSwitch.IsOn = true;
            periodicScanSwitch.IsOn = false;
            periodicIntervalBox.SelectedIndex = 1;
            RefreshScopeSummaryText();
        };

        var applyScopeBtn = new Button { Content = "Apply", MinWidth = 80 };
        applyScopeBtn.Click += (_, _) =>
        {
            RefreshScopeSummaryText();
            if (scopeBtn.Flyout is Flyout f)
            {
                f.Hide();
            }

            if (ViewModel.PeriodicScanEnabled && !ViewModel.IsScanning && ViewModel.ScanState == ScanLifecycleState.Idle)
            {
                ViewModel.StartStopScanCommand.Execute(null);
            }
        };

        scopeActions.Children.Add(resetScopeBtn);
        scopeActions.Children.Add(applyScopeBtn);

        scopeFlyoutPanel.Children.Add(scopeRangeLabel);
        scopeFlyoutPanel.Children.Add(scopeRangeBox);
        scopeFlyoutPanel.Children.Add(scopeSubnetLabel);
        scopeFlyoutPanel.Children.Add(scopeSubnetBox);
        scopeFlyoutPanel.Children.Add(scopePortsLabel);
        scopeFlyoutPanel.Children.Add(scopePortsBox);
        scopeFlyoutPanel.Children.Add(scanIPv6Switch);
        scopeFlyoutPanel.Children.Add(showOfflineSwitch);
        scopeFlyoutPanel.Children.Add(showCachedSwitch);
        scopeFlyoutPanel.Children.Add(periodicScanSwitch);
        scopeFlyoutPanel.Children.Add(periodicIntervalLabel);
        scopeFlyoutPanel.Children.Add(periodicIntervalBox);
        scopeFlyoutPanel.Children.Add(scopeHint);
        scopeFlyoutPanel.Children.Add(scopeActions);

        scopeBtn.Flyout = new Flyout
        {
            Content = new Border
            {
                Padding = new Thickness(10),
                Background = Brush(0xFF, 0x15, 0x15, 0x17),
                BorderBrush = Brush(0xFF, 0x2A, 0x2A, 0x2F),
                BorderThickness = new Thickness(1),
                DataContext = ViewModel,
                RequestedTheme = ElementTheme.Dark,
                Child = scopeFlyoutPanel
            }
        };
        Grid.SetColumn(scopeBtn, 2);
        titleGrid.Children.Add(scopeBtn);

        _scanActionSymbol = new SymbolIcon(Symbol.Play) { Margin = new Thickness(0, 0, 6, 0) };
        var scanBtnLabel = new TextBlock { VerticalAlignment = VerticalAlignment.Center };
        scanBtnLabel.SetBinding(TextBlock.TextProperty, new Binding { Path = new PropertyPath("ScanButtonText") });
        var scanBtnContent = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            Spacing = 0,
            Children = { _scanActionSymbol, scanBtnLabel }
        };

        var scanBtnTop = new Button
        {
            MinWidth = 100,
            Content = scanBtnContent,
            Margin = new Thickness(0, 0, 8, 0),
            UseSystemFocusVisuals = false
        };
        scanBtnTop.Resources["ButtonBorderBrushFocused"] = Brush(0x88, 0x4A, 0x8D, 0xF7);
        scanBtnTop.Resources["ButtonBackgroundFocused"] = Brush(0x33, 0x4A, 0x8D, 0xF7);
        scanBtnTop.SetBinding(Button.CommandProperty, new Binding { Path = new PropertyPath("StartStopScanCommand") });
        Grid.SetColumn(scanBtnTop, 3);
        titleGrid.Children.Add(scanBtnTop);

        var toolbarDivider = new Border
        {
            Width = 1,
            Height = 22,
            Background = Brush(0x66, 0x46, 0x4A, 0x52),
            Margin = new Thickness(2, 0, 8, 0),
            VerticalAlignment = VerticalAlignment.Center
        };
        Grid.SetColumn(toolbarDivider, 4);
        titleGrid.Children.Add(toolbarDivider);

        var overflowBtn = new Button
        {
            MinWidth = 40,
            Content = new SymbolIcon(Symbol.More),
            UseSystemFocusVisuals = false
        };
        overflowBtn.Resources["ButtonBorderBrushFocused"] = Brush(0x88, 0x4A, 0x8D, 0xF7);
        overflowBtn.Resources["ButtonBackgroundFocused"] = Brush(0x33, 0x4A, 0x8D, 0xF7);
        var overflowMenu = new MenuFlyout();
        var exportItem = new MenuFlyoutItem { Text = "Export" };
        exportItem.SetBinding(MenuFlyoutItem.CommandProperty, new Binding { Path = new PropertyPath("ExportCommand") });
        overflowMenu.Items.Add(exportItem);
        overflowBtn.Flyout = overflowMenu;
        Grid.SetColumn(overflowBtn, 5);
        titleGrid.Children.Add(overflowBtn);

        viewTitleCard.Child = titleGrid;
        Grid.SetRow(viewTitleCard, 0);
        content.Children.Add(viewTitleCard);

        // Controls row kept for rollback/testing (hidden for scope-flyout experiment)
        var controlsCard = Card(new Thickness(0, 0, 0, 8));
        controlsCard.Background = Brush(0xFF, 0x16, 0x16, 0x18);
        controlsCard.Visibility = Visibility.Collapsed;
        var controlsGrid = new Grid();
        controlsGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        controlsGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(12) });
        controlsGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(220) });
        controlsGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(12) });
        controlsGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(220) });
        controlsGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(12) });
        controlsGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

        var ipRangeStack = new StackPanel { Spacing = 4 };
        ipRangeStack.Children.Add(new TextBlock { Text = "IP Address Range", Opacity = 0.85 });
        var ipRangeBox = new TextBox { Style = _darkTextBoxStyle };
        ConfigureDarkTextBox(ipRangeBox);
        ipRangeBox.SetBinding(TextBox.TextProperty, new Binding { Path = new PropertyPath("IPRanges"), Mode = BindingMode.TwoWay });
        ipRangeStack.Children.Add(ipRangeBox);
        Grid.SetColumn(ipRangeStack, 0);
        controlsGrid.Children.Add(ipRangeStack);

        var subnetStack = new StackPanel { Spacing = 4 };
        subnetStack.Children.Add(new TextBlock { Text = "Subnet Mask", Opacity = 0.85 });
        var subnetMaskBox = new TextBox { Text = "255.255.255.0", Style = _darkTextBoxStyle };
        ConfigureDarkTextBox(subnetMaskBox);
        subnetStack.Children.Add(subnetMaskBox);
        Grid.SetColumn(subnetStack, 2);
        controlsGrid.Children.Add(subnetStack);

        var portsStack = new StackPanel { Spacing = 4 };
        portsStack.Children.Add(new TextBlock { Text = "Ports", Opacity = 0.85 });
        var portsBox = new TextBox { Style = _darkTextBoxStyle };
        ConfigureDarkTextBox(portsBox);
        portsBox.SetBinding(TextBox.TextProperty, new Binding { Path = new PropertyPath("Ports"), Mode = BindingMode.TwoWay });
        portsStack.Children.Add(portsBox);
        Grid.SetColumn(portsStack, 4);
        controlsGrid.Children.Add(portsStack);

        var scanBtn = new Button { MinWidth = 90, VerticalAlignment = VerticalAlignment.Bottom };
        scanBtn.SetBinding(Button.ContentProperty, new Binding { Path = new PropertyPath("ScanButtonText") });
        scanBtn.SetBinding(Button.CommandProperty, new Binding { Path = new PropertyPath("StartStopScanCommand") });
        Grid.SetColumn(scanBtn, 6);
        controlsGrid.Children.Add(scanBtn);

        controlsCard.Child = controlsGrid;
        Grid.SetRow(controlsCard, 1);
        content.Children.Add(controlsCard);

        // Search info strip row (status + next/prev) shown only when searching
        _searchInfoStrip = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            Spacing = 8,
            Visibility = Visibility.Collapsed,
            Margin = new Thickness(0, 0, 0, 8)
        };

        var prev = new Button { Content = "Prev" };
        prev.SetBinding(Button.CommandProperty, new Binding { Path = new PropertyPath("FindPreviousCommand") });
        _searchInfoStrip.Children.Add(prev);

        var next = new Button { Content = "Next" };
        next.SetBinding(Button.CommandProperty, new Binding { Path = new PropertyPath("FindNextCommand") });
        _searchInfoStrip.Children.Add(next);

        var searchStatus = new TextBlock
        {
            Opacity = 0.85,
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(8, 0, 0, 0)
        };
        searchStatus.SetBinding(TextBlock.TextProperty, new Binding { Path = new PropertyPath("SearchStatusText") });
        _searchInfoStrip.Children.Add(searchStatus);

        // Inline search info now lives in the global top bar; no separate strip in this view.

        // Guaranteed table-like view with header row + columns (no third-party dependency)
        var tableCard = Card(new Thickness(0, 0, 0, 0));
        tableCard.Background = Brush(0xFF, 0x13, 0x14, 0x17);
        _tableGrid = new Grid();
        _tableGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        _tableGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        _tableGrid.Width = _columnWidths.Sum() + 12;

        var headerBorder = new Border
        {
            Background = Brush(0xFF, 0x1D, 0x1F, 0x23),
            BorderBrush = Brush(0xFF, 0x33, 0x36, 0x3D),
            BorderThickness = new Thickness(0, 0, 0, 1),
            CornerRadius = new CornerRadius(6),
            Padding = new Thickness(0),
            Margin = new Thickness(6, 0, 6, 0)
        };

        var header = new Grid();
        _headerGrid = header;
        for (var i = 0; i < _columnWidths.Length; i++)
        {
            var colDef = new ColumnDefinition { Width = new GridLength(_columnWidths[i]) };
            header.ColumnDefinitions.Add(colDef);
            _headerColumns.Add(colDef);
        }

        AddSortableHeaderCell(header, "Device", "Hostname", _columnOrder.IndexOf("Hostname"));
        AddSortableHeaderCell(header, "IP Address", "IPAddress", _columnOrder.IndexOf("IPAddress"));
        AddSortableHeaderCell(header, "MAC Address", "MACAddress", _columnOrder.IndexOf("MACAddress"));
        AddSortableHeaderCell(header, "Status", "StateLabel", _columnOrder.IndexOf("StateLabel"));
        AddSortableHeaderCell(header, "First Seen", "FirstSeen", _columnOrder.IndexOf("FirstSeen"));
        AddSortableHeaderCell(header, "Last Seen", "LastSeen", _columnOrder.IndexOf("LastSeen"));
        AddSortableHeaderCell(header, "Manufacturer", "Vendor", _columnOrder.IndexOf("Vendor"));
        AddSortableHeaderCell(header, "Open Ports", "OpenPorts", _columnOrder.IndexOf("OpenPorts"));
        AddSortableHeaderCell(header, "Custom Name", "CustomName", _columnOrder.IndexOf("CustomName"));
        AddSortableHeaderCell(header, "IPv6 Address", "IPv6Address", _columnOrder.IndexOf("IPv6Address"));
        
        AddColumnResizeGrip(header, 0);
        AddColumnResizeGrip(header, 1);
        AddColumnResizeGrip(header, 2);
        AddColumnResizeGrip(header, 3);
        AddColumnResizeGrip(header, 4);
        AddColumnResizeGrip(header, 5);
        AddColumnResizeGrip(header, 6);
        AddColumnResizeGrip(header, 7);
        AddColumnResizeGrip(header, 8);
        AddColumnResizeGrip(header, 9);

        headerBorder.Child = header;
        Grid.SetRow(headerBorder, 0);
        _tableGrid.Children.Add(headerBorder);

        _resultsList = new ListView
        {
            SelectionMode = ListViewSelectionMode.Single,
            IsItemClickEnabled = false,
            HorizontalContentAlignment = HorizontalAlignment.Stretch,
            IsTabStop = true
        };
        ScrollViewer.SetHorizontalScrollBarVisibility(_resultsList, ScrollBarVisibility.Disabled);
        ScrollViewer.SetHorizontalScrollMode(_resultsList, ScrollMode.Disabled);
        _resultsList.ContainerContentChanging += OnResultContainerContentChanging;
        _resultsList.SetBinding(ItemsControl.ItemsSourceProperty, new Binding { Path = new PropertyPath("Results") });
        _resultsList.SetBinding(ListView.SelectedItemProperty, new Binding { Path = new PropertyPath("SelectedResult"), Mode = BindingMode.TwoWay });
        _resultsList.ItemContainerStyle = BuildDarkListViewStyle();
        _resultsList.ItemTemplate = BuildTableRowTemplate();
        _resultsList.SelectionChanged += (_, _) => RefreshVisibleRowVisuals();
        _resultsList.Margin = new Thickness(6, 0, 6, 0);

        Grid.SetRow(_resultsList, 1);
        _tableGrid.Children.Add(_resultsList);

        var tableScrollViewer = new ScrollViewer
        {
            HorizontalScrollBarVisibility = ScrollBarVisibility.Auto,
            HorizontalScrollMode = ScrollMode.Enabled,
            VerticalScrollBarVisibility = ScrollBarVisibility.Disabled,
            VerticalScrollMode = ScrollMode.Disabled
        };
        tableScrollViewer.Content = _tableGrid;
        tableCard.Child = tableScrollViewer;
        // Table must be in the star-sized row so ListView gets constrained height and can scroll.
        Grid.SetRow(tableCard, 2);
        content.Children.Add(tableCard);

        Grid.SetRow(content, 0);
        root.Children.Add(content);

        // Bottom-anchored status bar
        var footer = Card(new Thickness(0, 8, 0, 0));
        footer.Background = Brush(0xFF, 0x12, 0x13, 0x16);
        var footerGrid = new Grid();
        footerGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        footerGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

        var statusText = new TextBlock { VerticalAlignment = VerticalAlignment.Center };
        statusText.SetBinding(TextBlock.TextProperty, new Binding { Path = new PropertyPath("StatusText") });
        Grid.SetColumn(statusText, 0);
        footerGrid.Children.Add(statusText);

        if (!IsRunningAsAdmin())
        {
            var adminStack = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8, VerticalAlignment = VerticalAlignment.Center };
            
            var warningText = new TextBlock 
            { 
                Text = "⚠️ Standard User (Limited performance)", 
                Foreground = new SolidColorBrush(Windows.UI.Color.FromArgb(0xFF, 0xFF, 0xB3, 0x00)),
                FontSize = 12,
                VerticalAlignment = VerticalAlignment.Center
            };
            adminStack.Children.Add(warningText);

            var restartBtn = new Button 
            { 
                Content = "Restart as Admin", 
                FontSize = 11,
                Padding = new Thickness(8, 2, 8, 2),
                Background = new SolidColorBrush(Windows.UI.Color.FromArgb(0, 0, 0, 0)),
                BorderBrush = Brush(0xFF, 0x2A, 0x2A, 0x2F),
                BorderThickness = new Thickness(1),
                VerticalAlignment = VerticalAlignment.Center
            };
            restartBtn.Click += (s, e) => RestartAsAdmin();
            adminStack.Children.Add(restartBtn);

            Grid.SetColumn(adminStack, 1);
            footerGrid.Children.Add(adminStack);
        }

        footer.Child = footerGrid;
        Grid.SetRow(footer, 1);
        root.Children.Add(footer);

        Content = root;

        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
    }

    private void RefreshScopeSummaryText()
    {
        var range = string.IsNullOrWhiteSpace(ViewModel.IPRanges) ? "-" : ViewModel.IPRanges.Trim();
        var ports = string.IsNullOrWhiteSpace(ViewModel.Ports) ? "-" : ViewModel.Ports.Trim();
        _scopeSummary.Text = $"Scope: {range} • {ports}";
    }

    private static Border Card(Thickness margin)
    {
        return new Border
        {
            Padding = new Thickness(10),
            Margin = margin,
            CornerRadius = new CornerRadius(10),
            BorderThickness = new Thickness(1),
            BorderBrush = Brush(0xFF, 0x2A, 0x2A, 0x2F),
            Background = Brush(0xFF, 0x15, 0x15, 0x17)
        };
    }

    private static Style BuildDarkTextBoxStyle()
    {
        var style = new Style(typeof(TextBox));
        style.Setters.Add(new Setter(Control.BackgroundProperty, Brush(0xFF, 0x11, 0x12, 0x14)));
        style.Setters.Add(new Setter(Control.BorderBrushProperty, Brush(0xFF, 0x2A, 0x2A, 0x2F)));
        style.Setters.Add(new Setter(Control.ForegroundProperty, Brush(0xFF, 0xF2, 0xF2, 0xF4)));
        style.Setters.Add(new Setter(Control.BorderThicknessProperty, new Thickness(0)));
        style.Setters.Add(new Setter(Control.BorderBrushProperty, Brush(0x00, 0x00, 0x00, 0x00)));
        style.Setters.Add(new Setter(FrameworkElement.MarginProperty, new Thickness(0)));
        style.Setters.Add(new Setter(Control.PaddingProperty, new Thickness(0)));
        return style;
    }

    private static void ConfigureDarkTextBox(TextBox tb)
    {
        var bgNormal = Brush(0xFF, 0x11, 0x12, 0x14);
        var bgFocus = Brush(0xFF, 0x16, 0x18, 0x1D);
        var borderNormal = Brush(0xFF, 0x2A, 0x2A, 0x2F);
        var borderFocus = Brush(0xFF, 0x4A, 0x8D, 0xF7);
        var fg = Brush(0xFF, 0xF2, 0xF2, 0xF4);
        var sel = Brush(0x66, 0x4A, 0x8D, 0xF7);

        tb.RequestedTheme = ElementTheme.Dark;

        // Force TextBox template state brushes to dark to avoid white edit-state regressions.
        tb.Resources["TextControlBackground"] = bgNormal;
        tb.Resources["TextControlBackgroundPointerOver"] = bgFocus;
        tb.Resources["TextControlBackgroundFocused"] = bgFocus;
        tb.Resources["TextControlForeground"] = fg;
        tb.Resources["TextControlForegroundFocused"] = fg;
        tb.Resources["TextControlBorderBrush"] = borderNormal;
        tb.Resources["TextControlBorderBrushFocused"] = borderFocus;
        tb.Resources["TextControlPlaceholderForeground"] = Brush(0xFF, 0x9A, 0x9B, 0xA0);

        tb.Background = bgNormal;
        tb.BorderBrush = borderNormal;
        tb.Foreground = fg;
        tb.SelectionHighlightColor = sel;

        tb.GotFocus += (_, _) =>
        {
            tb.Background = bgFocus;
            tb.BorderBrush = borderFocus;
            tb.Foreground = fg;
        };

        tb.LostFocus += (_, _) =>
        {
            tb.Background = bgNormal;
            tb.BorderBrush = borderNormal;
            tb.Foreground = fg;
        };

        // Re-apply after text updates to avoid platform default edit brush flashes.
        tb.TextChanging += (_, _) =>
        {
            tb.Foreground = fg;
            tb.Background = tb.FocusState == FocusState.Unfocused ? bgNormal : bgFocus;
            tb.BorderBrush = tb.FocusState == FocusState.Unfocused ? borderNormal : borderFocus;
        };
    }

    private static SolidColorBrush Brush(byte a, byte r, byte g, byte b)
        => new(ColorHelper.FromArgb(a, r, g, b));

    private Style BuildDarkListViewStyle()
    {
        var style = new Style(typeof(ListViewItem));
        style.Setters.Add(new Setter(Control.BackgroundProperty, Brush(0x00, 0x00, 0x00, 0x00)));
        style.Setters.Add(new Setter(Control.BorderBrushProperty, Brush(0x00, 0x00, 0x00, 0x00)));
        style.Setters.Add(new Setter(Control.BorderThicknessProperty, new Thickness(0)));
        style.Setters.Add(new Setter(Control.PaddingProperty, new Thickness(0)));
        style.Setters.Add(new Setter(FrameworkElement.MarginProperty, new Thickness(0)));
        style.Setters.Add(new Setter(Control.HorizontalContentAlignmentProperty, HorizontalAlignment.Stretch));
        style.Setters.Add(new Setter(Control.VerticalContentAlignmentProperty, VerticalAlignment.Stretch));
        return style;
    }

    private void AddSortableHeaderCell(Grid grid, string text, string key, int col)
    {
        var icon = new FontIcon
        {
            Glyph = "\uE70D",
            FontSize = 12,
            Foreground = Brush(0xFF, 0x8C, 0x90, 0x98),
            Margin = new Thickness(4, 0, 0, 0),
            VerticalAlignment = VerticalAlignment.Center
        };

        var label = new TextBlock
        {
            Text = text,
            VerticalAlignment = VerticalAlignment.Center,
            TextTrimming = TextTrimming.CharacterEllipsis
        };

        var stack = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            Spacing = 0,
            HorizontalAlignment = HorizontalAlignment.Left
        };
        stack.Children.Add(label);
        stack.Children.Add(icon);

        var btn = new Button
        {
            Content = stack,
            HorizontalAlignment = HorizontalAlignment.Stretch,
            HorizontalContentAlignment = HorizontalAlignment.Left,
            Padding = new Thickness(2, 0, 10, 0),
            Margin = new Thickness(0),
            Background = Brush(0x00, 0x00, 0x00, 0x00),
            BorderBrush = Brush(0x00, 0x00, 0x00, 0x00),
            BorderThickness = new Thickness(0),
            Foreground = Brush(0xFF, 0xF2, 0xF2, 0xF4),
            Opacity = 0.95
        };

        btn.Click += (_, _) =>
        {
            ViewModel.SortBy(key);
            UpdateSortHeaderIndicators();
        };

        var highlight = new Border
        {
            CornerRadius = new CornerRadius(3),
            Padding = new Thickness(0),
            Child = btn,
            Background = Brush(0x00, 0x00, 0x00, 0x00),
            BorderBrush = Brush(0x00, 0x00, 0x00, 0x00),
            BorderThickness = new Thickness(1),
            Margin = new Thickness(0)
        };

        highlight.AddHandler(UIElement.PointerPressedEvent, new PointerEventHandler(Header_PointerPressed), true);
        highlight.AddHandler(UIElement.PointerMovedEvent, new PointerEventHandler(Header_PointerMoved), true);
        highlight.AddHandler(UIElement.PointerReleasedEvent, new PointerEventHandler(Header_PointerReleased), true);
        highlight.AddHandler(UIElement.PointerCaptureLostEvent, new PointerEventHandler(Header_PointerCaptureLost), true);

        _sortHeaderButtons[key] = btn;
        _sortHeaderIcons[key] = icon;
        _sortHeaderHighlights[key] = highlight;

        Grid.SetColumn(highlight, col);
        grid.Children.Add(highlight);
    }


    private DataTemplate BuildTableRowTemplate()
    {
        var sb = new System.Text.StringBuilder();
        sb.AppendLine("<DataTemplate xmlns='http://schemas.microsoft.com/winfx/2006/xaml/presentation' xmlns:x='http://schemas.microsoft.com/winfx/2006/xaml'>");
        sb.AppendLine("  <Border BorderBrush='#00000000' BorderThickness='0' Padding='0' Margin='0' Background='Transparent'>");
        
        var minWidth = _columnWidths.Sum() + 80;
        sb.AppendLine($"    <Grid MinWidth='{minWidth:F0}' Margin='0' Padding='0' Background='Transparent'>");
        
        sb.AppendLine("      <Grid.ColumnDefinitions>");
        for (int i = 0; i < _columnOrder.Count; i++)
        {
            sb.AppendLine($"        <ColumnDefinition Width='{_columnWidths[i]:F0}'/>");
        }
        sb.AppendLine("      </Grid.ColumnDefinitions>");

        for (int i = 0; i < _columnOrder.Count; i++)
        {
            var key = _columnOrder[i];
            var isLast = (i == _columnOrder.Count - 1);
            var thickness = isLast ? "0" : "0,0,1,0";
            var borderBrush = isLast ? "#00000000" : "#1E2A2F36";
            
            switch (key)
            {
                case "Hostname":
                    sb.AppendLine($"      <Border Grid.Column='{i}' Tag='Hostname' Background='{{Binding HostnameCellBrush}}' BorderBrush='{borderBrush}' BorderThickness='{thickness}' Padding='6,0' Margin='0'>");
                    sb.AppendLine("        <TextBlock Tag='Hostname' TextTrimming='CharacterEllipsis' Opacity='0.96'/>");
                    sb.AppendLine("      </Border>");
                    break;
                case "IPAddress":
                    sb.AppendLine($"      <Border Grid.Column='{i}' Tag='IPAddress' Background='{{Binding IPAddressCellBrush}}' BorderBrush='{borderBrush}' BorderThickness='{thickness}' Padding='6,0' Margin='0'>");
                    sb.AppendLine("        <TextBlock Tag='IPAddress' TextTrimming='CharacterEllipsis' Opacity='0.94'/>");
                    sb.AppendLine("      </Border>");
                    break;
                case "MACAddress":
                    sb.AppendLine($"      <Border Grid.Column='{i}' Tag='MACAddress' Background='{{Binding MACAddressCellBrush}}' BorderBrush='{borderBrush}' BorderThickness='{thickness}' Padding='6,0' Margin='0'>");
                    sb.AppendLine("        <TextBlock Tag='MACAddress' TextTrimming='CharacterEllipsis' Opacity='0.94'/>");
                    sb.AppendLine("      </Border>");
                    break;
                case "StateLabel":
                    sb.AppendLine($"      <Border Grid.Column='{i}' Tag='StateLabel' Background='{{Binding StatusCellBrush}}' BorderBrush='{borderBrush}' BorderThickness='{thickness}' Padding='6,0' Margin='0'>");
                    sb.AppendLine("        <Border Width='12' Height='12' CornerRadius='6' Background='{Binding StateBrush}' VerticalAlignment='Center' HorizontalAlignment='Left' ToolTipService.ToolTip='{Binding StateLabel}'/>");
                    sb.AppendLine("      </Border>");
                    break;
                case "FirstSeen":
                    sb.AppendLine($"      <Border Grid.Column='{i}' Tag='FirstSeen' Background='{{Binding FirstSeenCellBrush}}' BorderBrush='{borderBrush}' BorderThickness='{thickness}' Padding='6,0' Margin='0'>");
                    sb.AppendLine("        <TextBlock Tag='FirstSeen' TextTrimming='CharacterEllipsis' Opacity='0.94'/>");
                    sb.AppendLine("      </Border>");
                    break;
                case "LastSeen":
                    sb.AppendLine($"      <Border Grid.Column='{i}' Tag='LastSeen' Background='{{Binding LastSeenCellBrush}}' BorderBrush='{borderBrush}' BorderThickness='{thickness}' Padding='6,0' Margin='0'>");
                    sb.AppendLine("        <TextBlock Tag='LastSeen' TextTrimming='CharacterEllipsis' Opacity='0.94'/>");
                    sb.AppendLine("      </Border>");
                    break;
                case "Vendor":
                    sb.AppendLine($"      <Border Grid.Column='{i}' Tag='Vendor' Background='{{Binding VendorCellBrush}}' BorderBrush='{borderBrush}' BorderThickness='{thickness}' Padding='6,0' Margin='0'>");
                    sb.AppendLine("        <TextBlock Tag='Vendor' TextTrimming='CharacterEllipsis' Opacity='0.94'/>");
                    sb.AppendLine("      </Border>");
                    break;
                case "OpenPorts":
                    sb.AppendLine($"      <Border Grid.Column='{i}' Tag='OpenPorts' Background='{{Binding OpenPortsCellBrush}}' BorderBrush='{borderBrush}' BorderThickness='{thickness}' Padding='6,0' Margin='0'>");
                    sb.AppendLine("        <TextBlock Tag='OpenPorts' TextTrimming='CharacterEllipsis' Opacity='0.94'/>");
                    sb.AppendLine("      </Border>");
                    break;
                case "CustomName":
                    sb.AppendLine($"      <Border Grid.Column='{i}' Tag='CustomName' Background='{{Binding CustomNameCellBrush}}' BorderBrush='{borderBrush}' BorderThickness='{thickness}' Padding='6,0' Margin='0'>");
                    sb.AppendLine("        <TextBlock Tag='CustomName' TextTrimming='CharacterEllipsis' Opacity='0.94'/>");
                    sb.AppendLine("      </Border>");
                    break;
                case "IPv6Address":
                    sb.AppendLine($"      <Border Grid.Column='{i}' Tag='IPv6Address' Background='{{Binding IPv6AddressCellBrush}}' BorderBrush='{borderBrush}' BorderThickness='{thickness}' Padding='6,0' Margin='0'>");
                    sb.AppendLine("        <TextBlock Tag='IPv6Address' TextTrimming='CharacterEllipsis' Opacity='0.94'/>");
                    sb.AppendLine("      </Border>");
                    break;
            }
        }

        sb.AppendLine("    </Grid>");
        sb.AppendLine("  </Border>");
        sb.AppendLine("</DataTemplate>");

        return (DataTemplate)Microsoft.UI.Xaml.Markup.XamlReader.Load(sb.ToString());
    }



    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        ViewModel.PropertyChanged += ViewModel_PropertyChanged;
        SyncFindPanel();
        UpdateSortHeaderIndicators();
        UpdateScanActionVisual();
        RefreshVisibleRowVisuals();

        // Prevent bright initial focus ring on toolbar actions in dark mode.
        Focus(FocusState.Programmatic);
    }

    private void OnResultContainerContentChanging(ListViewBase sender, ContainerContentChangingEventArgs args)
    {
        if (args.Item is not ScanResultRow row) return;
        if (args.ItemContainer is not ListViewItem container) return;

        var rootBorder = container.ContentTemplateRoot as Border
            ?? FindDescendant<Border>(container);
        if (rootBorder is null) return;

        // Do not apply custom row background highlight here.
        // Current search focus is represented by list selection + text highlight only.
        var rowSelected = ReferenceEquals(row, ViewModel.SelectedResult) || row.IsCurrentSearchHit;
        if (rowSelected)
        {
            rootBorder.Background = Brush(0x66, 0x2E, 0x7D, 0xFF);
            rootBorder.BorderBrush = Brush(0xFF, 0x2E, 0x7D, 0xFF);
            rootBorder.BorderThickness = new Thickness(0);
        }
        else
        {
            rootBorder.Background = Brush(0x00, 0x00, 0x00, 0x00);
            rootBorder.BorderBrush = Brush(0x00, 0x00, 0x00, 0x00);
            rootBorder.BorderThickness = new Thickness(0);
        }

        ApplyTextMatchHighlight(rootBorder, row);
    }

    private void RefreshVisibleRowVisuals()
    {
        if (_resultsList is null) return;

        foreach (var item in _resultsList.Items)
        {
            if (item is not ScanResultRow row) continue;
            if (_resultsList.ContainerFromItem(item) is not ListViewItem container) continue;

            var rootBorder = container.ContentTemplateRoot as Border
                ?? FindDescendant<Border>(container);
            if (rootBorder is null) continue;

            ApplyRowChrome(rootBorder, container, row);
            ApplyTextMatchHighlight(rootBorder, row);
        }
    }

    private void ApplyRowChrome(Border rootBorder, ListViewItem container, ScanResultRow row)
    {
        var isSelected = container.IsSelected || ReferenceEquals(row, ViewModel.SelectedResult);
        if (isSelected)
        {
            rootBorder.Background = Brush(0x66, 0x2E, 0x7D, 0xFF);
            rootBorder.BorderBrush = Brush(0xCC, 0x8C, 0xA8, 0xFF);
            rootBorder.BorderThickness = new Thickness(0);
            return;
        }

        if (row.IsSearchMatch)
        {
            rootBorder.Background = Brush(0x22, 0x2E, 0x7D, 0xFF);
            rootBorder.BorderBrush = Brush(0x44, 0x8C, 0xA8, 0xFF);
            rootBorder.BorderThickness = new Thickness(0);
            return;
        }

        rootBorder.Background = Brush(0x00, 0x00, 0x00, 0x00);
        rootBorder.BorderBrush = Brush(0x00, 0x00, 0x00, 0x00);
        rootBorder.BorderThickness = new Thickness(0);
    }

    private void ApplyTextMatchHighlight(FrameworkElement root, ScanResultRow row)
    {
        var query = ViewModel.SearchText?.Trim();
        var isCurrent = ReferenceEquals(row, ViewModel.SelectedResult) || row.IsCurrentSearchHit;
        var isMatch = row.IsSearchMatch;

        HighlightTextByTag(root, "Hostname", row.Hostname, query, isMatch, isCurrent);
        HighlightTextByTag(root, "IPAddress", row.IPAddress, query, isMatch, isCurrent);
        HighlightTextByTag(root, "MACAddress", row.MACAddress, query, isMatch, isCurrent);
        HighlightTextByTag(root, "FirstSeen", row.FirstSeen?.ToString("yyyy-MM-dd HH:mm") ?? string.Empty, query, isMatch, isCurrent);
        HighlightTextByTag(root, "LastSeen", row.LastSeen?.ToString("yyyy-MM-dd HH:mm") ?? string.Empty, query, isMatch, isCurrent);
        HighlightTextByTag(root, "Vendor", row.Vendor, query, isMatch, isCurrent);
        HighlightTextByTag(root, "OpenPorts", row.OpenPorts ?? string.Empty, query, isMatch, isCurrent);
        HighlightTextByTag(root, "CustomName", row.CustomName ?? string.Empty, query, isMatch, isCurrent);
        HighlightTextByTag(root, "IPv6Address", row.IPv6Address ?? string.Empty, query, isMatch, isCurrent);
    }

    private void HighlightTextByTag(FrameworkElement root, string tag, string fullText, string? query, bool isMatch, bool strong)
    {
        var tb = FindTaggedTextBlock(root, tag);
        if (tb is null) return;

        tb.Text = fullText ?? string.Empty;
        tb.TextHighlighters.Clear();
        tb.Foreground = Brush(0xFF, 0xF2, 0xF2, 0xF4);
        tb.FontWeight = FontWeights.Normal;

        if (!isMatch || string.IsNullOrWhiteSpace(query) || string.IsNullOrEmpty(fullText))
        {
            return;
        }

        var idx = 0;
        var matched = false;
        while (idx < fullText.Length)
        {
            var hit = fullText.IndexOf(query, idx, StringComparison.OrdinalIgnoreCase);
            if (hit < 0) break;

            matched = true;

            var hl = new TextHighlighter
            {
                Foreground = Brush(0xFF, 0xE6, 0xF1, 0xFF),
                Background = Brush(0x80, 0x4A, 0x8D, 0xF7)
            };
            hl.Ranges.Add(new TextRange { StartIndex = hit, Length = query.Length });
            tb.TextHighlighters.Add(hl);

            idx = hit + query.Length;
        }

        if (matched)
        {
            tb.FontWeight = FontWeights.SemiBold;
        }
    }

    private TextBlock? FindTaggedTextBlock(DependencyObject root, string tag)
    {
        if (root is TextBlock tb && string.Equals(tb.Tag as string, tag, StringComparison.Ordinal))
        {
            return tb;
        }

        var count = VisualTreeHelper.GetChildrenCount(root);
        for (var i = 0; i < count; i++)
        {
            var result = FindTaggedTextBlock(VisualTreeHelper.GetChild(root, i), tag);
            if (result is not null)
            {
                return result;
            }
        }

        return null;
    }

    private void ScrollToSelectedResult()
    {
        if (_resultsList is null || ViewModel.SelectedResult is null) return;

        var target = ViewModel.SelectedResult;
        var targetIndex = ViewModel.Results.IndexOf(target);
        if (targetIndex < 0) return;

        // Keep Enter key behavior stable: do not steal focus from the search box.
        _resultsList.SelectedIndex = targetIndex;
        _resultsList.SelectedItem = target;

        // Single deferred pass with Default alignment: only scroll when needed.
        _resultsList.DispatcherQueue.TryEnqueue(() =>
        {
            _resultsList.UpdateLayout();
            _resultsList.ScrollIntoView(_resultsList.Items[targetIndex], ScrollIntoViewAlignment.Default);
        });
    }

    private static T? FindDescendant<T>(DependencyObject root) where T : DependencyObject
    {
        if (root is T match)
        {
            return match;
        }

        var count = VisualTreeHelper.GetChildrenCount(root);
        for (var i = 0; i < count; i++)
        {
            var child = VisualTreeHelper.GetChild(root, i);
            var hit = FindDescendant<T>(child);
            if (hit is not null)
            {
                return hit;
            }
        }

        return null;
    }

    private void OnUnloaded(object sender, RoutedEventArgs e)
    {
        ViewModel.PropertyChanged -= ViewModel_PropertyChanged;
    }

    private void ViewModel_PropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName is nameof(ScannerViewModel.ShowFindPanel) or nameof(ScannerViewModel.IsSearching) or nameof(ScannerViewModel.SearchText))
        {
            SyncFindPanel();
            if (_resultsList is not null)
            {
                _resultsList.UpdateLayout();
                RefreshVisibleRowVisuals();
            }
        }

        // Scope summary is composed from range + ports
        if (e.PropertyName is nameof(ScannerViewModel.IPRanges) or nameof(ScannerViewModel.Ports))
        {
            RefreshScopeSummaryText();
        }

        if (e.PropertyName is nameof(ScannerViewModel.CurrentSortColumn) or nameof(ScannerViewModel.IsSortAscending))
        {
            UpdateSortHeaderIndicators();
            if (_resultsList is not null)
            {
                _resultsList.ItemTemplate = BuildTableRowTemplate();
                _resultsList.UpdateLayout();
                RefreshVisibleRowVisuals();
            }
        }

        if (e.PropertyName is nameof(ScannerViewModel.ScanButtonText) or nameof(ScannerViewModel.IsScanning))
        {
            UpdateScanActionVisual();
        }

        if (e.PropertyName == nameof(ScannerViewModel.StatusText))
        {
            _resultsList?.UpdateLayout();
            RefreshVisibleRowVisuals();
        }

        if (e.PropertyName == nameof(ScannerViewModel.SelectedResult))
        {
            RefreshVisibleRowVisuals();
        }

        if (e.PropertyName == nameof(ScannerViewModel.SearchNavigationVersion))
        {
            ScrollToSelectedResult();
            RefreshVisibleRowVisuals();
        }
    }

    private void SyncFindPanel()
    {
        var show = ViewModel.IsSearching || !string.IsNullOrWhiteSpace(ViewModel.SearchText);
        _searchInfoStrip.Visibility = show ? Visibility.Visible : Visibility.Collapsed;
    }

    private void UpdateScanActionVisual()
    {
        if (_scanActionSymbol is null) return;

        if (ViewModel.IsScanning || string.Equals(ViewModel.ScanButtonText, "Stop", StringComparison.OrdinalIgnoreCase))
        {
            _scanActionSymbol.Symbol = Symbol.Stop;
        }
        else
        {
            _scanActionSymbol.Symbol = Symbol.Play;
        }
    }

    private void UpdateSortHeaderIndicators()
    {
        foreach (var kvp in _sortHeaderButtons)
        {
            var key = kvp.Key;
            var button = kvp.Value;
            var icon = _sortHeaderIcons[key];
            var highlight = _sortHeaderHighlights[key];

            if (_isDraggingColumn && string.Equals(key, _draggingColumnKey, StringComparison.OrdinalIgnoreCase))
            {
                icon.Glyph = "\uE70D";
                icon.Foreground = Brush(0xFF, 0x8C, 0x90, 0x98);
                button.Opacity = 1.0;
                highlight.Opacity = 0.6;
                highlight.Background = Brush(0x80, 0x4A, 0x8D, 0xF7);
                highlight.BorderBrush = Brush(0xFF, 0x4A, 0x8D, 0xF7);
            }
            else if (string.Equals(ViewModel.CurrentSortColumn, key, StringComparison.OrdinalIgnoreCase))
            {
                icon.Glyph = ViewModel.IsSortAscending ? "\uE70E" : "\uE70D"; // up/down sort glyphs
                icon.Foreground = Brush(0xFF, 0x4A, 0x8D, 0xF7);
                button.Opacity = 1.0;
                highlight.Opacity = 1.0;

                highlight.Background = Brush(0x33, 0x4A, 0x8D, 0xF7);
                highlight.BorderBrush = Brush(0x66, 0x4A, 0x8D, 0xF7);
            }
            else
            {
                icon.Glyph = "\uE70D"; // neutral sort
                icon.Foreground = Brush(0xFF, 0x8C, 0x90, 0x98);
                button.Opacity = 0.9;
                highlight.Opacity = 1.0;

                highlight.Background = Brush(0x00, 0x00, 0x00, 0x00);
                highlight.BorderBrush = Brush(0x00, 0x00, 0x00, 0x00);
            }
        }
    }

    private void AddColumnResizeGrip(Grid header, int leftColumnIndex)
    {
        var lastColumn = header.ColumnDefinitions.Count - 1;
        var isLastEdge = leftColumnIndex >= lastColumn;

        // For interior separators, host in the next column and align left.
        // For the final right edge, host in last column and align right.
        var hostColumn = isLastEdge ? lastColumn : Math.Min(leftColumnIndex + 1, lastColumn);

        var line = new Border
        {
            Width = 1,
            VerticalAlignment = VerticalAlignment.Stretch,
            HorizontalAlignment = isLastEdge ? HorizontalAlignment.Right : HorizontalAlignment.Left,
            Margin = isLastEdge ? new Thickness(0, 0, -1, 0) : new Thickness(-1, 0, 0, 0),
            Background = Brush(0x88, 0x8D, 0x96, 0xA4),
            IsHitTestVisible = false
        };

        var grip = new Grid
        {
            Width = 14,
            VerticalAlignment = VerticalAlignment.Stretch,
            HorizontalAlignment = isLastEdge ? HorizontalAlignment.Right : HorizontalAlignment.Left,
            Margin = isLastEdge ? new Thickness(7, -2, -7, -2) : new Thickness(-7, -2, -7, -2),
            Background = Brush(0x00, 0x00, 0x00, 0x00),
            IsHitTestVisible = true
        };

        grip.Children.Add(line);
        Grid.SetColumn(grip, hostColumn);
        header.Children.Add(grip);

        grip.PointerEntered += (_, _) =>
        {
            if (!_isResizingColumn)
                line.Background = Brush(0xDD, 0xA6, 0xB4, 0xFF);
        };

        grip.PointerExited += (_, _) =>
        {
            if (!_isResizingColumn)
                line.Background = Brush(0x88, 0x8D, 0x96, 0xA4);
        };

        grip.PointerPressed += (sender, e) =>
        {
            var g = (Grid)sender;
            var isLast = g.HorizontalAlignment == HorizontalAlignment.Right;
            var colIndex = isLast ? Grid.GetColumn(g) : Grid.GetColumn(g) - 1;

            _isResizingColumn = true;
            _resizingColumnIndex = colIndex;
            _resizeStartX = e.GetCurrentPoint(header).Position.X;
            _resizeStartWidth = _columnWidths[colIndex];
            line.Background = Brush(0xFF, 0xB8, 0xC4, 0xFF);
            g.CapturePointer(e.Pointer);
            e.Handled = true;
        };

        grip.PointerMoved += (sender, e) =>
        {
            if (!_isResizingColumn) return;
            var g = (Grid)sender;
            var isLast = g.HorizontalAlignment == HorizontalAlignment.Right;
            var colIndex = isLast ? Grid.GetColumn(g) : Grid.GetColumn(g) - 1;
            if (_resizingColumnIndex != colIndex) return;

            var currentX = e.GetCurrentPoint(header).Position.X;
            var delta = currentX - _resizeStartX;
            var newWidth = Math.Max(80, _resizeStartWidth + delta);
            _columnWidths[colIndex] = newWidth;

            if (colIndex < _headerColumns.Count)
                _headerColumns[colIndex].Width = new GridLength(newWidth);

            ApplyColumnWidthsToVisibleRows();
            e.Handled = true;
        };

        grip.PointerReleased += (sender, e) =>
        {
            _isResizingColumn = false;
            _resizingColumnIndex = -1;
            line.Background = Brush(0x88, 0x8D, 0x96, 0xA4);
            ((UIElement)sender).ReleasePointerCapture(e.Pointer);
            
            if (_resultsList is not null)
            {
                _resultsList.ItemTemplate = BuildTableRowTemplate();
            }

            SaveColumnLayout();

            e.Handled = true;
        };
    }






    private void ApplyColumnWidthsToVisibleRows()
    {
        if (_tableGrid is not null)
        {
            _tableGrid.Width = _columnWidths.Sum() + 12;
        }

        if (_resultsList is null) return;

        foreach (var item in _resultsList.Items)
        {
            if (_resultsList.ContainerFromItem(item) is not ListViewItem container) continue;
            if (container.ContentTemplateRoot is not FrameworkElement root) continue;

            var rowGrid = FindDescendant<Grid>(root);
            if (rowGrid is null) continue;
            if (rowGrid.ColumnDefinitions.Count < _columnWidths.Length) continue;

            for (var i = 0; i < _columnWidths.Length; i++)
            {
                rowGrid.ColumnDefinitions[i].Width = new GridLength(_columnWidths[i]);
            }

            foreach (var child in rowGrid.Children)
            {
                if (child is Border cellBorder && cellBorder.Tag is string cellTag)
                {
                    var newIndex = _columnOrder.IndexOf(cellTag);
                    if (newIndex >= 0)
                    {
                        Grid.SetColumn(cellBorder, newIndex);
                        if (newIndex == _columnOrder.Count - 1)
                        {
                            cellBorder.BorderThickness = new Thickness(0);
                        }
                        else
                        {
                            cellBorder.BorderThickness = new Thickness(0, 0, 1, 0);
                            cellBorder.BorderBrush = Brush(0x1E, 0x2A, 0x2F, 0x36);
                        }
                    }
                }
            }
        }
    }

    private void Header_PointerPressed(object sender, PointerRoutedEventArgs e)
    {
        var highlight = (Border)sender;
        var key = _sortHeaderHighlights.FirstOrDefault(x => ReferenceEquals(x.Value, highlight)).Key;
        if (string.IsNullOrEmpty(key)) return;

        _pointerPressStartPos = e.GetCurrentPoint(_headerGrid).Position;
        _draggingColumnKey = key;
        _isDraggingColumn = false;
    }

    private void Header_PointerMoved(object sender, PointerRoutedEventArgs e)
    {
        if (string.IsNullOrEmpty(_draggingColumnKey)) return;

        var highlight = (Border)sender;
        var currentPoint = e.GetCurrentPoint(_headerGrid);
        var currentX = currentPoint.Position.X;

        if (!_isDraggingColumn)
        {
            var pressPoint = _pointerPressStartPos;
            var deltaX = Math.Abs(currentPoint.Position.X - pressPoint.X);
            var deltaY = Math.Abs(currentPoint.Position.Y - pressPoint.Y);

            // Drag threshold of 8 pixels
            if (deltaX > 8)
            {
                _isDraggingColumn = true;
                highlight.CapturePointer(e.Pointer);
                
                // Initialize translation and set high ZIndex so it draws above other headers
                _dragTranslation.X = 0;
                highlight.RenderTransform = _dragTranslation;
                Canvas.SetZIndex(highlight, 99);

                // Immediately apply styling for dragging
                UpdateSortHeaderIndicators();
            }
        }
        else
        {
            _dragTranslation.X = currentX - _pointerPressStartPos.X;

            var curIndex = _columnOrder.IndexOf(_draggingColumnKey);
            if (curIndex >= 0)
            {
                // Left check
                if (curIndex > 0)
                {
                    var leftMidpoint = GetColumnLeft(curIndex - 1) + _columnWidths[curIndex - 1] / 2;
                    if (currentX < leftMidpoint)
                    {
                        SwapColumns(curIndex, curIndex - 1);
                    }
                }
                // Right check
                if (curIndex < _columnOrder.Count - 1)
                {
                    var rightMidpoint = GetColumnLeft(curIndex + 1) + _columnWidths[curIndex + 1] / 2;
                    if (currentX > rightMidpoint)
                    {
                        SwapColumns(curIndex, curIndex + 1);
                    }
                }
            }
            e.Handled = true;
        }
    }

    private void Header_PointerReleased(object sender, PointerRoutedEventArgs e)
    {
        if (string.IsNullOrEmpty(_draggingColumnKey)) return;

        var highlight = (Border)sender;
        if (_isDraggingColumn)
        {
            highlight.ReleasePointerCapture(e.Pointer);
            _isDraggingColumn = false;
            _draggingColumnKey = null;
            
            // Clear transform and restore normal Z-Index
            highlight.RenderTransform = null;
            Canvas.SetZIndex(highlight, 0);

            // Apply layout, rebuild template, and save configuration
            ApplyColumnOrderAndWidths(updateTemplate: true);
            UpdateSortHeaderIndicators();
            SaveColumnLayout();

            e.Handled = true;
        }
        else
        {
            _draggingColumnKey = null;
        }
    }

    private void Header_PointerCaptureLost(object sender, PointerRoutedEventArgs e)
    {
        var highlight = (Border)sender;
        _isDraggingColumn = false;
        _draggingColumnKey = null;
        
        highlight.RenderTransform = null;
        Canvas.SetZIndex(highlight, 0);

        ApplyColumnOrderAndWidths(updateTemplate: true);
        UpdateSortHeaderIndicators();
        SaveColumnLayout();
    }

    private void SwapColumns(int index1, int index2)
    {
        var tempKey = _columnOrder[index1];
        _columnOrder[index1] = _columnOrder[index2];
        _columnOrder[index2] = tempKey;

        var tempWidth = _columnWidths[index1];
        _columnWidths[index1] = _columnWidths[index2];
        _columnWidths[index2] = tempWidth;

        // Shift drag pointer origin to align visual translation seamlessly
        if (index2 > index1)
        {
            _pointerPressStartPos.X += _columnWidths[index1];
        }
        else
        {
            _pointerPressStartPos.X -= _columnWidths[index2];
        }

        // Apply new order to the grid and visible items (don't update template during drag)
        ApplyColumnOrderAndWidths(updateTemplate: false);
        UpdateSortHeaderIndicators();
    }

    private double GetColumnLeft(int index)
    {
        double left = 0;
        for (int i = 0; i < index && i < _columnWidths.Length; i++)
        {
            left += _columnWidths[i];
        }
        return left;
    }

    private void ApplyColumnOrderAndWidths(bool updateTemplate = false)
    {
        // 1. Update header column definitions widths
        for (var i = 0; i < _columnWidths.Length; i++)
        {
            if (i < _headerColumns.Count)
            {
                _headerColumns[i].Width = new GridLength(_columnWidths[i]);
            }
        }

        // 2. Update table grid width
        if (_tableGrid is not null)
        {
            _tableGrid.Width = _columnWidths.Sum() + 12;
        }

        // 3. Update header highlight positions (Grid.SetColumn)
        for (var i = 0; i < _columnOrder.Count; i++)
        {
            var key = _columnOrder[i];
            if (_sortHeaderHighlights.TryGetValue(key, out var highlight))
            {
                Grid.SetColumn(highlight, i);
            }
        }

        // 4. Update the ListView's ItemTemplate so any future row containers are built with correct columns
        if (updateTemplate && _resultsList is not null)
        {
            _resultsList.ItemTemplate = BuildTableRowTemplate();
        }

        // 5. Update visible row containers in the ListView
        ApplyColumnWidthsToVisibleRows();
    }

    private void SaveColumnLayout()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_columnLayoutPath)!);

            var items = new List<WinUIColumnLayoutItem>();
            for (int i = 0; i < _columnOrder.Count; i++)
            {
                items.Add(new WinUIColumnLayoutItem
                {
                    Key = _columnOrder[i],
                    Width = _columnWidths[i]
                });
            }

            var json = JsonSerializer.Serialize(items, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(_columnLayoutPath, json);
        }
        catch
        {
            // non-fatal
        }
    }

    private void LoadColumnLayoutOrDefault()
    {
        try
        {
            if (File.Exists(_columnLayoutPath))
            {
                var json = File.ReadAllText(_columnLayoutPath);
                var items = JsonSerializer.Deserialize<List<WinUIColumnLayoutItem>>(json);
                if (items != null && items.Count == _columnOrder.Count)
                {
                    var allValid = items.All(i => _columnOrder.Contains(i.Key));
                    if (allValid)
                    {
                        _columnOrder.Clear();
                        for (int i = 0; i < items.Count; i++)
                        {
                            _columnOrder.Add(items[i].Key);
                            _columnWidths[i] = items[i].Width;
                        }
                        return;
                    }
                }
            }
        }
        catch
        {
            // fallback
        }
    }

    private static bool IsRunningAsAdmin()
    {
        try
        {
            using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            var principal = new System.Security.Principal.WindowsPrincipal(identity);
            return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }

    private static void RestartAsAdmin()
    {
        var exePath = System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName;
        if (string.IsNullOrEmpty(exePath)) return;

        var psi = new System.Diagnostics.ProcessStartInfo
        {
            FileName = exePath,
            UseShellExecute = true,
            Verb = "runas"
        };

        try
        {
            System.Diagnostics.Process.Start(psi);
            Microsoft.UI.Xaml.Application.Current.Exit();
        }
        catch {}
    }
}