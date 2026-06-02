using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.UI;
using Microsoft.UI.Text;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Data;
using Microsoft.UI.Xaml.Media;
using NetworkScanner.WinUIPrototype.Pages;
using NetworkScanner.WinUIPrototype.ViewModels;
using WinRT.Interop;

using System.IO;
using System.Text.Json;
using Microsoft.UI.Windowing;
using Windows.Graphics;
namespace NetworkScanner.WinUIPrototype;

public sealed partial class MainWindow : Window
{
    private AppWindow? _appWindow;
    private bool _windowPlacementRestored;

    private sealed class SavedWindowPlacement
    {
        public int X { get; set; }
        public int Y { get; set; }
        public int Width { get; set; }
        public int Height { get; set; }
        public bool IsMaximized { get; set; }
    }

    private static string WindowPlacementFilePath =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "NetworkScanner", "WinUIPrototype", "window-state.json");
    private readonly ScannerViewModel _vm;
    private readonly ColumnDefinition _navColumn;
    private readonly ContentControl _contentHost;
    private readonly Button _searchToggleBtn;
    private TextBox _searchBox = null!;
    private Button _searchPrevBtn = null!;
    private Button _searchNextBtn = null!;
    private TextBlock _searchStatusText = null!;

    private Button _liveScanBtn = null!;
    private Button _deepInfoBtn = null!;
    private Button _historyBtn = null!;
    private Button _aboutBtn = null!;
    private Button _settingsBtn = null!;

    private TextBlock _liveScanLabel = null!;
    private TextBlock _deepInfoLabel = null!;
    private TextBlock _historyLabel = null!;
    private TextBlock _aboutLabel = null!;
    private TextBlock _settingsLabel = null!;

    private bool _navCollapsed;

    private static SolidColorBrush BgWindow => Brush(0xFF, 0x0E, 0x0F, 0x11);
    private static SolidColorBrush BgCard => Brush(0xFF, 0x15, 0x15, 0x17);
    private static SolidColorBrush BgNav => Brush(0xFF, 0x12, 0x13, 0x16);
    private static SolidColorBrush BgButton => Brush(0xFF, 0x1E, 0x20, 0x24);
    private static SolidColorBrush BgButtonHover => Brush(0xFF, 0x25, 0x28, 0x2E);
    private static SolidColorBrush BgSelected => Brush(0xFF, 0x26, 0x32, 0x49);
    private static SolidColorBrush BorderSubtle => Brush(0xFF, 0x2A, 0x2A, 0x2F);
    private static SolidColorBrush TextPrimary => Brush(0xFF, 0xF2, 0xF2, 0xF4);
    private static SolidColorBrush TextMuted => Brush(0xFF, 0xB6, 0xB7, 0xBB);
    private static SolidColorBrush Accent => Brush(0xFF, 0x4A, 0x8D, 0xF7);

    public MainWindow()
    {
        _vm = ((App)Application.Current).ScannerViewModel;
        _vm.PropertyChanged += Vm_PropertyChanged;

        Title = "Network Scanner";

        ExtendsContentIntoTitleBar = true;

        var root = new Grid { Background = BgWindow };
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });

        var topBar = BuildTopBar(out _searchToggleBtn);
        Grid.SetRow(topBar, 0);
        root.Children.Add(topBar);

        SetTitleBar(topBar);

        var body = new Grid();
        _navColumn = new ColumnDefinition { Width = new GridLength(220) };
        body.ColumnDefinitions.Add(_navColumn);
        body.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        Grid.SetRow(body, 1);

        var nav = new Border
        {
            Margin = new Thickness(10, 0, 8, 10),
            Padding = new Thickness(8),
            CornerRadius = new CornerRadius(10),
            BorderThickness = new Thickness(1),
            BorderBrush = BorderSubtle,
            Background = BgNav
        };

        var navStack = new Grid();
        navStack.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        navStack.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        navStack.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        var topNav = new StackPanel { Spacing = 8 };
        var collapseBtn = new Button
        {
            Content = "☰",
            Height = 32,
            HorizontalAlignment = HorizontalAlignment.Stretch,
            HorizontalContentAlignment = HorizontalAlignment.Left,
            Padding = new Thickness(12, 0, 0, 0),
            Background = BgButton,
            BorderBrush = BorderSubtle,
            Foreground = TextPrimary
        };
        collapseBtn.Click += (_, _) => ToggleNav();
        topNav.Children.Add(collapseBtn);

        (_liveScanBtn, _liveScanLabel) = BuildNavButton(Symbol.Find, "Live Scan", () => SelectView("live"));
        (_deepInfoBtn, _deepInfoLabel) = BuildNavButton(Symbol.Preview, "Deep Info", () => SelectView("deep"));
        (_historyBtn, _historyLabel) = BuildNavButton(Symbol.Clock, "History", () => SelectView("history"));
        topNav.Children.Add(_liveScanBtn);
        topNav.Children.Add(_deepInfoBtn);
        topNav.Children.Add(_historyBtn);

        Grid.SetRow(topNav, 0);
        navStack.Children.Add(topNav);

        var bottomNav = new StackPanel { Spacing = 8 };
        (_aboutBtn, _aboutLabel) = BuildNavButton(Symbol.Help, "About", () => SelectView("about"));
        (_settingsBtn, _settingsLabel) = BuildNavButton(Symbol.Setting, "Settings", () => SelectView("settings"));
        bottomNav.Children.Add(_aboutBtn);
        bottomNav.Children.Add(_settingsBtn);
        Grid.SetRow(bottomNav, 2);
        navStack.Children.Add(bottomNav);

        nav.Child = navStack;
        Grid.SetColumn(nav, 0);
        body.Children.Add(nav);

        _contentHost = new ContentControl { Margin = new Thickness(0, 0, 10, 10) };
        Grid.SetColumn(_contentHost, 1);
        body.Children.Add(_contentHost);

        root.Children.Add(body);
        Content = root;

        InitializeWindowInterop();
        Activated += MainWindow_Activated;
        Closed += MainWindow_Closed;

        SelectView("live");
        UpdateSearchButtonVisual();
    }

    private FrameworkElement BuildTopBar(out Button searchToggleBtn)
    {
        var border = new Border
        {
            Margin = new Thickness(10, 10, 150, 8),
            Padding = new Thickness(10, 8, 10, 8),
            CornerRadius = new CornerRadius(10),
            BorderThickness = new Thickness(1),
            BorderBrush = BorderSubtle,
            Background = BgCard
        };

        var row = new Grid();
        row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(16) });
        row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

        var icon = new FontIcon { Glyph = "\uE968", FontSize = 18, VerticalAlignment = VerticalAlignment.Center, Foreground = Accent };
        Grid.SetColumn(icon, 0);
        row.Children.Add(icon);

        var name = new TextBlock
        {
            Text = "Network Scanner",
            FontSize = 17,
            FontWeight = FontWeights.SemiBold,
            Margin = new Thickness(8, 0, 0, 0),
            VerticalAlignment = VerticalAlignment.Center,
            Foreground = TextPrimary
        };
        Grid.SetColumn(name, 1);
        row.Children.Add(name);

        var searchSurface = new Border
        {
            Height = 34,
            CornerRadius = new CornerRadius(8),
            BorderThickness = new Thickness(1),
            BorderBrush = BorderSubtle,
            Background = Brush(0xFF, 0x11, 0x12, 0x14),
            Padding = new Thickness(6, 0, 6, 0),
            Margin = new Thickness(0)
        };

        var searchGrid = new Grid();
        searchGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) }); // input
        searchGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(86) }); // status (fixed to prevent jump)
        searchGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(28) }); // prev
        searchGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(28) }); // next
        searchGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(30) }); // toggle

        _searchBox = new TextBox
        {
            PlaceholderText = "Search devices, IPs, hostnames...",
            Height = 30,
            BorderThickness = new Thickness(0),
            Background = Brush(0xFF, 0x11, 0x12, 0x14),
            Foreground = TextPrimary,
            SelectionHighlightColor = Brush(0x66, 0x4A, 0x8D, 0xF7),
            VerticalAlignment = VerticalAlignment.Center,
            RequestedTheme = ElementTheme.Dark
        };
        ConfigureDarkSearchTextBox(_searchBox);
        _searchBox.SetBinding(TextBox.TextProperty, new Binding
        {
            Source = _vm,
            Path = new PropertyPath("SearchText"),
            Mode = BindingMode.TwoWay,
            UpdateSourceTrigger = UpdateSourceTrigger.PropertyChanged
        });
        _searchBox.KeyDown += (_, e) =>
        {
            if (e.Key == Windows.System.VirtualKey.Enter)
            {
                _vm.FindNextCommand.Execute(null);
                e.Handled = true;
            }
            else if (e.Key == Windows.System.VirtualKey.Escape)
            {
                _vm.ToggleFindCommand.Execute(null);
                e.Handled = true;
            }
        };
        Grid.SetColumn(_searchBox, 0);
        searchGrid.Children.Add(_searchBox);

        _searchStatusText = new TextBlock
        {
            VerticalAlignment = VerticalAlignment.Center,
            HorizontalAlignment = HorizontalAlignment.Right,
            Margin = new Thickness(4, 0, 4, 0),
            Foreground = TextMuted,
            Visibility = Visibility.Collapsed,
            TextAlignment = TextAlignment.Right
        };
        _searchStatusText.SetBinding(TextBlock.TextProperty, new Binding
        {
            Source = _vm,
            Path = new PropertyPath("SearchStatusText")
        });
        Grid.SetColumn(_searchStatusText, 1);
        searchGrid.Children.Add(_searchStatusText);

        _searchPrevBtn = new Button
        {
            Width = 24,
            Height = 24,
            Padding = new Thickness(0),
            Margin = new Thickness(2, 0, 0, 0),
            Background = Brush(0x00, 0x00, 0x00, 0x00),
            BorderBrush = Brush(0x00, 0x00, 0x00, 0x00),
            Foreground = TextMuted,
            Visibility = Visibility.Collapsed,
            Content = new SymbolIcon(Symbol.Back)
            {
                Foreground = TextMuted
            }
        };
        _searchPrevBtn.SetBinding(Button.CommandProperty, new Binding
        {
            Source = _vm,
            Path = new PropertyPath("FindPreviousCommand")
        });
        Grid.SetColumn(_searchPrevBtn, 2);
        searchGrid.Children.Add(_searchPrevBtn);

        _searchNextBtn = new Button
        {
            Width = 24,
            Height = 24,
            Padding = new Thickness(0),
            Margin = new Thickness(2, 0, 0, 0),
            Background = Brush(0x00, 0x00, 0x00, 0x00),
            BorderBrush = Brush(0x00, 0x00, 0x00, 0x00),
            Foreground = TextMuted,
            Visibility = Visibility.Collapsed,
            Content = new SymbolIcon(Symbol.Forward)
            {
                Foreground = TextMuted
            }
        };
        _searchNextBtn.SetBinding(Button.CommandProperty, new Binding
        {
            Source = _vm,
            Path = new PropertyPath("FindNextCommand")
        });
        Grid.SetColumn(_searchNextBtn, 3);
        searchGrid.Children.Add(_searchNextBtn);

        searchToggleBtn = new Button
        {
            Width = 26,
            Height = 26,
            Padding = new Thickness(0),
            Margin = new Thickness(2, 0, 0, 0),
            Background = Brush(0x00, 0x00, 0x00, 0x00),
            BorderBrush = Brush(0x00, 0x00, 0x00, 0x00),
            Foreground = TextPrimary
        };
        searchToggleBtn.Click += (_, _) =>
        {
            var hasText = !string.IsNullOrWhiteSpace(_vm.SearchText);
            if (!hasText && !_vm.IsSearching)
            {
                _searchBox?.Focus(FocusState.Programmatic);
                return;
            }

            _vm.ToggleFindCommand.Execute(null);
        };
        Grid.SetColumn(searchToggleBtn, 4);
        searchGrid.Children.Add(searchToggleBtn);

        searchSurface.Child = searchGrid;
        Grid.SetColumn(searchSurface, 3);
        row.Children.Add(searchSurface);

        border.Child = row;
        return border;
    }

    private void Vm_PropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(ScannerViewModel.SearchText)
            || e.PropertyName == nameof(ScannerViewModel.IsSearching)
            || e.PropertyName == nameof(ScannerViewModel.SearchStatusText)
            || e.PropertyName == nameof(ScannerViewModel.SearchMatchCount)
            || e.PropertyName == nameof(ScannerViewModel.CanNavigateSearch))
        {
            UpdateSearchButtonVisual();
        }
    }

    private void UpdateSearchButtonVisual()
    {
        if (_searchToggleBtn is null) return;

        var hasText = !string.IsNullOrWhiteSpace(_vm.SearchText);
        var active = _vm.IsSearching || hasText;

        _searchToggleBtn.Content = new SymbolIcon(active ? Symbol.Cancel : Symbol.Find)
        {
            Foreground = active ? Accent : TextMuted
        };
        ToolTipService.SetToolTip(_searchToggleBtn, active ? "Cancel search" : "Search");

        // Ensure VM search mode tracks actual text presence so state never drifts.
        if (hasText && !_vm.IsSearching)
        {
            _vm.IsSearching = true;
        }
        else if (!hasText && _vm.IsSearching)
        {
            _vm.IsSearching = false;
        }

        var navVisible = (active && _vm.CanNavigateSearch) ? Visibility.Visible : Visibility.Collapsed;
        if (_searchPrevBtn is not null)
        {
            _searchPrevBtn.Visibility = navVisible;
        }

        if (_searchNextBtn is not null)
        {
            _searchNextBtn.Visibility = navVisible;
        }

        if (_searchStatusText is not null)
        {
            _searchStatusText.Visibility = active ? Visibility.Visible : Visibility.Collapsed;
            _searchStatusText.Foreground = active ? TextPrimary : TextMuted;
            _searchStatusText.MaxWidth = 120;
            _searchStatusText.TextTrimming = TextTrimming.CharacterEllipsis;
        }
    }

    private (Button button, TextBlock label) BuildNavButton(Symbol symbol, string text, Action click)
    {
        var btn = new Button
        {
            HorizontalAlignment = HorizontalAlignment.Stretch,
            HorizontalContentAlignment = HorizontalAlignment.Left,
            Padding = new Thickness(12, 9, 10, 9),
            Foreground = TextPrimary
        };

        btn.Resources["ButtonBackground"] = BgButton;
        btn.Resources["ButtonBackgroundPointerOver"] = BgButtonHover;
        btn.Resources["ButtonBackgroundPressed"] = BgSelected;
        btn.Resources["ButtonBorderBrush"] = BorderSubtle;
        btn.Resources["ButtonBorderBrushPointerOver"] = BorderSubtle;
        btn.Resources["ButtonForeground"] = TextPrimary;
        btn.Resources["ButtonForegroundPointerOver"] = TextPrimary;
        btn.Resources["ButtonForegroundPressed"] = TextPrimary;

        var row = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8 };
        row.Children.Add(new SymbolIcon(symbol) { Foreground = TextMuted });
        var label = new TextBlock { Text = text, VerticalAlignment = VerticalAlignment.Center, Foreground = TextPrimary };
        row.Children.Add(label);
        btn.Content = row;

        btn.Click += (_, _) => click();
        return (btn, label);
    }

    private void ToggleNav()
    {
        _navCollapsed = !_navCollapsed;
        if (_navCollapsed)
        {
            _navColumn.Width = new GridLength(84);
            SetLabelsVisibility(Visibility.Collapsed);
        }
        else
        {
            _navColumn.Width = new GridLength(220);
            SetLabelsVisibility(Visibility.Visible);
        }
    }

    private void SetLabelsVisibility(Visibility v)
    {
        _liveScanLabel.Visibility = v;
        _deepInfoLabel.Visibility = v;
        _historyLabel.Visibility = v;
        _aboutLabel.Visibility = v;
        _settingsLabel.Visibility = v;
    }

    private void SelectView(string view)
    {
        StyleNavButton(_liveScanBtn, view == "live");
        StyleNavButton(_deepInfoBtn, view == "deep");
        StyleNavButton(_historyBtn, view == "history");
        StyleNavButton(_aboutBtn, view == "about");
        StyleNavButton(_settingsBtn, view == "settings");

        _contentHost.Content = view switch
        {
            "live" => new ScannerPage(),
            "deep" => new DetailsPage(),
            "history" => new FeatureMapPage(),
            "about" => new AboutPage(),
            "settings" => new SettingsPage(),
            _ => new ScannerPage()
        };
    }

    private void StyleNavButton(Button button, bool selected)
    {
        if (selected)
        {
            button.Resources["ButtonBackground"] = BgSelected;
            button.Resources["ButtonBackgroundPointerOver"] = BgSelected;
            button.Resources["ButtonBorderBrush"] = Accent;
            button.Resources["ButtonBorderBrushPointerOver"] = Accent;
        }
        else
        {
            button.Resources["ButtonBackground"] = BgButton;
            button.Resources["ButtonBackgroundPointerOver"] = BgButtonHover;
            button.Resources["ButtonBorderBrush"] = BorderSubtle;
            button.Resources["ButtonBorderBrushPointerOver"] = BorderSubtle;
        }

        button.ClearValue(Control.BackgroundProperty);
        button.ClearValue(Control.BorderBrushProperty);

        button.Opacity = selected ? 1.0 : 0.92;
    }

    private static void ConfigureDarkSearchTextBox(TextBox tb)
    {
        var bg = Brush(0xFF, 0x11, 0x12, 0x14);
        var bgHover = Brush(0xFF, 0x15, 0x16, 0x19);
        var bgFocus = Brush(0xFF, 0x16, 0x18, 0x1D);
        var fg = Brush(0xFF, 0xF2, 0xF2, 0xF4);
        var fgPlaceholder = Brush(0xFF, 0x9A, 0x9B, 0xA0);
        var borderFocus = Brush(0xFF, 0x4A, 0x8D, 0xF7);
        var borderIdle = Brush(0x00, 0x00, 0x00, 0x00);

        // Force TextBox template state brushes (idle/hover/focus/edit) to dark.
        tb.Resources["TextControlBackground"] = bg;
        tb.Resources["TextControlBackgroundPointerOver"] = bgHover;
        tb.Resources["TextControlBackgroundFocused"] = bgFocus;
        tb.Resources["TextControlForeground"] = fg;
        tb.Resources["TextControlForegroundFocused"] = fg;
        tb.Resources["TextControlPlaceholderForeground"] = fgPlaceholder;
        tb.Resources["TextControlBorderBrush"] = borderIdle;
        tb.Resources["TextControlBorderBrushFocused"] = borderFocus;

        tb.RequestedTheme = ElementTheme.Dark;
        tb.Background = bg;
        tb.Foreground = fg;
        tb.BorderBrush = borderIdle;
        tb.SelectionHighlightColor = Brush(0x66, 0x4A, 0x8D, 0xF7);

        void ApplyBorder(bool focused)
        {
            tb.BorderBrush = focused ? borderFocus : borderIdle;
            tb.Foreground = fg;
            tb.Background = focused ? bgFocus : bg;
        }

        tb.Loaded += (_, _) => ApplyBorder(tb.FocusState != FocusState.Unfocused);
        tb.GotFocus += (_, _) => ApplyBorder(true);
        tb.LostFocus += (_, _) => ApplyBorder(false);
        tb.TextChanging += (_, _) => ApplyBorder(tb.FocusState != FocusState.Unfocused);
    }

    private static SolidColorBrush Brush(byte a, byte r, byte g, byte b)
        => new(ColorHelper.FromArgb(a, r, g, b));

    [DllImport("user32.dll")]
    private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    private const int SW_MINIMIZE = 6;
    private const int SW_MAXIMIZE = 3;
    private const int SW_RESTORE = 9;

    private void InitializeWindowInterop()
    {
        var hwnd = WindowNative.GetWindowHandle(this);
        var windowId = Microsoft.UI.Win32Interop.GetWindowIdFromWindow(hwnd);
        _appWindow = AppWindow.GetFromWindowId(windowId);

        try
        {
            var iconPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Assets", "app_icon.ico");
            if (File.Exists(iconPath))
            {
                _appWindow?.SetIcon(iconPath);
            }
        }
        catch
        {
            // non-fatal
        }
    }

    private void MainWindow_Activated(object sender, WindowActivatedEventArgs args)
    {
        if (_windowPlacementRestored) return;
        _windowPlacementRestored = true;
        TryRestoreWindowPlacement();
    }

    private void MainWindow_Closed(object sender, WindowEventArgs args)
    {
        TrySaveWindowPlacement();
    }

    private void TryRestoreWindowPlacement()
    {
        try
        {
            if (_appWindow is null) return;
            if (!File.Exists(WindowPlacementFilePath)) return;

            var json = File.ReadAllText(WindowPlacementFilePath);
            var state = JsonSerializer.Deserialize<SavedWindowPlacement>(json);
            if (state is null) return;

            var width = Math.Max(800, state.Width);
            var height = Math.Max(600, state.Height);

            _appWindow.MoveAndResize(new RectInt32(state.X, state.Y, width, height));

            if (state.IsMaximized && _appWindow.Presenter is OverlappedPresenter presenter)
            {
                presenter.Maximize();
            }
        }
        catch
        {
            // non-fatal
        }
    }

    private void TrySaveWindowPlacement()
    {
        try
        {
            if (_appWindow is null) return;

            var state = new SavedWindowPlacement
            {
                X = _appWindow.Position.X,
                Y = _appWindow.Position.Y,
                Width = _appWindow.Size.Width,
                Height = _appWindow.Size.Height,
                IsMaximized = _appWindow.Presenter is OverlappedPresenter p && p.State == OverlappedPresenterState.Maximized
            };

            var dir = Path.GetDirectoryName(WindowPlacementFilePath);
            if (!string.IsNullOrWhiteSpace(dir))
                Directory.CreateDirectory(dir);

            var json = JsonSerializer.Serialize(state, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(WindowPlacementFilePath, json);
        }
        catch
        {
            // non-fatal
        }
    }


    private AppWindow? GetCurrentAppWindow()
    {
        try
        {
            var hwnd = WindowNative.GetWindowHandle(this);
            if (hwnd == IntPtr.Zero) return null;
            var windowId = Microsoft.UI.Win32Interop.GetWindowIdFromWindow(hwnd);
            return AppWindow.GetFromWindowId(windowId);
        }
        catch
        {
            return null;
        }
    }

}