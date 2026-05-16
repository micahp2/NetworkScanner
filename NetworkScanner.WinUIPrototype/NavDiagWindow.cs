using System;
using System.Collections.Generic;
using System.IO;
using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using NetworkScanner.WinUIPrototype.Pages;

namespace NetworkScanner.WinUIPrototype;

public sealed class NavDiagWindow : Window
{
    private readonly int _level;
    private readonly string _logPath;

    public NavDiagWindow()
    {
        _level = ParseLevel(Environment.GetEnvironmentVariable("NS_NAV_DIAG_LEVEL"));
        _logPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "NetworkScanner.WinUIPrototype",
            "nav-diag.log");

        Log($"Ctor.Start level={_level}");

        Title = $"NavigationView Diagnostics (L{_level})";

        var root = new Grid
        {
            Background = Brush(0xFF, 0x0E, 0x0F, 0x11)
        };

        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });

        var info = new Border
        {
            Margin = new Thickness(10, 10, 10, 8),
            Padding = new Thickness(10, 8, 10, 8),
            CornerRadius = new CornerRadius(8),
            BorderThickness = new Thickness(1),
            BorderBrush = Brush(0xFF, 0x2A, 0x2A, 0x2F),
            Background = Brush(0xFF, 0x15, 0x15, 0x17),
            Child = new TextBlock
            {
                Text = $"NavigationView diagnostic mode active. Level={_level}.\nLevels 0-8 = prior sweep, 9-13 = ScannerPage bisect.",
                Foreground = Brush(0xFF, 0xF2, 0xF2, 0xF4),
                TextWrapping = TextWrapping.Wrap
            }
        };
        Grid.SetRow(info, 0);
        root.Children.Add(info);

        FrameworkElement host = _level switch
        {
            0 => BuildLevel0Host(),
            <= 8 => BuildBaselineNav(_level),
            _ => BuildScannerBisectNav(_level)
        };

        Grid.SetRow(host, 1);
        root.Children.Add(host);

        Content = root;

        Activated += (_, _) => Log("Window.Activated");
        Closed += (_, _) => Log("Window.Closed");

        Log("Ctor.End");
    }

    private FrameworkElement BuildLevel0Host()
    {
        Log("Build.Level0.NoNavigationView");
        return new Border
        {
            Margin = new Thickness(10, 0, 10, 10),
            Background = Brush(0xFF, 0x12, 0x13, 0x16),
            CornerRadius = new CornerRadius(10),
            BorderBrush = Brush(0xFF, 0x2A, 0x2A, 0x2F),
            BorderThickness = new Thickness(1),
            Child = new TextBlock
            {
                Text = "Level 0: no NavigationView in visual tree.",
                Margin = new Thickness(12),
                Foreground = Brush(0xFF, 0xB6, 0xB7, 0xBB)
            }
        };
    }

    // Original cumulative sweep (kept for reference)
    private FrameworkElement BuildBaselineNav(int level)
    {
        Log($"BuildNav.Start level={level}");

        var nav = CreateBaseNav();

        if (level >= 2)
        {
            nav.PaneDisplayMode = NavigationViewPaneDisplayMode.Left;
            nav.IsPaneOpen = true;
            Log("BuildNav.L2.LeftMode");

            AddItems(nav, useFontIcon: false);
            Log("BuildNav.L2.MenuItemsAdded.SymbolIcon");
        }

        if (level >= 3)
        {
            AddFooterItems(nav, useFontIcon: false);
            Log("BuildNav.L3.FooterItemsAdded.SymbolIcon");
        }

        if (level >= 4)
        {
            nav.PaneDisplayMode = NavigationViewPaneDisplayMode.LeftCompact;
            nav.IsPaneOpen = true;
            nav.OpenPaneLength = 220;
            nav.CompactPaneLength = 64;
            nav.IsPaneToggleButtonVisible = true;
            Log("BuildNav.L4.LeftCompact");
        }

        if (level >= 5)
        {
            nav.Content = PlaceholderContent("Diagnostic content host");
            Log("BuildNav.L5.ContentAssigned");
        }

        if (level >= 6)
        {
            nav.MenuItems.Clear();
            nav.FooterMenuItems.Clear();
            AddItems(nav, useFontIcon: true);
            AddFooterItems(nav, useFontIcon: true);
            Log("BuildNav.L6.ReplacedItemsWithFontIcon");
        }

        if (level >= 7)
        {
            nav.Resources["NavigationViewExpandedPaneBackground"] = Brush(0xFF, 0x12, 0x13, 0x16);
            nav.Resources["NavigationViewDefaultPaneBackground"] = Brush(0xFF, 0x12, 0x13, 0x16);
            nav.Resources["NavigationViewTopPaneBackground"] = Brush(0xFF, 0x12, 0x13, 0x16);
            Log("BuildNav.L7.ResourcesApplied");
        }

        if (level >= 8)
        {
            nav.Loaded += (_, _) =>
            {
                try
                {
                    if (nav.MenuItems.Count > 0)
                    {
                        nav.SelectedItem = nav.MenuItems[0];
                        Log("BuildNav.L8.SelectedItemAssignedOnLoaded");
                    }
                }
                catch (Exception ex)
                {
                    Log("BuildNav.L8.SelectedItemAssignFailed", ex);
                }
            };
        }

        Log("BuildNav.End");
        return nav;
    }

    // ScannerPage-focused bisect
    // L9: Left + Symbol items + ScannerPage (direct Page content)
    // L10: add LeftCompact pane behavior
    // L11: switch to FontIcon items
    // L12: apply nav resources
    // L13: assign SelectedItem on Loaded
    // L14: Frame assigned as NavigationView content (no navigation)
    // L15: Frame.Navigate(typeof(DetailsPage))
    // L16: Frame.Navigate(typeof(ScannerPage))
    private FrameworkElement BuildScannerBisectNav(int level)
    {
        Log($"BuildNavBisect.Start level={level}");

        var nav = CreateBaseNav();

        nav.PaneDisplayMode = NavigationViewPaneDisplayMode.Left;
        nav.IsPaneOpen = true;
        Log("BuildNavBisect.L9.LeftMode");

        AddItems(nav, useFontIcon: false);
        AddFooterItems(nav, useFontIcon: false);
        Log("BuildNavBisect.L9.Items.SymbolIcon");

        var scannerSafe = string.Equals(Environment.GetEnvironmentVariable("NS_SCANNER_SAFE"), "1", StringComparison.OrdinalIgnoreCase);

        Frame? frame = null;

        if (level >= 14)
        {
            frame = new Frame();
            nav.Content = frame;
            Log($"BuildNavBisect.L14.FrameAssigned safe={scannerSafe}");
        }
        else
        {
            nav.Content = new ScannerPage();
            Log($"BuildNavBisect.L9.ScannerPageAssigned safe={scannerSafe}");
        }

        if (level >= 15 && frame is not null)
        {
            try
            {
                frame.Navigate(typeof(DetailsPage));
                Log("BuildNavBisect.L15.FrameNavigated.DetailsPage");
            }
            catch (Exception ex)
            {
                Log("BuildNavBisect.L15.FrameNavigateFailed.DetailsPage", ex);
            }
        }

        if (level >= 16 && frame is not null)
        {
            try
            {
                frame.Navigate(typeof(ScannerPage));
                Log("BuildNavBisect.L16.FrameNavigated.ScannerPage");
            }
            catch (Exception ex)
            {
                Log("BuildNavBisect.L16.FrameNavigateFailed.ScannerPage", ex);
            }
        }

        if (level >= 10)
        {
            nav.PaneDisplayMode = NavigationViewPaneDisplayMode.LeftCompact;
            nav.IsPaneOpen = true;
            nav.OpenPaneLength = 220;
            nav.CompactPaneLength = 64;
            nav.IsPaneToggleButtonVisible = true;
            Log("BuildNavBisect.L10.LeftCompact");
        }

        if (level >= 11)
        {
            nav.MenuItems.Clear();
            nav.FooterMenuItems.Clear();
            AddItems(nav, useFontIcon: true);
            AddFooterItems(nav, useFontIcon: true);
            Log("BuildNavBisect.L11.Items.FontIcon");
        }

        if (level >= 12)
        {
            nav.Resources["NavigationViewExpandedPaneBackground"] = Brush(0xFF, 0x12, 0x13, 0x16);
            nav.Resources["NavigationViewDefaultPaneBackground"] = Brush(0xFF, 0x12, 0x13, 0x16);
            nav.Resources["NavigationViewTopPaneBackground"] = Brush(0xFF, 0x12, 0x13, 0x16);
            Log("BuildNavBisect.L12.ResourcesApplied");
        }

        if (level >= 13)
        {
            nav.Loaded += (_, _) =>
            {
                try
                {
                    if (nav.MenuItems.Count > 0)
                    {
                        nav.SelectedItem = nav.MenuItems[0];
                        Log("BuildNavBisect.L13.SelectedItemAssignedOnLoaded");
                    }
                }
                catch (Exception ex)
                {
                    Log("BuildNavBisect.L13.SelectedItemAssignFailed", ex);
                }
            };
        }

        Log("BuildNavBisect.End");
        return nav;
    }

    private NavigationView CreateBaseNav()
    {
        var nav = new NavigationView
        {
            Margin = new Thickness(10, 0, 10, 10),
            IsBackButtonVisible = NavigationViewBackButtonVisible.Collapsed,
            IsSettingsVisible = false,
            AlwaysShowHeader = false,
            Background = Brush(0xFF, 0x0E, 0x0F, 0x11)
        };

        nav.Loaded += (_, _) => Log("Nav.Loaded");
        nav.DisplayModeChanged += (_, args) => Log($"Nav.DisplayModeChanged mode={args.DisplayMode}");
        nav.SelectionChanged += (_, args) =>
        {
            var tag = (args.SelectedItemContainer as NavigationViewItem)?.Tag?.ToString() ?? "<null>";
            Log($"Nav.SelectionChanged tag={tag}");
        };

        return nav;
    }

    private void AddItems(NavigationView nav, bool useFontIcon)
    {
        AddMenuItem(nav.MenuItems, "live", "Live Scan", useFontIcon);
        AddMenuItem(nav.MenuItems, "deep", "Deep Info", useFontIcon);
        AddMenuItem(nav.MenuItems, "history", "History", useFontIcon);
    }

    private void AddFooterItems(NavigationView nav, bool useFontIcon)
    {
        AddMenuItem(nav.FooterMenuItems, "about", "About", useFontIcon);
        AddMenuItem(nav.FooterMenuItems, "settings", "Settings", useFontIcon);
    }

    private static FrameworkElement PlaceholderContent(string text)
    {
        return new Border
        {
            Margin = new Thickness(12),
            Background = Brush(0xFF, 0x13, 0x14, 0x17),
            CornerRadius = new CornerRadius(8),
            BorderBrush = Brush(0xFF, 0x2A, 0x2A, 0x2F),
            BorderThickness = new Thickness(1),
            Child = new TextBlock
            {
                Text = text,
                Margin = new Thickness(12),
                Foreground = Brush(0xFF, 0xF2, 0xF2, 0xF4)
            }
        };
    }

    private void AddMenuItem(IList<object> collection, string key, string label, bool useFontIcon)
    {
        var item = new NavigationViewItem
        {
            Tag = key,
            Content = label
        };

        if (useFontIcon)
        {
            item.Icon = new FontIcon
            {
                Glyph = key switch
                {
                    "live" => "\uE721",
                    "deep" => "\uE722",
                    "history" => "\uE823",
                    "about" => "\uE897",
                    "settings" => "\uE713",
                    _ => "\uE10F"
                },
                FontFamily = new FontFamily("Segoe Fluent Icons"),
                FontSize = 16
            };
        }
        else
        {
            item.Icon = key switch
            {
                "live" => new SymbolIcon(Symbol.Refresh),
                "deep" => new SymbolIcon(Symbol.Find),
                "history" => new SymbolIcon(Symbol.Clock),
                "about" => new SymbolIcon(Symbol.Help),
                "settings" => new SymbolIcon(Symbol.Setting),
                _ => new SymbolIcon(Symbol.Page)
            };
        }

        collection.Add(item);
    }

    private static int ParseLevel(string? value)
    {
        if (int.TryParse(value, out var parsed))
        {
            return Math.Clamp(parsed, 0, 16);
        }

        return 0;
    }

    private void Log(string stage, Exception? ex = null)
    {
        try
        {
            var dir = Path.GetDirectoryName(_logPath);
            if (!string.IsNullOrWhiteSpace(dir))
            {
                Directory.CreateDirectory(dir);
            }

            var line = $"[{DateTime.Now:O}] {stage}";
            if (ex is not null)
            {
                line += "\n" + ex;
            }

            File.AppendAllText(_logPath, line + "\n\n");
        }
        catch
        {
            // ignore diagnostics write failures
        }
    }

    private static SolidColorBrush Brush(byte a, byte r, byte g, byte b)
        => new(ColorHelper.FromArgb(a, r, g, b));
}
