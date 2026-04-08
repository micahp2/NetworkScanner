namespace NetworkScanner;

using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.IO;
using System.Linq;
using System.ComponentModel;
using System.Collections.ObjectModel;
using NetworkScanner.Models;
using NetworkScanner.Services;
using Microsoft.Win32;

public partial class MainWindow : Window
{
    private readonly NetworkScannerService _scannerService;
    private readonly DatabaseService _dbService;
    private readonly ObservableCollection<ScanResult> _results;
    private readonly HashSet<string> _resultIPIndex = new();

    // Search state
    private List<ScanResult> _searchMatches = new();
    private int _searchIndex = -1;
    private string _searchTerm = "";

    public MainWindow()
    {
        InitializeComponent();

        _dbService = new DatabaseService();
        _ = _dbService.InitializeAsync();

        _scannerService = new NetworkScannerService(_dbService);
        _results        = new ObservableCollection<ScanResult>();
        ResultsGrid.ItemsSource = _results;

        _scannerService.HostFound     += (_, r) => Dispatcher.Invoke(() => AddResultToGrid(r));
        _scannerService.StatusChanged += (_, s) => Dispatcher.Invoke(() => UpdateStatus(s));
        _scannerService.ScanCompleted += (_, _) => Dispatcher.Invoke(OnScanCompleted);

        _ = LoadCachedDevicesAsync();

        // Ctrl+F opens the find popup
        InputBindings.Add(new KeyBinding(
            new RelayCommand(_ => OpenFindPopup()),
            new KeyGesture(Key.F, ModifierKeys.Control)));

        // Build context menu dynamically when it opens so it always reflects
        // the currently selected row
        ResultsGrid.ContextMenuOpening += ResultsGrid_ContextMenuOpening;
        ResultsGrid.ContextMenu = new ContextMenu(); // placeholder — rebuilt on open

        // Close the find popup when the user clicks anywhere outside it.
        // We use PreviewMouseDown on the Window (tunnels before any element
        // handles it) so the click still reaches the DataGrid normally —
        // no mouse capture, no scroll blocking.
        PreviewMouseDown += (_, e) =>
        {
            if (!FindPopup.IsOpen) return;
            // Hit-test: is the click inside the popup's visual tree?
            if (FindPopup.Child is Visual popupRoot &&
                e.OriginalSource is DependencyObject src &&
                popupRoot.IsAncestorOf(src))
                return; // click was inside — keep popup open
            // Click was outside — close it
            FindPopup.IsOpen = false;
        };

        // Pre-fill ports
        PortsText.Text = "80";

        // Set version from assembly, fall back to csproj literal
        var ver = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version;
        VersionText.Text = ver != null ? $"v{ver.Major}.{ver.Minor}.{ver.Build}" : "v1.0.2";

        AutoDetectNetworkRange();
    }

    // ── Port parsing ─────────────────────────────────────────────────────────

    private static List<int> ParsePorts(string input)
    {
        var ports = new HashSet<int>();
        if (string.IsNullOrWhiteSpace(input)) return new();

        foreach (var item in input.Split(','))
        {
            var t = item.Trim();
            if (t.Contains('-'))
            {
                var p = t.Split('-');
                if (p.Length == 2 &&
                    int.TryParse(p[0].Trim(), out int s) &&
                    int.TryParse(p[1].Trim(), out int e))
                    for (int i = s; i <= e; i++)
                        if (i is >= 1 and <= 65535) ports.Add(i);
            }
            else if (int.TryParse(t, out int port) && port is >= 1 and <= 65535)
                ports.Add(port);
        }
        return ports.OrderBy(p => p).ToList();
    }

    // ── Network range auto-detect ─────────────────────────────────────────────

    private void AutoDetectNetworkRange()
    {
        try
        {
            var nics = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces();
            foreach (var nic in nics)
            {
                if (nic.OperationalStatus != System.Net.NetworkInformation.OperationalStatus.Up) continue;
                if (nic.NetworkInterfaceType != System.Net.NetworkInformation.NetworkInterfaceType.Ethernet &&
                    nic.NetworkInterfaceType != System.Net.NetworkInformation.NetworkInterfaceType.Wireless80211) continue;

                foreach (var uni in nic.GetIPProperties().UnicastAddresses)
                {
                    if (uni.Address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) continue;
                    var parts = uni.Address.ToString().Split('.');
                    if (parts.Length != 4) continue;
                    if (parts[0] == "169" && parts[1] == "254") continue; // skip APIPA/Tailscale
                    if (parts[0] == "127") continue;

                    RangesText.Text = $"{parts[0]}.{parts[1]}.{parts[2]}.0/24";
                    return;
                }
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"AutoDetect: {ex.Message}");
        }
    }

    // ── Button handlers ───────────────────────────────────────────────────────

    private async Task LoadCachedDevicesAsync()
    {
        try
        {
            var devices = await _dbService.GetAllDevicesAsync();
            int loaded = 0;

            foreach (var d in devices)
            {
                if (string.IsNullOrWhiteSpace(d.IPAddress)) continue;
                d.IsCached = true;

                if (_resultIPIndex.Add(d.IPAddress))
                {
                    _results.Add(d);
                    loaded++;
                }
            }

            if (loaded > 0)
                UpdateStatus($"Loaded {loaded} cached device(s)");
        }
        catch
        {
            // non-fatal startup cache load
        }
    }
    private void StartButton_Click(object sender, RoutedEventArgs e)
    {
        if (_scannerService.IsScanning)
        {
            _scannerService.StopScan();
            StartButton.Content   = "▶  Scan";
            StartButton.IsEnabled = true;
            App.PlayScanStopped();
            return;
        }

        // Split on commas AND newlines so users can enter multiple ranges either way:
        //   "192.168.2.0/24, 192.168.4.0/24"  (comma-separated on one line)
        //   or one range per line
        var ranges = RangesText.Text
            .Split(new[] { ",", "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries)
            .Select(r => r.Trim()).Where(r => r.Length > 0).ToList();

        if (ranges.Count == 0)
        {
            MessageBox.Show("Please enter an IP range.\n\nExamples:\n  192.168.1.0/24\n  192.168.1.1-254",
                "No Range", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var ports = ParsePorts(PortsText.Text);
        if (ports.Count == 0)
        {
            MessageBox.Show("Please enter at least one port.\n\nExamples:\n  80\n  22,80,443\n  8080-8090",
                "No Ports", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        ClearSearch();

        foreach (var r in _results)
        {
            r.IsOnline = false;
            r.IsCached = true;
        }

        StartButton.IsEnabled = false;
        StartButton.Content   = "⏹  Stop";
        Dispatcher.InvokeAsync(async () => { await Task.Delay(300); StartButton.IsEnabled = true; });

        _ = _scannerService.StartScanAsync(new ScanOptions
        {
            IPRanges     = ranges,
            Ports        = ports,
            ResolveDNS   = true,
            LookupMAC    = true,
            LookupVendor = true,
            ScanIPv4     = true,
            ScanIPv6     = false,
        });
    }

    private void ClearButton_Click(object sender, RoutedEventArgs e)
    {
        _results.Clear();
        _resultIPIndex.Clear();
        ClearSearch();
        UpdateStatus("Ready");
    }

    private void ExportButton_Click(object sender, RoutedEventArgs e)
    {
        if (_results.Count == 0)
        {
            MessageBox.Show("No results to export.", "Export",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var dlg = new SaveFileDialog
        {
            Filter     = "CSV files|*.csv|All files|*.*",
            DefaultExt = "csv",
            FileName   = $"scan-{DateTime.Now:yyyyMMdd-HHmmss}",
        };

        if (dlg.ShowDialog() != true) return;

        try
        {
            static string Esc(string? v) =>
                v is null ? "\"\"" : "\"" + v.Replace("\"", "\"\"") + "\"";

            using var w = new StreamWriter(dlg.FileName);
            w.WriteLine("IP Address,Hostname,MAC Address,Vendor,Open Ports,IPv6 Address");
            foreach (var r in _results)
                w.WriteLine($"{Esc(r.IPAddress)},{Esc(r.Hostname)},{Esc(r.MACAddress)}," +
                            $"{Esc(r.Vendor)},{Esc(string.Join("; ", r.OpenPorts))},{Esc(r.IPv6Address)}");

            MessageBox.Show($"Exported {_results.Count} results to {Path.GetFileName(dlg.FileName)}.",
                "Export Complete");
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Export failed: {ex.Message}", "Error",
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    // ── Grid management ───────────────────────────────────────────────────────

    private void AddResultToGrid(ScanResult result)
    {
        result.IsOnline = result.IsResponsive;
        result.IsCached = false;

        if (_resultIPIndex.Add(result.IPAddress))
        {
            _results.Add(result);
            UpdateStatus($"Found {_results.Count} device(s)");
            // If a search is active, check whether this new row matches
            if (!string.IsNullOrEmpty(SearchBox.Text))
                RefreshSearchHighlights();
        }
        else
        {
            // In-place update for late-arriving fields (e.g. IPv6, vendor)
            var existing = _results.FirstOrDefault(r => r.IPAddress == result.IPAddress);
            if (existing != null)
            {
                existing.IsOnline = result.IsResponsive;
                existing.IsCached = false;

                if (result.IPv6Address != null && existing.IPv6Address == null)
                    existing.IPv6Address = result.IPv6Address;
                if (result.Vendor != null && existing.Vendor == null)
                    existing.Vendor = result.Vendor;
            }
        }
    }

    private void UpdateStatus(string status) => StatusText.Text = status;

    private void OnScanCompleted()
    {
        StartButton.Content   = "▶  Scan";
        StartButton.IsEnabled = true;
                UpdateStatus($"Scan complete - {_results.Count} active host(s)");
        App.PlayScanComplete();
    }

    // ── Context menu ──────────────────────────────────────────────────────────
    //
    //  Copy  ▶  IP Address       — copies that field to clipboard
    //           Hostname
    //           MAC Address
    //           Vendor
    //           Open Ports
    //           IPv6 Address
    //
    //  Browse ▶  :80             — opens http://ip:port in default browser
    //            :443              (https for 443/8443, http otherwise)
    //            :8080
    //
    //  Shell  ▶  SSH :22         — opens ssh user@ip in Windows Terminal / PowerShell
    //            RDP :3389         (mstsc /v:ip for 3389)
    //            :port             (generic: opens WT with the address copied)

    private void ResultsGrid_ContextMenuOpening(object sender, ContextMenuEventArgs e)
    {
        var row = (ResultsGrid.SelectedItem as ScanResult)
               ?? _results.FirstOrDefault();

        var menu = ResultsGrid.ContextMenu!;
        menu.Items.Clear();

        if (row == null)
        {
            e.Handled = true; // nothing selected — suppress menu
            return;
        }

        // ── Copy submenu ─────────────────────────────────────────────────────
        var copy = new MenuItem { Header = "Copy" };
        AddCopyItem(copy, "IP Address",   row.IPAddress);
        AddCopyItem(copy, "Hostname",     row.Hostname);
        AddCopyItem(copy, "MAC Address",  row.MACAddress);
        AddCopyItem(copy, "Vendor",       row.Vendor);
        AddCopyItem(copy, "Open Ports",   row.OpenPortsString);
        AddCopyItem(copy, "IPv6 Address", row.IPv6Address);
        menu.Items.Add(copy);

        // ── Browse submenu ───────────────────────────────────────────────────
        if (row.OpenPorts.Count > 0)
        {
            var browse = new MenuItem { Header = "Browse" };
            foreach (var port in row.OpenPorts)
            {
                // Use https for well-known TLS ports, http otherwise
                var scheme = port is 443 or 8443 or 9443 ? "https" : "http";
                var url    = $"{scheme}://{row.IPAddress}:{port}";
                var item   = new MenuItem { Header = $":{port}  ({scheme})", Tag = url };
                item.Click += (_, _) => OpenUrl((string)((MenuItem)item).Tag);
                browse.Items.Add(item);
            }
            menu.Items.Add(browse);
        }

        // ── Shell submenu ────────────────────────────────────────────────────
        if (row.OpenPorts.Count > 0 || !string.IsNullOrEmpty(row.IPAddress))
        {
            var shell = new MenuItem { Header = "Shell" };

            // SSH (port 22)
            if (row.OpenPorts.Contains(22))
            {
                var ssh = new MenuItem { Header = $"SSH  ({row.IPAddress}:22)" };
                ssh.Click += (_, _) => OpenShell("ssh", row.IPAddress, 22);
                shell.Items.Add(ssh);
            }

            // RDP (port 3389)
            if (row.OpenPorts.Contains(3389))
            {
                var rdp = new MenuItem { Header = $"RDP  ({row.IPAddress}:3389)" };
                rdp.Click += (_, _) => OpenRdp(row.IPAddress);
                shell.Items.Add(rdp);
            }

            // All other open ports as generic terminal entries
            var otherPorts = row.OpenPorts.Where(p => p is not 22 and not 3389);
            if (otherPorts.Any() && shell.Items.Count > 0)
                shell.Items.Add(new Separator());

            foreach (var port in otherPorts)
            {
                var p    = port; // capture
                var item = new MenuItem { Header = $":{p}  ({row.IPAddress}:{p})" };
                item.Click += (_, _) => OpenShell(null, row.IPAddress, p);
                shell.Items.Add(item);
            }

            // Even with no open ports, offer a bare terminal to the IP
            if (shell.Items.Count == 0)
            {
                var bare = new MenuItem { Header = $"Terminal → {row.IPAddress}" };
                bare.Click += (_, _) => OpenShell(null, row.IPAddress, 0);
                shell.Items.Add(bare);
            }

            menu.Items.Add(shell);
        }
    }

    private static void AddCopyItem(MenuItem parent, string label, string? value)
    {
        var item = new MenuItem
        {
            Header    = label,
            IsEnabled = !string.IsNullOrEmpty(value),
        };
        item.Click += (_, _) =>
        {
            try { Clipboard.SetText(value ?? ""); }
            catch { /* clipboard may be locked */ }
        };
        parent.Items.Add(item);
    }

    private void VersionLink_RequestNavigate(object sender,
        System.Windows.Navigation.RequestNavigateEventArgs e)
    {
        OpenUrl(e.Uri.AbsoluteUri);
        e.Handled = true;
    }

    private static void OpenUrl(string url)
    {
        try { Process.Start(new ProcessStartInfo(url) { UseShellExecute = true }); }
        catch (Exception ex) { MessageBox.Show($"Could not open browser:\n{ex.Message}"); }
    }

    private static void OpenRdp(string ip)
    {
        try { Process.Start(new ProcessStartInfo("mstsc", $"/v:{ip}") { UseShellExecute = true }); }
        catch (Exception ex) { MessageBox.Show($"Could not open RDP:\n{ex.Message}"); }
    }

    private static void OpenShell(string? protocol, string ip, int port)
    {
        try
        {
            // Build the command string
            string cmd = protocol switch
            {
                "ssh" => $"ssh {ip}",
                _     => port > 0 ? $"# {ip}:{port}" : $"# {ip}",
            };

            // Try Windows Terminal first, fall back to PowerShell
            if (TryLaunch("wt.exe", $"new-tab -- powershell -NoExit -Command \"{cmd}\"")) return;
            if (TryLaunch("powershell.exe", $"-NoExit -Command \"{cmd}\"")) return;
            TryLaunch("cmd.exe", $"/k echo {cmd}");
        }
        catch (Exception ex) { MessageBox.Show($"Could not open shell:\n{ex.Message}"); }
    }

    private static bool TryLaunch(string exe, string args)
    {
        try
        {
            Process.Start(new ProcessStartInfo(exe, args) { UseShellExecute = true });
            return true;
        }
        catch { return false; }
    }

    // ── Find button / popup ───────────────────────────────────────────────────

    private void FindButton_Click(object sender, RoutedEventArgs e) => OpenFindPopup();

    private void OpenFindPopup()
    {
        FindPopup.IsOpen = true;
        SearchBox.Focus();
        SearchBox.SelectAll();
    }

    // ── Search / Find ─────────────────────────────────────────────────────────
    // Searches across IP, Hostname, MAC, Vendor, IPv6, Ports (all columns).
    // Matching rows get a subtle blue tint via the IsSearchMatch property.
    // Enter / ↓ button = next match. Shift+Enter / ↑ button = previous match.

    private void SearchBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        RefreshSearchHighlights();
        if (_searchMatches.Count > 0)
            NavigateToMatch(0);
        else
            SearchStatus.Text = _searchMatches.Count == 0 && SearchBox.Text.Length > 0
                ? "No matches" : "";
    }

    private void SearchBox_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
        {
            if (Keyboard.Modifiers.HasFlag(ModifierKeys.Shift))
                SearchPrev_Click(sender, e);
            else
                SearchNext_Click(sender, e);
            e.Handled = true;
        }
        else if (e.Key == Key.Escape)
        {
            FindPopup.IsOpen = false;
            e.Handled = true;
        }
    }

    private void SearchNext_Click(object sender, RoutedEventArgs e)
    {
        if (_searchMatches.Count == 0) return;
        NavigateToMatch((_searchIndex + 1) % _searchMatches.Count);
    }

    private void SearchPrev_Click(object sender, RoutedEventArgs e)
    {
        if (_searchMatches.Count == 0) return;
        NavigateToMatch((_searchIndex - 1 + _searchMatches.Count) % _searchMatches.Count);
    }

    private void RefreshSearchHighlights()
    {
        var term = SearchBox.Text.Trim();

        // Clear all highlights
        foreach (var r in _results)
            r.IsSearchMatch = false;
        _searchMatches.Clear();
        _searchIndex = -1;

        if (string.IsNullOrEmpty(term))
        {
            _searchTerm = "";
            foreach (var r in _results) r.SearchTerm = "";
            SearchStatus.Text = "";
            return;
        }

        _searchTerm = term;

        // Case-insensitive substring match across all visible fields
        foreach (var r in _results)
        {
            if (RowMatchesTerm(r, term))
            {
                r.IsSearchMatch = true;
                r.SearchTerm    = term;   // drives per-cell highlight
                _searchMatches.Add(r);
            }
            else
            {
                r.SearchTerm = "";
            }
        }

        SearchStatus.Text = _searchMatches.Count switch
        {
            0 => "No matches",
            1 => "1 match",
            _ => $"{_searchMatches.Count} matches",
        };
    }

    private static bool RowMatchesTerm(ScanResult r, string term)
    {
        var ci = StringComparison.OrdinalIgnoreCase;
        return (r.IPAddress?.Contains(term, ci)      == true) ||
               (r.Hostname?.Contains(term, ci)       == true) ||
               (r.MACAddress?.Contains(term, ci)     == true) ||
               (r.Vendor?.Contains(term, ci)         == true) ||
               (r.IPv6Address?.Contains(term, ci)    == true) ||
               (r.OpenPortsString?.Contains(term, ci) == true);
    }

    private void NavigateToMatch(int index)
    {
        if (_searchMatches.Count == 0) return;
        _searchIndex = index;
        var target = _searchMatches[_searchIndex];

        // Scroll and select the target row
        ResultsGrid.ScrollIntoView(target);
        ResultsGrid.SelectedItem = target;

        SearchStatus.Text = $"{_searchIndex + 1} / {_searchMatches.Count}";
    }

    private void ClearSearch()
    {
        _searchTerm = "";
        foreach (var r in _results) { r.IsSearchMatch = false; r.SearchTerm = ""; }
        _searchMatches.Clear();
        _searchIndex  = -1;
        SearchStatus.Text = "";
    }

    // ── Sorting ───────────────────────────────────────────────────────────────
    // We handle ALL column sorts manually so that the DataGrid's built-in
    // ICollectionView sort never runs. Mixing the two causes the sort state
    // to desync after switching columns, making subsequent sorts go haywire.

    private void ResultsGrid_Sorting(object sender, DataGridSortingEventArgs e)
    {
        // Always take full control — never let DataGrid sort the collection itself
        e.Handled = true;

        var header = e.Column.SortMemberPath ?? e.Column.Header?.ToString() ?? "";
        var asc    = e.Column.SortDirection != ListSortDirection.Ascending;

        try
        {
            List<ScanResult> sorted;

            if (header == "IPAddress")
            {
                // Numeric IP sort
                var comparer = new ByteArrayComparer();
                sorted = asc
                    ? _results.OrderBy(r =>
                          System.Net.IPAddress.TryParse(r.IPAddress, out var a)
                              ? a.GetAddressBytes() : Array.Empty<byte>(), comparer).ToList()
                    : _results.OrderByDescending(r =>
                          System.Net.IPAddress.TryParse(r.IPAddress, out var a)
                              ? a.GetAddressBytes() : Array.Empty<byte>(), comparer).ToList();
            }
            else
            {
                // Alphabetic sort on whatever property SortMemberPath points to
                sorted = asc
                    ? _results.OrderBy(r => GetSortKey(r, header),
                          StringComparer.OrdinalIgnoreCase).ToList()
                    : _results.OrderByDescending(r => GetSortKey(r, header),
                          StringComparer.OrdinalIgnoreCase).ToList();
            }

            // Update the collection in-place
            _results.Clear();
            foreach (var r in sorted) _results.Add(r);

            // Update sort-arrow indicators: show only on the clicked column
            foreach (var col in ResultsGrid.Columns)
                col.SortDirection = col == e.Column
                    ? (asc ? ListSortDirection.Ascending : ListSortDirection.Descending)
                    : (ListSortDirection?)null;

            // Re-apply search highlights after sort
            if (!string.IsNullOrEmpty(_searchTerm))
                RefreshSearchHighlights();
        }
        catch { /* ignore */ }
    }

    private static string GetSortKey(ScanResult r, string memberPath) => memberPath switch
    {
        "IPAddress"       => r.IPAddress       ?? "",
        "Hostname"        => r.Hostname        ?? "",
        "MACAddress"      => r.MACAddress      ?? "",
        "Vendor"          => r.Vendor          ?? "",
        "OpenPortsString" => r.OpenPortsString ?? "",
        "IPv6Address"     => r.IPv6Address     ?? "",
        "CustomName"      => r.CustomName      ?? "",
        "IsOnline"        => r.IsOnline ? "1" : "0",
        "IsCached"        => r.IsCached ? "1" : "0",
        "FirstSeen"       => r.FirstSeen?.ToString("O") ?? "",
        "LastSeen"        => r.LastSeen?.ToString("O") ?? "",
        _                 => r.IPAddress       ?? "",
    };

    // Simple ICommand wrapper for InputBindings
    private sealed class RelayCommand(Action<object?> execute) : System.Windows.Input.ICommand
    {
        public event EventHandler? CanExecuteChanged { add { } remove { } }
        public bool CanExecute(object? p) => true;
        public void Execute(object? p) => execute(p);
    }

    private sealed class ByteArrayComparer : IComparer<byte[]>
    {
        public int Compare(byte[]? x, byte[]? y)
        {
            if (x is null || y is null) return 0;
            for (int i = 0; i < Math.Min(x.Length, y.Length); i++)
            {
                int c = x[i].CompareTo(y[i]);
                if (c != 0) return c;
            }
            return x.Length.CompareTo(y.Length);
        }
    }
}

/// <summary>
/// A TextBlock that highlights occurrences of SearchTerm within its Text
/// by splitting the text into alternating normal/highlighted Runs.
/// The highlight colour is a bright yellow-orange that is readable on both
/// dark and light backgrounds (#FFB300 background, black foreground).
/// </summary>
public class HighlightTextBlock : TextBlock
{
    public static readonly DependencyProperty SearchTermProperty =
        DependencyProperty.Register(nameof(SearchTerm), typeof(string),
            typeof(HighlightTextBlock),
            new FrameworkPropertyMetadata(string.Empty, OnSearchTermChanged));

    public string SearchTerm
    {
        get => (string)GetValue(SearchTermProperty);
        set => SetValue(SearchTermProperty, value);
    }

    // Rebind Text property so we can observe it too
    public new static readonly DependencyProperty TextProperty =
        DependencyProperty.Register(nameof(Text), typeof(string),
            typeof(HighlightTextBlock),
            new FrameworkPropertyMetadata(string.Empty, OnSearchTermChanged));

    public new string? Text
    {
        get => (string?)GetValue(TextProperty);
        set => SetValue(TextProperty, value);
    }

    private static void OnSearchTermChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
        => ((HighlightTextBlock)d).UpdateInlines();

    private static readonly Brush HighlightBg = new SolidColorBrush(Color.FromRgb(0xFF, 0xB3, 0x00)); // amber
    private static readonly Brush HighlightFg = Brushes.Black;

    private void UpdateInlines()
    {
        Inlines.Clear();
        var text = Text ?? string.Empty;
        var term = SearchTerm ?? string.Empty;

        if (string.IsNullOrEmpty(term) || string.IsNullOrEmpty(text))
        {
            Inlines.Add(new Run(text));
            return;
        }

        int pos = 0;
        while (pos < text.Length)
        {
            int idx = text.IndexOf(term, pos, StringComparison.OrdinalIgnoreCase);
            if (idx < 0)
            {
                Inlines.Add(new Run(text[pos..]));
                break;
            }
            if (idx > pos)
                Inlines.Add(new Run(text[pos..idx]));

            // Highlighted run — keep the original casing from the source text
            var hi = new Run(text.Substring(idx, term.Length))
            {
                Background = HighlightBg,
                Foreground = HighlightFg,
                FontWeight = FontWeights.SemiBold,
            };
            Inlines.Add(hi);
            pos = idx + term.Length;
        }
    }
}