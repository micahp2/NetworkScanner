namespace NetworkScanner;

using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.IO;
using System.Linq;
using System.ComponentModel;
using NetworkScanner.Models;
using NetworkScanner.Services;
using Microsoft.Win32;

public partial class MainWindow : Window
{
    private NetworkScannerService _scannerService;
    private List<ScanResult> _results;

    public MainWindow()
    {
        InitializeComponent();
        
        _scannerService = new NetworkScannerService();
        _results = new List<ScanResult>();

        _scannerService.HostFound += (s, result) =>
        {
            this.Dispatcher.Invoke(() => AddResultToGrid(result));
        };

        _scannerService.StatusChanged += (s, status) =>
        {
            this.Dispatcher.Invoke(() => UpdateStatus(status));
        };

        _scannerService.ScanCompleted += (s, e) =>
        {
            this.Dispatcher.Invoke(() => ScanCompleted());
        };

        // Auto-detect and prefill network range
        AutoDetectNetworkRange();
    }

    private List<int> ParsePorts(string portInput)
    {
        var ports = new HashSet<int>();
        
        if (string.IsNullOrWhiteSpace(portInput))
            return new List<int>();

        // Split by comma for multiple entries
        foreach (var item in portInput.Split(','))
        {
            var trimmed = item.Trim();
            
            // Check if it's a range (e.g., "80-443")
            if (trimmed.Contains("-"))
            {
                var parts = trimmed.Split('-');
                if (parts.Length == 2 && 
                    int.TryParse(parts[0].Trim(), out int start) && 
                    int.TryParse(parts[1].Trim(), out int end))
                {
                    // Add all ports in range
                    for (int port = start; port <= end; port++)
                    {
                        if (port >= 1 && port <= 65535)
                            ports.Add(port);
                    }
                }
            }
            // Single port number
            else if (int.TryParse(trimmed, out int port))
            {
                if (port >= 1 && port <= 65535)
                    ports.Add(port);
            }
        }

        return ports.OrderBy(p => p).ToList();
    }

    private void AutoDetectNetworkRange()
    {
        try
        {
            var hostName = System.Net.Dns.GetHostName();
            var hostEntry = System.Net.Dns.GetHostEntry(hostName);
            
            foreach (var address in hostEntry.AddressList)
            {
                if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    var octets = address.ToString().Split('.');
                    if (octets.Length == 4)
                    {
                        // Assume /24 network (most common)
                        var networkRange = $"{octets[0]}.{octets[1]}.{octets[2]}.0/24";
                        RangesText.Text = networkRange;
                        System.Diagnostics.Debug.WriteLine($"Auto-detected network range: {networkRange}");
                        return;
                    }
                }
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"Error auto-detecting network: {ex.Message}");
        }
    }

    private void StartButton_Click(object sender, RoutedEventArgs e)
    {
        // If currently scanning, stop instead
        if (_scannerService != null && _scannerService.IsScanning)
        {
            _scannerService.StopScan();
            StartButton.Content = "▶ Start Scan";
            StartButton.IsEnabled = true;
            return;
        }

        var ranges = RangesText.Text
            .Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries)
            .ToList();

        if (ranges.Count == 0)
        {
            MessageBox.Show("Please enter at least one IP range");
            return;
        }

        var ports = ParsePorts(PortsText.Text);

        if (ports.Count == 0)
        {
            MessageBox.Show("Please enter at least one port (e.g., '80,443' or '80-443')");
            return;
        }

        var options = new ScanOptions
        {
            IPRanges = ranges,
            Ports = ports,
            ResolveDNS = DnsCheck.IsChecked ?? true,
            LookupMAC = MacCheck.IsChecked ?? true,
            LookupVendor = VendorCheck.IsChecked ?? true,
            ScanIPv4 = IPv4Check.IsChecked ?? true,
            ScanIPv6 = IPv6Check.IsChecked ?? true,
        };

        _results.Clear();
        ResultsGrid.ItemsSource = null;

        StartButton.Content = "⏹ Stop Scan";
        // Keep button enabled so user can click to stop
        _ = _scannerService.StartScanAsync(options);
    }

    private void ClearButton_Click(object sender, RoutedEventArgs e)
    {
        _results.Clear();
        ResultsGrid.ItemsSource = null;
    }

    private void ExportButton_Click(object sender, RoutedEventArgs e)
    {
        if (_results.Count == 0)
        {
            MessageBox.Show("No results to export");
            return;
        }

        var dialog = new SaveFileDialog
        {
            Filter = "CSV files|*.csv|All files|*.*",
            DefaultExt = "csv",
            FileName = $"scan-{DateTime.Now:yyyyMMdd-HHmmss}"
        };

        if (dialog.ShowDialog() == true)
        {
            try
            {
                ExportToCSV(dialog.FileName);
                MessageBox.Show($"Exported {_results.Count} results to {Path.GetFileName(dialog.FileName)}");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error exporting: {ex.Message}");
            }
        }
    }

    private void ExportToCSV(string filePath)
    {
        using (var writer = new StreamWriter(filePath))
        {
            writer.WriteLine("IP Address,IP Version,Hostname,MAC Address,Vendor,Open Ports");
            foreach (var result in _results)
            {
                var ports = string.Join("; ", result.OpenPorts);
                writer.WriteLine($"\"{result.IPAddress}\",\"{result.IPVersion}\",\"{result.Hostname ?? "N/A"}\",\"{result.MACAddress ?? "N/A"}\",\"{result.Vendor ?? "N/A"}\",\"{ports}\"");
            }
        }
    }

    private void AddResultToGrid(ScanResult result)
    {
        // Don't add duplicate IPs
        if (!_results.Any(r => r.IPAddress == result.IPAddress))
        {
            _results.Add(result);
            RefreshGrid();
            
            // Update status with actual count of results found
            UpdateStatus($"Found {_results.Count} active device(s)");
        }
    }

    private void RefreshGrid()
    {
        ResultsGrid.ItemsSource = null;
        ResultsGrid.ItemsSource = _results;
    }

    private void UpdateStatus(string status)
    {
        StatusText.Text = status;
    }

    private void ScanCompleted()
    {
        StartButton.Content = "▶ Start Scan";
        StartButton.IsEnabled = true;
        MessageBox.Show($"Scan complete! Found {_results.Count} active hosts.");
    }

    private void ResultsGrid_Sorting(object sender, DataGridSortingEventArgs e)
    {
        if (e.Column.Header.ToString() == "IP Address")
        {
            e.Handled = true;
            var direction = e.Column.SortDirection;
            
            try
            {
                if (direction == null || direction == ListSortDirection.Descending)
                {
                    _results = _results.OrderBy(r => System.Net.IPAddress.Parse(r.IPAddress).GetAddressBytes(), new ByteArrayComparer()).ToList();
                    e.Column.SortDirection = ListSortDirection.Ascending;
                }
                else
                {
                    _results = _results.OrderByDescending(r => System.Net.IPAddress.Parse(r.IPAddress).GetAddressBytes(), new ByteArrayComparer()).ToList();
                    e.Column.SortDirection = ListSortDirection.Descending;
                }
                
                RefreshGrid();
            }
            catch
            {
                // Ignore sorting errors
            }
        }
    }

    private class ByteArrayComparer : System.Collections.Generic.IComparer<byte[]>
    {
        public int Compare(byte[]? x, byte[]? y)
        {
            if (x == null || y == null) return 0;
            for (int i = 0; i < System.Math.Min(x.Length, y.Length); i++)
            {
                int cmp = x[i].CompareTo(y[i]);
                if (cmp != 0) return cmp;
            }
            return x.Length.CompareTo(y.Length);
        }
    }
}
