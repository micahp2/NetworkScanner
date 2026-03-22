namespace NetworkScanner.Models;

using System.ComponentModel;
using System.Runtime.CompilerServices;

public class ScanResult : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;

    private void Set<T>(ref T field, T value, [CallerMemberName] string? name = null)
    {
        if (!Equals(field, value)) { field = value; PropertyChanged?.Invoke(this, new(name)); }
    }

    private string _ipAddress = "";
    private string _ipVersion = "IPv4";
    private string? _hostname;
    private string? _macAddress;
    private string? _vendor;
    private string? _ipv6Address;
    private List<int> _openPorts = new();
    private DateTime _scanTime = DateTime.Now;
    private bool _isResponsive;
    private bool _isSearchMatch;
    private string _searchTerm = "";

    public string  IPAddress   { get => _ipAddress;   set => Set(ref _ipAddress, value); }
    public string  IPVersion   { get => _ipVersion;   set => Set(ref _ipVersion, value); }
    public string? Hostname    { get => _hostname;    set => Set(ref _hostname, value); }
    public string? MACAddress  { get => _macAddress;  set => Set(ref _macAddress, value); }
    public string? Vendor      { get => _vendor;      set => Set(ref _vendor, value); }
    public string? IPv6Address { get => _ipv6Address; set => Set(ref _ipv6Address, value); }

    public List<int> OpenPorts
    {
        get => _openPorts;
        set { Set(ref _openPorts, value); PropertyChanged?.Invoke(this, new(nameof(OpenPortsString))); }
    }

    public string OpenPortsString => string.Join(", ", _openPorts);

    public DateTime ScanTime      { get => _scanTime;      set => Set(ref _scanTime, value); }
    public bool     IsResponsive  { get => _isResponsive;  set => Set(ref _isResponsive, value); }
    /// <summary>Set by the search UI to highlight matching rows. Not persisted.</summary>
    public bool   IsSearchMatch { get => _isSearchMatch; set => Set(ref _isSearchMatch, value); }
    /// <summary>Current search term — drives per-cell text highlight. Not persisted.</summary>
    public string SearchTerm    { get => _searchTerm;    set => Set(ref _searchTerm, value); }
}
