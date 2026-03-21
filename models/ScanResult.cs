namespace NetworkScanner.Models;

public class ScanResult
{
    public string IPAddress { get; set; } = "";
    public string IPVersion { get; set; } = "IPv4";
    public string? Hostname { get; set; }
    public string? MACAddress { get; set; }
    public string? Vendor { get; set; }
    public List<int> OpenPorts { get; set; } = new();
    public string OpenPortsString => string.Join(", ", OpenPorts);
    public DateTime ScanTime { get; set; } = DateTime.Now;
    public bool IsResponsive { get; set; }
}
