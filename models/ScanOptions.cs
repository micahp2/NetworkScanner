namespace NetworkScanner.Models;

public class ScanOptions
{
    public List<string> IPRanges { get; set; } = new();
    public List<int> Ports { get; set; } = new(new[] { 22, 53, 80, 443, 3306, 8080, 8443 });
    public int PingTimeout { get; set; } = 3000;  // Increased to 3 seconds
    public int PortTimeout { get; set; } = 1500;  // Increased to 1.5 seconds
    public bool ResolveDNS { get; set; } = true;
    public bool LookupMAC { get; set; } = true;
    public bool LookupVendor { get; set; } = true;
    public bool ScanIPv4 { get; set; } = true;
    public bool ScanIPv6 { get; set; } = true;
}
