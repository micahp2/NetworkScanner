using NetworkScanner.WinUIPrototype.Models;

namespace NetworkScanner.WinUIPrototype.Common;

public static class DeviceActions
{
    public static void CopyText(string? value)
    {
        if (string.IsNullOrEmpty(value)) return;
        try
        {
            var package = new Windows.ApplicationModel.DataTransfer.DataPackage();
            package.SetText(value);
            Windows.ApplicationModel.DataTransfer.Clipboard.SetContent(package);
            Windows.ApplicationModel.DataTransfer.Clipboard.Flush();
        }
        catch { }
    }

    public static void CopyField(ScanResultRow row, string fieldName)
    {
        var val = fieldName.ToLowerInvariant() switch
        {
            "ip" or "ip address" => row.IPAddress,
            "hostname" => row.Hostname,
            "mac" or "mac address" => row.MACAddress,
            "vendor" => row.Vendor,
            "open ports" => row.OpenPorts,
            "ipv6" or "ipv6 address" => row.IPv6Address,
            "custom name" => row.CustomName,
            "notes" => row.Notes,
            _ => null
        };
        CopyText(val);
    }

    public static void CopyDeviceProfile(ScanResultRow row)
    {
        var json = System.Text.Json.JsonSerializer.Serialize(new
        {
            row.IPAddress,
            row.Hostname,
            row.MACAddress,
            row.Vendor,
            row.OpenPorts,
            row.IPv6Address,
            row.CustomName,
            row.OperatingSystem,
            row.OsHint,
            row.DeviceIconKey,
            Tags =             row.Tags,
            row.Notes,
            PortActions = DevicePortActionHelper.Deserialize(row.PortActionsJson),
            row.StateLabel,
            FirstSeen = row.FirstSeenText,
            LastSeen = row.LastSeenText
        }, new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
        CopyText(json);
    }

    public static void OpenUrl(string url)
    {
        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(url) { UseShellExecute = true });
        }
        catch { }
    }

    public static void BrowsePort(string ip, int port)
    {
        var scheme = port is 443 or 8443 or 9443 ? "https" : "http";
        OpenUrl($"{scheme}://{ip}:{port}");
    }

    public static void OpenRdp(string ip)
    {
        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("mstsc", $"/v:{ip}") { UseShellExecute = true });
        }
        catch { }
    }

    public static void OpenShell(string ip, int port = 0, string? sshUser = null)
    {
        string cmd;
        if (port == 22)
            cmd = string.IsNullOrWhiteSpace(sshUser) ? $"ssh {ip}" : $"ssh {sshUser}@{ip}";
        else if (port > 0)
            cmd = $"# {ip}:{port}";
        else
            cmd = $"# {ip}";

        if (!TryLaunch("wt.exe", $"new-tab -- powershell -NoExit -Command \"{cmd}\"") &&
            !TryLaunch("powershell.exe", $"-NoExit -Command \"{cmd}\""))
        {
            TryLaunch("cmd.exe", $"/k echo {cmd}");
        }
    }

    public static void OpenTelnet(string ip, int port = 23)
    {
        var cmd = $"telnet {ip} {port}";
        if (!TryLaunch("wt.exe", $"new-tab -- cmd /k {cmd}") &&
            !TryLaunch("cmd.exe", $"/k {cmd}"))
        {
            throw new InvalidOperationException("Telnet client not available. Enable Telnet Client in Windows Optional Features.");
        }
    }

    public static List<int> ParseOpenPorts(string portsText)
    {
        if (string.IsNullOrWhiteSpace(portsText))
            return new List<int>();

        return portsText
            .Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries)
            .Select(x => int.TryParse(x.Trim(), out var p) ? p : -1)
            .Where(p => p is >= 1 and <= 65535)
            .Distinct()
            .OrderBy(p => p)
            .ToList();
    }

    private static bool TryLaunch(string exe, string args)
    {
        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(exe, args) { UseShellExecute = true });
            return true;
        }
        catch { return false; }
    }
}
