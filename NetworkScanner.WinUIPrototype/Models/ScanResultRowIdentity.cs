using NetworkScanner.Core;
using NetworkScanner.Models;
using NetworkScanner.WinUIPrototype.Common;

namespace NetworkScanner.WinUIPrototype.Models;

public static class ScanResultRowIdentity
{
    public static void MergeScanFields(ScanResultRow target, ScanResultRow incoming)
    {
        if (!string.IsNullOrWhiteSpace(incoming.IPAddress))
            target.IPAddress = incoming.IPAddress;
        if (!string.IsNullOrWhiteSpace(incoming.Hostname))
            target.Hostname = incoming.Hostname;
        if (!string.IsNullOrWhiteSpace(incoming.MACAddress))
            target.MACAddress = incoming.MACAddress;
        if (!string.IsNullOrWhiteSpace(incoming.Vendor))
            target.Vendor = incoming.Vendor;
        if (!string.IsNullOrWhiteSpace(incoming.IPv6Address))
            target.IPv6Address = incoming.IPv6Address;
        if (!string.IsNullOrWhiteSpace(incoming.OpenPorts))
            target.SetLivePortsFromScan(incoming.OpenPorts);
        else
            target.SetLivePortsFromScan(string.Empty);

        target.IsOnline = incoming.IsOnline;
        target.IsCached = incoming.IsCached;
        target.LastSeen = incoming.LastSeen ?? DateTimeOffset.Now;
        target.FirstSeen ??= incoming.FirstSeen;
    }

    public static void ApplyUserMetadata(ScanResultRow target, ScanResult source)
    {
        if (!string.IsNullOrWhiteSpace(source.CustomName))
            target.CustomName = source.CustomName;
        if (!string.IsNullOrWhiteSpace(source.OperatingSystem))
            target.OperatingSystem = source.OperatingSystem;
        if (!string.IsNullOrWhiteSpace(source.OsHint))
            target.OsHint = source.OsHint;
        if (!string.IsNullOrWhiteSpace(source.OsHintSource))
            target.OsHintSource = source.OsHintSource;
        if (!string.IsNullOrWhiteSpace(source.DeviceIconKey))
            target.DeviceIconKey = source.DeviceIconKey;
        if (!string.IsNullOrWhiteSpace(source.Notes))
            target.Notes = source.Notes;
        target.SetTags(DeviceIdentityHelper.ParseTags(source.TagsJson));
        if (!string.IsNullOrWhiteSpace(source.OpenPortsString))
            target.SetCachedPortsFromDb(source.OpenPortsString);
        if (!string.IsNullOrWhiteSpace(source.IPv6Address))
            target.IPv6Address = source.IPv6Address;
        if (!string.IsNullOrWhiteSpace(source.PortActionsJson))
            target.SetPortActionsFromJson(source.PortActionsJson);
    }

    public static ScanResult ToScanResult(ScanResultRow row)
    {
        return new ScanResult
        {
            IPAddress = row.IPAddress,
            Hostname = string.IsNullOrWhiteSpace(row.Hostname) ? null : row.Hostname,
            MACAddress = string.IsNullOrWhiteSpace(row.MACAddress) ? null : row.MACAddress,
            Vendor = string.IsNullOrWhiteSpace(row.Vendor) ? null : row.Vendor,
            IPv6Address = string.IsNullOrWhiteSpace(row.IPv6Address) ? null : row.IPv6Address,
            OpenPorts = ParseOpenPorts(row.OpenPorts),
            CustomName = string.IsNullOrWhiteSpace(row.CustomName) ? null : row.CustomName,
            OperatingSystem = string.IsNullOrWhiteSpace(row.OperatingSystem) ? null : row.OperatingSystem,
            OsHint = string.IsNullOrWhiteSpace(row.OsHint) ? null : row.OsHint,
            OsHintSource = string.IsNullOrWhiteSpace(row.OsHintSource) ? null : row.OsHintSource,
            DeviceIconKey = row.DeviceIconKey,
            TagsJson = DeviceIdentityHelper.SerializeTags(row.Tags),
            Notes = string.IsNullOrWhiteSpace(row.Notes) ? null : row.Notes,
            PortActionsJson = row.PortActionsJson,
            FirstSeen = row.FirstSeen?.DateTime,
            LastSeen = row.LastSeen?.DateTime,
            IsOnline = row.IsOnline,
            IsCached = row.IsCached,
            IsResponsive = row.IsOnline,
            ScanTime = DateTime.Now
        };
    }

    private static List<int> ParseOpenPorts(string portsText)
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
}
