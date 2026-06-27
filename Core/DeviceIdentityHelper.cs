using System.Text.RegularExpressions;
using NetworkScanner.Models;

namespace NetworkScanner.Core;

public static class DeviceIdentityHelper
{
    private static readonly Regex MacPattern = new(@"^([0-9A-F]{2}-){5}[0-9A-F]{2}$", RegexOptions.Compiled);

    public static string? NormalizeMac(string? mac)
    {
        if (string.IsNullOrWhiteSpace(mac)) return null;
        var normalized = mac.Trim().Replace(':', '-').ToUpperInvariant();
        return MacPattern.IsMatch(normalized) ? normalized : null;
    }

    public static bool IsValidMac(string? mac) => NormalizeMac(mac) is not null;

    public static T? FindExistingRow<T>(IEnumerable<T> rows, string? mac, string ip, Func<T, string> getMac, Func<T, string> getIp)
        where T : class
    {
        var normalizedMac = NormalizeMac(mac);
        if (normalizedMac is not null)
        {
            var byMac = rows.FirstOrDefault(r => string.Equals(NormalizeMac(getMac(r)), normalizedMac, StringComparison.OrdinalIgnoreCase));
            if (byMac is not null) return byMac;
        }

        if (!string.IsNullOrWhiteSpace(ip))
        {
            return rows.FirstOrDefault(r => string.Equals(getIp(r), ip, StringComparison.OrdinalIgnoreCase));
        }

        return null;
    }

    public static void MergeScanFields(ScanResult target, ScanResult incoming)
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
        if (incoming.OpenPorts is { Count: > 0 })
            target.OpenPorts = incoming.OpenPorts;

        target.IsOnline = incoming.IsOnline;
        target.IsResponsive = incoming.IsResponsive;
        target.IsCached = incoming.IsCached;
        target.LastSeen = incoming.LastSeen ?? DateTime.Now;
        target.FirstSeen ??= incoming.FirstSeen;
        target.ScanTime = incoming.ScanTime;
    }

    public static void ApplyUserMetadata(ScanResult target, ScanResult source)
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
        if (!string.IsNullOrWhiteSpace(source.TagsJson))
            target.TagsJson = source.TagsJson;
        if (!string.IsNullOrWhiteSpace(source.Notes))
            target.Notes = source.Notes;
        if (!string.IsNullOrWhiteSpace(source.PortActionsJson))
            target.PortActionsJson = source.PortActionsJson;
        if (source.OpenPorts is { Count: > 0 } && string.IsNullOrWhiteSpace(target.OpenPortsString))
            target.OpenPorts = source.OpenPorts;
    }

    public static string SerializeTags(IEnumerable<string>? tags)
    {
        if (tags is null) return "[]";
        var list = tags.Where(t => !string.IsNullOrWhiteSpace(t)).Select(t => t.Trim()).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        return System.Text.Json.JsonSerializer.Serialize(list);
    }

    public static List<string> ParseTags(string? tagsJson)
    {
        if (string.IsNullOrWhiteSpace(tagsJson)) return new List<string>();
        try
        {
            return System.Text.Json.JsonSerializer.Deserialize<List<string>>(tagsJson) ?? new List<string>();
        }
        catch
        {
            return tagsJson.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();
        }
    }
}
