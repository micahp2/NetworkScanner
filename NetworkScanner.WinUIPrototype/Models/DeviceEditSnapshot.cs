using NetworkScanner.Core;

namespace NetworkScanner.WinUIPrototype.Models;

public sealed class DeviceEditSnapshot
{
    public string CustomName { get; init; } = string.Empty;
    public string OperatingSystem { get; init; } = string.Empty;
    public string Notes { get; init; } = string.Empty;
    public string DeviceIconKey { get; init; } = "Generic";
    public string TagsJson { get; init; } = "[]";
    public string OsHint { get; init; } = string.Empty;
    public string OsHintSource { get; init; } = string.Empty;

    public static DeviceEditSnapshot FromRow(ScanResultRow row) => new()
    {
        CustomName = row.CustomName ?? string.Empty,
        OperatingSystem = row.OperatingSystem ?? string.Empty,
        Notes = row.Notes ?? string.Empty,
        DeviceIconKey = string.IsNullOrWhiteSpace(row.DeviceIconKey) ? "Generic" : row.DeviceIconKey,
        TagsJson = DeviceIdentityHelper.SerializeTags(row.Tags),
        OsHint = row.OsHint ?? string.Empty,
        OsHintSource = row.OsHintSource ?? string.Empty
    };

    public void ApplyTo(ScanResultRow row)
    {
        row.CustomName = CustomName;
        row.OperatingSystem = OperatingSystem;
        row.Notes = Notes;
        row.DeviceIconKey = DeviceIconKey;
        row.SetTags(DeviceIdentityHelper.ParseTags(TagsJson));
        row.OsHint = OsHint;
        row.OsHintSource = OsHintSource;
    }

    public bool Matches(ScanResultRow row) =>
        string.Equals(CustomName, row.CustomName, StringComparison.Ordinal) &&
        string.Equals(OperatingSystem, row.OperatingSystem, StringComparison.Ordinal) &&
        string.Equals(Notes, row.Notes, StringComparison.Ordinal) &&
        string.Equals(DeviceIconKey, row.DeviceIconKey, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(TagsJson, DeviceIdentityHelper.SerializeTags(row.Tags), StringComparison.OrdinalIgnoreCase) &&
        string.Equals(OsHint, row.OsHint, StringComparison.Ordinal) &&
        string.Equals(OsHintSource, row.OsHintSource, StringComparison.Ordinal);
}
