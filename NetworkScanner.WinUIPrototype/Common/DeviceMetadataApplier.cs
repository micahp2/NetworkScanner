using NetworkScanner.Core;
using NetworkScanner.Models;
using NetworkScanner.WinUIPrototype.Models;

namespace NetworkScanner.WinUIPrototype.Common;

public static class DeviceMetadataApplier
{
    public static void Apply(DeviceEditSnapshot source, ScanResultRow target, DeviceMetadataApplyOptions options)
    {
        if (options.ApplyCustomName && ShouldWrite(target.CustomName, source.CustomName, options.FillMissingOnly))
            target.CustomName = source.CustomName;

        if (options.ApplyOperatingSystem && ShouldWrite(target.OperatingSystem, source.OperatingSystem, options.FillMissingOnly))
            target.OperatingSystem = source.OperatingSystem;

        if (options.ApplyDeviceIconKey && ShouldWriteIcon(target.DeviceIconKey, source.DeviceIconKey, options.FillMissingOnly))
            target.DeviceIconKey = source.DeviceIconKey;

        if (options.ApplyNotes && ShouldWrite(target.Notes, source.Notes, options.FillMissingOnly))
            target.Notes = source.Notes;

        if (options.ApplyTags)
        {
            if (!options.FillMissingOnly || target.Tags.Count == 0)
                target.SetTags(DeviceIdentityHelper.ParseTags(source.TagsJson));
            else
                MergeTags(target, source.TagsJson);
        }

        if (options.ApplyOsHint)
        {
            if (ShouldWrite(target.OsHint, source.OsHint, options.FillMissingOnly))
                target.OsHint = source.OsHint;
            if (ShouldWrite(target.OsHintSource, source.OsHintSource, options.FillMissingOnly))
                target.OsHintSource = source.OsHintSource;
        }
    }

    public static void CopyUserFields(ScanResultRow source, ScanResultRow target)
    {
        target.CustomName = source.CustomName;
        target.OperatingSystem = source.OperatingSystem;
        target.Notes = source.Notes;
        target.DeviceIconKey = source.DeviceIconKey;
        target.SetTags(source.Tags);
    }

    public static UserDeviceMetadata BuildPersistPatch(ScanResultRow row, DeviceMetadataApplyOptions options)
    {
        var patch = new NetworkScanner.Models.UserDeviceMetadata();
        if (options.ApplyCustomName)
        {
            patch.UpdateCustomName = true;
            patch.CustomName = string.IsNullOrWhiteSpace(row.CustomName) ? null : row.CustomName;
        }
        if (options.ApplyOperatingSystem)
        {
            patch.UpdateOperatingSystem = true;
            patch.OperatingSystem = string.IsNullOrWhiteSpace(row.OperatingSystem) ? null : row.OperatingSystem;
        }
        if (options.ApplyDeviceIconKey)
        {
            patch.UpdateDeviceIconKey = true;
            patch.DeviceIconKey = string.IsNullOrWhiteSpace(row.DeviceIconKey) ? "Generic" : row.DeviceIconKey;
        }
        if (options.ApplyTags)
        {
            patch.UpdateTags = true;
            patch.TagsJson = DeviceIdentityHelper.SerializeTags(row.Tags);
        }
        if (options.ApplyNotes)
        {
            patch.UpdateNotes = true;
            patch.Notes = string.IsNullOrWhiteSpace(row.Notes) ? null : row.Notes;
        }
        if (options.ApplyOsHint)
        {
            patch.UpdateOsHint = true;
            patch.OsHint = string.IsNullOrWhiteSpace(row.OsHint) ? null : row.OsHint;
            patch.UpdateOsHintSource = true;
            patch.OsHintSource = string.IsNullOrWhiteSpace(row.OsHintSource) ? null : row.OsHintSource;
        }
        return patch;
    }

    private static bool ShouldWrite(string current, string incoming, bool fillMissingOnly) =>
        !fillMissingOnly || string.IsNullOrWhiteSpace(current);

    private static bool ShouldWriteIcon(string current, string incoming, bool fillMissingOnly) =>
        !fillMissingOnly || string.IsNullOrWhiteSpace(current) ||
        string.Equals(current, "Generic", StringComparison.OrdinalIgnoreCase);

    private static void MergeTags(ScanResultRow target, string sourceTagsJson)
    {
        var merged = target.Tags.ToList();
        foreach (var tag in DeviceIdentityHelper.ParseTags(sourceTagsJson))
        {
            if (!merged.Contains(tag, StringComparer.OrdinalIgnoreCase))
                merged.Add(tag);
        }
        target.SetTags(merged);
    }
}
