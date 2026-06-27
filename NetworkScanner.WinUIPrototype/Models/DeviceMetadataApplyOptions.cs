namespace NetworkScanner.WinUIPrototype.Models;

public sealed class DeviceMetadataApplyOptions
{
    public bool ApplyCustomName { get; set; } = true;
    public bool ApplyOperatingSystem { get; set; } = true;
    public bool ApplyDeviceIconKey { get; set; } = true;
    public bool ApplyTags { get; set; } = true;
    public bool ApplyNotes { get; set; } = true;
    public bool ApplyOsHint { get; set; }

    /// <summary>When true, only writes fields that are empty on the target device.</summary>
    public bool FillMissingOnly { get; set; } = true;
}
