namespace NetworkScanner.Models;

/// <summary>User-editable device fields persisted by MAC address.</summary>
public class UserDeviceMetadata
{
    public string? CustomName { get; set; }
    public bool UpdateCustomName { get; set; }

    public string? OperatingSystem { get; set; }
    public bool UpdateOperatingSystem { get; set; }

    public string? OsHint { get; set; }
    public bool UpdateOsHint { get; set; }

    public string? OsHintSource { get; set; }
    public bool UpdateOsHintSource { get; set; }

    public string? DeviceIconKey { get; set; }
    public bool UpdateDeviceIconKey { get; set; }

    public string? TagsJson { get; set; }
    public bool UpdateTags { get; set; }

    public string? Notes { get; set; }
    public bool UpdateNotes { get; set; }

    public string? PortActionsJson { get; set; }
    public bool UpdatePortActions { get; set; }
}
