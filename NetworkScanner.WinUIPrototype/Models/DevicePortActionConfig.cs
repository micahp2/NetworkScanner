namespace NetworkScanner.WinUIPrototype.Models;

public sealed class DevicePortActionConfig
{
    public DevicePortActionKind Kind { get; set; } = DevicePortActionKind.Auto;
    public string? CustomTarget { get; set; }

    public static DevicePortActionConfig Auto { get; } = new();

    public DevicePortActionConfig Clone() => new() { Kind = Kind, CustomTarget = CustomTarget };

    public bool IsDefault =>
        Kind == DevicePortActionKind.Auto && string.IsNullOrWhiteSpace(CustomTarget);
}
