namespace NetworkScanner.WinUIPrototype.Models;

public enum DevicePortSource
{
    Live,
    Cached,
    Both
}

public sealed class DevicePortDisplayItem
{
    public int Port { get; init; }
    public string ServiceName { get; init; } = string.Empty;
    public DevicePortSource Source { get; init; }
    public DevicePortActionKind ActionKind { get; init; } = DevicePortActionKind.Auto;
    public string ActionLabel { get; init; } = string.Empty;

    public bool HasCustomAction => ActionKind != DevicePortActionKind.Auto;

    public string SourceLabel => Source switch
    {
        DevicePortSource.Live => "Live",
        DevicePortSource.Cached => "Cached",
        DevicePortSource.Both => "Live + cached",
        _ => string.Empty
    };

    public string TooltipText
    {
        get
        {
            var baseText = string.IsNullOrWhiteSpace(ServiceName)
                ? $":{Port} ({SourceLabel})"
                : $":{Port} {ServiceName} ({SourceLabel})";
            if (HasCustomAction && !string.IsNullOrWhiteSpace(ActionLabel))
                return $"{baseText} · {ActionLabel}";
            return baseText;
        }
    }
}
