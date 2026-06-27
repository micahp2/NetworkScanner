using System.Text.Json;
using NetworkScanner.WinUIPrototype.Models;

namespace NetworkScanner.WinUIPrototype.Common;

public static class DevicePortActionHelper
{
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    public static IReadOnlyList<DevicePortActionKind> SelectableKinds { get; } =
        Enum.GetValues<DevicePortActionKind>().ToList();

    public static string GetKindDisplayName(DevicePortActionKind kind) => kind switch
    {
        DevicePortActionKind.Auto => "Auto (detect from port)",
        DevicePortActionKind.Browse => "Browse (HTTP/HTTPS)",
        DevicePortActionKind.Http => "Open HTTP",
        DevicePortActionKind.Https => "Open HTTPS",
        DevicePortActionKind.Ssh => "SSH shell",
        DevicePortActionKind.Rdp => "Remote Desktop",
        DevicePortActionKind.Telnet => "Telnet",
        DevicePortActionKind.CustomUrl => "Custom URL",
        DevicePortActionKind.CustomApp => "Custom app / command",
        _ => kind.ToString()
    };

    public static string GetShortLabel(DevicePortActionKind kind) => kind switch
    {
        DevicePortActionKind.Auto => string.Empty,
        DevicePortActionKind.Browse => "Web",
        DevicePortActionKind.Http => "HTTP",
        DevicePortActionKind.Https => "HTTPS",
        DevicePortActionKind.Ssh => "SSH",
        DevicePortActionKind.Rdp => "RDP",
        DevicePortActionKind.Telnet => "Telnet",
        DevicePortActionKind.CustomUrl => "URL",
        DevicePortActionKind.CustomApp => "App",
        _ => kind.ToString()
    };

    public static DevicePortActionKind InferKind(int port) => port switch
    {
        443 or 8443 or 9443 => DevicePortActionKind.Https,
        80 or 8080 or 8000 or 8888 => DevicePortActionKind.Browse,
        22 => DevicePortActionKind.Ssh,
        3389 => DevicePortActionKind.Rdp,
        23 => DevicePortActionKind.Telnet,
        _ => DevicePortActionKind.Auto
    };

    public static DevicePortActionKind ResolveKind(int port, DevicePortActionConfig config) =>
        config.Kind == DevicePortActionKind.Auto ? InferKind(port) : config.Kind;

    public static string Serialize(IReadOnlyDictionary<int, DevicePortActionConfig> actions)
    {
        if (actions.Count == 0) return "{}";
        var payload = actions
            .Where(kvp => !kvp.Value.IsDefault)
            .ToDictionary(kvp => kvp.Key.ToString(), kvp => kvp.Value);
        return JsonSerializer.Serialize(payload, JsonOptions);
    }

    public static Dictionary<int, DevicePortActionConfig> Deserialize(string? json)
    {
        var result = new Dictionary<int, DevicePortActionConfig>();
        if (string.IsNullOrWhiteSpace(json) || json.Trim() is "{}" or "[]")
            return result;

        try
        {
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
                return result;

            foreach (var property in doc.RootElement.EnumerateObject())
            {
                if (!int.TryParse(property.Name, out var port) || port is < 1 or > 65535)
                    continue;

                var config = ParseConfig(property.Value);
                if (!config.IsDefault)
                    result[port] = config;
            }
        }
        catch
        {
            // ignore malformed persisted data
        }

        return result;
    }

    public static void Execute(ScanResultRow row, int port, DevicePortActionConfig config)
    {
        var kind = ResolveKind(port, config);
        if (kind == DevicePortActionKind.Auto)
        {
            if (!TryExecuteAuto(row, port))
                throw new InvalidOperationException($"No automatic action for port {port}. Choose an action type.");
            return;
        }

        switch (kind)
        {
            case DevicePortActionKind.Browse:
                DeviceActions.BrowsePort(row.IPAddress, port);
                break;
            case DevicePortActionKind.Http:
                DeviceActions.OpenUrl($"http://{row.IPAddress}:{port}");
                break;
            case DevicePortActionKind.Https:
                DeviceActions.OpenUrl($"https://{row.IPAddress}:{port}");
                break;
            case DevicePortActionKind.Ssh:
                DeviceActions.OpenShell(row.IPAddress, 22);
                break;
            case DevicePortActionKind.Rdp:
                DeviceActions.OpenRdp(row.IPAddress);
                break;
            case DevicePortActionKind.Telnet:
                DeviceActions.OpenTelnet(row.IPAddress, port);
                break;
            case DevicePortActionKind.CustomUrl:
                LaunchCustomUrl(config.CustomTarget, row.IPAddress, port);
                break;
            case DevicePortActionKind.CustomApp:
                LaunchCustomApp(config.CustomTarget, row.IPAddress, port);
                break;
        }
    }

    public static bool TryExecuteAuto(ScanResultRow row, int port)
    {
        if (port is 80 or 443 or 8080 or 8443 or 8000 or 8888)
        {
            DeviceActions.BrowsePort(row.IPAddress, port);
            return true;
        }

        if (port == 22)
        {
            DeviceActions.OpenShell(row.IPAddress, 22);
            return true;
        }

        if (port == 3389)
        {
            DeviceActions.OpenRdp(row.IPAddress);
            return true;
        }

        if (port == 23)
        {
            DeviceActions.OpenTelnet(row.IPAddress);
            return true;
        }

        return false;
    }

    public static string ExpandTemplate(string? template, string ip, int port) =>
        (template ?? string.Empty)
            .Replace("{ip}", ip, StringComparison.OrdinalIgnoreCase)
            .Replace("{port}", port.ToString(), StringComparison.OrdinalIgnoreCase)
            .Trim();

    private static DevicePortActionConfig ParseConfig(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.String)
        {
            if (Enum.TryParse<DevicePortActionKind>(element.GetString(), true, out var kind))
                return new DevicePortActionConfig { Kind = kind };
            return DevicePortActionConfig.Auto;
        }

        if (element.ValueKind != JsonValueKind.Object)
            return DevicePortActionConfig.Auto;

        var config = new DevicePortActionConfig();
        if (element.TryGetProperty("kind", out var kindProp) &&
            Enum.TryParse<DevicePortActionKind>(kindProp.GetString(), true, out var parsedKind))
            config.Kind = parsedKind;
        else if (element.TryGetProperty("Kind", out var legacyKindProp) &&
                 Enum.TryParse<DevicePortActionKind>(legacyKindProp.GetString(), true, out var legacyKind))
            config.Kind = legacyKind;

        if (element.TryGetProperty("customTarget", out var targetProp))
            config.CustomTarget = targetProp.GetString();
        else if (element.TryGetProperty("CustomTarget", out var legacyTargetProp))
            config.CustomTarget = legacyTargetProp.GetString();

        return config;
    }

    private static void LaunchCustomUrl(string? template, string ip, int port)
    {
        var url = ExpandTemplate(template, ip, port);
        if (string.IsNullOrWhiteSpace(url))
            throw new InvalidOperationException("Enter a custom URL template.");
        DeviceActions.OpenUrl(url);
    }

    private static void LaunchCustomApp(string? template, string ip, int port)
    {
        var command = ExpandTemplate(template, ip, port);
        if (string.IsNullOrWhiteSpace(command))
            throw new InvalidOperationException("Enter a custom app command.");

        if (command.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
            command.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            DeviceActions.OpenUrl(command);
            return;
        }

        var spaceIndex = command.IndexOf(' ');
        if (spaceIndex < 0)
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(command) { UseShellExecute = true });
            return;
        }

        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(command[..spaceIndex], command[(spaceIndex + 1)..])
        {
            UseShellExecute = true
        });
    }
}
