using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;

namespace NetworkScanner.WinUIPrototype.Common;

public readonly record struct DeviceIconChoice(string Key, string Label, Symbol? Symbol = null, string? Glyph = null);

public static class DeviceIconHelper
{
    private static readonly FontFamily FluentIcons = new("Segoe Fluent Icons");

    /// <summary>Legacy named icons for devices saved before the full glyph picker.</summary>
    private static readonly Dictionary<string, DeviceIconChoice> LegacyNamedIcons =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["Generic"] = new("Generic", "Generic", Symbol.AllApps),
            ["Router"] = new("Router", "Router / Gateway", Glyph: "\uE968"),
            ["Switch"] = new("Switch", "Network Switch", Glyph: "\uE839"),
            ["AccessPoint"] = new("AccessPoint", "Wi-Fi AP", Glyph: "\uE701"),
            ["Modem"] = new("Modem", "Modem", Glyph: "\uE968"),
            ["Firewall"] = new("Firewall", "Firewall", Glyph: "\uE83E"),
            ["VPN"] = new("VPN", "VPN", Glyph: "\uE774"),
            ["Server"] = new("Server", "Server", Symbol.Library),
            ["NAS"] = new("NAS", "NAS / Storage", Symbol.SaveLocal),
            ["Cloud"] = new("Cloud", "Cloud Device", Glyph: "\uE753"),
            ["Desktop"] = new("Desktop", "Desktop PC", Symbol.Home),
            ["Laptop"] = new("Laptop", "Laptop", Glyph: "\uE770"),
            ["Tablet"] = new("Tablet", "Tablet", Glyph: "\uE70F"),
            ["Phone"] = new("Phone", "Phone", Symbol.Phone),
            ["Mobile"] = new("Mobile", "Mobile", Glyph: "\uE717"),
            ["Watch"] = new("Watch", "Watch / Wearable", Symbol.Clock),
            ["Printer"] = new("Printer", "Printer", Symbol.Print),
            ["Scanner"] = new("Scanner", "Scanner", Symbol.Scan),
            ["Camera"] = new("Camera", "Camera", Symbol.Camera),
            ["Doorbell"] = new("Doorbell", "Doorbell", Glyph: "\uE728"),
            ["Lock"] = new("Lock", "Smart Lock", Glyph: "\uE72E"),
            ["Light"] = new("Light", "Smart Light", Glyph: "\uE706"),
            ["Thermostat"] = new("Thermostat", "Thermostat", Glyph: "\uE1CA"),
            ["Plug"] = new("Plug", "Smart Plug", Glyph: "\uEC06"),
            ["Sensor"] = new("Sensor", "Sensor", Glyph: "\uE1D2"),
            ["Hub"] = new("Hub", "Smart Hub", Symbol.Setting),
            ["TV"] = new("TV", "TV / Display", Symbol.Video),
            ["Speaker"] = new("Speaker", "Speaker", Glyph: "\uE767"),
            ["Soundbar"] = new("Soundbar", "Soundbar", Glyph: "\uE7F6"),
            ["Streaming"] = new("Streaming", "Streaming Stick", Glyph: "\uE714"),
            ["Console"] = new("Console", "Game Console", Glyph: "\uE7FC"),
            ["Controller"] = new("Controller", "Game Controller", Glyph: "\uE7FC"),
            ["IOT"] = new("IOT", "IoT Device", Symbol.Contact),
            ["Garage"] = new("Garage", "Garage Opener", Glyph: "\uE804"),
            ["Vehicle"] = new("Vehicle", "Vehicle", Glyph: "\uE804"),
            ["Drone"] = new("Drone", "Drone", Glyph: "\uE945"),
            ["Robot"] = new("Robot", "Robot / Vacuum", Glyph: "\uE99A"),
            ["Medical"] = new("Medical", "Medical Device", Glyph: "\uE95E"),
            ["POS"] = new("POS", "POS / Register", Symbol.Shop),
            ["Kiosk"] = new("Kiosk", "Kiosk", Glyph: "\uE782"),
            ["ATM"] = new("ATM", "ATM / Banking", Glyph: "\uE825"),
            ["Industrial"] = new("Industrial", "Industrial PLC", Glyph: "\uE964"),
            ["Solar"] = new("Solar", "Solar / Power", Glyph: "\uE945"),
            ["UPS"] = new("UPS", "UPS / Battery", Glyph: "\uE83F"),
            ["Projector"] = new("Projector", "Projector", Glyph: "\uE714"),
            ["VoIP"] = new("VoIP", "VoIP Phone", Glyph: "\uE717"),
            ["Intercom"] = new("Intercom", "Intercom", Glyph: "\uE720"),
            ["PBX"] = new("PBX", "PBX", Glyph: "\uE717"),
            ["RaspberryPi"] = new("RaspberryPi", "SBC / Pi", Glyph: "\uE7F8"),
            ["Docker"] = new("Docker", "Container Host", Glyph: "\uE7EF"),
            ["VM"] = new("VM", "Virtual Machine", Glyph: "\uE7F4"),
            ["Database"] = new("Database", "Database", Glyph: "\uE7F4"),
            ["MailServer"] = new("MailServer", "Mail Server", Symbol.Mail),
            ["WebServer"] = new("WebServer", "Web Server", Symbol.Globe),
            ["DNS"] = new("DNS", "DNS Server", Glyph: "\uE968"),
            ["Proxy"] = new("Proxy", "Proxy", Glyph: "\uE774"),
            ["Backup"] = new("Backup", "Backup", Symbol.Save),
            ["Archive"] = new("Archive", "Archive", Glyph: "\uE81C"),
            ["Development"] = new("Development", "Dev Board", Glyph: "\uE943"),
            ["Test"] = new("Test", "Equipment", Symbol.Preview),
            ["Unknown"] = new("Unknown", "Unknown", Symbol.Help)
        };

    public static IReadOnlyList<string> FluentGlyphs => FluentIconCatalog.AllGlyphs;

    public static void PreloadFluentGlyphs() => FluentIconCatalog.Preload();

    public static Task<IReadOnlyList<string>> GetFluentGlyphsAsync() => FluentIconCatalog.GetGlyphsAsync();

    public static bool IsHexGlyphKey(string? key) =>
        TryParseHexGlyphKey(key, out _);

    public static string FormatGlyphKey(string glyph)
    {
        var cp = char.ConvertToUtf32(glyph, 0);
        return cp.ToString("X4");
    }

    public static string FormatGlyphKey(int codePoint) => codePoint.ToString("X4");

    public static DeviceIconChoice GetChoice(string? key)
    {
        if (!string.IsNullOrWhiteSpace(key) && LegacyNamedIcons.TryGetValue(key, out var choice))
            return choice;
        return LegacyNamedIcons["Generic"];
    }

    public static Symbol GetSymbol(string? key) => GetChoice(key).Symbol ?? Symbol.AllApps;

    public static IconElement CreateIconElement(string? key)
    {
        if (TryParseHexGlyphKey(key, out var glyphChar))
        {
            return new FontIcon
            {
                Glyph = glyphChar,
                FontFamily = FluentIcons
            };
        }

        if (!string.IsNullOrWhiteSpace(key) && LegacyNamedIcons.TryGetValue(key, out var choice))
        {
            if (choice.Symbol is Symbol symbol)
                return new SymbolIcon { Symbol = symbol };
            if (!string.IsNullOrEmpty(choice.Glyph))
            {
                return new FontIcon
                {
                    Glyph = choice.Glyph,
                    FontFamily = FluentIcons
                };
            }
        }

        return new FontIcon
        {
            Glyph = "\uE700",
            FontFamily = FluentIcons
        };
    }

    public static Viewbox CreateIconView(string? key, double size = 40) =>
        new() { Width = size, Height = size, Child = CreateIconElement(key) };

    private static bool TryParseHexGlyphKey(string? key, out string glyphChar)
    {
        glyphChar = string.Empty;
        if (string.IsNullOrWhiteSpace(key))
            return false;

        var hex = key.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? key[2..] : key;
        if (hex.Length is < 4 or > 6)
            return false;

        foreach (var ch in hex)
        {
            if (!Uri.IsHexDigit(ch))
                return false;
        }

        var codePoint = Convert.ToInt32(hex, 16);
        if (codePoint <= 0 || codePoint > 0x10FFFF)
            return false;

        glyphChar = char.ConvertFromUtf32(codePoint);
        return true;
    }
}
