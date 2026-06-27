namespace NetworkScanner.Services;

using System;
using System.IO;
using System.Threading.Tasks;
using System.Collections.Generic;
using Dapper;
using Microsoft.Data.Sqlite;
using NetworkScanner.Models;
using NetworkScanner.Core;

public class DatabaseService
{
    private readonly string _connectionString;

    public DatabaseService(string? dbPath = null)
    {
        if (string.IsNullOrWhiteSpace(dbPath))
        {
            var appData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            var folder = Path.Combine(appData, "NetworkScanner");
            Directory.CreateDirectory(folder);
            dbPath = Path.Combine(folder, "scanner.db");
        }

        _connectionString = $"Data Source={dbPath}";
    }

    public async Task InitializeAsync()
    {
        using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync();
        await connection.ExecuteAsync("PRAGMA journal_mode=WAL;");

        await connection.ExecuteAsync(@"
CREATE TABLE IF NOT EXISTS Devices (
    MacAddress TEXT PRIMARY KEY,
    ActiveIpAddress TEXT,
    Hostname TEXT,
    CustomName TEXT,
    Vendor TEXT,
    FirstSeen TEXT,
    LastSeen TEXT,
    IsOnline INTEGER NOT NULL DEFAULT 0
);");

        await connection.ExecuteAsync(@"
CREATE TABLE IF NOT EXISTS OuiCache (
    Prefix TEXT PRIMARY KEY,
    VendorName TEXT,
    LastUpdated TEXT
);");

        await MigrateSchemaAsync(connection);
    }

    private static async Task MigrateSchemaAsync(SqliteConnection connection)
    {
        var columns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var rows = await connection.QueryAsync<(long cid, string name, string type, long notnull, string dflt, long pk)>("PRAGMA table_info(Devices);");
        foreach (var row in rows)
            columns.Add(row.name);

        async Task AddColumn(string name, string ddl)
        {
            if (!columns.Contains(name))
                await connection.ExecuteAsync($"ALTER TABLE Devices ADD COLUMN {ddl};");
        }

        await AddColumn("OperatingSystem", "OperatingSystem TEXT");
        await AddColumn("OsHint", "OsHint TEXT");
        await AddColumn("OsHintSource", "OsHintSource TEXT");
        await AddColumn("DeviceIconKey", "DeviceIconKey TEXT DEFAULT 'Generic'");
        await AddColumn("Tags", "Tags TEXT");
        await AddColumn("Notes", "Notes TEXT");
        await AddColumn("OpenPorts", "OpenPorts TEXT");
        await AddColumn("IPv6Address", "IPv6Address TEXT");
        await AddColumn("PortActions", "PortActions TEXT");
    }

    public async Task UpsertDeviceAsync(ScanResult device)
    {
        var normalizedMac = DeviceIdentityHelper.NormalizeMac(device.MACAddress);
        if (normalizedMac is null) return;

        using var connection = new SqliteConnection(_connectionString);

        const string sql = @"
INSERT INTO Devices (MacAddress, ActiveIpAddress, Hostname, CustomName, Vendor, FirstSeen, LastSeen, IsOnline,
    OperatingSystem, OsHint, OsHintSource, DeviceIconKey, Tags, Notes, OpenPorts, IPv6Address)
VALUES (@MacAddress, @ActiveIpAddress, @Hostname, @CustomName, @Vendor, @FirstSeen, @LastSeen, @IsOnline,
    @OperatingSystem, @OsHint, @OsHintSource, @DeviceIconKey, @Tags, @Notes, @OpenPorts, @IPv6Address)
ON CONFLICT(MacAddress) DO UPDATE SET
    ActiveIpAddress = COALESCE(NULLIF(excluded.ActiveIpAddress, ''), Devices.ActiveIpAddress),
    Hostname        = COALESCE(NULLIF(excluded.Hostname, ''), Devices.Hostname),
    CustomName      = COALESCE(NULLIF(excluded.CustomName, ''), Devices.CustomName),
    Vendor          = COALESCE(NULLIF(excluded.Vendor, ''), Devices.Vendor),
    FirstSeen       = COALESCE(Devices.FirstSeen, excluded.FirstSeen),
    LastSeen        = COALESCE(excluded.LastSeen, Devices.LastSeen),
    IsOnline        = excluded.IsOnline,
    OsHint          = COALESCE(NULLIF(excluded.OsHint, ''), Devices.OsHint),
    OsHintSource    = COALESCE(NULLIF(excluded.OsHintSource, ''), Devices.OsHintSource),
    OpenPorts       = COALESCE(NULLIF(excluded.OpenPorts, ''), Devices.OpenPorts),
    IPv6Address     = COALESCE(NULLIF(excluded.IPv6Address, ''), Devices.IPv6Address);
";

        await connection.ExecuteAsync(sql, new
        {
            MacAddress = normalizedMac,
            ActiveIpAddress = device.IPAddress,
            Hostname = device.Hostname,
            CustomName = device.CustomName,
            Vendor = device.Vendor,
            FirstSeen = (device.FirstSeen ?? device.ScanTime).ToString("o"),
            LastSeen = (device.LastSeen ?? device.ScanTime).ToString("o"),
            IsOnline = device.IsOnline ? 1 : 0,
            OperatingSystem = device.OperatingSystem,
            OsHint = device.OsHint,
            OsHintSource = device.OsHintSource,
            DeviceIconKey = string.IsNullOrWhiteSpace(device.DeviceIconKey) ? "Generic" : device.DeviceIconKey,
            Tags = device.TagsJson,
            Notes = device.Notes,
            OpenPorts = device.OpenPorts is { Count: > 0 } ? device.OpenPortsString : null,
            IPv6Address = device.IPv6Address
        });
    }

    public async Task UpdateUserMetadataAsync(string macAddress, UserDeviceMetadata patch)
    {
        var normalizedMac = DeviceIdentityHelper.NormalizeMac(macAddress);
        if (normalizedMac is null) return;

        using var connection = new SqliteConnection(_connectionString);

        var sets = new List<string>();
        var param = new DynamicParameters();
        param.Add("MacAddress", normalizedMac);

        if (patch.UpdateCustomName)
        {
            sets.Add("CustomName = @CustomName");
            param.Add("CustomName", patch.CustomName);
        }
        if (patch.UpdateOperatingSystem)
        {
            sets.Add("OperatingSystem = @OperatingSystem");
            param.Add("OperatingSystem", patch.OperatingSystem);
        }
        if (patch.UpdateOsHint)
        {
            sets.Add("OsHint = @OsHint");
            param.Add("OsHint", patch.OsHint);
        }
        if (patch.UpdateOsHintSource)
        {
            sets.Add("OsHintSource = @OsHintSource");
            param.Add("OsHintSource", patch.OsHintSource);
        }
        if (patch.UpdateDeviceIconKey)
        {
            sets.Add("DeviceIconKey = @DeviceIconKey");
            param.Add("DeviceIconKey", string.IsNullOrWhiteSpace(patch.DeviceIconKey) ? "Generic" : patch.DeviceIconKey);
        }
        if (patch.UpdateTags)
        {
            sets.Add("Tags = @Tags");
            param.Add("Tags", patch.TagsJson);
        }
        if (patch.UpdateNotes)
        {
            sets.Add("Notes = @Notes");
            param.Add("Notes", patch.Notes);
        }
        if (patch.UpdatePortActions)
        {
            sets.Add("PortActions = @PortActions");
            param.Add("PortActions", patch.PortActionsJson);
        }

        if (sets.Count == 0) return;

        var sql = $"UPDATE Devices SET {string.Join(", ", sets)} WHERE MacAddress = @MacAddress;";
        await connection.ExecuteAsync(sql, param);
    }

    public async Task<ScanResult?> GetDeviceByMacAsync(string macAddress)
    {
        var normalizedMac = DeviceIdentityHelper.NormalizeMac(macAddress);
        if (normalizedMac is null) return null;

        using var connection = new SqliteConnection(_connectionString);
        return await connection.QuerySingleOrDefaultAsync<ScanResult>(DeviceSelectSql + " WHERE MacAddress = @mac;", new { mac = normalizedMac });
    }

    private const string DeviceSelectSql = @"
SELECT
    ActiveIpAddress AS IPAddress,
    Hostname,
    CustomName,
    Vendor,
    FirstSeen,
    LastSeen,
    IsOnline,
    MacAddress AS MACAddress,
    OperatingSystem,
    OsHint,
    OsHintSource,
    DeviceIconKey,
    Tags AS TagsJson,
    Notes,
    OpenPorts AS OpenPortsString,
    IPv6Address,
    PortActions AS PortActionsJson
FROM Devices";

    public async Task<string?> GetCachedVendorAsync(string prefix)
    {
        if (string.IsNullOrWhiteSpace(prefix)) return null;
        using var connection = new SqliteConnection(_connectionString);
        return await connection.QuerySingleOrDefaultAsync<string>(
            "SELECT VendorName FROM OuiCache WHERE Prefix = @prefix;", new { prefix });
    }

    public async Task CacheVendorAsync(string prefix, string vendorName)
    {
        if (string.IsNullOrWhiteSpace(prefix) || string.IsNullOrWhiteSpace(vendorName)) return;
        using var connection = new SqliteConnection(_connectionString);
        await connection.ExecuteAsync(@"
INSERT INTO OuiCache (Prefix, VendorName, LastUpdated)
VALUES (@prefix, @vendorName, @lastUpdated)
ON CONFLICT(Prefix) DO UPDATE SET
    VendorName = excluded.VendorName,
    LastUpdated = excluded.LastUpdated;
", new { prefix, vendorName, lastUpdated = DateTime.UtcNow.ToString("o") });
    }

    public async Task<IEnumerable<ScanResult>> GetAllDevicesAsync()
    {
        using var connection = new SqliteConnection(_connectionString);
        return await connection.QueryAsync<ScanResult>(DeviceSelectSql + " ORDER BY COALESCE(LastSeen, FirstSeen) DESC;");
    }

    public Task<string?> GetOuiVendorAsync(string prefix) => GetCachedVendorAsync(prefix);
    public Task CacheOuiVendorAsync(string prefix, string vendorName) => CacheVendorAsync(prefix, vendorName);
}
