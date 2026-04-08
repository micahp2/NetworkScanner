namespace NetworkScanner.Services;

using System;
using System.IO;
using System.Threading.Tasks;
using System.Collections.Generic;
using Dapper;
using Microsoft.Data.Sqlite;
using NetworkScanner.Models;

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
    }

    public async Task UpsertDeviceAsync(ScanResult device)
    {
        if (string.IsNullOrWhiteSpace(device.MACAddress)) return;

        using var connection = new SqliteConnection(_connectionString);

        const string sql = @"
INSERT INTO Devices (MacAddress, ActiveIpAddress, Hostname, CustomName, Vendor, FirstSeen, LastSeen, IsOnline)
VALUES (@MacAddress, @ActiveIpAddress, @Hostname, @CustomName, @Vendor, @FirstSeen, @LastSeen, @IsOnline)
ON CONFLICT(MacAddress) DO UPDATE SET
    ActiveIpAddress = COALESCE(NULLIF(excluded.ActiveIpAddress, ''), Devices.ActiveIpAddress),
    Hostname        = COALESCE(NULLIF(excluded.Hostname, ''), Devices.Hostname),
    CustomName      = COALESCE(NULLIF(excluded.CustomName, ''), Devices.CustomName),
    Vendor          = COALESCE(NULLIF(excluded.Vendor, ''), Devices.Vendor),
    FirstSeen       = COALESCE(Devices.FirstSeen, excluded.FirstSeen),
    LastSeen        = COALESCE(excluded.LastSeen, Devices.LastSeen),
    IsOnline        = excluded.IsOnline;
";

        await connection.ExecuteAsync(sql, new
        {
            MacAddress = device.MACAddress,
            ActiveIpAddress = device.IPAddress,
            Hostname = device.Hostname,
            CustomName = device.CustomName,
            Vendor = device.Vendor,
            FirstSeen = (device.FirstSeen ?? device.ScanTime).ToString("o"),
            LastSeen = (device.LastSeen ?? device.ScanTime).ToString("o"),
            IsOnline = device.IsOnline ? 1 : 0
        });
    }

    public async Task<ScanResult?> GetDeviceByMacAsync(string macAddress)
    {
        if (string.IsNullOrWhiteSpace(macAddress)) return null;

        using var connection = new SqliteConnection(_connectionString);
        return await connection.QuerySingleOrDefaultAsync<ScanResult>(@"
SELECT
    ActiveIpAddress AS IPAddress,
    Hostname,
    CustomName,
    Vendor,
    FirstSeen,
    LastSeen,
    IsOnline,
    MacAddress AS MACAddress
FROM Devices
WHERE MacAddress = @mac;
", new { mac = macAddress });
    }

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
        return await connection.QueryAsync<ScanResult>(@"
SELECT
    ActiveIpAddress AS IPAddress,
    Hostname,
    CustomName,
    Vendor,
    FirstSeen,
    LastSeen,
    IsOnline,
    MacAddress AS MACAddress
FROM Devices
ORDER BY COALESCE(LastSeen, FirstSeen) DESC;
");
    }

    public Task<string?> GetOuiVendorAsync(string prefix) => GetCachedVendorAsync(prefix);
    public Task CacheOuiVendorAsync(string prefix, string vendorName) => CacheVendorAsync(prefix, vendorName);
}
