# NetworkScanner

Fast Windows LAN scanner built with WPF and .NET 8.

Repository: https://github.com/micahp2/NetworkScanner

## What this app does

- Scans IPv4 ranges (single host, dash ranges, CIDR)
- Resolves hostnames (reverse DNS)
- Resolves MAC addresses (neighbor table + ARP + SendARP)
- Looks up vendors by OUI (with local caching)
- Scans configurable TCP ports
- Shows IPv6 neighbor info when available
- Exports results to CSV
- Supports search, sort, dark mode, and context actions

## Supported input formats

IP range field examples:

- `192.168.1.100` (single host)
- `192.168.1.1-100` (last octet range)
- `192.168.1.1-192.168.1.200` (full range)
- `192.168.1.0/24` (CIDR)
- Multiple ranges separated by commas or new lines

Ports field examples:

- `80`
- `22,80,443`
- `8080-8090`
- `22,80,443,8080-8090`

## Local build

```powershell
dotnet restore
dotnet build -c Release
```

Run from Visual Studio or:

```powershell
dotnet run -c Debug
```

## Release build

Version source of truth is `NetworkScanner.csproj` (`<Version>`).

Scripts:

- `publish.cmd` - builds self-contained win-x64 release zip
- `releasemode.bat` - builds framework-dependent and self-contained zips (and can create GH release if `gh` is available)

Recommended artifact:

- `publish\NetworkScanner-v<version>-win-x64.zip`

## Verifying downloaded binaries

After download, verify file hash in PowerShell:

```powershell
Get-FileHash .\NetworkScanner-v<version>-win-x64.zip -Algorithm SHA256
```

Compare the output with the checksum published in the release notes.

## QA and guardrails

- `README-QA.md` - one-command regression run
- `BUG_REGRESSION_CHECKLIST.md` - manual regression checks
- `scripts/verify_encoding_guardrails.ps1` - encoding/corruption safety checks

## Notes

- Vendor lookup can be blank for unknown, locally-administered, or rate-limited OUIs.
- Some network environments (AP isolation, proxy ARP, VLAN boundaries) can limit MAC visibility.

## License

MIT (see `LICENSE`).
