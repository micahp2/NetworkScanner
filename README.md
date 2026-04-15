# Network Scanner

A fast, open-source Windows network scanner built with WPF and .NET 8.

**[https://github.com/micahp2/NetworkScanner](https://github.com/micahp2/NetworkScanner)**

---

## Features

| | |
|---|---|
| 🔍 **Full subnet scan** | Enumerates every host in a CIDR range (e.g. `192.168.1.0/24`) plus additional devices from the OS connection tables |
| 🖥 **Hostname resolution** | Reverse DNS for every live host |
| 🔌 **MAC address lookup** | Three-layer resolution: modern neighbor table (GetIpNetTable2) → legacy ARP cache → active SendARP probe |
| 🌐 **IPv6 / NDP** | Reads the Windows IPv6 neighbor table to surface MACs for devices that silently drop IPv4 ARP (common on managed Wi-Fi networks) |
| 🏭 **Vendor identification** | OUI lookup via macvendors.com with per-prefix caching and rate-limit handling |
| 🔓 **Port scanning** | Configurable port list with comma and range syntax (`22,80,443,8080-8090`) |
| 🌑 **Dark mode** | Follows the Windows system theme; dark title bar via DWM |
| 📋 **Context menu** | Copy any field · Browse open ports in the browser · Open SSH/RDP/terminal from any row |
| 🔎 **Find / search** | Popup search bar (Ctrl+F) with live highlighting and ↑/↓ navigation across all columns |
| ↕ **Sortable columns** | All columns; IP Address sorts numerically |
| 📁 **CSV export** | All fields including IPv6 |
| 🔔 **Sound events** | Windows notification sound on scan complete; critical stop sound when cancelled |
| 🔄 **Live theme switching** | Responds instantly to Windows dark/light mode toggle — no restart needed |
| 🌐 **Multi-range scanning** | Scan multiple non-contiguous subnets in one pass: `192.168.2.0/24, 192.168.4.0/24` |

---

## Screenshots

> _Add screenshots here once you have them._

---

## Usage

1. **Launch** — the app auto-detects your subnet and pre-fills the IP range field
2. **Set ports** — default is `80`; supports any combination:
   - Single: `22`
   - Multiple: `22,80,443`
   - Range: `8080-8090`
   - Mixed: `22,80,443,8080-8090`
3. **Click Scan** — results stream in as hosts respond; click again to stop
4. **Right-click any row** for the context menu:
   - **Copy →** copies any single field to the clipboard
   - **Browse →** opens `http(s)://ip:port` in your default browser for each open port
   - **Shell →** SSH opens Windows Terminal/PowerShell with `ssh user@ip`; RDP opens `mstsc`
5. **Find** (or Ctrl+F) — popup search bar; matched text is highlighted in amber in every cell
6. **Export** — saves all results to CSV including IPv6 addresses

### IP Range formats

```
192.168.1.0/24          CIDR (scans .1 through .254)
192.168.1.1-254         last-octet range
192.168.1.1-192.168.1.254   full range
192.168.1.100           single host
```

---

## How MAC resolution works

MAC addresses are resolved in three passes, from fastest to most aggressive:

1. **OS neighbor table snapshot** — reads `GetIpNetTable2` (modern) and `GetIpNetTable` (legacy) plus `netsh interface ipv4/ipv6 show neighbors` before and after the ping sweep. This catches everything Windows already knows.

2. **IPv6 NDP table** — `netsh interface ipv6 show neighbors` reveals MACs for devices that silently drop IPv4 ARP (common with managed UniFi APs, switches, and iOS/Android devices on Wi-Fi). EUI-64 IPv6 addresses mathematically encode the MAC, so MACs can be extracted even from `Unreachable` NDP entries.

3. **Active SendARP probe** — for hosts still missing a MAC after the above, `SendARP()` issues a directed ARP request and reads the MAC directly from its output buffer (not from the OS table, which is unreliable for this purpose).

### Why some devices still show no MAC

If a device is on a **Wi-Fi network with client isolation enabled** (default on UniFi and many enterprise APs), the AP filters ARP between wireless clients. Your machine's ARP/NDP requests are dropped before reaching the device. The OS marks these as `00-00-00-00-00-00 Unreachable`. This is an intentional network policy — no userland Windows application can work around it without raw packet capture (which requires a kernel driver).

Running the scanner from a **wired connection on the same switch** will resolve MACs for all devices.

### Tailscale / VPN note

When Tailscale (or similar VPN software) is running, it registers a virtual TAP adapter with a `169.254.x.x` (APIPA) address and an `Ethernet` interface type. This can cause Windows to report the wrong local subnet. The scanner filters out `169.254.x.x` addresses and prefers routable private-range addresses (`10.x`, `172.16-31.x`, `192.168.x`) when detecting the local subnet. Tailscale may also prevent some devices from being discovered due to its routing table modifications.

---

## Building

**Requirements:**
- Windows 10 or 11
- .NET 8.0 SDK or later

```bash
git clone https://github.com/micahp2/NetworkScanner
cd NetworkScanner
dotnet build
dotnet run
```

Or open `NetworkScanner.sln` in Visual Studio 2022+.

**Release build:**
```bash
dotnet publish -c Release -r win-x64 --self-contained false
```

---

## Architecture

```
NetworkScanner/
├── models/
│   ├── ScanResult.cs          # Result model with INotifyPropertyChanged
│   └── ScanOptions.cs         # Scan configuration
├── services/
│   ├── IPHelperAPI.cs         # P/Invoke: GetIpNetTable2, GetIpNetTable,
│   │                          #   SendARP, GetExtendedTcpTable/UdpTable,
│   │                          #   DWM, winmm (sounds)
│   └── NetworkScannerService.cs  # 6-phase scan engine
├── App.xaml / App.xaml.cs    # Theme (dark/light), DWM title bar, sounds
├── MainWindow.xaml            # UI layout, column definitions
└── MainWindow.xaml.cs         # All UI logic: scan, search, sort,
                               #   context menu, highlight text block
```

### Scan phases

| Phase | What happens |
|---|---|
| 1 | Build candidate IP list from user's range + OS connection tables |
| 2 | Pre-scan MAC snapshot (ARP cache, NDP table, netsh) |
| 3 | Ping all candidates at concurrency 50 — ICMP first, then 10 TCP ports in parallel |
| 4 | 800ms settle delay for ARP/NDP cache to finish writing |
| 5 | Post-ping MAC snapshot — merge with pre-scan, run NDP EUI-64 extraction |
| 6 | Enrich each live host (DNS, MAC, vendor, ports) and stream results to UI |

### Key APIs used

| API | Purpose |
|---|---|
| `GetIpNetTable2` (iphlpapi) | Modern IPv4/IPv6 neighbor table |
| `GetIpNetTable` (iphlpapi) | Legacy ARP cache |
| `SendARP` (iphlpapi) | Active directed ARP probe |
| `GetExtendedTcpTable` (iphlpapi) | Active TCP connections for device discovery |
| `GetExtendedUdpTable` (iphlpapi) | Active UDP listeners for device discovery |
| `DwmSetWindowAttribute` (dwmapi) | Dark title bar (attr 20 / 19) |
| `PlaySound` (winmm) | Windows sound events |
| `netsh interface ipv4/ipv6 show neighbors` | Stale ARP + NDP entries not visible via API |
| macvendors.com API | OUI → vendor name lookup |

---

## Troubleshooting

**No devices found**
- Confirm the IP range matches your network (the auto-detected value should be correct)
- Try running as Administrator — some ARP operations are more reliable with elevated privileges
- If using a VPN, disconnect it and rescan

**Missing MAC addresses**
- Wi-Fi with client isolation: connect via Ethernet for full MAC visibility
- Run a second scan — the first ping sweep populates the ARP cache for subsequent lookups
- Some devices (managed switches, IoT with hardened firmware) actively refuse ARP

**Scan is slow**
- Reduce the port list — each port adds a TCP probe per host
- Reduce the IP range to a smaller subnet

**Wrong subnet auto-detected**
- Disconnect VPN/Tailscale or manually enter the correct range

---

## Changelog

### v1.0.6

- Improvements to OUI/Vendor caching.

### v1.0.5

- Various fixes and improvements.

### v1.0.4

- Added persistent column layout preferences (visibility + order) between runs.
- Added column management UX improvements and default column ordering.
- Fixed Online/State behavior during refresh scans (cached vs live transitions).
- Improved startup cache loading behavior and in-place refresh semantics.
- Added resilience for corrupted column-layout JSON (fallback to defaults + rewrite).

### v1.0.2
- Live theme switching — app responds instantly to Windows dark/light mode toggle without restart
- Multi-range scanning — IP Range field now accepts comma-separated ranges: `192.168.2.0/24, 192.168.4.0/24, 192.168.6.1-100`
- Off-subnet MAC indicator — devices reachable via router (different subnet) show `—` in MAC column instead of blank, making clear this is expected (ARP does not cross routers)
- All theme brush references changed to `DynamicResource` so the entire UI repaints on theme change
- Fixed: sort on any column after IP Address column no longer scrambles results
- Fixed: `OperationCanceledException` flood in VS debug output silenced

### v1.0.0
- Initial public release
- Full /24 subnet scan (not just OS-table-known devices)
- Three-layer MAC resolution with IPv6 NDP EUI-64 extraction
- Tailscale/VPN interface detection fix (169.254.x.x filtering)
- Dark mode with themed title bar, scrollbars, and input fields (DynamicResource)
- Per-cell search highlighting (HighlightTextBlock)
- Context menu: Copy / Browse / Shell
- Sound events on scan complete and scan stop
- Consistent all-manual sorting (no DataGrid ICollectionView conflict)
- OUI vendor lookup with caching and rate-limit backoff
- IPv6 address column

---

## License

MIT — see [LICENSE](LICENSE)