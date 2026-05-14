# WinUI 3 Prototype Feature Map

This document maps existing **WPF NetworkScanner** capabilities to the new **WinUI 3 prototype**.

> Scope: UI/UX parity and mock interactions only. No real network scanning, ARP/NDP, DNS, OUI lookup, DB persistence, or CSV file IO is performed by the prototype.

## 1) Core Scan Workflow

| Existing capability (WPF) | Prototype mapping (WinUI 3) | Status |
|---|---|---|
| Enter one or multiple IP ranges | Scanner page toolbar → `IP Ranges` textbox | ✅ Exposed |
| Enter ports (single/list/range syntax) | Scanner page toolbar → `Ports` textbox | ✅ Exposed |
| Start/Stop scan | Scanner page toolbar → `Scan/Stop` button | ✅ Mock interaction |
| Live status updates while scanning | Status bar text updates during simulated host stream | ✅ Mock interaction |
| Scan completion feedback | Status changes to complete and logs completion action | ✅ Mock interaction |
| Clear results | `Clear` button clears results and resets status | ✅ Mock interaction |
| Export CSV | `Export` button simulates CSV generation and logs output summary | ✅ Mock interaction |

## 2) Result Grid / Data Surface

| Existing capability (WPF) | Prototype mapping (WinUI 3) | Status |
|---|---|---|
| Results table with key fields | DataGrid with Online, State, Custom Name, First/Last Seen, IP, Hostname, MAC, Vendor, Ports, IPv6 | ✅ Exposed |
| Cached + live row states | `State` column shows Cached/Live via mock row model | ✅ Exposed |
| Editable custom name | `Custom Name` column editable | ✅ Exposed |
| Persistent known devices shown at startup | Preloaded mock cached rows | ✅ Mock interaction |
| Stream-in scan results | Mock scan inserts fresh rows over time | ✅ Mock interaction |

## 3) Search / Find

| Existing capability (WPF) | Prototype mapping (WinUI 3) | Status |
|---|---|---|
| Find popup / panel | Toggleable Find panel | ✅ Exposed |
| Search text input | Find textbox bound to `SearchText` | ✅ Exposed |
| Next/Previous match navigation | `↑` / `↓` buttons with match index display | ✅ Mock interaction |
| Match count feedback | Search status text (`No matches`, `N matches`, `i / N`) | ✅ Exposed |

## 4) Column Management

| Existing capability (WPF) | Prototype mapping (WinUI 3) | Status |
|---|---|---|
| Show/hide columns | `Columns` flyout with toggle items | ✅ Mock interaction |
| Remember column layout | UI model scaffolded (`ColumnSettings`), persistence toggle exposed in settings | ✅ Future-ready scaffold |

## 5) Context Actions (Row Actions)

| Existing capability (WPF) | Prototype mapping (WinUI 3) | Status |
|---|---|---|
| Copy field values (IP/Hostname/MAC/Vendor/Ports/IPv6) | Right rail `Copy` action buttons | ✅ Mock interaction |
| Browse open ports in browser | Right rail `Browse` buttons (`:80`, `:443`, `:8080`) | ✅ Mock interaction |
| Shell actions (SSH/RDP/Terminal) | Right rail `Shell` buttons | ✅ Mock interaction |
| Action feedback | Last action log panel | ✅ Exposed |

## 6) Settings & Configuration Surface

| Existing capability (WPF/service) | Prototype mapping (WinUI 3) | Status |
|---|---|---|
| Resolve DNS option | Settings page toggle | ✅ Exposed |
| Lookup MAC option | Settings page toggle | ✅ Exposed |
| Lookup Vendor option | Settings page toggle | ✅ Exposed |
| IPv4/IPv6 scan toggles | Settings page toggles | ✅ Exposed |
| Ping/Port timeout values | Settings page `NumberBox` controls | ✅ Exposed |
| Theme behavior (system/light/dark) | Settings page radio options | ✅ Exposed (future wiring) |
| Sound preferences | Settings page toggles | ✅ Exposed (mock) |
| Persistence preferences | Settings page toggles | ✅ Exposed (mock) |

## 7) Navigation / Information Architecture

| Existing capability (single-window WPF) | Prototype mapping (WinUI 3) | Status |
|---|---|---|
| Main scanner screen | NavigationView → Scanner page | ✅ Exposed |
| Advanced settings | NavigationView → Settings page | ✅ Exposed |
| In-app feature map reference | NavigationView → Feature Map page | ✅ Added |

## 8) Architecture Scaffold for Future Implementation

Implemented in prototype for smoother migration to production:

- MVVM-style structure
  - `ViewModels/ScannerViewModel.cs`
  - `Models/ScanResultRow.cs`, `Models/ColumnSetting.cs`
  - `Common/ObservableObject.cs`, `Common/RelayCommand.cs`
- Shared app-level view model instance (`App.ScannerViewModel`) reused across pages
- Command-based interaction points for scan, clear, export, find, copy, browse, shell
- Column visibility model that can be connected to persisted settings later

## 9) Known Intentional Gaps (Prototype Only)

Not implemented in this prototype by design:

- Real scanning engine integration (`NetworkScannerService`)
- SQLite persistence integration (`DatabaseService`)
- Actual CSV file dialog/write flow
- Real context-menu launching behavior (browser/shell/RDP)
- Per-cell text highlighting visuals identical to WPF custom `HighlightTextBlock`
- WPF-specific DWM title bar + sound API wiring

These are planned as follow-on implementation tasks when transitioning from prototype to production WinUI.
