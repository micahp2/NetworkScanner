# WinUI 3 Prototype UI Handoff (Current State)

## Purpose
This document explains the **current WinUI 3 prototype UI** in `NetworkScanner.WinUIPrototype`, how it is wired, how to run/integrate it, and what remains before this can be promoted toward production.

---

## 1) Current UI Architecture

The prototype is currently running in a **compatibility-first, code-built UI mode** due to environment-specific XAML parsing instability encountered during development.

### Key characteristics
- Top-level UI is created in C# code-behind (not primarily XAML-driven for main shell/pages).
- Self-contained publish flow is used for reliable local execution.
- Search/navigation, table rendering, and row highlighting are implemented via custom composition + bindings.

### Main shell (`MainWindow`)
- Left navigation rail with views:
  - Live Scan
  - Deep Info
  - History
  - About
  - Settings
- Top app bar with:
  - app icon/name
  - unified search control surface (query + status + prev/next + stateful search/cancel)
  - window controls

### Scanner workspace (`ScannerPage`)
- `Live Scan` title bar with:
  - Scope summary chip
  - Scope flyout button
  - Stateful Scan/Cancel action (icon + text)
  - Overflow menu (Export)
- Main results area:
  - table-like header + rows (custom ListView template)
  - sortable headers with active sort indicators
  - column resize grips
  - per-column sort tinting
  - status dots (live/cached/offline)
- Bottom anchored status bar:
  - live/cached/total summary
  - scan phase text

---

## 2) Search UX (Implemented Behavior)

Search is integrated into one control surface in the top bar.

### Behavior
- Search button is stateful (search vs cancel behavior).
- Prev/Next are shown only when search is active and navigation is meaningful.
- Match status text is shown inline in the same search surface.
- `Enter` in search triggers next result.
- `Esc` toggles cancel behavior.

### Visual behavior
- All matching rows get text-level match highlight.
- Current search target gets stronger emphasis.
- Next/Prev navigation now performs a smoother deferred scroll (`ScrollIntoViewAlignment.Default`) to reduce jumpiness.

---

## 3) Scope UX (Implemented Behavior)

The former always-visible IP/Subnet/Ports controls are preserved for rollback but hidden.

### Current pattern
- Scope is represented by a compact **summary chip** in the Live Scan bar.
- Scope flyout contains editable fields:
  - IP range
  - subnet mask
  - ports
- Flyout has Apply/Reset actions.
- Summary text updates from scope inputs.

---

## 4) Theming / Dark Mode Notes

Dark styling is force-applied on editable fields (including top search and scope inputs) via explicit control resources and event-backed brush stabilization.

### Why this exists
Certain WinUI template states were reverting to bright white defaults in edit/focus transitions on this machine. The prototype applies scoped overrides to keep editing visually dark and consistent.

---

## 5) How To Run / Integrate Locally

Use the self-contained publish flow:

```powershell
$repo = "C:\Users\mstro\OneDrive\Documents\GitHub\NetworkScanner"
$proj = "$repo\NetworkScanner.WinUIPrototype\NetworkScanner.WinUIPrototype.csproj"
$out  = "C:\Temp\NetworkScannerWinUI"

Get-Process NetworkScanner.WinUIPrototype -ErrorAction SilentlyContinue | Stop-Process -Force
Remove-Item $out -Recurse -Force -ErrorAction SilentlyContinue

dotnet publish $proj -c Release -r win-x64 `
  /p:SelfContained=true `
  /p:WindowsAppSDKSelfContained=true `
  /p:WindowsPackageType=None `
  -o $out

& "$out\NetworkScanner.WinUIPrototype.exe"
```

---

## 6) Integration Guidance (Into Live Product)

### Recommended migration path
1. Keep this prototype as a dedicated UI branch/reference implementation.
2. Move stable view-model contracts and command surfaces first.
3. Rebuild production-ready views with standard WinUI/XAML once environment/runtime compatibility constraints are removed.
4. Replace mock scan pipeline with real services progressively.

### Important
Current implementation prioritizes **runtime stability on this dev environment** and **UX iteration speed** over long-term maintainability of UI markup.

---

## 7) Remaining Work Before Production Candidate

## A) Functional parity / behavior hardening
- [ ] Verify all original WPF features have production-grade WinUI equivalents (not mock).
- [ ] Replace mock scan/host events with real scanner service wiring.
- [ ] Persist user settings (scope, columns, sort prefs, theme choices).
- [ ] Add robust error surfaces and retries.

## B) Table/grid foundation
- [ ] Decide final table technology for production (custom ListView template vs DataGrid/table control).
- [ ] Add tested, deterministic keyboard nav and accessibility semantics.
- [ ] Validate column resize behavior and persistence.
- [ ] Add robust virtualization/perf strategy for large result sets.

## C) Search UX completion
- [ ] Finalize search highlight style tokens and accessibility contrast.
- [ ] Ensure predictable scroll-to-match behavior under all data sizes.
- [ ] Add explicit “jump to first/last” affordances if needed.

## D) UI polish + design system
- [ ] Consolidate hard-coded color values into a tokenized theme resource model.
- [ ] Create consistent hover/pressed/focus states for all controls.
- [ ] Remove compatibility-specific visual hacks once stable XAML path is restored.

## E) Packaging / deployment
- [ ] Decide packaging model (unpackaged self-contained vs packaged install flow).
- [ ] Add CI build/publish checks for WinUI prototype output.
- [ ] Validate on clean machines and supported Windows versions.

## F) Code quality / architecture
- [ ] Reduce code-behind UI construction where appropriate (move to maintainable view layer).
- [ ] Add unit tests for VM search/sort/state transitions.
- [ ] Add UI automation tests for primary flows (scan, search next/prev, sorting, resizing).

---

## 8) Files Most Relevant To Current UI

- `NetworkScanner.WinUIPrototype/MainWindow.xaml.cs`
- `NetworkScanner.WinUIPrototype/Pages/ScannerPage.xaml.cs`
- `NetworkScanner.WinUIPrototype/ViewModels/ScannerViewModel.cs`
- `NetworkScanner.WinUIPrototype/Models/ScanResultRow.cs`
- `NetworkScanner.WinUIPrototype/NetworkScanner.WinUIPrototype.csproj`
- `docs/WINUI_PROTOTYPE_FEATURE_MAP.md`
- `docs/WINUI_PROTOTYPE_LOCAL_STABILITY_NOTES.md`

---

## 9) Summary

This prototype now demonstrates the intended modern WinUI layout direction with:
- integrated top-bar search experience,
- compact scope flyout pattern,
- table-first scanner view,
- sortable/resizable columns,
- anchored status bar,
- and dark-mode aligned editing behavior.

It is suitable as a **design/interaction baseline**, with the checklist above defining what must be completed before live-product readiness.
