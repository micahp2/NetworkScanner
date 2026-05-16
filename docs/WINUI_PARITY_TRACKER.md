# WinUI Feature Parity Tracker

## Current status

- P0 Scan start/stop/cancel: ✅ Functionally achieved
  - Lifecycle parity validated through repeated live testing against WPF.
  - Remaining work is UI polish only (not lifecycle correctness).

- P0 Live updates + status stream: ✅ Achieved
  - Incremental rows and phase/status updates now stream during scan.

- P0 Real backend path: ✅ Achieved
  - WinUI scanner uses real scan service path (with optional mock fallback).

- P1 UI/UX polish in progress:
  - ✅ First Seen / Last Seen columns restored
  - ✅ Selection visibility improved
  - ✅ Open ports null/pill cleaned
  - 🟡 Header/data alignment and resize affordance tuning continues

- Window placement persistence: ✅ Achieved
  - WinUI now restores prior window position and size between launches.
