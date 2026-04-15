# Changelog - 2026-04-15

## Summary
Stability checkpoint for scan quality, metadata consistency, and release safety.

## Included changes
- Improved first/last seen handling and persistence consistency.
- Improved MAC resolution behavior and reduced duplicate identity propagation.
- Range behavior and scan target transparency improvements.
- Added QA/regression scripts and encoding guardrails.
- Added release checklist updates and version bump discipline.

## Current version
- App display version: `v1.0.5`
- Project version: `1.0.1`
- File/assembly version: `1.0.1.0`

## Notes
- OUI vendor lookup should use local-first caching to avoid remote throttling.
- If vendor is blank, likely causes are unknown OUI or remote rate limits.
