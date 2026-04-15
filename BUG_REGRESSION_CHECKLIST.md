# NetworkScanner Regression Checklist (Critical Bug Fixes)

## Scope
1. Last Seen updates correctly.
2. First Seen is preserved and displayed.
3. MAC addresses load and display consistently.
4. Ports-to-scan value updates between runs.
5. Single-IP range input does not fan out to full subnet.

## RC-01 First Seen / Last Seen
1. Scan a known host/range.
2. Record First Seen and Last Seen.
3. Wait 5-10 seconds.
4. Scan same target again.

Expected:
- First Seen unchanged
- Last Seen updated

## RC-02 MAC Consistency
1. Scan same host/range multiple times.
2. Confirm MAC appears each run and row updates consistently.

## RC-03 Ports Between Runs
1. Scan with ports: 22,80
2. Change to 443,3389 and scan again

Expected:
- second run uses updated ports
- UI not force-reset to 80

## RC-04 Single-IP Behavior
1. Enter single IP only (e.g., 192.168.1.10)
2. Run scan

Expected:
- only that host scanned
- no subnet fan-out

## RC-05 Persistence Spot Check
1. Scan known MAC host
2. Close and reopen app
3. Confirm persistence fields remain sane

Expected:
- stable MAC key
- First Seen preserved
- Last Seen reflects latest scan

## Release Gate (do not skip)
- [ ] Run `run_regression.ps1` and confirm PASS
- [ ] Confirm no mojibake/encoding corruption in edited files
- [ ] Bump version in `MainWindow.xaml` and `NetworkScanner.csproj`
- [ ] Build Release successfully

