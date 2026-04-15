# QA Quick Run (Regression)

This project includes a one-command regression runner for critical scanner bugs.

## Run

From project root:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\run_regression.ps1
```

## What it does

- Runs code-level regression checks in `verify_regression_fixes.ps1`
- Runs `dotnet build`
- Writes a timestamped log file under:
  - `artifacts/qa/regression_YYYYMMDD_HHMMSS.log`

## Pass / Fail

- **PASS**: script exits with code 0 and summary shows no failed checks.
- **FAIL**: script exits non-zero, with failed checks and/or build failure listed in summary.

## Manual follow-up

Use `BUG_REGRESSION_CHECKLIST.md` for behavior-level validation:
- First Seen / Last Seen
- MAC consistency
- Ports updated between runs
- Single-IP scan behavior
- Persistence sanity check
