#!/usr/bin/env python3
from __future__ import annotations
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
INCLUDE_EXT = {
    '.cs', '.xaml', '.md', '.txt', '.csproj', '.sln',
    '.ps1', '.cmd', '.bat', '.json', '.py', '.xml', '.config'
}
SKIP_DIRS = {'.git', 'bin', 'obj', '.vs', 'artifacts', '__pycache__'}

# Build suspicious mojibake tokens at runtime to avoid embedding them directly in this file.
SUSPICIOUS_TOKENS = [
    ''.join(chr(c) for c in (0x00E2, 0x20AC, 0x2122)),
    ''.join(chr(c) for c in (0x00E2, 0x20AC, 0x0153)),
    ''.join(chr(c) for c in (0x00E2, 0x20AC)),
    chr(0x00C3),
]


def safe_print(msg: str) -> None:
    try:
        print(msg)
    except UnicodeEncodeError:
        print(msg.encode('ascii', errors='backslashreplace').decode('ascii'))


def include_file(path: pathlib.Path) -> bool:
    if any(part in SKIP_DIRS for part in path.parts):
        return False
    name = path.name.lower()
    if name in {'check_encoding.py'}:
        return False
    if name.startswith('__') and name.endswith('.py'):
        return False
    if name in {'license', 'readme', 'readme.md'}:
        return True
    if name.endswith('.xaml.cs'):
        return True
    return path.suffix.lower() in INCLUDE_EXT


def has_bad_controls(text: str) -> bool:
    for ch in text:
        o = ord(ch)
        if o < 32 and o not in (9, 10, 13):
            return True
    return False


def main() -> int:
    failures: list[str] = []
    checked = 0

    for p in ROOT.rglob('*'):
        if not p.is_file() or not include_file(p):
            continue

        rel = p.relative_to(ROOT).as_posix()
        checked += 1
        data = p.read_bytes()

        try:
            text = data.decode('utf-8', errors='strict')
        except UnicodeDecodeError as e:
            failures.append(f"{rel}: not valid UTF-8 ({e})")
            continue

        if has_bad_controls(text):
            failures.append(f"{rel}: contains disallowed control characters")

        if chr(0xFFFD) in text:
            failures.append(f"{rel}: contains Unicode replacement character U+FFFD")

        for tok in SUSPICIOUS_TOKENS:
            if tok in text:
                failures.append(f"{rel}: contains suspicious mojibake token")
                break

    if failures:
        safe_print('[FAIL] Encoding guardrails failed')
        for f in failures:
            safe_print(' - ' + f)
        safe_print(f'Checked files: {checked}')
        return 1

    safe_print(f'[PASS] Encoding guardrails passed (checked {checked} files)')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
