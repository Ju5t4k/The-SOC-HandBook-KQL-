#!/usr/bin/env python3
"""Structural lint for .kql files. Not a parser: catches the mistakes that have broken queries here before.

    python3 tools/lint_kql.py queries detections

Checks: balanced brackets outside strings and comments, union legs separated by commas,
lets that are never used, `!matches regex` (not valid KQL), renaming inside `distinct`,
`join ... on ... and` (KQL uses commas), trailing whitespace.
"""
import pathlib
import re
import sys

TOKEN = re.compile(r'@"[^"]*"|@\'[^\']*\'|"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'|//.*')


def clean(src):
    """Blank out strings and drop comments, line by line."""
    return "\n".join(TOKEN.sub(lambda m: "" if m.group(0).startswith("//") else '""', line) for line in src.split("\n"))


def lint(path):
    src = path.read_text()
    code = clean(src)
    issues = []
    for o, c in ("()", "[]", "{}"):
        if code.count(o) != code.count(c):
            issues.append(f"unbalanced {o}{c}: {code.count(o)} vs {code.count(c)}")
    if re.search(r"!matches", code):
        issues.append("'!matches regex' is not KQL; use not(x matches regex y)")
    if re.search(r"\|\s*distinct\s+\w+\s*=", code):
        issues.append("distinct cannot rename; project first")
    if re.search(r"\bjoin\b[^|\n]*\bon\b[^|\n]*\band\b", code):
        issues.append("join ... on ... and: use commas between join keys")
    for m in re.finditer(r"^let\s+(\w+)\s*=", code, re.M):
        name = m.group(1)
        if len(re.findall(r"\b" + name + r"\b", code)) < 2:
            issues.append(f"unused let {name}")
    for i, line in enumerate(src.split("\n"), 1):
        if line.endswith(" "):
            issues.append(f"trailing whitespace on line {i}")
    lines, in_union = code.split("\n"), False
    for i, line in enumerate(lines):
        s = line.strip()
        if re.search(r"\bunion\b", s):
            in_union = True
        if in_union and s.startswith("(") and i > 0:
            prev = [x for x in lines[:i] if x.strip()][-1].strip()
            if not (prev.endswith(",") or re.search(r"union( isfuzzy=true)?$", prev) or prev.endswith("=")):
                issues.append(f"union leg without a comma before line {i + 1}")
        if s.startswith("|") and not line.startswith(" "):
            in_union = False
    return issues


def main():
    roots = [pathlib.Path(a) for a in sys.argv[1:]] or [pathlib.Path("queries")]
    files = sorted(f for r in roots if r.exists() for f in r.rglob("*.kql"))
    bad = 0
    for f in files:
        for issue in lint(f):
            print(f"{f}: {issue}")
            bad += 1
    print(f"{len(files)} files, {bad} issues")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
