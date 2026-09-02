#!/usr/bin/env python3
"""Validate the query header blocks in queries/*.kql.

Every query in this repo is one block delimited by `// ----` rules. This checks
that each block carries the metadata and the prose an analyst needs at 2am, that
the fill-in block exists, and that the query is time-bounded.

Run: python3 tools/validate.py
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
QUERIES = ROOT / "queries"
INDEX = QUERIES / "README.md"

BLOCK = re.compile(
    r"(^// -{10,}\s*\n)(.*?)(^// -{10,}\s*\n)(.*?)(?=^// -{10,}|^// #{10,}|\Z)",
    re.MULTILINE | re.DOTALL,
)
META = ["QUERY", "VERSION", "TABLES", "ATT&CK"]
SECTIONS = ["FILL IN:", "WHAT YOU GET:", "HOW TO READ IT:", "MODIFY IT:"]
VERSION_RE = re.compile(r"^\d{4}\.\d{2}\.\d{2}$")
TIME_BOUND_RE = re.compile(r"ago\(|between\s*\(|startofday\(|_startTime|TimeGenerated\s*[><]")
FILL_IN_RE = re.compile(r"^// ={4,} FILL IN", re.MULTILINE)


def meta_of(header):
    out = {}
    for line in header.splitlines():
        m = re.match(r"//\s+([A-Z&]+):\s*(.*)$", line)
        if m:
            out[m.group(1)] = m.group(2).strip()
    return out


def sections_of(header):
    return [s for s in SECTIONS if re.search(r"^//\s+" + re.escape(s), header, re.MULTILINE)]


def modify_bullets(header):
    body = header.split("MODIFY IT:", 1)[-1] if "MODIFY IT:" in header else ""
    return len(re.findall(r"^//\s+-\s+\S", body, re.MULTILINE))


def main():
    problems = []
    titles = {}
    files = sorted(QUERIES.glob("*.kql"))
    if not files:
        print("no query files found under queries/", file=sys.stderr)
        return 1

    index_text = INDEX.read_text() if INDEX.exists() else ""
    total = 0

    for path in files:
        text = path.read_text()
        rel = path.relative_to(ROOT)
        blocks = list(BLOCK.finditer(text))
        if not blocks:
            problems.append(f"{rel}: no query blocks found")
            continue

        for match in blocks:
            header, body = match.group(2), match.group(4)
            meta = meta_of(header)
            name = meta.get("QUERY", "<untitled>")
            where = f"{rel} [{name}]"
            total += 1

            for field in META:
                if not meta.get(field):
                    problems.append(f"{where}: missing '{field}:' in the header")

            version = meta.get("VERSION", "")
            if version and not VERSION_RE.match(version):
                problems.append(f"{where}: VERSION '{version}' is not YYYY.MM.DD")

            missing = [s for s in SECTIONS if s not in sections_of(header)]
            for section in missing:
                problems.append(f"{where}: missing '{section}' section")

            if modify_bullets(header) < 2:
                problems.append(f"{where}: needs at least two 'MODIFY IT' bullets")

            if not FILL_IN_RE.search(body):
                problems.append(f"{where}: no '// ===== FILL IN' block")

            code = "\n".join(l for l in body.splitlines() if not l.strip().startswith("//"))
            if not TIME_BOUND_RE.search(code):
                problems.append(f"{where}: query body has no visible time bound")

            if name in titles:
                problems.append(f"{where}: duplicate query name, also in {titles[name]}")
            titles[name] = where

            if name != "<untitled>" and name not in index_text:
                problems.append(f"{where}: not listed in queries/README.md")

    if problems:
        print(f"{len(problems)} problem(s):\n", file=sys.stderr)
        for p in problems:
            print(f"  {p}", file=sys.stderr)
        return 1

    print(f"OK — {total} queries in {len(files)} files, all headers valid.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
