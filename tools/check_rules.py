#!/usr/bin/env python3
"""Check detection rules in detections/: each DC-*.kql against its .yaml.

    python3 tools/check_rules.py           check, exit 1 on any problem
    python3 tools/check_rules.py --sync    copy each .kql body into its .yaml query block, then check

The .kql is the source. Its header is the leading block of // lines; the body
is everything after it. The YAML query must equal the body exactly.
"""
import pathlib
import re
import sys
import uuid

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
DETECTIONS = ROOT / "detections"

HEADER_FIELDS = ["Logic:", "Tuning:", "False positives:", "Data:", "Lookback:", "Playbook:", "ATT&CK:"]
TACTICS = {"Reconnaissance", "ResourceDevelopment", "InitialAccess", "Execution", "Persistence",
           "PrivilegeEscalation", "DefenseEvasion", "CredentialAccess", "Discovery", "LateralMovement",
           "Collection", "Exfiltration", "CommandAndControl", "Impact"}
SEVERITIES = {"High", "Medium", "Low", "Informational"}
OPERATORS = {"gt", "lt", "eq", "ne"}
RULE_FIELDS = ["id", "name", "description", "severity", "requiredDataConnectors", "queryFrequency",
               "queryPeriod", "triggerOperator", "triggerThreshold", "tactics", "relevantTechniques",
               "query", "entityMappings", "customDetails", "alertDetailsOverride", "version", "kind"]
HUNTING_FIELDS = ["id", "name", "description", "requiredDataConnectors", "tactics", "relevantTechniques",
                  "query", "version"]
RULE_ONLY = ["kind", "severity", "queryFrequency", "queryPeriod", "triggerOperator", "triggerThreshold",
             "alertDetailsOverride", "eventGroupingSettings"]


def split_kql(text):
    """Return (header lines, body) of a detection .kql file."""
    lines = text.split("\n")
    i = 0
    while i < len(lines) and lines[i].startswith("//"):
        i += 1
    header = lines[:i]
    body = "\n".join(lines[i:]).strip("\n")
    return header, body


def to_timespan(value):
    m = re.fullmatch(r"(\d+)([mhd])", str(value))
    if not m:
        return None
    n, unit = int(m.group(1)), m.group(2)
    return n * {"m": 1, "h": 60, "d": 1440}[unit]


def sync(yaml_path, body):
    """Replace the query block in a YAML file with the .kql body, keeping everything else."""
    lines = yaml_path.read_text().split("\n")
    out, i = [], 0
    while i < len(lines):
        if lines[i].startswith("query: |"):
            out.append("query: |")
            out.extend(("  " + b) if b else "" for b in body.split("\n"))
            i += 1
            while i < len(lines) and (lines[i].startswith("  ") or lines[i] == ""):
                i += 1
            continue
        out.append(lines[i])
        i += 1
    yaml_path.write_text("\n".join(out).rstrip("\n") + "\n")


def check():
    problems, ids = [], {}
    kqls = sorted(DETECTIONS.rglob("DC-*.kql"))
    for kql in kqls:
        header, body = split_kql(kql.read_text())
        head = "\n".join(header)
        for field in HEADER_FIELDS:
            if f"// {field}" not in head:
                problems.append(f"{kql.name}: header missing '{field}'")
        if kql.name.endswith(".defender.kql"):
            if "Timestamp" not in body:
                problems.append(f"{kql.name}: Advanced Hunting variant should use Timestamp")
            continue
        yml = kql.with_suffix(".yaml")
        if not yml.exists():
            problems.append(f"{kql.name}: no matching .yaml")
            continue
        try:
            rule = yaml.safe_load(yml.read_text())
        except yaml.YAMLError as e:
            problems.append(f"{yml.name}: YAML error: {e}")
            continue
        hunting = "kind" not in rule
        for f in (HUNTING_FIELDS if hunting else RULE_FIELDS):
            if f not in rule:
                problems.append(f"{yml.name}: missing '{f}'")
        if hunting:
            for f in RULE_ONLY:
                if f in rule:
                    problems.append(f"{yml.name}: hunting query must not have '{f}'")
        query = str(rule.get("query", "")).strip("\n")
        if query != body:
            problems.append(f"{yml.name}: query differs from {kql.name} (run --sync)")
        try:
            uuid.UUID(str(rule.get("id")))
        except ValueError:
            problems.append(f"{yml.name}: id is not a GUID")
        if rule.get("id") in ids:
            problems.append(f"{yml.name}: id duplicates {ids[rule.get('id')]}")
        ids[rule.get("id")] = yml.name
        if len(str(rule.get("name", ""))) > 100:
            problems.append(f"{yml.name}: name over 100 characters")
        if len(str(rule.get("description", ""))) > 255:
            problems.append(f"{yml.name}: description over 255 characters")
        for t in rule.get("tactics", []) or []:
            if t not in TACTICS:
                problems.append(f"{yml.name}: unknown tactic '{t}'")
        for t in rule.get("relevantTechniques", []) or []:
            if not re.fullmatch(r"T\d{4}(\.\d{3})?", str(t)):
                problems.append(f"{yml.name}: bad technique id '{t}'")
        for c in rule.get("requiredDataConnectors", []) or []:
            for dt in c.get("dataTypes", []):
                if not re.search(r"\b" + re.escape(dt) + r"\b", body):
                    problems.append(f"{yml.name}: data type '{dt}' not used in the query")
        if not re.fullmatch(r"\d+\.\d+\.\d+", str(rule.get("version", ""))):
            problems.append(f"{yml.name}: version must be a.b.c")
        if hunting:
            continue
        if rule.get("severity") not in SEVERITIES:
            problems.append(f"{yml.name}: bad severity")
        if rule.get("triggerOperator") not in OPERATORS:
            problems.append(f"{yml.name}: bad triggerOperator")
        freq, period = to_timespan(rule.get("queryFrequency")), to_timespan(rule.get("queryPeriod"))
        if freq is None or period is None:
            problems.append(f"{yml.name}: queryFrequency/queryPeriod must look like 5m, 1h, 14d")
        else:
            if period > 14 * 1440:
                problems.append(f"{yml.name}: queryPeriod over 14d")
            if freq > period:
                problems.append(f"{yml.name}: queryFrequency longer than queryPeriod")
        maps = rule.get("entityMappings", []) or []
        if not maps or len(maps) > 10:
            problems.append(f"{yml.name}: need 1-10 entityMappings")
        for m in maps:
            fms = m.get("fieldMappings", [])
            if not fms or len(fms) > 3:
                problems.append(f"{yml.name}: {m.get('entityType')} needs 1-3 fieldMappings")
            for fm in fms:
                col = fm.get("columnName", "")
                if not re.search(r"\b" + re.escape(col) + r"\b", body):
                    problems.append(f"{yml.name}: entity column '{col}' not in query")
        details = rule.get("customDetails", {}) or {}
        if len(details) > 20:
            problems.append(f"{yml.name}: over 20 customDetails")
        for k, col in details.items():
            if len(k) > 20:
                problems.append(f"{yml.name}: customDetails key '{k}' over 20 characters")
            if not re.search(r"\b" + re.escape(str(col)) + r"\b", body):
                problems.append(f"{yml.name}: customDetails column '{col}' not in query")
        ado = rule.get("alertDetailsOverride", {}) or {}
        for key in ("alertDisplayNameFormat", "alertDescriptionFormat"):
            placeholders = re.findall(r"\{\{([^}]+)\}\}", str(ado.get(key, "")))
            if len(placeholders) > 3:
                problems.append(f"{yml.name}: {key} has over 3 placeholders")
            for col in placeholders:
                if col != col.strip() or not re.search(r"\b" + re.escape(col) + r"\b", body):
                    problems.append(f"{yml.name}: {key} placeholder '{col}' not in query")
    for yml in sorted(DETECTIONS.rglob("DC-*.yaml")):
        if not yml.with_suffix(".kql").exists():
            problems.append(f"{yml.name}: no matching .kql")
    return kqls, problems


def main():
    if "--sync" in sys.argv:
        for kql in sorted(DETECTIONS.rglob("DC-*.kql")):
            yml = kql.with_suffix(".yaml")
            if yml.exists() and not kql.name.endswith(".defender.kql"):
                sync(yml, split_kql(kql.read_text())[1])
    kqls, problems = check()
    for p in problems:
        print(p)
    print(f"{len(kqls)} detection files, {len(problems)} problems")
    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()
