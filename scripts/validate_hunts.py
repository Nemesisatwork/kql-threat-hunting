#!/usr/bin/env python3
"""Validate KQL threat hunting metadata, repository structure, and query syntax."""

from __future__ import annotations

import argparse
import datetime as dt
import re
import sys
from pathlib import Path

VALID_TACTICS = {
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
}

REQUIRED_FIELDS = {
    "id",
    "title",
    "platform",
    "product",
    "tactic",
    "techniques",
    "status",
    "severity",
    "author",
    "date",
    "data_sources",
    "query_file",
}

VALID_STATUSES = {"experimental", "testing", "production"}
VALID_SEVERITIES = {"low", "medium", "high", "critical"}

REQUIRED_SECTIONS = [
    "## Hypothesis",
    "## Telemetry & Data Sources",
    "## Query Logic",
    "## Triage & Investigation Steps",
    "## Known False Positives",
]

ID_PATTERN = re.compile(r"^TH-KQL-\d{4}$")
TECHNIQUE_PATTERN = re.compile(r"^T\d{4}(\.\d{3})?$")


def strip_inline_comment(value: str) -> str:
    """Remove trailing YAML inline comments outside quotes."""
    in_single = False
    in_double = False
    for idx, ch in enumerate(value):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            if idx == 0 or value[idx - 1].isspace():
                return value[:idx].strip()
    return value.strip()


def unquote(value: str) -> str:
    """Strip matching surrounding single or double quotes."""
    if len(value) >= 2 and (
        (value[0] == '"' and value[-1] == '"') or (value[0] == "'" and value[-1] == "'")
    ):
        return value[1:-1]
    return value


def parse_frontmatter(text: str) -> tuple[dict[str, object] | None, str, str | None]:
    """Parse YAML frontmatter using stdlib so validation needs no external deps."""
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return None, text, "Missing opening '---' YAML frontmatter delimiter"

    end_idx = None
    for idx in range(1, len(lines)):
        if lines[idx].strip() == "---":
            end_idx = idx
            break

    if end_idx is None:
        return None, text, "Missing closing '---' YAML frontmatter delimiter"

    fm_lines = lines[1:end_idx]
    body = "\n".join(lines[end_idx + 1 :])
    data: dict[str, object] = {}
    current_list_key: str | None = None

    for line_no, raw_line in enumerate(fm_lines, start=2):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if stripped.startswith("- "):
            if current_list_key is None:
                return None, body, f"Line {line_no}: list item without parent key"
            item = unquote(strip_inline_comment(stripped[2:]))
            if item:
                lst = data[current_list_key]
                assert isinstance(lst, list)
                lst.append(item)
            continue

        if ":" not in raw_line:
            return None, body, f"Line {line_no}: expected 'key: value' syntax"

        key, raw_val = raw_line.split(":", 1)
        key = key.strip()
        val = strip_inline_comment(raw_val)

        if not val:
            data[key] = []
            current_list_key = key
        else:
            current_list_key = None
            if val.startswith("[") and val.endswith("]"):
                items = [unquote(part.strip()) for part in val[1:-1].split(",") if part.strip()]
                data[key] = items
            else:
                data[key] = unquote(val)

    return data, body, None


def strip_kql_comments_and_strings(query: str) -> tuple[str, list[str]]:
    """Strip KQL line comments and string literals for delimiter checking."""
    errors: list[str] = []
    out: list[str] = []
    i = 0
    n = len(query)

    while i < n:
        ch = query[i]

        if query.startswith("//", i):
            newline = query.find("\n", i)
            i = n if newline == -1 else newline + 1
            out.append(" ")
            continue

        if ch == "@" and i + 1 < n and query[i + 1] in ('"', "'"):
            quote = query[i + 1]
            i += 2
            closed = False
            while i < n:
                if query[i] == quote:
                    if i + 1 < n and query[i + 1] == quote:
                        i += 2
                        continue
                    i += 1
                    closed = True
                    break
                i += 1
            if not closed:
                errors.append(f"Unclosed KQL verbatim string literal (@{quote}...)")
            out.append(" ")
            continue

        if ch in ('"', "'"):
            quote = ch
            i += 1
            closed = False
            while i < n:
                if query[i] == "\\" and i + 1 < n:
                    i += 2
                    continue
                if query[i] == quote:
                    i += 1
                    closed = True
                    break
                i += 1
            if not closed:
                errors.append(f"Unclosed string literal ({quote}...)")
            out.append(" ")
            continue

        out.append(ch)
        i += 1

    return "".join(out), errors


def check_balanced_delimiters(code: str) -> list[str]:
    """Ensure (), [], and {} are balanced in stripped query code."""
    pairs = {")": "(", "]": "[", "}": "{"}
    openers = set(pairs.values())
    stack: list[str] = []

    for ch in code:
        if ch in openers:
            stack.append(ch)
        elif ch in pairs:
            if not stack or stack[-1] != pairs[ch]:
                return [f"Unmatched closing delimiter '{ch}'"]
            stack.pop()

    if stack:
        return [f"Unclosed delimiter '{stack[-1]}'"]
    return []


def validate_query_file(query_path: Path) -> list[str]:
    """Validate raw KQL syntax and formatting rules."""
    errors: list[str] = []
    content = query_path.read_text(encoding="utf-8")

    if not content.strip():
        return ["Query file is empty"]

    if re.search(r"```", content):
        errors.append("Query file contains a Markdown code fence; store raw KQL only")

    stripped, lex_errors = strip_kql_comments_and_strings(content)
    errors.extend(lex_errors)
    errors.extend(check_balanced_delimiters(stripped))

    non_comment_code = stripped.strip()
    if not non_comment_code:
        errors.append("Query file contains comments only and no executable KQL")
    elif "|" not in non_comment_code:
        errors.append("KQL query should include at least one pipe operator ('|')")

    return errors


def validate_hunt(md_path: Path, repo_root: Path, seen_ids: set[str]) -> tuple[dict[str, object] | None, list[str]]:
    """Validate one hunt markdown file and its paired .kql file."""
    errors: list[str] = []
    rel = md_path.relative_to(repo_root)
    parts = rel.parts

    if len(parts) != 2:
        return None, [f"{rel}: expected path '<tactic>/<hunt>.md'"]

    dir_tactic = parts[0]
    text = md_path.read_text(encoding="utf-8")
    fm, body, fm_err = parse_frontmatter(text)
    if fm_err or fm is None:
        return None, [f"{rel}: {fm_err}"]

    missing = sorted(REQUIRED_FIELDS - set(fm.keys()))
    if missing:
        errors.append(f"{rel}: missing frontmatter fields: {', '.join(missing)}")
        return fm, errors

    hunt_id = str(fm["id"])
    if not ID_PATTERN.match(hunt_id):
        errors.append(f"{rel}: invalid id '{hunt_id}' (expected TH-KQL-<NNNN>)")
    elif hunt_id in seen_ids:
        errors.append(f"{rel}: duplicate id '{hunt_id}'")
    else:
        seen_ids.add(hunt_id)

    if str(fm["platform"]).lower() != "kql":
        errors.append(f"{rel}: platform must be 'kql'")

    tactic = str(fm["tactic"]).lower()
    if tactic not in VALID_TACTICS:
        errors.append(f"{rel}: unknown MITRE tactic '{tactic}'")
    elif tactic != dir_tactic:
        errors.append(f"{rel}: frontmatter tactic '{tactic}' does not match folder '{dir_tactic}'")

    techniques = fm["techniques"]
    if not isinstance(techniques, list) or not techniques:
        errors.append(f"{rel}: 'techniques' must be a non-empty list")
    else:
        for tech in techniques:
            if not TECHNIQUE_PATTERN.match(str(tech)):
                errors.append(f"{rel}: invalid MITRE technique ID '{tech}'")

    if str(fm["status"]).lower() not in VALID_STATUSES:
        errors.append(f"{rel}: status '{fm['status']}' must be one of {sorted(VALID_STATUSES)}")

    if str(fm["severity"]).lower() not in VALID_SEVERITIES:
        errors.append(f"{rel}: severity '{fm['severity']}' must be one of {sorted(VALID_SEVERITIES)}")

    try:
        dt.date.fromisoformat(str(fm["date"]))
    except ValueError:
        errors.append(f"{rel}: invalid ISO date '{fm['date']}' (expected YYYY-MM-DD)")

    data_sources = fm["data_sources"]
    if not isinstance(data_sources, list) or not data_sources:
        errors.append(f"{rel}: 'data_sources' must be a non-empty list")

    query_file = str(fm["query_file"])
    expected_query_name = f"{md_path.stem}.kql"
    if query_file != expected_query_name:
        errors.append(f"{rel}: query_file '{query_file}' should match '{expected_query_name}'")

    query_path = md_path.parent / query_file
    if not query_path.is_file():
        errors.append(f"{rel}: paired query file '{query_file}' does not exist")
    else:
        for q_err in validate_query_file(query_path):
            errors.append(f"{query_path.relative_to(repo_root)}: {q_err}")

    for section in REQUIRED_SECTIONS:
        if section not in body:
            errors.append(f"{rel}: missing required section '{section}'")

    return fm, errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate KQL threat hunting queries and metadata.")
    parser.add_argument("--summary", action="store_true", help="Print a summary table of validated hunts.")
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent.parent
    all_errors: list[str] = []
    seen_ids: set[str] = set()
    hunts: list[dict[str, object]] = []

    for tactic_dir in sorted(p for p in repo_root.iterdir() if p.is_dir() and p.name in VALID_TACTICS):
        for md_path in sorted(tactic_dir.glob("*.md")):
            fm, errors = validate_hunt(md_path, repo_root, seen_ids)
            all_errors.extend(errors)
            if fm and not errors:
                hunts.append(fm)

        for q_path in sorted(tactic_dir.glob("*.kql")):
            paired_md = q_path.with_suffix(".md")
            if not paired_md.is_file():
                all_errors.append(
                    f"{q_path.relative_to(repo_root)}: orphaned query file without matching '{paired_md.name}'"
                )

    if not hunts and not all_errors:
        print("No threat hunts found to validate.", file=sys.stderr)
        return 1

    if args.summary and hunts:
        print(f"Validated {len(hunts)} KQL threat hunt(s):\n")
        print(f"{'ID':<13} {'Tactic':<20} {'Techniques':<22} {'Title'}")
        print("-" * 82)
        for hunt in sorted(hunts, key=lambda h: str(h["id"])):
            techs = ", ".join(str(t) for t in hunt["techniques"])  # type: ignore[union-attr]
            print(f"{str(hunt['id']):<13} {str(hunt['tactic']):<20} {techs:<22} {hunt['title']}")
        print()

    if all_errors:
        print("Validation failed with the following error(s):", file=sys.stderr)
        for err in all_errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    print(f"SUCCESS: All {len(hunts)} KQL threat hunt(s) passed validation.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
