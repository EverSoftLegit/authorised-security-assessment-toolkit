#!/usr/bin/env python3
"""Combine toolkit/ZAP/Nmap JSON results into a draft Markdown report.

Findings are sorted by severity. Tool errors recorded in the inputs (for
example unreachable hosts or out-of-scope redirects) are listed as coverage
gaps so that a failed run is not mistaken for a clean result.
Exit codes: 0 report written, 1 report written but some inputs failed to load.
"""
from __future__ import annotations

import argparse
import html
import sys
from collections import Counter
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from toolkit.common import SEVERITIES, load_json, utc_now

UNRATED = "UNRATED"
ORDER = [*SEVERITIES, UNRATED]


def md(value: Any) -> str:
    """Make untrusted text safe for a Markdown table cell or paragraph.

    Scanner output can contain attacker-influenced strings (URLs, banners).
    HTML-escaping stops raw tags rendering in Markdown viewers; escaping
    brackets and backticks stops link or code-span injection; newlines become
    <br> so table rows stay intact.
    """
    text = html.escape(str(value if value is not None else ""), quote=False)
    for char in "\\`|[]":
        text = text.replace(char, "\\" + char)
    return text.replace("\r", " ").replace("\n", "<br>")


def normalise_severity(value: Any) -> str:
    severity = str(value or "").upper()
    if severity == "INFORMATIONAL":
        return "INFO"
    return severity if severity in SEVERITIES else UNRATED


def load_input(filename: str) -> tuple[dict[str, Any], list[dict[str, Any]], list[str]]:
    """Validate one toolkit JSON file fully before anything is added to the report."""
    document = load_json(filename)
    if not isinstance(document, dict):
        raise ValueError("top-level JSON value is not an object")
    findings = document.get("findings", [])
    if not isinstance(findings, list) or not all(isinstance(item, dict) for item in findings):
        raise ValueError("'findings' must be a list of objects")
    errors = [f"{item.get('url') or item.get('target') or item.get('resource') or 'item'}: {item['error']}"
              for item in document.get("observations", []) or []
              if isinstance(item, dict) and item.get("error")]
    return document, findings, errors


def build_report(inputs: list[str], assessment: str, client: str) -> tuple[str, int, list[str]]:
    all_findings: list[dict[str, Any]] = []
    sources: list[dict[str, str]] = []
    load_errors: list[str] = []
    coverage_gaps: list[str] = []
    for filename in inputs:
        try:
            document, findings, errors = load_input(filename)
        except (OSError, ValueError) as exc:
            load_errors.append(f"{filename}: {exc}")
            continue
        tool = str(document.get("tool", "Unknown tool"))
        sources.append({"file": filename, "tool": tool, "target": str(document.get("target", "Not specified"))})
        coverage_gaps.extend(f"{tool}: {error}" for error in errors)
        for item in findings:
            all_findings.append({**item, "severity": normalise_severity(item.get("severity")),
                                 "_source_file": filename, "_tool": tool})

    # Stable sort: highest severity first, original order within each level.
    all_findings.sort(key=lambda item: ORDER.index(item["severity"]))
    counts = Counter(item["severity"] for item in all_findings)

    lines = [
        f"# {md(assessment)}", "", f"**Client/environment:** {md(client)}  ",
        f"**Generated (UTC):** {utc_now()}  ",
        "**Classification:** CONFIDENTIAL — replace according to client policy", "",
        "> Draft generated from scanner/tool output. All observations require analyst validation; "
        "do not represent unverified alerts as confirmed vulnerabilities.", "",
        "## Executive summary", "",
        f"The imported files contain **{len(all_findings)} finding/alert record(s)**. "
        "Severity counts are tool-assigned starting points and must be reviewed by the assessment lead.", "",
    ]
    if coverage_gaps or load_errors:
        lines += [f"**Coverage warning:** {len(coverage_gaps)} tool error(s) and {len(load_errors)} "
                  "unreadable input file(s) — see the sections below. Results are incomplete.", ""]
    lines += ["| Severity | Count |", "|---|---:|"]
    for severity in ORDER:
        if severity != UNRATED or counts.get(UNRATED):
            lines.append(f"| {severity} | {counts.get(severity, 0)} |")

    lines += ["", "## Findings", ""]
    if not all_findings:
        lines.append("No findings were imported. This does not establish that the target is secure.")
    for index, item in enumerate(all_findings, 1):
        lines += [f"### {index}. {md(item.get('title') or 'Untitled finding')} — {item['severity']}", "",
                  f"**Description:** {md(item.get('description')) or 'Not supplied'}", "",
                  f"**Evidence:** {md(item.get('evidence')) or 'Not supplied'}", "",
                  f"**Recommendation:** {md(item.get('recommendation')) or 'Analyst action required'}", "",
                  f"**Source:** {md(item['_tool'])} ({md(item['_source_file'])})", "",
                  f"**Confidence:** {md(item.get('confidence')) or 'Not specified'}", ""]

    lines += ["## Imported sources", "", "| File | Tool | Target |", "|---|---|---|"]
    lines += [f"| {md(s['file'])} | {md(s['tool'])} | {md(s['target'])} |" for s in sources]
    if coverage_gaps:
        lines += ["", "## Coverage gaps (tool errors)", ""] + [f"- {md(gap)}" for gap in coverage_gaps]
    if load_errors:
        lines += ["", "## Import errors", ""] + [f"- {md(error)}" for error in load_errors]
    lines += ["", "## Analyst review checklist", "",
              "- [ ] Confirm each target and observation was within the approved scope.",
              "- [ ] Reproduce and manually validate each candidate finding.",
              "- [ ] Remove false positives and duplicate records (e.g. the same header reported by ZAP and script 02).",
              "- [ ] Confirm severity, business impact and affected assets with evidence.",
              "- [ ] Re-run or explain every coverage gap.",
              "- [ ] Ensure evidence is sanitised and contains no credentials or personal data.",
              "- [ ] Obtain review approval before delivering the report.", ""]
    return "\n".join(lines), len(all_findings), load_errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", nargs="+", help="JSON results from this toolkit's scripts")
    parser.add_argument("--assessment", default="Authorised Security Assessment")
    parser.add_argument("--client", default="Client / Lab (replace with approved name)")
    parser.add_argument("--output", default="assessment-report.md")
    args = parser.parse_args()

    report, count, load_errors = build_report(args.inputs, args.assessment, args.client)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(report, encoding="utf-8")
    print(f"Wrote {output} ({count} finding/alert record(s)); review before delivery.")
    return 1 if load_errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
