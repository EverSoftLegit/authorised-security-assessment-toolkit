#!/usr/bin/env python3
"""Combine toolkit/ZAP/Nmap JSON results into a concise Markdown report."""
import argparse
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from toolkit.common import load_json

ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def md(value) -> str:
    return str(value or "").replace("|", "\\|").replace("\r", " ").replace("\n", "<br>")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", nargs="+", help="JSON results from this toolkit, Nmap/ZAP parsers, etc.")
    parser.add_argument("--assessment", default="Authorised Security Assessment")
    parser.add_argument("--client", default="Client / Lab (replace with approved name)")
    parser.add_argument("--output", default="assessment-report.md")
    args = parser.parse_args()

    all_findings, sources, load_errors = [], [], []
    for filename in args.inputs:
        try:
            document = load_json(filename)
            findings = document.get("findings", [])
            sources.append({"file": filename, "tool": document.get("tool", "Unknown tool"),
                            "target": document.get("target", "Not specified"),
                            "note": document.get("note", "")})
            for item in findings:
                all_findings.append({**item, "_source_file": filename,
                                     "_tool": document.get("tool", "Unknown tool")})
        except (OSError, ValueError, AttributeError, TypeError) as exc:
            load_errors.append(f"{filename}: {exc}")

    counts = Counter(str(item.get("severity", "INFO")).upper() for item in all_findings)
    lines = [
        f"# {args.assessment}", "", f"**Client/environment:** {args.client}  ",
        f"**Generated (UTC):** {datetime.now(timezone.utc).isoformat(timespec='seconds')}  ",
        "**Classification:** CONFIDENTIAL — replace according to client policy", "",
        "> Draft generated from scanner/tool output. All observations require analyst validation; "
        "do not represent unverified alerts as confirmed vulnerabilities.", "",
        "## Executive summary", "",
        f"The imported files contain **{len(all_findings)} finding/alert record(s)**. "
        "Severity counts are shown below and should be reviewed by the assessment lead.", "",
        "| Severity | Count |", "|---|---:|",
    ]
    for severity in ORDER:
        lines.append(f"| {severity} | {counts.get(severity, 0)} |")
    lines += ["", "## Findings", ""]
    if not all_findings:
        lines.append("No findings were imported. This does not establish that the target is secure.")
    for index, item in enumerate(all_findings, 1):
        severity = str(item.get("severity", "INFO")).upper()
        lines += [f"### {index}. {md(item.get('title', 'Untitled finding'))} — {severity}", "",
                  f"**Description:** {md(item.get('description'))}", "",
                  f"**Evidence:** {md(item.get('evidence')) or 'Not supplied'}", "",
                  f"**Recommendation:** {md(item.get('recommendation')) or 'Analyst action required'}", "",
                  f"**Source:** {md(item.get('_tool'))} (`{md(item.get('_source_file'))}`)", "",
                  f"**Confidence:** {md(item.get('confidence')) or 'Not specified'}", ""]
    lines += ["## Imported sources", "", "| File | Tool | Target |", "|---|---|---|"]
    for source in sources:
        lines.append(f"| `{md(source['file'])}` | {md(source['tool'])} | {md(source['target'])} |")
    if load_errors:
        lines += ["", "## Import errors", ""] + [f"- {md(error)}" for error in load_errors]
    lines += ["", "## Analyst review checklist", "",
              "- [ ] Confirm each target and observation was within the approved scope.",
              "- [ ] Reproduce and manually validate each candidate finding.",
              "- [ ] Remove false positives and duplicate records.",
              "- [ ] Confirm severity, business impact and affected assets with evidence.",
              "- [ ] Ensure evidence is sanitised and contains no credentials or personal data.",
              "- [ ] Obtain review approval before delivering the report.", ""]
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(lines), encoding="utf-8")
    print(f"Wrote {output} ({len(all_findings)} finding/alert record(s)); review before delivery.")
    return 1 if load_errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
