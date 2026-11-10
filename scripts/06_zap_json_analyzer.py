#!/usr/bin/env python3
"""Normalise alerts from an OWASP ZAP "Traditional JSON" report for triage.

Alerts an analyst marked as "False Positive" in ZAP are excluded and counted.
Only instance URIs are copied: request/response evidence is deliberately left
out because it can contain session tokens or personal data.
Exit codes: 0 completed, 2 unreadable or malformed input.
"""
from __future__ import annotations

import argparse
import html
import re
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from toolkit.common import load_json, make_finding, result_document, write_json

# ZAP codes: riskcode 0-3; confidence 0 = False Positive ... 4 = Confirmed.
RISK_BY_CODE = {"0": "INFO", "1": "LOW", "2": "MEDIUM", "3": "HIGH"}
RISK_BY_NAME = {"informational": "INFO", "info": "INFO", "low": "LOW", "medium": "MEDIUM", "high": "HIGH"}
CONFIDENCE_BY_CODE = {"0": "False Positive", "1": "Low", "2": "Medium", "3": "High", "4": "Confirmed"}


def strip_html(value: Any) -> str:
    """ZAP descriptions contain <p> markup; reduce to plain text for the report."""
    text = re.sub(r"<[^>]+>", " ", str(value or ""))
    return re.sub(r"\s+", " ", html.unescape(text)).strip()


def alert_severity(alert: dict[str, Any]) -> str:
    """Prefer the numeric riskcode; fall back to 'risk' or the first word of 'riskdesc'."""
    code = str(alert.get("riskcode", "")).strip()
    if code in RISK_BY_CODE:
        return RISK_BY_CODE[code]
    text = str(alert.get("risk") or alert.get("riskdesc") or "").strip()
    return RISK_BY_NAME.get(text.split(" ")[0].lower() if text else "", "INFO")


def alert_confidence(alert: dict[str, Any]) -> str:
    raw = str(alert.get("confidence", "")).strip()
    return CONFIDENCE_BY_CODE.get(raw, raw or "Not stated")


def analyse(report: Any) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, int]]:
    """Return (findings, observations, counters) from a loaded ZAP JSON document."""
    if not isinstance(report, dict):
        raise ValueError("ZAP report must be a JSON object")
    sites = report.get("site", [])
    if isinstance(sites, dict):  # some ZAP versions emit a single site as an object
        sites = [sites]
    if not isinstance(sites, list):
        raise ValueError("'site' must be a list or object")

    findings, observations = [], []
    counters = {"false_positives_excluded": 0, "malformed_alerts_skipped": 0, "duplicates_skipped": 0}
    seen: set[tuple[Any, ...]] = set()
    for site in sites:
        if not isinstance(site, dict):
            counters["malformed_alerts_skipped"] += 1
            continue
        site_name = str(site.get("@name") or site.get("name") or "unknown site")
        for alert in site.get("alerts", []) or []:
            if not isinstance(alert, dict):
                counters["malformed_alerts_skipped"] += 1
                continue
            confidence = alert_confidence(alert)
            if confidence == "False Positive":
                counters["false_positives_excluded"] += 1
                continue
            title = str(alert.get("alert") or alert.get("name") or "Unnamed ZAP alert")
            severity = alert_severity(alert)
            instances = [i for i in alert.get("instances", []) or [] if isinstance(i, dict)]
            uris = sorted({str(i["uri"]) for i in instances if i.get("uri")})
            key = (site_name, title, severity, tuple(uris))
            if key in seen:
                counters["duplicates_skipped"] += 1
                continue
            seen.add(key)

            evidence_parts = [f"Site: {site_name}", f"Instances: {len(instances)}",
                              f"Scanner confidence: {confidence}"]
            if uris:
                more = f" (+{len(uris) - 20} more)" if len(uris) > 20 else ""
                evidence_parts.append("Affected URI(s): " + ", ".join(uris[:20]) + more)
            findings.append(make_finding(
                title, severity,
                strip_html(alert.get("desc")) or "No description supplied by the scanner.",
                evidence="\n".join(evidence_parts),
                recommendation=strip_html(alert.get("solution")) or "Review the scanner recommendation and validate manually.",
                source="OWASP ZAP JSON report",
                confidence=f"Scanner-generated ({confidence}); requires manual validation",
            ))
            observations.append({"site": site_name, "alert": title, "risk": severity, "confidence": confidence,
                                 "instance_count": len(instances), "cweid": alert.get("cweid"),
                                 "pluginid": alert.get("pluginid")})
    return findings, observations, counters


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("json_file", help="OWASP ZAP JSON report")
    parser.add_argument("--output", help="JSON output path")
    args = parser.parse_args()
    try:
        findings, observations, counters = analyse(load_json(args.json_file))
    except (OSError, ValueError) as exc:  # json.JSONDecodeError is a ValueError
        parser.error(f"Cannot read input: {exc}")

    document = result_document("owasp-zap-json-analyser", str(args.json_file), findings,
                               observations=observations, **counters,
                               note="Scanner alerts are leads for triage; confirm exploitability and impact "
                                    "before reporting as verified findings.")
    write_json(document, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
