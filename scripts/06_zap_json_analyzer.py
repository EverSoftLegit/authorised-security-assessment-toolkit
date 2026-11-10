#!/usr/bin/env python3
"""Normalise alerts from an OWASP ZAP JSON report for triage and reporting."""
import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from toolkit.common import load_json, make_finding, result_document, write_json

SEVERITY = {"high": "HIGH", "medium": "MEDIUM", "low": "LOW", "informational": "INFO", "info": "INFO"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("json_file", help="OWASP ZAP JSON report")
    parser.add_argument("--output", help="JSON output path")
    args = parser.parse_args()
    report = load_json(args.json_file)
    sites = report.get("site", []) if isinstance(report, dict) else []
    findings, observations = [], []
    seen = set()
    for site in sites:
        site_name = site.get("name", "unknown site")
        for alert in site.get("alerts", []):
            title = alert.get("alert", "Unnamed ZAP alert")
            risk = alert.get("risk", alert.get("riskdesc", "Informational")).split(" ")[0].lower()
            severity = SEVERITY.get(risk, "INFO")
            instances = alert.get("instances", [])
            uris = sorted({item.get("uri", "") for item in instances if item.get("uri")})
            key = (site_name, title, severity, tuple(uris))
            if key in seen:
                continue
            seen.add(key)
            evidence_parts = [f"Site: {site_name}", f"Instances: {len(instances)}"]
            if uris:
                evidence_parts.append("Affected URI(s): " + ", ".join(uris[:20]))
            if alert.get("confidence"):
                evidence_parts.append("Scanner confidence: " + str(alert["confidence"]))
            findings.append(make_finding(
                title, severity,
                alert.get("desc", "No description supplied by the scanner."),
                evidence="\n".join(evidence_parts),
                recommendation=alert.get("solution", "Review the scanner recommendation and validate manually."),
                source="OWASP ZAP JSON report",
                confidence="Scanner-generated; requires manual validation"
            ))
            observations.append({"site": site_name, "alert": title, "risk": severity,
                                 "instance_count": len(instances), "cweid": alert.get("cweid"),
                                 "pluginid": alert.get("pluginid")})
    document = result_document("owasp-zap-json-analyser", str(args.json_file), findings,
                               observations=observations,
                               note="Scanner alerts are leads for triage; confirm exploitability and impact before reporting as verified findings.")
    write_json(document, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
