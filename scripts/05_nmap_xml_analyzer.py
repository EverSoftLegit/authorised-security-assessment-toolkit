#!/usr/bin/env python3
"""Summarise an existing Nmap XML file; this script does not run Nmap.

Optionally pass --scope to label hosts that are not in the approved scope, so
that results from an over-broad scan are not reported by mistake.
Exit codes: 0 completed, 2 unreadable or malformed input.
"""
from __future__ import annotations

import argparse
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from toolkit.common import Scope, make_finding, result_document, write_json

# Keyed by TCP port only: the port tells us what is *conventionally* there.
# The description always shows what Nmap actually reported, because a service
# can run on a non-standard port (or a different service on a standard one).
# Severities are starting points; they ignore vantage point (internet vs internal).
PORT_GUIDANCE: dict[int, tuple[str, str, str]] = {
    21: ("FTP", "MEDIUM", "review whether plaintext authentication or anonymous access is possible."),
    23: ("Telnet", "HIGH", "replace with an encrypted management protocol where possible."),
    445: ("SMB", "MEDIUM", "verify network restrictions, patching and share permissions."),
    1433: ("Microsoft SQL Server", "MEDIUM", "verify intended reachability and authentication controls."),
    3306: ("MySQL", "MEDIUM", "verify that database access is restricted to required clients."),
    3389: ("RDP", "MEDIUM", "verify access restrictions, MFA and secure remote-access controls."),
    5432: ("PostgreSQL", "MEDIUM", "verify network reachability and authentication controls."),
    6379: ("Redis", "MEDIUM", "verify network restrictions and authentication configuration."),
    9200: ("Elasticsearch HTTP", "MEDIUM", "verify authentication and network restrictions."),
    27017: ("MongoDB", "MEDIUM", "verify authentication and network restrictions."),
}


def parse_nmap_xml(path: str | Path) -> ET.Element:
    root = ET.parse(path).getroot()  # local analyst-supplied file
    if root.tag != "nmaprun":
        raise ValueError(f"Expected <nmaprun> root element, found <{root.tag}>")
    return root


def analyse(root: ET.Element, scope: Scope | None = None) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    """Return (hosts, findings, warnings) from a parsed <nmaprun> element."""
    hosts, findings, warnings = [], [], []
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue
        ips = [n.get("addr", "") for n in host.findall("address") if n.get("addrtype") in {"ipv4", "ipv6"}]
        hostnames = [n.get("name", "") for n in host.findall("hostnames/hostname")]
        in_scope = None
        if scope is not None:
            in_scope = any(_safe_allows(scope, ip) for ip in ips)
        open_ports = []
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue  # "open|filtered" and "filtered" are not counted as exposure
            try:
                number = int(port.get("portid", ""))
            except ValueError:
                warnings.append(f"Skipped port with invalid portid {port.get('portid')!r} on {ips}")
                continue
            service = port.find("service")
            record = {"protocol": port.get("protocol"), "port": number,
                      "service": service.get("name") if service is not None else None,
                      "product": service.get("product") if service is not None else None,
                      "version": service.get("version") if service is not None else None}
            open_ports.append(record)

            guidance = PORT_GUIDANCE.get(number) if record["protocol"] == "tcp" else None
            if not guidance:
                continue
            label, severity, advice = guidance
            reported = record["service"] or "unknown"
            version = " ".join(v for v in (record["product"], record["version"]) if v) or "not identified"
            scope_note = "" if in_scope is not False else " HOST NOT IN SUPPLIED SCOPE - do not report without confirmation."
            findings.append(make_finding(
                f"Review exposed TCP {number} ({label} port; Nmap service: {reported})", severity,
                f"TCP {number} is conventionally used by {label}; {advice}"
                f" Nmap identified the service as '{reported}'.{scope_note}",
                evidence=f"Host: {', '.join(ips)}; port: {number}/tcp; service: {reported}; product/version: {version}",
                recommendation="Confirm business need, restrict source networks, harden configuration and validate patch level.",
                source="Nmap XML", confidence="Exposure indicator from the scan's vantage point; not proof of vulnerability",
            ))
        hosts.append({"addresses": ips, "hostnames": hostnames, "in_scope": in_scope, "open_ports": open_ports})
    return hosts, findings, warnings


def _safe_allows(scope: Scope, ip: str) -> bool:
    try:
        return scope.allows_host(ip)
    except ValueError:
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("xml_file", help="Nmap XML output produced separately with -oX")
    parser.add_argument("--scope", help="Optional scope JSON used to label out-of-scope hosts")
    parser.add_argument("--output", help="JSON output path")
    args = parser.parse_args()
    try:
        scope = Scope.from_file(args.scope) if args.scope else None
        root = parse_nmap_xml(args.xml_file)
    except (OSError, ValueError, ET.ParseError) as exc:
        parser.error(f"Cannot read input: {exc}")

    hosts, findings, warnings = analyse(root, scope)
    document = result_document("nmap-xml-analyser", str(args.xml_file), findings, hosts=hosts,
                               parse_warnings=warnings, scan_args=root.get("args"),
                               note="Open ports are exposure observations, not confirmed vulnerabilities. "
                                    "Validate service context manually.")
    write_json(document, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
