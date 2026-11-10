#!/usr/bin/env python3
"""Summarise an existing Nmap XML file; this script does not run Nmap."""
import argparse
import xml.etree.ElementTree as ET
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from toolkit.common import make_finding, result_document, write_json

PORT_GUIDANCE = {
    21: ("MEDIUM", "FTP is exposed; review whether plaintext authentication or unnecessary anonymous access is possible."),
    23: ("HIGH", "Telnet is exposed; replace with an encrypted management protocol where possible."),
    445: ("MEDIUM", "SMB is exposed; verify network restrictions, patching and share permissions."),
    1433: ("MEDIUM", "A Microsoft SQL Server port is exposed; verify intended network reachability and authentication controls."),
    3306: ("MEDIUM", "A MySQL service port is exposed; verify that database access is restricted to required clients."),
    3389: ("MEDIUM", "RDP is exposed; verify access restrictions, MFA and secure remote-access controls."),
    5432: ("MEDIUM", "A PostgreSQL service port is exposed; verify network reachability and authentication controls."),
    6379: ("MEDIUM", "A Redis service port is exposed; verify network restrictions and authentication configuration."),
    9200: ("MEDIUM", "An Elasticsearch HTTP port is exposed; verify authentication and network restrictions."),
    27017: ("MEDIUM", "A MongoDB service port is exposed; verify authentication and network restrictions."),
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("xml_file", help="Nmap XML output produced separately with -oX")
    parser.add_argument("--output", help="JSON output path")
    args = parser.parse_args()
    root = ET.parse(args.xml_file).getroot()
    hosts, findings = [], []
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue
        addresses = [node.get("addr", "") for node in host.findall("address")]
        hostnames = [node.get("name", "") for node in host.findall("hostnames/hostname")]
        open_ports = []
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port.find("service")
            record = {"protocol": port.get("protocol"), "port": int(port.get("portid", "0")),
                      "service": service.get("name") if service is not None else None,
                      "product": service.get("product") if service is not None else None,
                      "version": service.get("version") if service is not None else None}
            open_ports.append(record)
            guidance = PORT_GUIDANCE.get(record["port"])
            if guidance:
                severity, description = guidance
                findings.append(make_finding(
                    f"Review exposed {record['service'] or 'service'} port {record['port']}", severity,
                    description,
                    evidence=f"Host: {', '.join(addresses)}; port: {record['port']}/{record['protocol']}; "
                             f"service: {record['service']}; product/version: {record['product']} {record['version']}",
                    recommendation="Confirm business need, restrict source networks, harden service configuration and validate patch level.",
                    source="Nmap XML", confidence="Exposure indicator only; not proof of vulnerability"
                ))
        hosts.append({"addresses": addresses, "hostnames": hostnames, "open_ports": open_ports})
    document = result_document("nmap-xml-analyser", str(args.xml_file), findings, hosts=hosts,
                               note="Open ports are exposure observations, not confirmed vulnerabilities. Validate service context manually.")
    write_json(document, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
