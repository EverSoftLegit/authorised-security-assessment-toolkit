#!/usr/bin/env python3
"""Inspect TLS certificate metadata for authorised HTTPS hosts.

Makes one TLS handshake per target. Certificate verification remains enabled.
"""
import argparse
import socket
import ssl
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from toolkit.common import Scope, ScopeError, make_finding, result_document, write_json


def parse_target(value: str) -> tuple[str, int, str]:
    candidate = value if "://" in value else "https://" + value
    parsed = urllib.parse.urlsplit(candidate)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("Target must be an HTTPS URL or hostname[:port]")
    return parsed.hostname, parsed.port or 443, candidate


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope", required=True, help="Authorised scope JSON")
    parser.add_argument("targets", nargs="+", help="HTTPS URLs or host[:port] values")
    parser.add_argument("--timeout", type=float, default=6.0)
    parser.add_argument("--warn-days", type=int, default=30)
    parser.add_argument("--output", help="JSON output path")
    args = parser.parse_args()
    scope = Scope.from_file(args.scope)
    findings, observations = [], []
    context = ssl.create_default_context()
    for target in args.targets:
        try:
            host, port, url = parse_target(target)
            scope.check_url(url)
            with socket.create_connection((host, port), timeout=args.timeout) as raw_sock:
                with context.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                    cert = tls_sock.getpeercert()
                    not_after = cert.get("notAfter")
                    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc) if not_after else None
                    days_left = (expiry - datetime.now(timezone.utc)).days if expiry else None
                    sans = [value for kind, value in cert.get("subjectAltName", []) if kind == "DNS"]
                    observations.append({"target": target, "tls_version": tls_sock.version(),
                                         "cipher": tls_sock.cipher()[0] if tls_sock.cipher() else None,
                                         "issuer": cert.get("issuer"), "subject_alt_names": sans,
                                         "not_after": expiry.isoformat() if expiry else None,
                                         "days_until_expiry": days_left})
                    if days_left is not None and days_left < args.warn_days:
                        findings.append(make_finding(
                            "TLS certificate nearing expiry", "MEDIUM" if days_left >= 0 else "HIGH",
                            "The certificate validity period is near its end or has expired.",
                            evidence=f"{target}: {days_left} day(s) remaining; notAfter={not_after}",
                            recommendation="Renew the certificate and verify automated renewal and deployment.",
                            source="TLS certificate metadata"
                        ))
        except ssl.SSLCertVerificationError as exc:
            observations.append({"target": target, "error": f"Certificate verification failed: {exc}"})
            findings.append(make_finding(
                "TLS certificate validation failed", "HIGH",
                "The TLS handshake failed certificate validation. The precise cause requires review.",
                evidence=str(exc), recommendation="Check certificate validity, hostname matching, chain completeness and trust configuration.",
                source="TLS handshake"
            ))
        except (ScopeError, OSError, ValueError, ssl.SSLError) as exc:
            observations.append({"target": target, "error": str(exc)})
    document = result_document("tls-certificate-audit", ", ".join(args.targets), findings,
                               observations=observations,
                               note="Only certificate metadata is inspected; no protocol downgrade or cipher-enumeration tests are performed.")
    write_json(document, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
