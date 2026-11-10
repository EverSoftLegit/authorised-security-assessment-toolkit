#!/usr/bin/env python3
"""Inspect TLS certificate metadata for authorised HTTPS hosts.

One verified TLS handshake per target; scope is checked before connecting.
Because verification stays on, an expired, self-signed, or mismatched
certificate surfaces as a verification failure (with OpenSSL's reason) rather
than as parsed metadata. Use --cafile for hosts signed by a private CA.
Exit codes: 0 completed, 1 completed with errors, 2 bad input.
"""
from __future__ import annotations

import argparse
import socket
import ssl
import sys
import time
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from toolkit.common import Scope, ScopeError, make_finding, result_document, write_json


def parse_target(value: str) -> tuple[str, int, str]:
    """Accept https://host[:port] or host[:port]; return (host, port, url)."""
    candidate = value if "://" in value else "https://" + value
    parsed = urllib.parse.urlsplit(candidate)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("Target must be an HTTPS URL or hostname[:port]")
    port = parsed.port  # raises ValueError for out-of-range ports
    return parsed.hostname, (port if port is not None else 443), candidate


def name_to_text(name: Any) -> str:
    """Flatten getpeercert()'s nested ((('CN', 'x'),),) structure to 'CN=x, O=y'."""
    return ", ".join(f"{key}={value}" for rdn in name or () for key, value in rdn)


def describe_certificate(cert: dict[str, Any], now: float | None = None) -> dict[str, Any]:
    """Pure helper so expiry maths can be unit-tested without a network."""
    now = time.time() if now is None else now
    not_after = cert.get("notAfter")
    # ssl.cert_time_to_seconds parses OpenSSL's GMT format independent of locale.
    expiry = ssl.cert_time_to_seconds(not_after) if not_after else None
    return {
        "subject": name_to_text(cert.get("subject")),
        "issuer": name_to_text(cert.get("issuer")),
        "subject_alt_names": [f"{kind}:{value}" for kind, value in cert.get("subjectAltName", ())],
        "not_after": datetime.fromtimestamp(expiry, timezone.utc).isoformat() if expiry else None,
        "days_until_expiry": int((expiry - now) // 86400) if expiry else None,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope", required=True, help="Authorised scope JSON")
    parser.add_argument("targets", nargs="+", help="HTTPS URLs or host[:port] values")
    parser.add_argument("--timeout", type=float, default=6.0)
    parser.add_argument("--warn-days", type=int, default=14,
                        help="Flag certificates expiring within this many days (default 14)")
    parser.add_argument("--cafile", help="Additional trusted CA bundle (e.g. an internal PKI root)")
    parser.add_argument("--output", help="JSON output path")
    args = parser.parse_args()
    try:
        scope = Scope.from_file(args.scope)
        context = ssl.create_default_context(cafile=args.cafile)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))

    findings: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []
    for target in args.targets:
        try:
            host, port, url = parse_target(target)
            scope.check_url(url)  # before any DNS lookup or connection
            with socket.create_connection((host, port), timeout=args.timeout) as raw_sock:
                with context.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                    details = describe_certificate(tls_sock.getpeercert())
                    cipher = tls_sock.cipher()
                    observations.append({
                        "target": target,
                        "connected_ip": tls_sock.getpeername()[0],  # evidence of where DNS pointed
                        "tls_version": tls_sock.version(),
                        "cipher": cipher[0] if cipher else None,
                        **details,
                    })
            days_left = details["days_until_expiry"]
            if days_left is not None and days_left < args.warn_days:
                findings.append(make_finding(
                    f"TLS certificate expires within {args.warn_days} days", "LOW",
                    "The certificate is valid but close to expiry. Short-lived certificates with automated "
                    "renewal routinely reach this window; confirm renewal is working before escalating.",
                    evidence=f"{target}: {days_left} day(s) remaining; notAfter={details['not_after']}",
                    recommendation="Confirm automated renewal and deployment, or renew manually.",
                    source="TLS certificate metadata",
                ))
        except ssl.SSLCertVerificationError as exc:
            # Must come before OSError: SSLCertVerificationError is a subclass of it.
            reason = exc.verify_message or str(exc)
            observations.append({"target": target, "error": f"Certificate verification failed: {reason}",
                                 "verify_code": exc.verify_code})
            findings.append(make_finding(
                f"TLS certificate verification failed ({reason})", "MEDIUM",
                "The handshake failed certificate validation from this machine's trust store. Causes include "
                "expiry, hostname mismatch, an incomplete chain, or a private CA not trusted locally.",
                evidence=f"{target}: OpenSSL verify code {exc.verify_code}: {reason}",
                recommendation="Confirm the cause; if the host uses an internal CA, re-run with --cafile "
                               "before reporting. Otherwise fix validity, hostname, or chain configuration.",
                source="TLS handshake",
            ))
        except (ScopeError, OSError, ValueError) as exc:  # OSError includes ssl.SSLError and DNS errors
            observations.append({"target": target, "error": f"{type(exc).__name__}: {exc}"})

    document = result_document("tls-certificate-audit", ", ".join(args.targets), findings,
                               observations=observations,
                               note="Only certificate metadata from one verified handshake is inspected; "
                                    "no protocol-version or cipher-suite enumeration is performed.")
    write_json(document, args.output)
    return 1 if any("error" in item for item in observations) else 0


if __name__ == "__main__":
    raise SystemExit(main())
