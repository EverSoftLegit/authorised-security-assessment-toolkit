#!/usr/bin/env python3
"""Review common HTTP security headers on explicitly in-scope web URLs.

This performs one bounded HEAD request per URL (GET fallback for 405/501).
It does not crawl, fuzz, authenticate, or exploit the application.
"""
import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from toolkit.common import Scope, ScopeError, make_finding, result_document, safe_http_request, write_json

CHECKS = [
    ("content-security-policy", "MEDIUM", "Content-Security-Policy is absent.", "Define a restrictive CSP appropriate to the application; test it before enforcement."),
    ("x-content-type-options", "LOW", "X-Content-Type-Options is absent.", "Set X-Content-Type-Options: nosniff."),
    ("referrer-policy", "LOW", "Referrer-Policy is absent.", "Set a privacy-conscious Referrer-Policy, such as strict-origin-when-cross-origin."),
    ("permissions-policy", "LOW", "Permissions-Policy is absent.", "Explicitly disable browser features the application does not need."),
]


def read_targets(args) -> list[str]:
    values = list(args.url or [])
    if args.file:
        values.extend(line.strip() for line in Path(args.file).read_text(encoding="utf-8").splitlines()
                      if line.strip() and not line.lstrip().startswith("#"))
    return list(dict.fromkeys(values))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope", required=True, help="Authorised scope JSON")
    parser.add_argument("--url", action="append", help="In-scope URL; can be repeated")
    parser.add_argument("--file", help="File containing one URL per line")
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--output", help="JSON output path")
    args = parser.parse_args()
    targets = read_targets(args)
    if not targets:
        parser.error("Provide at least one --url or --file")
    scope = Scope.from_file(args.scope)
    findings, observations = [], []
    for url in targets:
        try:
            scope.check_url(url)
            status, headers, _body, final_url = safe_http_request(
                url, scope, method="HEAD", timeout=args.timeout, max_bytes=1024
            )
            if status in {405, 501}:
                status, headers, _body, final_url = safe_http_request(
                    url, scope, method="GET", timeout=args.timeout, max_bytes=1024
                )
            observations.append({"url": url, "final_url": final_url, "http_status": status,
                                 "headers_observed": sorted(headers.keys())})
            for header, severity, description, recommendation in CHECKS:
                if header not in headers:
                    findings.append(make_finding(
                        f"Missing {header}", severity, description,
                        evidence=f"{final_url} returned HTTP {status} without {header}.",
                        recommendation=recommendation, source="HTTP response headers",
                        confidence="Informational indicator; manually assess application context"
                    ))
            if final_url.startswith("https://") and "strict-transport-security" not in headers:
                findings.append(make_finding(
                    "Strict-Transport-Security header absent", "LOW",
                    "The HTTPS response did not include HSTS.",
                    evidence=final_url, recommendation="Consider enabling HSTS after confirming all relevant subdomains support HTTPS.",
                    source="HTTP response headers"
                ))
            if "x-frame-options" not in headers and "content-security-policy" in headers and "frame-ancestors" not in headers["content-security-policy"].lower():
                findings.append(make_finding(
                    "Clickjacking protection requires review", "LOW",
                    "X-Frame-Options is absent and the observed CSP does not appear to include frame-ancestors.",
                    evidence=final_url, recommendation="Set CSP frame-ancestors or X-Frame-Options according to the application's embedding requirements.",
                    source="HTTP response headers"
                ))
        except (ScopeError, RuntimeError, ValueError) as exc:
            observations.append({"url": url, "error": str(exc)})
    document = result_document("http-security-header-audit", ", ".join(targets), findings, observations=observations,
                               note="Header absence is a hardening signal, not proof of an exploitable vulnerability.")
    write_json(document, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
