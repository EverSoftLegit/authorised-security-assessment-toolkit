#!/usr/bin/env python3
"""Review common HTTP security headers on explicitly in-scope web URLs.

One bounded HEAD request per URL (GET fallback for 405/501), with every
redirect destination scope-checked before it is requested. It does not crawl,
fuzz, authenticate, or exploit the application.
Exit codes: 0 completed, 1 completed with request/scope errors, 2 bad input.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from toolkit.common import (
    RequestError, Scope, ScopeError, make_finding, result_document, safe_http_request, write_json,
)

# Ratings are starting points for triage. A missing header is a hardening gap,
# not a demonstrated vulnerability, so nothing here is rated above LOW.
# Referrer-Policy: modern browsers already default to strict-origin-when-cross-origin.
CHECKS = [
    ("content-security-policy", "LOW", "Content-Security-Policy is absent.",
     "Define a restrictive CSP appropriate to the application; test it in report-only mode first."),
    ("x-content-type-options", "INFO", "X-Content-Type-Options is absent.",
     "Set X-Content-Type-Options: nosniff."),
    ("referrer-policy", "INFO", "Referrer-Policy is absent (browser default applies).",
     "Set an explicit Referrer-Policy, such as strict-origin-when-cross-origin."),
    ("permissions-policy", "INFO", "Permissions-Policy is absent.",
     "Explicitly disable browser features the application does not need."),
]
HEADER_CONFIDENCE = "Informational indicator; manually assess application context"


def read_targets(urls: list[str] | None, file: str | None) -> list[str]:
    values = list(urls or [])
    if file:
        values.extend(line.strip() for line in Path(file).read_text(encoding="utf-8").splitlines()
                      if line.strip() and not line.lstrip().startswith("#"))
    return list(dict.fromkeys(values))  # de-duplicate, keep order


def hsts_max_age(value: str) -> int | None:
    """Return the max-age directive in seconds, or None if missing/unparsable."""
    match = re.search(r"max-age\s*=\s*\"?(\d+)\"?", value, re.IGNORECASE)
    return int(match.group(1)) if match else None


def evaluate_headers(final_url: str, status: int, headers: dict[str, str]) -> list[dict[str, Any]]:
    """Pure function (no I/O) so it can be unit-tested with plain dictionaries."""
    findings = []
    evidence = f"{final_url} returned HTTP {status}"
    for header, severity, description, recommendation in CHECKS:
        if header not in headers:
            findings.append(make_finding(
                f"Missing {header}", severity, description,
                evidence=f"{evidence} without {header}.", recommendation=recommendation,
                source="HTTP response headers", confidence=HEADER_CONFIDENCE,
            ))

    if final_url.startswith("https://"):
        hsts = headers.get("strict-transport-security")
        max_age = hsts_max_age(hsts) if hsts else None
        if not max_age:  # absent, unparsable, or max-age=0 (which disables HSTS)
            findings.append(make_finding(
                "Strict-Transport-Security absent or disabled", "LOW",
                "The HTTPS response did not include an HSTS policy with a positive max-age.",
                evidence=f"{evidence}; Strict-Transport-Security: {hsts or '(absent)'}",
                recommendation="Enable HSTS after confirming all relevant subdomains support HTTPS.",
                source="HTTP response headers", confidence=HEADER_CONFIDENCE,
            ))

    # Framing only matters for HTML documents; skip APIs, images, etc.
    if "text/html" in headers.get("content-type", "").lower():
        csp = headers.get("content-security-policy", "").lower()
        if "x-frame-options" not in headers and "frame-ancestors" not in csp:
            findings.append(make_finding(
                "No anti-framing header observed", "LOW",
                "The HTML response has neither X-Frame-Options nor a CSP frame-ancestors directive. "
                "Clickjacking impact depends on whether the page offers state-changing actions.",
                evidence=evidence, source="HTTP response headers", confidence=HEADER_CONFIDENCE,
                recommendation="Set CSP frame-ancestors (or X-Frame-Options) according to embedding requirements.",
            ))
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope", required=True, help="Authorised scope JSON")
    parser.add_argument("--url", action="append", help="In-scope URL; can be repeated")
    parser.add_argument("--file", help="File containing one URL per line")
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--output", help="JSON output path")
    args = parser.parse_args()
    try:
        scope = Scope.from_file(args.scope)
        targets = read_targets(args.url, args.file)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    if not targets:
        parser.error("Provide at least one --url or --file")

    findings: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []
    for url in targets:
        try:
            # safe_http_request scope-checks the URL and every redirect before connecting.
            result = safe_http_request(url, scope, method="HEAD", timeout=args.timeout, max_bytes=1024)
            method = "HEAD"
            if result.status in {405, 501}:
                result = safe_http_request(url, scope, method="GET", timeout=args.timeout, max_bytes=1024)
                method = "GET"
            observation = {"url": url, "final_url": result.final_url, "method": method,
                           "http_status": result.status, "redirect_chain": result.redirect_chain,
                           "headers_observed": sorted(result.headers)}
            if result.status >= 300:
                # Error pages and unfollowed redirects often lack the application's headers.
                observation["note"] = "Header checks skipped: final response was not 2xx."
            else:
                findings.extend(evaluate_headers(result.final_url, result.status, result.headers))
            observations.append(observation)
        except (ScopeError, RequestError) as exc:
            observations.append({"url": url, "error": str(exc)})

    document = result_document("http-security-header-audit", ", ".join(targets), findings,
                               observations=observations,
                               note="Header absence is a hardening signal, not proof of an exploitable vulnerability.")
    write_json(document, args.output)
    return 1 if any("error" in item for item in observations) else 0


if __name__ == "__main__":
    raise SystemExit(main())
