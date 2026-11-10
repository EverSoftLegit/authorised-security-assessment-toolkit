#!/usr/bin/env python3
"""Collect sitemap/robots.txt references without crawling application pages.

Only /robots.txt, /sitemap.xml and a small bounded number of further sitemap
documents are requested; safe_http_request scope-checks each one and every
redirect. Listed page URLs are recorded (if in scope) but never requested.
Exit codes: 0 completed, 1 completed with errors, 2 bad input.
"""
from __future__ import annotations

import argparse
import sys
import urllib.parse
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from toolkit.common import (
    RequestError, Scope, ScopeError, make_finding, parse_untrusted_xml, result_document,
    safe_http_request, write_json,
)

MAX_SITEMAPS = 5           # documents fetched, including /sitemap.xml
MAX_URLS = 500             # inventory entries kept
MAX_IGNORED_SAMPLES = 20   # out-of-scope entries echoed back as examples


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].lower()


def parse_sitemap(xml_bytes: bytes) -> tuple[list[str], list[str]]:
    """Return (page_urls, child_sitemaps) from a <urlset> or <sitemapindex>.

    Only <url>/<loc> and <sitemap>/<loc> are read, so extension elements such
    as <image:image><image:loc> are not mistaken for pages. Documents with a
    DTD are refused by parse_untrusted_xml (see toolkit/common.py).
    """
    root = parse_untrusted_xml(xml_bytes)
    kind = local_name(root.tag)
    if kind not in {"urlset", "sitemapindex"}:
        raise ValueError(f"Not a sitemap document (root element <{kind}>)")
    entry_tag = "url" if kind == "urlset" else "sitemap"
    locations = []
    for entry in root:
        if local_name(entry.tag) != entry_tag:
            continue
        for child in entry:
            if local_name(child.tag) == "loc" and child.text and child.text.strip():
                locations.append(child.text.strip())
    return (locations, []) if kind == "urlset" else ([], locations)


def parse_robots(text: str, robots_url: str) -> tuple[list[str], list[str]]:
    """Return (disallow_paths, sitemap_urls). Comments and empty Disallow lines are ignored."""
    disallows, sitemaps = [], []
    for line in text.splitlines():
        stripped = line.split("#", 1)[0].strip()
        field, sep, value = stripped.partition(":")
        if not sep:
            continue
        field, value = field.strip().lower(), value.strip()
        if field == "disallow" and value:
            disallows.append(value)
        elif field == "sitemap" and value:
            sitemaps.append(urllib.parse.urljoin(robots_url, value))  # resolve relative entries
    return disallows, sitemaps


def origin_of(base_url: str) -> str:
    """Reduce --base-url to scheme://host[:port]; reject paths, queries, and fragments."""
    parsed = urllib.parse.urlsplit(base_url)
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("--base-url must be an origin such as https://app.example.test")
    return f"{parsed.scheme}://{parsed.netloc}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope", required=True, help="Authorised scope JSON")
    parser.add_argument("--base-url", required=True, help="In-scope site origin, e.g. https://app.example.test")
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--output", help="JSON output path")
    args = parser.parse_args()
    try:
        scope = Scope.from_file(args.scope)
        base = origin_of(args.base_url)
        scope.check_url(base + "/")
    except (OSError, ValueError) as exc:  # ScopeError is a ValueError
        parser.error(str(exc))

    observations: list[dict[str, Any]] = []
    urls: set[str] = set()
    disallows: list[str] = []
    ignored: list[str] = []
    ignored_count = 0
    inventory_capped = False

    robots_url = base + "/robots.txt"
    sitemap_queue = [base + "/sitemap.xml"]
    try:
        robots = safe_http_request(robots_url, scope, timeout=args.timeout, max_bytes=200_000)
        observations.append({"resource": "robots.txt", "url": robots.final_url, "status": robots.status})
        if robots.status < 300:
            disallows, robot_sitemaps = parse_robots(robots.body.decode("utf-8", errors="replace"),
                                                     robots.final_url)
            sitemap_queue.extend(robot_sitemaps)
    except (ScopeError, RequestError) as exc:
        observations.append({"resource": "robots.txt", "url": robots_url, "error": str(exc)})

    visited: set[str] = set()
    while sitemap_queue and len(visited) < MAX_SITEMAPS and not inventory_capped:
        sitemap = sitemap_queue.pop(0)
        if sitemap in visited:
            continue
        visited.add(sitemap)
        try:
            result = safe_http_request(sitemap, scope, timeout=args.timeout, max_bytes=1_000_000)
            visited.add(result.final_url)
            observations.append({"resource": "sitemap", "url": result.final_url, "status": result.status})
            if result.status >= 300:
                continue
            if result.truncated:
                raise ValueError("Sitemap exceeded 1,000,000 bytes and was truncated; not parsed")
            page_urls, child_sitemaps = parse_sitemap(result.body)
            for item in page_urls:
                try:
                    scope.check_url(item)  # recorded only; never requested
                except ScopeError:
                    ignored_count += 1
                    if len(ignored) < MAX_IGNORED_SAMPLES:
                        ignored.append(item)
                    continue
                if len(urls) >= MAX_URLS:
                    inventory_capped = True
                    break
                urls.add(item)
            sitemap_queue.extend(child for child in child_sitemaps if child not in visited)
        except (ScopeError, RequestError, ValueError, ET.ParseError) as exc:
            observations.append({"resource": "sitemap", "url": sitemap, "error": str(exc)})

    findings = []
    if disallows:
        findings.append(make_finding(
            "Robots.txt disallow directives observed", "INFO",
            "robots.txt lists paths crawlers are asked to avoid. These directives are not access controls "
            "and may point to areas worth manual review.",
            evidence="\n".join(disallows[:100]),
            recommendation="Ensure sensitive resources are protected by authentication and authorisation, not robots.txt.",
            source="robots.txt", confidence="Informational",
        ))
    document = result_document(
        "sitemap-endpoint-inventory", base, findings,
        inventory=sorted(urls), inventory_capped=inventory_capped,
        robots_disallow_directives=disallows,
        out_of_scope_entries_ignored=ignored_count, out_of_scope_examples=ignored,
        unvisited_sitemaps=sitemap_queue[:20],
        observations=observations,
        note="This utility does not request discovered application URLs or test their security.",
    )
    write_json(document, args.output)
    return 1 if any("error" in item for item in observations) else 0


if __name__ == "__main__":
    raise SystemExit(main())
