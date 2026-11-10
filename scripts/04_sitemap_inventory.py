#!/usr/bin/env python3
"""Collect sitemap/robots.txt references without crawling application pages.

Only /robots.txt, /sitemap.xml and a small bounded number of sitemap-index
children are requested. Every URL is checked against the explicit scope first.
"""
import argparse
import urllib.parse
import xml.etree.ElementTree as ET
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from toolkit.common import Scope, ScopeError, make_finding, result_document, safe_http_request, write_json

MAX_SITEMAPS = 5
MAX_URLS = 500


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].lower()


def parse_sitemap(xml_bytes: bytes) -> tuple[list[str], list[str]]:
    root = ET.fromstring(xml_bytes)
    page_urls, child_sitemaps = [], []
    root_kind = local_name(root.tag)
    for element in root.iter():
        if local_name(element.tag) == "loc" and element.text:
            value = element.text.strip()
            if root_kind == "sitemapindex":
                child_sitemaps.append(value)
            else:
                page_urls.append(value)
    return page_urls, child_sitemaps


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope", required=True, help="Authorised scope JSON")
    parser.add_argument("--base-url", required=True, help="In-scope site origin, e.g. https://app.example.test")
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--output", help="JSON output path")
    args = parser.parse_args()
    scope = Scope.from_file(args.scope)
    base = args.base_url.rstrip("/")
    scope.check_url(base + "/")
    observations, urls, disallows, sitemap_queue = [], set(), [], []

    robots_url = urllib.parse.urljoin(base + "/", "robots.txt")
    try:
        status, _headers, body, final_url = safe_http_request(robots_url, scope, timeout=args.timeout, max_bytes=200_000)
        observations.append({"resource": "robots.txt", "url": final_url, "status": status})
        if status < 400:
            for line in body.decode("utf-8", errors="replace").splitlines():
                stripped = line.strip()
                if stripped.lower().startswith("disallow:"):
                    disallows.append(stripped.split(":", 1)[1].strip())
                elif stripped.lower().startswith("sitemap:"):
                    sitemap_queue.append(stripped.split(":", 1)[1].strip())
    except (ScopeError, RuntimeError, ValueError) as exc:
        observations.append({"resource": "robots.txt", "error": str(exc)})

    sitemap_queue.insert(0, urllib.parse.urljoin(base + "/", "sitemap.xml"))
    visited = set()
    while sitemap_queue and len(visited) < MAX_SITEMAPS and len(urls) < MAX_URLS:
        sitemap = sitemap_queue.pop(0)
        if sitemap in visited:
            continue
        visited.add(sitemap)
        try:
            status, _headers, body, final_url = safe_http_request(sitemap, scope, timeout=args.timeout, max_bytes=1_000_000)
            observations.append({"resource": "sitemap", "url": final_url, "status": status})
            if status >= 400:
                continue
            page_urls, child_sitemaps = parse_sitemap(body)
            for item in page_urls:
                try:
                    scope.check_url(item)
                    urls.add(item)
                except ScopeError:
                    observations.append({"ignored_out_of_scope_sitemap_entry": item})
            for child in child_sitemaps:
                try:
                    scope.check_url(child)
                    if child not in visited:
                        sitemap_queue.append(child)
                except ScopeError:
                    observations.append({"ignored_out_of_scope_sitemap": child})
        except (ScopeError, RuntimeError, ValueError, ET.ParseError) as exc:
            observations.append({"resource": "sitemap", "url": sitemap, "error": str(exc)})

    findings = []
    if disallows:
        findings.append(make_finding(
            "Robots.txt disallow directives observed", "INFO",
            "The robots.txt file lists paths requested not to be crawled. These directives are not access controls.",
            evidence="\n".join(disallows[:100]),
            recommendation="Ensure sensitive resources are protected by authentication and authorisation, not robots.txt.",
            source="robots.txt", confidence="Informational"
        ))
    document = result_document("sitemap-endpoint-inventory", base, findings,
                               inventory=sorted(urls), robots_disallow_directives=disallows,
                               observations=observations,
                               note="This utility does not request discovered application URLs or test their security.")
    write_json(document, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
