"""Unit tests for the pure parsing/evaluation helpers, including malformed input."""
from __future__ import annotations

import ssl
import xml.etree.ElementTree as ET

import pytest

from conftest import load_script
from toolkit.common import Scope

headers_mod = load_script("02_http_headers_audit.py")
tls_mod = load_script("03_tls_certificate_audit.py")
sitemap_mod = load_script("04_sitemap_inventory.py")
nmap_mod = load_script("05_nmap_xml_analyzer.py")
zap_mod = load_script("06_zap_json_analyzer.py")
report_mod = load_script("07_report_builder.py")

NS = 'xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"'


# --- 02 header evaluation ----------------------------------------------------

def _titles(findings):
    return {f["title"] for f in findings}


def test_all_headers_present_gives_no_findings():
    headers = {"content-security-policy": "default-src 'self'; frame-ancestors 'none'",
               "x-content-type-options": "nosniff", "referrer-policy": "no-referrer",
               "permissions-policy": "camera=()", "strict-transport-security": "max-age=31536000",
               "content-type": "text/html"}
    assert headers_mod.evaluate_headers("https://a.test/", 200, headers) == []


def test_missing_csp_and_xfo_on_html_flags_framing():
    titles = _titles(headers_mod.evaluate_headers("http://a.test/", 200, {"content-type": "text/html"}))
    assert "No anti-framing header observed" in titles
    assert "Strict-Transport-Security absent or disabled" not in titles  # plain HTTP: HSTS not applicable


def test_framing_not_flagged_for_non_html():
    titles = _titles(headers_mod.evaluate_headers("https://a.test/api", 200, {"content-type": "application/json"}))
    assert "No anti-framing header observed" not in titles


@pytest.mark.parametrize("value, expected", [("max-age=0", 0), ("max-age=31536000; includeSubDomains", 31536000),
                                             ('max-age="600"', 600), ("includeSubDomains", None)])
def test_hsts_max_age_parsing(value, expected):
    assert headers_mod.hsts_max_age(value) == expected


def test_hsts_max_age_zero_is_flagged():
    findings = headers_mod.evaluate_headers("https://a.test/", 200, {"strict-transport-security": "max-age=0"})
    assert "Strict-Transport-Security absent or disabled" in _titles(findings)


def test_header_findings_never_exceed_low():
    findings = headers_mod.evaluate_headers("https://a.test/", 200, {"content-type": "text/html"})
    assert {f["severity"] for f in findings} <= {"LOW", "INFO"}


# --- 03 TLS helpers ------------------------------------------------------------

@pytest.mark.parametrize("value, expected", [
    ("app.example.test", ("app.example.test", 443)),
    ("app.example.test:8443", ("app.example.test", 8443)),
    ("https://[2001:db8::1]:443/", ("2001:db8::1", 443)),
])
def test_tls_parse_target(value, expected):
    assert tls_mod.parse_target(value)[:2] == expected


@pytest.mark.parametrize("value", ["http://app.example.test", "app.example.test:99999", "https://"])
def test_tls_parse_target_rejects_bad_input(value):
    with pytest.raises(ValueError):
        tls_mod.parse_target(value)


def test_describe_certificate_expiry_and_names():
    cert = {"subject": ((("commonName", "app.example.test"),),),
            "issuer": ((("organizationName", "Test CA"),), (("commonName", "Test Root"),)),
            "subjectAltName": (("DNS", "app.example.test"), ("IP Address", "192.0.2.1")),
            "notAfter": "Jan 11 00:00:00 2030 GMT"}
    now = ssl.cert_time_to_seconds("Jan  1 00:00:00 2030 GMT")
    details = tls_mod.describe_certificate(cert, now=now)
    assert details["days_until_expiry"] == 10
    assert details["issuer"] == "organizationName=Test CA, commonName=Test Root"
    assert "IP Address:192.0.2.1" in details["subject_alt_names"]


def test_describe_certificate_without_not_after():
    assert tls_mod.describe_certificate({}, now=0)["days_until_expiry"] is None


# --- 04 sitemap / robots parsing ------------------------------------------------

def test_sitemap_ignores_image_extension_locations():
    xml = (f'<urlset {NS} xmlns:image="http://www.google.com/schemas/sitemap-image/1.1">'
           '<url><loc> https://a.test/p </loc><image:image><image:loc>https://cdn.test/i.jpg</image:loc>'
           '</image:image></url></urlset>').encode()
    assert sitemap_mod.parse_sitemap(xml) == (["https://a.test/p"], [])


def test_sitemap_index_returns_children():
    xml = f'<sitemapindex {NS}><sitemap><loc>https://a.test/s1.xml</loc></sitemap></sitemapindex>'.encode()
    assert sitemap_mod.parse_sitemap(xml) == ([], ["https://a.test/s1.xml"])


def test_sitemap_without_namespace_still_parses():
    assert sitemap_mod.parse_sitemap(b"<urlset><url><loc>https://a.test/</loc></url></urlset>")[0] == ["https://a.test/"]


@pytest.mark.parametrize("body, error", [
    (b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><urlset><url><loc>&a;</loc></url></urlset>', ValueError),
    (b"<html><body>Not found</body></html>", ValueError),
    (b"<urlset><url><loc>unterminated", ET.ParseError),
    (b"", ET.ParseError),
])
def test_sitemap_rejects_dtd_html_and_broken_xml(body, error):
    with pytest.raises(error):
        sitemap_mod.parse_sitemap(body)


def test_robots_parsing_handles_comments_relative_sitemaps_and_empty_disallow():
    text = ("User-agent: *\nDisallow: /admin # private\nDisallow:\n"
            "SITEMAP: /maps/sitemap.xml\nSitemap: https://a.test/other.xml\n")
    disallows, sitemaps = sitemap_mod.parse_robots(text, "https://a.test/robots.txt")
    assert disallows == ["/admin"]
    assert sitemaps == ["https://a.test/maps/sitemap.xml", "https://a.test/other.xml"]


@pytest.mark.parametrize("base", ["https://a.test/app", "https://a.test/?q=1"])
def test_base_url_must_be_an_origin(base):
    with pytest.raises(ValueError):
        sitemap_mod.origin_of(base)


# --- 05 Nmap ----------------------------------------------------------------------

def _nmap(ports_xml: str, addr: str = "192.0.2.10", state: str = "up") -> ET.Element:
    return ET.fromstring(f'<nmaprun><host><status state="{state}"/><address addr="{addr}" addrtype="ipv4"/>'
                         f'<address addr="00:11:22:33:44:55" addrtype="mac"/><ports>{ports_xml}</ports></host></nmaprun>')


def test_nmap_reports_actual_service_on_conventional_port():
    root = _nmap('<port protocol="tcp" portid="23"><state state="open"/><service name="ssh"/></port>')
    hosts, findings, _ = nmap_mod.analyse(root)
    assert "Nmap service: ssh" in findings[0]["title"]
    assert hosts[0]["addresses"] == ["192.0.2.10"]  # MAC excluded


def test_nmap_ignores_udp_closed_filtered_and_down_hosts():
    root = _nmap('<port protocol="udp" portid="23"><state state="open"/></port>'
                 '<port protocol="tcp" portid="445"><state state="open|filtered"/></port>')
    assert nmap_mod.analyse(root)[1] == []
    assert nmap_mod.analyse(_nmap('<port protocol="tcp" portid="23"><state state="open"/></port>', state="down"))[0] == []


def test_nmap_bad_portid_is_a_warning_not_a_crash():
    root = _nmap('<port protocol="tcp" portid="abc"><state state="open"/></port>')
    hosts, findings, warnings = nmap_mod.analyse(root)
    assert findings == [] and len(warnings) == 1


def test_nmap_scope_labels_out_of_scope_hosts():
    scope = Scope({"cidrs": ["198.51.100.0/24"], "ports": [445]})
    hosts, findings, _ = nmap_mod.analyse(_nmap('<port protocol="tcp" portid="445"><state state="open"/></port>'), scope)
    assert hosts[0]["in_scope"] is False
    assert "NOT IN SUPPLIED SCOPE" in findings[0]["description"]


def test_nmap_rejects_non_nmap_xml(tmp_path):
    path = tmp_path / "x.xml"
    path.write_text("<other/>")
    with pytest.raises(ValueError):
        nmap_mod.parse_nmap_xml(path)


# --- 06 ZAP -------------------------------------------------------------------------

def _alert(**overrides):
    alert = {"alert": "Test alert", "riskcode": "2", "confidence": "2", "riskdesc": "Medium (Medium)",
             "desc": "<p>Line &amp; text</p>", "instances": [{"uri": "https://a.test/x"}]}
    alert.update(overrides)
    return alert


def test_zap_uses_riskcode_strips_html_and_maps_confidence():
    findings, _, _ = zap_mod.analyse({"site": [{"@name": "https://a.test", "alerts": [_alert()]}]})
    assert findings[0]["severity"] == "MEDIUM"
    assert findings[0]["description"] == "Line & text"
    assert "Site: https://a.test" in findings[0]["evidence"]
    assert "Scanner confidence: Medium" in findings[0]["evidence"]


def test_zap_excludes_false_positives_and_counts_them():
    findings, _, counters = zap_mod.analyse({"site": [{"alerts": [_alert(confidence="0")]}]})
    assert findings == [] and counters["false_positives_excluded"] == 1


def test_zap_single_site_object_and_riskdesc_fallback():
    report = {"site": {"name": "s", "alerts": [_alert(riskcode=None, riskdesc="High (Low)")]}}
    assert zap_mod.analyse(report)[0][0]["severity"] == "HIGH"


@pytest.mark.parametrize("report", [{"site": [1, {"alerts": ["x", None]}]}, {"site": [{"alerts": None}]}])
def test_zap_malformed_entries_are_skipped(report):
    findings, _, counters = zap_mod.analyse(report)
    assert findings == []


@pytest.mark.parametrize("report", [[], "x", {"site": "nope"}])
def test_zap_rejects_wrong_top_level_shapes(report):
    with pytest.raises(ValueError):
        zap_mod.analyse(report)


# --- 07 report builder ----------------------------------------------------------------

def test_md_neutralises_html_links_and_table_breaks():
    out = report_mod.md("<img src=x onerror=alert(1)> [click](javascript:x) a|b `c`\nnext")
    assert "<img" not in out and "&lt;img" in out
    assert "\\[click\\]" in out and "a\\|b" in out and "\\`c\\`" in out and "<br>next" in out


@pytest.mark.parametrize("value, expected", [("high", "HIGH"), ("Informational", "INFO"), ("weird", "UNRATED"), (None, "UNRATED")])
def test_severity_normalisation(value, expected):
    assert report_mod.normalise_severity(value) == expected
