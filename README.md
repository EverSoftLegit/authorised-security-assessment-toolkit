# Authorised Security Assessment Toolkit

A small Python portfolio project demonstrating practical security-assessment automation: explicit scope validation, safe web-response inspection, TLS certificate metadata review, limited sitemap inventory, offline Nmap/ZAP report parsing, and Markdown report generation.

**Purpose:** demonstrate repeatable assessment support and reporting discipline. This is not an exploitation framework and does not establish that a target is secure.

## Scripts

| Script | Purpose | Network activity |
|---|---|---|
| `01_scope_check.py` | Check hostnames, IPs, URLs and ports against an explicit JSON allow-list | None |
| `02_http_headers_audit.py` | Inspect common HTTP security headers with bounded requests and scope-checked redirects | One HEAD request per URL; GET fallback only for 405/501 |
| `03_tls_certificate_audit.py` | Review certificate identity, issuer, expiry and negotiated TLS metadata | One verified TLS handshake per target |
| `04_sitemap_inventory.py` | Read `robots.txt` and a bounded number of sitemap documents; list in-scope URLs | Limited requests to robots/sitemap resources only; does not crawl listed pages |
| `05_nmap_xml_analyzer.py` | Parse existing Nmap XML and flag service-exposure items for analyst review | None; offline parser only |
| `06_zap_json_analyzer.py` | Normalise OWASP ZAP JSON alerts and instance evidence | None; offline parser only |
| `07_report_builder.py` | Combine JSON outputs into a Markdown draft report | None; offline report generation |

Shared functionality lives in `toolkit/common.py`.

## Requirements

- Python 3.10 or later
- Runtime: Python standard library only
- Optional testing dependency: `pytest`

## Quick start

Clone the repository, then run:

```bash
python3 --version
python3 scripts/01_scope_check.py --scope scope.example.json https://app.example.test 192.0.2.10
```

The example file uses reserved example domains and documentation IP ranges. Replace it with a written, approved scope file before any real assessment. Do not add a real client target to a public repository.

### HTTP header review

Create a private `scope.json` with only authorised domains/CIDRs and permitted ports. Then:

```bash
python3 scripts/02_http_headers_audit.py \
  --scope scope.json \
  --url https://app.your-authorised-domain.test \
  --output output/headers.json
```

### TLS certificate review

```bash
python3 scripts/03_tls_certificate_audit.py \
  --scope scope.json \
  app.your-authorised-domain.test:443 \
  --output output/tls.json
```

Certificate verification is enabled. The script does not disable validation to retrieve an untrusted certificate.

### Limited sitemap inventory

```bash
python3 scripts/04_sitemap_inventory.py \
  --scope scope.json \
  --base-url https://app.your-authorised-domain.test \
  --output output/inventory.json
```

The script requests only `robots.txt`, `sitemap.xml`, and a small capped number of sitemap-index children. It does not request every discovered URL.

### Analyse existing tool output (offline)

Generate Nmap XML separately during an approved assessment, then parse it:

```bash
python3 scripts/05_nmap_xml_analyzer.py sample_data/nmap-sample.xml \
  --output output/nmap-analysis.json
```

Export an OWASP ZAP report in JSON format, then parse it:

```bash
python3 scripts/06_zap_json_analyzer.py zap-report.json \
  --output output/zap-analysis.json
```

### Generate a Markdown report

```bash
python3 scripts/07_report_builder.py \
  output/nmap-analysis.json output/zap-analysis.json \
  --assessment "Authorised Web and Infrastructure Review" \
  --client "Approved Lab Environment" \
  --output output/assessment-report.md
```

Review and validate every item before using the report. The report generator intentionally labels imported records as requiring analyst validation.

## Scope file format

```json
{
  "domains": ["example.test", "*.example.test"],
  "cidrs": ["192.0.2.0/24"],
  "ports": [80, 443, 8080, 8443]
}
```

- Domains match exactly. A wildcard such as `*.example.test` matches subdomains, not the apex `example.test`.
- CIDRs are checked with Python's `ipaddress` module.
- If `ports` is present, URL ports must be listed.
- Scope is checked before each HTTP request and each redirect destination.

## Safety and limitations

- Use only on systems for which you have explicit written authorisation.
- Do not commit client domains, IPs, credentials, tokens, reports, personal data, or internal screenshots.
- The scripts do not exploit vulnerabilities, brute-force credentials, bypass authentication, evade detection, establish persistence, or exfiltrate data.
- The Nmap and ZAP utilities parse existing output; they do not launch those tools.
- Missing headers and open ports are observations, not automatically vulnerabilities. Validate business context and exploitability before assigning severity.
- HTTP header and sitemap checks are intentionally narrow and can miss issues. A clean result is not proof of security.

## Tests

```bash
python3 -m pytest -q
```

## Portfolio demonstration

Use the provided offline sample files to show the parsers and report builder without connecting to any external host:

```bash
mkdir -p output
python3 scripts/05_nmap_xml_analyzer.py sample_data/nmap-sample.xml --output output/nmap.json
python3 scripts/06_zap_json_analyzer.py sample_data/zap-sample.json --output output/zap.json
python3 scripts/07_report_builder.py output/nmap.json output/zap.json --client "Demonstration Lab" --output output/demo-report.md
```

The sample findings are synthetic and must be described as demonstrations, not client discoveries.
