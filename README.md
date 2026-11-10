# Authorised Security Assessment Toolkit

![tests](https://github.com/EverSoftLegit/authorised-security-assessment-toolkit/actions/workflows/tests.yml/badge.svg)

A small Python portfolio project demonstrating practical security-assessment automation: explicit scope validation, safe web-response inspection, TLS certificate metadata review, limited sitemap inventory, offline Nmap/ZAP report parsing, and Markdown report generation.

**Purpose:** demonstrate repeatable assessment support and reporting discipline. This is not an exploitation framework and does not establish that a target is secure.

## Scripts

| Script | Purpose | Network activity |
|---|---|---|
| `01_scope_check.py` | Check URLs, IPs and `host[:port]` values against an explicit JSON allow-list | None (no DNS lookups) |
| `02_http_headers_audit.py` | Inspect common HTTP security headers with bounded requests and scope-checked redirects | One HEAD request per URL (plus in-scope redirects, max 4); GET fallback only for 405/501 |
| `03_tls_certificate_audit.py` | Review certificate identity, issuer, expiry and negotiated TLS metadata | One verified TLS handshake per target |
| `04_sitemap_inventory.py` | Read `robots.txt` and a bounded number of sitemap documents; list in-scope URLs | Limited requests to robots/sitemap resources only; does not crawl listed pages |
| `05_nmap_xml_analyzer.py` | Parse existing Nmap XML, flag service-exposure items for review, optionally label out-of-scope hosts | None; offline parser only |
| `06_zap_json_analyzer.py` | Normalise OWASP ZAP Traditional JSON alerts (affected URIs only; analyst-marked false positives excluded) | None; offline parser only |
| `07_report_builder.py` | Combine JSON outputs into a Markdown draft report | None; offline report generation |
| `08_android_manifest_review.py` | Review an apktool-decoded `AndroidManifest.xml` and network security config: debuggable, backup, cleartext, user-CA trust, exported components, custom URL schemes | None; offline review of an APK you decoded |

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

Certificate verification is enabled. The script does not disable validation to retrieve an untrusted certificate, so an expired, self-signed or mismatched certificate is reported as a verification failure with OpenSSL's reason rather than as parsed metadata. For hosts signed by an internal CA, add `--cafile internal-root.pem` before treating a failure as a finding.

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
  --scope scope.example.json \
  --output output/nmap-analysis.json
```

Export an OWASP ZAP report in JSON format, then parse it:

```bash
python3 scripts/06_zap_json_analyzer.py zap-report.json \
  --output output/zap-analysis.json
```

### Android manifest review (offline)

Decode an APK you are authorised to test with [apktool](https://apktool.org/), then review the output folder:

```bash
apktool d app.apk -o app-decoded
python3 scripts/08_android_manifest_review.py app-decoded --output output/android.json
```

The script reads `AndroidManifest.xml`, `apktool.yml` (for `targetSdkVersion`, which changes several Android defaults) and the referenced network security config. It does not install, run, or modify the app. A manifest copied straight out of the APK is binary XML and is rejected with a reminder to decode it first. Exported components and settings are leads for dynamic testing, not confirmed vulnerabilities.

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

The loader fails closed rather than guessing:

- Only the keys `domains`, `cidrs` and `ports` are accepted; a typo such as `port` is an error.
- `ports` is required and must be a non-empty list of integers 1–65535. There is no "any port" default.
- Domains match exactly after lower-casing, trailing-dot removal and IDNA encoding. A wildcard is allowed only as the whole left-most label: `*.example.test` matches subdomains, not the apex. `*`, `*.test` and `app*.example.test` are rejected. (Without a public-suffix list, `*.co.uk` cannot be detected as too broad; review scope files by eye.)
- IP addresses go in `cidrs` (use `/32` or `/128` for one host). CIDRs are parsed strictly, so `192.0.2.10/24` is an error instead of silently becoming `192.0.2.0/24`; `/0` is rejected.
- Scope is checked before each HTTP request, each redirect destination, and each TLS connection.
- Scope is checked against the **name or IP supplied**, not against where DNS resolves it. A hostname in scope that points at a third party (for example a dangling CNAME) will still be contacted. The TLS script records the IP it actually connected to as evidence.
- `HTTP(S)_PROXY` environment variables are honoured, so traffic can be routed through an intercepting proxy; scope is still checked against the destination URL.

## Safety and limitations

- Use only on systems for which you have explicit written authorisation.
- Do not commit client domains, IPs, credentials, tokens, reports, personal data, or internal screenshots.
- The scripts do not exploit vulnerabilities, brute-force credentials, bypass authentication, evade detection, establish persistence, or exfiltrate data.
- The Nmap and ZAP utilities parse existing output; they do not launch those tools.
- Missing headers and open ports are observations, not automatically vulnerabilities. Tool severities are starting points for triage; header findings are capped at LOW, and port ratings ignore whether the scan was internal or internet-facing. Validate business context and exploitability before assigning severity.
- The report builder lists tool errors (unreachable hosts, out-of-scope redirects) as coverage gaps, so a failed run is not mistaken for a clean one.
- HTTP header and sitemap checks are intentionally narrow and can miss issues. A clean result is not proof of security.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Completed; for `01`, every target was in scope |
| 1 | Completed with problems: out-of-scope targets (`01`), request/scope errors (`02`–`04`), or unreadable inputs (`07`) |
| 2 | Invalid arguments, scope file, or input file (argparse error) |

## Tests

```bash
python3 -m pytest -q
```

Tests never contact external hosts. HTTP behaviour (redirect scope checks, timeouts, malformed responses, size caps) is tested against throwaway servers bound to `127.0.0.1`.

## Portfolio demonstration

Use the provided offline sample files to show the parsers and report builder without connecting to any external host:

```bash
mkdir -p output
python3 scripts/05_nmap_xml_analyzer.py sample_data/nmap-sample.xml --scope scope.example.json --output output/nmap.json
python3 scripts/06_zap_json_analyzer.py sample_data/zap-sample.json --output output/zap.json
python3 scripts/08_android_manifest_review.py sample_data/android --output output/android.json
python3 scripts/07_report_builder.py output/nmap.json output/zap.json output/android.json --client "Demonstration Lab" --output output/demo-report.md
```

The sample findings are synthetic and must be described as demonstrations, not client discoveries.
