# Portfolio Demonstration Assessment

**Client/environment:** Synthetic Lab Data  
**Generated (UTC):** 2026-11-10T12:22:16+00:00  
**Classification:** CONFIDENTIAL — replace according to client policy

> Draft generated from scanner/tool output. All observations require analyst validation; do not represent unverified alerts as confirmed vulnerabilities.

## Executive summary

The imported files contain **2 finding/alert record(s)**. Severity counts are tool-assigned starting points and must be reviewed by the assessment lead.

| Severity | Count |
|---|---:|
| CRITICAL | 0 |
| HIGH | 0 |
| MEDIUM | 1 |
| LOW | 1 |
| INFO | 0 |

## Findings

### 1. Review exposed TCP 445 (SMB port; Nmap service: microsoft-ds) — MEDIUM

**Description:** TCP 445 is conventionally used by SMB; verify network restrictions, patching and share permissions. Nmap identified the service as 'microsoft-ds'.

**Evidence:** Host: 192.0.2.10; port: 445/tcp; service: microsoft-ds; product/version: not identified

**Recommendation:** Confirm business need, restrict source networks, harden configuration and validate patch level.

**Source:** nmap-xml-analyser (examples/nmap-analysis.json)

**Confidence:** Exposure indicator from the scan's vantage point; not proof of vulnerability

### 2. Example: X-Content-Type-Options Header Missing — LOW

**Description:** Sample scanner alert for demonstrating report normalisation. This is not a real assessment result.

**Evidence:** Site: https://app.example.test<br>Instances: 1<br>Scanner confidence: Medium<br>Affected URI(s): https://app.example.test/

**Recommendation:** Set X-Content-Type-Options: nosniff where appropriate.

**Source:** owasp-zap-json-analyser (examples/zap-analysis.json)

**Confidence:** Scanner-generated (Medium); requires manual validation

## Imported sources

| File | Tool | Target |
|---|---|---|
| examples/nmap-analysis.json | nmap-xml-analyser | sample_data/nmap-sample.xml |
| examples/zap-analysis.json | owasp-zap-json-analyser | sample_data/zap-sample.json |

## Analyst review checklist

- [ ] Confirm each target and observation was within the approved scope.
- [ ] Reproduce and manually validate each candidate finding.
- [ ] Remove false positives and duplicate records (e.g. the same header reported by ZAP and script 02).
- [ ] Confirm severity, business impact and affected assets with evidence.
- [ ] Re-run or explain every coverage gap.
- [ ] Ensure evidence is sanitised and contains no credentials or personal data.
- [ ] Obtain review approval before delivering the report.
