# Portfolio Demonstration Assessment

**Client/environment:** Synthetic Lab Data  
**Generated (UTC):** 2026-11-10T12:06:05+00:00  
**Classification:** CONFIDENTIAL — replace according to client policy

> Draft generated from scanner/tool output. All observations require analyst validation; do not represent unverified alerts as confirmed vulnerabilities.

## Executive summary

The imported files contain **2 finding/alert record(s)**. Severity counts are shown below and should be reviewed by the assessment lead.

| Severity | Count |
|---|---:|
| CRITICAL | 0 |
| HIGH | 0 |
| MEDIUM | 1 |
| LOW | 1 |
| INFO | 0 |

## Findings

### 1. Review exposed microsoft-ds port 445 — MEDIUM

**Description:** SMB is exposed; verify network restrictions, patching and share permissions.

**Evidence:** Host: 192.0.2.10; port: 445/tcp; service: microsoft-ds; product/version: None None

**Recommendation:** Confirm business need, restrict source networks, harden service configuration and validate patch level.

**Source:** nmap-xml-analyser (`examples/nmap-analysis.json`)

**Confidence:** Exposure indicator only; not proof of vulnerability

### 2. Example: X-Content-Type-Options Header Missing — LOW

**Description:** Sample scanner alert for demonstrating report normalisation. This is not a real assessment result.

**Evidence:** Site: https://app.example.test<br>Instances: 1<br>Affected URI(s): https://app.example.test/<br>Scanner confidence: Medium

**Recommendation:** Set X-Content-Type-Options: nosniff where appropriate.

**Source:** owasp-zap-json-analyser (`examples/zap-analysis.json`)

**Confidence:** Scanner-generated; requires manual validation

## Imported sources

| File | Tool | Target |
|---|---|---|
| `examples/nmap-analysis.json` | nmap-xml-analyser | sample_data/nmap-sample.xml |
| `examples/zap-analysis.json` | owasp-zap-json-analyser | sample_data/zap-sample.json |

## Analyst review checklist

- [ ] Confirm each target and observation was within the approved scope.
- [ ] Reproduce and manually validate each candidate finding.
- [ ] Remove false positives and duplicate records.
- [ ] Confirm severity, business impact and affected assets with evidence.
- [ ] Ensure evidence is sanitised and contains no credentials or personal data.
- [ ] Obtain review approval before delivering the report.
