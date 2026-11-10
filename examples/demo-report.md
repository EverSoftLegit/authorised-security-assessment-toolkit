# Portfolio Demonstration Assessment

**Client/environment:** Synthetic Lab Data  
**Generated (UTC):** 2026-11-10T15:49:46+00:00  
**Classification:** CONFIDENTIAL — replace according to client policy

> Draft generated from scanner/tool output. All observations require analyst validation; do not represent unverified alerts as confirmed vulnerabilities.

## Executive summary

The imported files contain **11 finding/alert record(s)**. Severity counts are tool-assigned starting points and must be reviewed by the assessment lead.

| Severity | Count |
|---|---:|
| CRITICAL | 0 |
| HIGH | 1 |
| MEDIUM | 3 |
| LOW | 4 |
| INFO | 3 |

## Findings

### 1. Application is debuggable — HIGH

**Description:** android:debuggable="true" lets anyone with ADB access attach a debugger and read the app's private data with run-as. Release builds should never set it.

**Evidence:** com.example.labapp: &lt;application android:debuggable="true"&gt;

**Recommendation:** Confirm this is the release build; remove debuggable from release configuration.

**Source:** android-manifest-review (examples/android-manifest-analysis.json)

**Confidence:** Definitive for this APK; confirm it is the production build

### 2. Review exposed TCP 445 (SMB port; Nmap service: microsoft-ds) — MEDIUM

**Description:** TCP 445 is conventionally used by SMB; verify network restrictions, patching and share permissions. Nmap identified the service as 'microsoft-ds'.

**Evidence:** Host: 192.0.2.10; port: 445/tcp; service: microsoft-ds; product/version: not identified

**Recommendation:** Confirm business need, restrict source networks, harden configuration and validate patch level.

**Source:** nmap-xml-analyser (examples/nmap-analysis.json)

**Confidence:** Exposure indicator from the scan's vantage point; not proof of vulnerability

### 3. App trusts user-installed CA certificates — MEDIUM

**Description:** A certificate authority installed by the user (or by malware or an MDM profile) can intercept this app's TLS traffic.

**Evidence:** com.example.labapp: &lt;base-config&gt; contains &lt;certificates src="user"/&gt;

**Recommendation:** Trust only system CAs in release builds; move user-CA trust into &lt;debug-overrides&gt;.

**Source:** android-manifest-review (examples/android-manifest-analysis.json)

**Confidence:** Static configuration indicator; confirm with dynamic testing

### 4. Exported provider component(s) without permission protection (1) — MEDIUM

**Description:** Other apps on the device can invoke these provider components. Review each for sensitive actions or data reachable without authorisation.

**Evidence:** .NotesProvider

**Recommendation:** Set exported="false" where not needed, or require a signature-level permission; validate all incoming intent data.

**Source:** android-manifest-review (examples/android-manifest-analysis.json)

**Confidence:** Static configuration indicator; confirm with dynamic testing

### 5. Example: X-Content-Type-Options Header Missing — LOW

**Description:** Sample scanner alert for demonstrating report normalisation. This is not a real assessment result.

**Evidence:** Site: https://app.example.test<br>Instances: 1<br>Scanner confidence: Medium<br>Affected URI(s): https://app.example.test/

**Recommendation:** Set X-Content-Type-Options: nosniff where appropriate.

**Source:** owasp-zap-json-analyser (examples/zap-analysis.json)

**Confidence:** Scanner-generated (Medium); requires manual validation

### 6. Application data backup is enabled — LOW

**Description:** android:allowBackup is absent (defaults to true). From API 31, adb backup excludes app data unless debuggable, but cloud backup and device-to-device transfer still apply.

**Evidence:** com.example.labapp: allowBackup=(absent); targetSdk=34

**Recommendation:** Set allowBackup="false", or define backup rules that exclude tokens and sensitive files.

**Source:** android-manifest-review (examples/android-manifest-analysis.json)

**Confidence:** Static configuration indicator; confirm with dynamic testing

### 7. Exported service component(s) without permission protection (1) — LOW

**Description:** Other apps on the device can invoke these service components. Review each for sensitive actions or data reachable without authorisation.

**Evidence:** .SyncService (custom permission com.example.labapp.permission.SYNC is not signature-level)

**Recommendation:** Set exported="false" where not needed, or require a signature-level permission; validate all incoming intent data.

**Source:** android-manifest-review (examples/android-manifest-analysis.json)

**Confidence:** Static configuration indicator; confirm with dynamic testing

### 8. Exported receiver component(s) without permission protection (1) — LOW

**Description:** Other apps on the device can invoke these receiver components. Review each for sensitive actions or data reachable without authorisation.

**Evidence:** .PushReceiver

**Recommendation:** Set exported="false" where not needed, or require a signature-level permission; validate all incoming intent data.

**Source:** android-manifest-review (examples/android-manifest-analysis.json)

**Confidence:** Static configuration indicator; confirm with dynamic testing

### 9. Cleartext traffic permitted for specific domains — INFO

**Description:** domain-config entries allow HTTP to the listed domains.

**Evidence:** legacy.example.test

**Recommendation:** Confirm each domain needs HTTP and carries no sensitive data.

**Source:** android-manifest-review (examples/android-manifest-analysis.json)

**Confidence:** Static configuration indicator; confirm with dynamic testing

### 10. Exported activity component(s) without permission protection (1) — INFO

**Description:** Other apps on the device can invoke these activity components. Review each for sensitive actions or data reachable without authorisation.

**Evidence:** .DeepLinkActivity

**Recommendation:** Set exported="false" where not needed, or require a signature-level permission; validate all incoming intent data.

**Source:** android-manifest-review (examples/android-manifest-analysis.json)

**Confidence:** Static configuration indicator; confirm with dynamic testing

### 11. Custom URL schemes registered — INFO

**Description:** Any installed app can register the same custom scheme, so links using it can be intercepted. Sensitive data (e.g. OAuth codes) should not travel through custom-scheme links.

**Evidence:** labapp://

**Recommendation:** Prefer verified https App Links for sensitive flows; validate deep-link parameters.

**Source:** android-manifest-review (examples/android-manifest-analysis.json)

**Confidence:** Static configuration indicator; confirm with dynamic testing

## Imported sources

| File | Tool | Target |
|---|---|---|
| examples/nmap-analysis.json | nmap-xml-analyser | sample_data/nmap-sample.xml |
| examples/zap-analysis.json | owasp-zap-json-analyser | sample_data/zap-sample.json |
| examples/android-manifest-analysis.json | android-manifest-review | sample_data/android/AndroidManifest.xml |

## Analyst review checklist

- [ ] Confirm each target and observation was within the approved scope.
- [ ] Reproduce and manually validate each candidate finding.
- [ ] Remove false positives and duplicate records (e.g. the same header reported by ZAP and script 02).
- [ ] Confirm severity, business impact and affected assets with evidence.
- [ ] Re-run or explain every coverage gap.
- [ ] Ensure evidence is sanitised and contains no credentials or personal data.
- [ ] Obtain review approval before delivering the report.
