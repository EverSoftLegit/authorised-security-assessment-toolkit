"""Tests for 08_android_manifest_review.py using small inline manifests (no APKs, no network)."""
from __future__ import annotations

import json
import subprocess
import sys
import xml.etree.ElementTree as ET

import pytest

from conftest import ROOT, load_script

mod = load_script("08_android_manifest_review.py")
NS = 'xmlns:android="http://schemas.android.com/apk/res/android"'


def manifest(app_attrs: str = "", body: str = "", extra: str = "") -> ET.Element:
    return ET.fromstring(f'<manifest {NS} package="com.example.t">{extra}'
                         f'<application android:allowBackup="false" {app_attrs}>{body}</application></manifest>')


def titles(findings):
    return [f["title"] for f in findings]


def test_clean_manifest_has_no_findings():
    findings, summary = mod.analyse(manifest(), target_sdk=34)
    assert findings == [] and summary["package"] == "com.example.t"


def test_debuggable_is_high_and_testonly_info():
    findings, _ = mod.analyse(manifest('android:debuggable="true" android:testOnly="true"'), 34)
    by_title = {f["title"]: f["severity"] for f in findings}
    assert by_title["Application is debuggable"] == "HIGH"
    assert by_title["Application is marked testOnly"] == "INFO"


@pytest.mark.parametrize("sdk, phrase", [(34, "From API 31"), (30, "adb backup")])
def test_allow_backup_absent_defaults_true_with_sdk_specific_note(sdk, phrase):
    root = ET.fromstring(f'<manifest {NS} package="p"><application/></manifest>')
    findings, _ = mod.analyse(root, sdk)
    assert phrase in findings[0]["description"]


@pytest.mark.parametrize("attrs, sdk, flagged", [
    ('android:usesCleartextTraffic="true"', 34, True),
    ("", 27, True),       # default true below API 28
    ("", 28, False),      # default false from API 28
    ("", None, False),    # unknown SDK: do not guess
])
def test_cleartext_defaults_depend_on_target_sdk(attrs, sdk, flagged):
    findings, _ = mod.analyse(manifest(attrs), sdk)
    assert ("Cleartext (HTTP) traffic is permitted" in titles(findings)) is flagged


@pytest.mark.parametrize("component, sdk, expected", [
    ('<activity android:name=".A" android:exported="false"><intent-filter/></activity>', 30, False),
    ('<activity android:name=".A"><intent-filter/></activity>', 30, True),   # implicit export
    ('<service android:name=".S"/>', 30, False),
    ('<provider android:name=".P"/>', 16, True),     # pre-17 provider default
    ('<provider android:name=".P"/>', 17, False),
    ('<provider android:name=".P"/>', None, None),   # depends on unknown SDK
])
def test_is_exported_rules(component, sdk, expected):
    element = ET.fromstring(f"<wrapper {NS}>{component}</wrapper>")[0]  # wrapper declares the namespace
    assert mod.is_exported(element, sdk) is expected


def test_launcher_activity_is_not_reported():
    body = ('<activity android:name=".Main" android:exported="true"><intent-filter>'
            '<action android:name="android.intent.action.MAIN"/>'
            '<category android:name="android.intent.category.LAUNCHER"/></intent-filter></activity>')
    assert mod.analyse(manifest(body=body), 34)[0] == []


def test_permission_protection_and_weak_custom_permission():
    extra = ('<permission android:name="p.WEAK" android:protectionLevel="normal"/>'
             '<permission android:name="p.STRONG" android:protectionLevel="signature|privileged"/>')
    body = ('<receiver android:name=".Weak" android:exported="true" android:permission="p.WEAK"/>'
            '<receiver android:name=".Strong" android:exported="true" android:permission="p.STRONG"/>'
            '<receiver android:name=".SystemPerm" android:exported="true" android:permission="android.permission.BIND_JOB_SERVICE"/>'
            '<provider android:name=".Read" android:exported="true" android:readPermission="p.STRONG"/>')
    findings, _ = mod.analyse(manifest(body=body, extra=extra), 34)
    assert len(findings) == 1
    assert ".Weak" in findings[0]["evidence"] and ".Strong" not in findings[0]["evidence"]


def test_unprotected_exported_provider_is_medium():
    body = '<provider android:name=".Notes" android:authorities="a" android:exported="true"/>'
    findings, _ = mod.analyse(manifest(body=body), 34)
    assert findings[0]["severity"] == "MEDIUM"


def test_custom_schemes_exclude_web_and_non_browsable():
    body = ('<activity android:name=".L" android:exported="true"><intent-filter>'
            '<category android:name="android.intent.category.BROWSABLE"/>'
            '<data android:scheme="https"/><data android:scheme="myapp"/></intent-filter>'
            '<intent-filter><data android:scheme="internal"/></intent-filter></activity>')
    assert mod.custom_schemes(manifest(body=body).find("application")) == ["myapp"]


def test_network_security_config_user_ca_and_cleartext():
    nsc = ET.fromstring('<network-security-config><base-config cleartextTrafficPermitted="true">'
                        '<trust-anchors><certificates src="user"/></trust-anchors></base-config>'
                        '<debug-overrides><trust-anchors><certificates src="user"/></trust-anchors></debug-overrides>'
                        '</network-security-config>')
    found = titles(mod.review_network_security_config(nsc, "p"))
    assert "App trusts user-installed CA certificates" in found
    assert "Network security config permits cleartext traffic globally" in found


def test_user_ca_only_in_debug_overrides_is_not_flagged():
    nsc = ET.fromstring('<network-security-config><debug-overrides><trust-anchors>'
                        '<certificates src="user"/></trust-anchors></debug-overrides></network-security-config>')
    assert mod.review_network_security_config(nsc, "p") == []


@pytest.mark.parametrize("xml", ["<other/>", "<manifest/>"])
def test_rejects_non_manifest_or_missing_application(xml):
    with pytest.raises(ValueError):
        mod.analyse(ET.fromstring(xml))


def test_binary_manifest_and_dtd_are_refused(tmp_path):
    binary = tmp_path / "AndroidManifest.xml"
    binary.write_bytes(b"\x03\x00\x08\x00rest-of-binary")
    with pytest.raises(ValueError, match="apktool"):
        mod.load_xml(binary)
    dtd = tmp_path / "x.xml"
    dtd.write_text('<!DOCTYPE m [<!ENTITY a "b">]><manifest/>')
    with pytest.raises(ValueError, match="DOCTYPE"):
        mod.load_xml(dtd)


def test_target_sdk_from_apktool_yml(tmp_path):
    (tmp_path / "apktool.yml").write_text("sdkInfo:\n  minSdkVersion: '21'\n  targetSdkVersion: '33'\n")
    assert mod.read_target_sdk(manifest(), tmp_path) == 33


def test_cli_on_sample_folder_and_report_integration(tmp_path):
    out = tmp_path / "android.json"
    run = subprocess.run([sys.executable, str(ROOT / "scripts" / "08_android_manifest_review.py"),
                          str(ROOT / "sample_data" / "android"), "--output", str(out)],
                         capture_output=True, text=True)
    assert run.returncode == 0, run.stderr
    data = json.loads(out.read_text())
    assert data["app_summary"]["target_sdk"] == 34
    assert "Application is debuggable" in titles(data["findings"])
    report = tmp_path / "r.md"
    run = subprocess.run([sys.executable, str(ROOT / "scripts" / "07_report_builder.py"), str(out),
                          "--output", str(report)], capture_output=True, text=True)
    assert run.returncode == 0 and "### 1. Application is debuggable — HIGH" in report.read_text()


def test_cli_missing_path_exits_2(tmp_path):
    run = subprocess.run([sys.executable, str(ROOT / "scripts" / "08_android_manifest_review.py"),
                          str(tmp_path / "nope")], capture_output=True, text=True)
    assert run.returncode == 2
