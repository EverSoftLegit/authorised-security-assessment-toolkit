#!/usr/bin/env python3
"""Review an apktool-decoded AndroidManifest.xml for common configuration risks.

Offline only: decode an APK you are authorised to test with `apktool d app.apk`
first, then pass the output folder or the manifest file. Nothing is executed,
installed, or sent anywhere.

If given a folder, the script also reads:
- apktool.yml for targetSdkVersion (several defaults depend on it), and
- the network security config referenced by the manifest (res/xml/<name>.xml).

Exit codes: 0 completed, 2 unreadable or malformed input.
"""
from __future__ import annotations

import argparse
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from toolkit.common import make_finding, parse_untrusted_xml, result_document, write_json

ANDROID = "{http://schemas.android.com/apk/res/android}"
COMPONENT_TAGS = ("activity", "activity-alias", "service", "receiver", "provider")
# Exported components are normal (launchers, deep links, sync services), so
# ratings are review prompts. Providers expose data directly, hence higher.
EXPORT_SEVERITY = {"activity": "INFO", "activity-alias": "INFO", "service": "LOW",
                   "receiver": "LOW", "provider": "MEDIUM"}
SOURCE = "AndroidManifest.xml (static review)"
STATIC_CONFIDENCE = "Static configuration indicator; confirm with dynamic testing"


def attr(element: ET.Element, name: str) -> str | None:
    """Read an android:-namespaced attribute, e.g. attr(app, 'debuggable')."""
    return element.get(ANDROID + name)


def is_true(value: str | None) -> bool:
    return (value or "").strip().lower() == "true"


# --- loading --------------------------------------------------------------------

def locate_manifest(path: Path) -> Path:
    manifest = path / "AndroidManifest.xml" if path.is_dir() else path
    if not manifest.is_file():
        raise ValueError(f"No AndroidManifest.xml found at {path}")
    return manifest


def load_xml(path: Path) -> ET.Element:
    data = path.read_bytes()
    # A manifest copied straight out of the APK is compiled binary XML, not text.
    if data[:2] == b"\x03\x00":
        raise ValueError(f"{path} is binary Android XML; decode the APK with `apktool d` first")
    return parse_untrusted_xml(data)


def read_target_sdk(manifest_root: ET.Element, decoded_dir: Path) -> int | None:
    """Prefer <uses-sdk> in the manifest; fall back to apktool.yml's sdkInfo."""
    uses_sdk = manifest_root.find("uses-sdk")
    if uses_sdk is not None and (attr(uses_sdk, "targetSdkVersion") or "").isdigit():
        return int(attr(uses_sdk, "targetSdkVersion"))
    apktool_yml = decoded_dir / "apktool.yml"
    if apktool_yml.is_file():
        match = re.search(r"targetSdkVersion:\s*'?(\d+)'?", apktool_yml.read_text(encoding="utf-8", errors="replace"))
        if match:
            return int(match.group(1))
    return None


def load_network_security_config(app: ET.Element, decoded_dir: Path) -> tuple[ET.Element | None, str | None]:
    """Return (parsed config, reference) for android:networkSecurityConfig="@xml/name"."""
    reference = attr(app, "networkSecurityConfig")
    if not reference or not reference.startswith("@xml/"):
        return None, reference
    path = decoded_dir / "res" / "xml" / (reference[len("@xml/"):] + ".xml")
    if not path.is_file():
        return None, reference
    return load_xml(path), reference


# --- component analysis -------------------------------------------------------------

def is_exported(component: ET.Element, target_sdk: int | None) -> bool | None:
    """Apply Android's rules for whether a component is reachable by other apps.

    An explicit android:exported wins. Otherwise a component with an
    <intent-filter> is exported (from API 31 the attribute is mandatory in that
    case). A provider without the attribute is exported only below API 17.
    Returns None when the answer depends on an unknown targetSdk.
    """
    explicit = attr(component, "exported")
    if explicit is not None:
        return is_true(explicit)
    if component.tag == "provider":
        return None if target_sdk is None else target_sdk < 17
    return component.find("intent-filter") is not None


def is_launcher(component: ET.Element) -> bool:
    for intent_filter in component.findall("intent-filter"):
        actions = {attr(a, "name") for a in intent_filter.findall("action")}
        categories = {attr(c, "name") for c in intent_filter.findall("category")}
        if "android.intent.action.MAIN" in actions and "android.intent.category.LAUNCHER" in categories:
            return True
    return False


def has_permission(component: ET.Element, app_permission: str | None) -> bool:
    """A component is protected by its own permission, the app-wide one, or (providers) read/write permissions."""
    names = ["permission", "readPermission", "writePermission"] if component.tag == "provider" else ["permission"]
    return any(attr(component, name) for name in names) or bool(app_permission)


def weak_custom_permissions(manifest_root: ET.Element) -> set[str]:
    """Permissions this app defines with a protection level any installed app can obtain."""
    weak = set()
    for permission in manifest_root.findall("permission"):
        level = (attr(permission, "protectionLevel") or "normal").lower()
        if "signature" not in level and attr(permission, "name"):
            weak.add(attr(permission, "name"))
    return weak


def custom_schemes(app: ET.Element) -> list[str]:
    """Non-web URL schemes from BROWSABLE intent filters (any app can register the same scheme)."""
    schemes = set()
    for intent_filter in app.iter("intent-filter"):
        categories = {attr(c, "name") for c in intent_filter.findall("category")}
        if "android.intent.category.BROWSABLE" not in categories:
            continue
        for data in intent_filter.findall("data"):
            scheme = attr(data, "scheme")
            if scheme and scheme.lower() not in {"http", "https"}:
                schemes.add(scheme)
    return sorted(schemes)


# --- analysis -------------------------------------------------------------------------

def analyse(manifest_root: ET.Element, target_sdk: int | None = None,
            nsc_root: ET.Element | None = None) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Return (findings, observations). Pure function: no file or network access."""
    if manifest_root.tag != "manifest":
        raise ValueError(f"Expected <manifest> root element, found <{manifest_root.tag}>")
    app = manifest_root.find("application")
    if app is None:
        raise ValueError("Manifest has no <application> element")
    package = manifest_root.get("package", "unknown package")
    sdk_text = str(target_sdk) if target_sdk is not None else "unknown"
    findings: list[dict[str, Any]] = []

    if is_true(attr(app, "debuggable")):
        findings.append(make_finding(
            "Application is debuggable", "HIGH",
            "android:debuggable=\"true\" lets anyone with ADB access attach a debugger and read the "
            "app's private data with run-as. Release builds should never set it.",
            evidence=f"{package}: <application android:debuggable=\"true\">",
            recommendation="Confirm this is the release build; remove debuggable from release configuration.",
            source=SOURCE, confidence="Definitive for this APK; confirm it is the production build",
        ))

    allow_backup = attr(app, "allowBackup")
    if allow_backup is None or is_true(allow_backup):
        note = ("From API 31, adb backup excludes app data unless debuggable, but cloud backup and "
                "device-to-device transfer still apply." if target_sdk is not None and target_sdk >= 31
                else "Below API 31 this also allows `adb backup` extraction of app data.")
        findings.append(make_finding(
            "Application data backup is enabled", "LOW",
            f"android:allowBackup is {'absent (defaults to true)' if allow_backup is None else 'true'}. {note}",
            evidence=f"{package}: allowBackup={allow_backup or '(absent)'}; targetSdk={sdk_text}",
            recommendation="Set allowBackup=\"false\", or define backup rules that exclude tokens and sensitive files.",
            source=SOURCE, confidence=STATIC_CONFIDENCE,
        ))

    if is_true(attr(app, "testOnly")):
        findings.append(make_finding(
            "Application is marked testOnly", "INFO",
            "android:testOnly=\"true\" indicates a test build that should not be distributed.",
            evidence=f"{package}: testOnly=\"true\"", source=SOURCE, confidence=STATIC_CONFIDENCE,
            recommendation="Confirm which build was supplied for testing.",
        ))

    cleartext = attr(app, "usesCleartextTraffic")
    # Default is true below API 28, false from API 28. A network security config overrides it.
    if nsc_root is None and (is_true(cleartext) or (cleartext is None and target_sdk is not None and target_sdk < 28)):
        findings.append(make_finding(
            "Cleartext (HTTP) traffic is permitted", "LOW",
            "The app may send traffic over unencrypted HTTP. Impact depends on whether it actually does.",
            evidence=f"{package}: usesCleartextTraffic={cleartext or '(absent)'}; targetSdk={sdk_text}",
            recommendation="Disable cleartext traffic and confirm all endpoints use HTTPS (verify with a proxy).",
            source=SOURCE, confidence=STATIC_CONFIDENCE,
        ))

    if nsc_root is not None:
        findings.extend(review_network_security_config(nsc_root, package))

    weak_permissions = weak_custom_permissions(manifest_root)
    app_permission = attr(app, "permission")
    exported: dict[str, list[str]] = {tag: [] for tag in COMPONENT_TAGS}
    undetermined: list[str] = []
    for component in app:
        if component.tag not in COMPONENT_TAGS:
            continue
        name = attr(component, "name") or "(unnamed)"
        state = is_exported(component, target_sdk)
        if state is None:
            undetermined.append(name)
            continue
        if not state or is_launcher(component):
            continue
        permission = attr(component, "permission") or app_permission
        if not has_permission(component, app_permission):
            exported[component.tag].append(name)
        elif permission in weak_permissions:
            exported[component.tag].append(f"{name} (custom permission {permission} is not signature-level)")

    for tag, names in exported.items():
        if not names:
            continue
        findings.append(make_finding(
            f"Exported {tag} component(s) not protected by a signature permission ({len(names)})", EXPORT_SEVERITY[tag],
            f"Other apps on the device can invoke these {tag} components. Review each for sensitive "
            "actions or data reachable without authorisation.",
            evidence="\n".join(names[:30]) + (f"\n(+{len(names) - 30} more)" if len(names) > 30 else ""),
            recommendation="Set exported=\"false\" where not needed, or require a signature-level permission; "
                           "validate all incoming intent data.",
            source=SOURCE, confidence=STATIC_CONFIDENCE,
        ))

    schemes = custom_schemes(app)
    if schemes:
        findings.append(make_finding(
            "Custom URL schemes registered", "INFO",
            "Any installed app can register the same custom scheme, so links using it can be intercepted. "
            "Sensitive data (e.g. OAuth codes) should not travel through custom-scheme links.",
            evidence=", ".join(f"{s}://" for s in schemes), source=SOURCE, confidence=STATIC_CONFIDENCE,
            recommendation="Prefer verified https App Links for sensitive flows; validate deep-link parameters.",
        ))

    observations = {
        "package": package,
        "target_sdk": target_sdk,
        "requested_permissions": sorted(filter(None, (attr(p, "name") for p in manifest_root.findall("uses-permission")))),
        "exported_state_undetermined": undetermined,
        "custom_url_schemes": schemes,
    }
    return findings, observations


def review_network_security_config(nsc_root: ET.Element, package: str) -> list[dict[str, Any]]:
    """Check base/domain configs for cleartext and user-installed CA trust (debug-overrides are ignored)."""
    findings = []
    base = nsc_root.find("base-config")
    if base is not None and is_true(base.get("cleartextTrafficPermitted")):
        findings.append(make_finding(
            "Network security config permits cleartext traffic globally", "LOW",
            "base-config sets cleartextTrafficPermitted=\"true\" for all domains.",
            evidence=f"{package}: <base-config cleartextTrafficPermitted=\"true\">", source=SOURCE,
            recommendation="Remove the global allowance; scope any required exceptions to specific domains.",
            confidence=STATIC_CONFIDENCE,
        ))
    cleartext_domains = [d.text.strip() for config in nsc_root.iter("domain-config")
                         if is_true(config.get("cleartextTrafficPermitted"))
                         for d in config.findall("domain") if d.text]
    if cleartext_domains:
        findings.append(make_finding(
            "Cleartext traffic permitted for specific domains", "INFO",
            "domain-config entries allow HTTP to the listed domains.",
            evidence=", ".join(cleartext_domains), source=SOURCE, confidence=STATIC_CONFIDENCE,
            recommendation="Confirm each domain needs HTTP and carries no sensitive data.",
        ))
    # <debug-overrides> only apply to debuggable builds, so they are skipped here.
    for config in [base, *nsc_root.iter("domain-config")]:
        if config is None:
            continue
        if any(c.get("src") == "user" for c in config.iter("certificates")):
            findings.append(make_finding(
                "App trusts user-installed CA certificates", "MEDIUM",
                "A certificate authority installed by the user (or by malware or an MDM profile) can "
                "intercept this app's TLS traffic.",
                evidence=f"{package}: <{config.tag}> contains <certificates src=\"user\"/>", source=SOURCE,
                recommendation="Trust only system CAs in release builds; move user-CA trust into <debug-overrides>.",
                confidence=STATIC_CONFIDENCE,
            ))
            break
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("path", help="apktool output folder, or a decoded AndroidManifest.xml")
    parser.add_argument("--target-sdk", type=int, help="Override targetSdkVersion if apktool.yml is unavailable")
    parser.add_argument("--output", help="JSON output path")
    args = parser.parse_args()
    try:
        manifest_path = locate_manifest(Path(args.path))
        decoded_dir = manifest_path.parent
        root = load_xml(manifest_path)
        target_sdk = args.target_sdk if args.target_sdk is not None else read_target_sdk(root, decoded_dir)
        app = root.find("application")
        nsc_root, nsc_ref = load_network_security_config(app, decoded_dir) if app is not None else (None, None)
        findings, observations = analyse(root, target_sdk, nsc_root)
    except (OSError, ValueError, ET.ParseError) as exc:
        parser.error(f"Cannot review manifest: {exc}")

    if nsc_ref and nsc_root is None:
        observations["network_security_config_note"] = f"{nsc_ref} referenced but not found or not an @xml resource"
    # Named app_summary (a dict), not "observations" (a list of per-target results in other scripts).
    document = result_document("android-manifest-review", str(manifest_path), findings,
                               app_summary=observations,
                               note="Static manifest review only. Exported components and settings are leads for "
                                    "dynamic testing, not confirmed vulnerabilities.")
    write_json(document, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
