"""Shared scope validation, HTTP handling, and JSON helpers.

The toolkit is intentionally non-invasive: it does not perform exploitation,
credential attacks, brute force, stealth, persistence, or data extraction.
"""
from __future__ import annotations

import ipaddress
import json
import socket
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

USER_AGENT = "Authorised-Security-Assessment-Toolkit/1.0 (+scope-controlled)"


class ScopeError(ValueError):
    """Raised when a target is not explicitly included in the supplied scope."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def load_json(path: str | Path) -> Any:
    with Path(path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def write_json(data: dict[str, Any], path: str | Path | None) -> None:
    rendered = json.dumps(data, indent=2, sort_keys=False)
    if path:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)


def _normalise_host(host: str) -> str:
    host = host.strip().rstrip(".").lower()
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        try:
            return host.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ScopeError(f"Invalid hostname: {host!r}") from exc


class Scope:
    """Explicit allow-list for domains, IP ranges, and TCP ports.

    Example scope file:
      {"domains": ["example.test", "*.example.test"],
       "cidrs": ["192.0.2.0/24"], "ports": [80, 443]}

    Wildcards are limited to a complete left-most label (for example,
    *.example.test matches app.example.test, not example.test itself).
    """

    def __init__(self, config: dict[str, Any]):
        raw_domains = config.get("domains", [])
        raw_cidrs = config.get("cidrs", [])
        raw_ports = config.get("ports", [])
        if not isinstance(raw_domains, list) or not isinstance(raw_cidrs, list) or not isinstance(raw_ports, list):
            raise ValueError("domains, cidrs, and ports must be JSON arrays")
        if any(not isinstance(item, str) for item in raw_domains + raw_cidrs):
            raise ValueError("domain and CIDR entries must be strings")
        self.domains = [_normalise_host(x) for x in raw_domains if not x.startswith("*.")]
        self.wildcards = [_normalise_host(x[2:]) for x in raw_domains if x.startswith("*.")]
        self.cidrs = [ipaddress.ip_network(x, strict=False) for x in raw_cidrs]
        self.ports = {int(p) for p in raw_ports}
        if any(p < 1 or p > 65535 for p in self.ports):
            raise ValueError("Scope ports must be between 1 and 65535")

    @classmethod
    def from_file(cls, path: str | Path) -> "Scope":
        config = load_json(path)
        if not isinstance(config, dict):
            raise ValueError("Scope file must contain a JSON object")
        if not (config.get("domains") or config.get("cidrs")):
            raise ValueError("Scope must define at least one domain or CIDR")
        return cls(config)

    def allows_host(self, host: str) -> bool:
        candidate = _normalise_host(host)
        try:
            address = ipaddress.ip_address(candidate)
            return any(address in network for network in self.cidrs)
        except ValueError:
            pass
        if candidate in self.domains:
            return True
        return any(candidate.endswith("." + suffix) for suffix in self.wildcards)

    def check_url(self, url: str) -> urllib.parse.SplitResult:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme not in {"http", "https"}:
            raise ScopeError("Only http:// and https:// URLs are supported")
        if not parsed.hostname:
            raise ScopeError("URL must contain a hostname")
        if parsed.username or parsed.password:
            raise ScopeError("URLs containing embedded credentials are not allowed")
        try:
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
        except ValueError as exc:
            raise ScopeError("Invalid URL port") from exc
        if self.ports and port not in self.ports:
            raise ScopeError(f"Port {port} is not included in the scope allow-list")
        if not self.allows_host(parsed.hostname):
            raise ScopeError(f"Host {parsed.hostname!r} is outside the authorised scope")
        return parsed


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Disable automatic redirects so every redirect can be scope-checked."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: N802
        return None


def safe_http_request(
    url: str,
    scope: Scope,
    *,
    method: str = "GET",
    timeout: float = 8.0,
    max_redirects: int = 4,
    max_bytes: int = 1_000_000,
) -> tuple[int, dict[str, str], bytes, str]:
    """Make a bounded HTTP request, checking scope before every network hop."""
    current = url
    opener = urllib.request.build_opener(NoRedirectHandler())
    for hop in range(max_redirects + 1):
        scope.check_url(current)
        request = urllib.request.Request(
            current,
            method=method,
            headers={"User-Agent": USER_AGENT, "Accept": "*/*"},
        )
        try:
            response = opener.open(request, timeout=timeout)
        except urllib.error.HTTPError as exc:
            response = exc
        except (urllib.error.URLError, TimeoutError, socket.timeout, ssl_error_types()) as exc:  # type: ignore[misc]
            raise RuntimeError(f"Request failed for {current}: {exc}") from exc

        status = int(response.code)
        headers = {k.lower(): v for k, v in response.headers.items()}
        if status in {301, 302, 303, 307, 308}:
            location = headers.get("location")
            response.close()
            if not location:
                return status, headers, b"", current
            if hop >= max_redirects:
                raise RuntimeError("Maximum redirect count exceeded")
            current = urllib.parse.urljoin(current, location)
            # The next loop checks the redirect destination before connecting.
            continue
        body = response.read(max_bytes + 1)
        response.close()
        if len(body) > max_bytes:
            body = body[:max_bytes]
        return status, headers, body, current
    raise RuntimeError("Maximum redirect count exceeded")


def ssl_error_types():
    # Kept as a function to avoid importing SSL for tools that only parse files.
    import ssl
    return ssl.SSLError


def result_document(tool: str, target: str, findings: list[dict[str, Any]], **extra: Any) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "tool": tool,
        "generated_at": utc_now(),
        "target": target,
        "findings": findings,
        **extra,
    }


def make_finding(
    title: str,
    severity: str,
    description: str,
    *,
    evidence: str = "",
    recommendation: str = "",
    source: str = "",
    confidence: str = "Needs manual validation",
) -> dict[str, Any]:
    return {
        "title": title,
        "severity": severity.upper(),
        "description": description,
        "evidence": evidence,
        "recommendation": recommendation,
        "source": source,
        "confidence": confidence,
    }
