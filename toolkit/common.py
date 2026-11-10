"""Shared scope validation, HTTP handling, and JSON helpers.

The toolkit is intentionally non-invasive: it does not perform exploitation,
credential attacks, brute force, stealth, persistence, or data extraction.
"""
from __future__ import annotations

import http.client
import ipaddress
import json
import re
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, NamedTuple

USER_AGENT = "Authorised-Security-Assessment-Toolkit/1.1 (+scope-controlled)"

# Single source of truth for severity labels used by every script and the report.
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

SCOPE_KEYS = {"domains", "cidrs", "ports"}
_DTD = re.compile(rb"<!\s*(DOCTYPE|ENTITY)", re.IGNORECASE)
# One DNS label after IDNA encoding: letters, digits, hyphen (underscore tolerated).
_LABEL = re.compile(r"^[a-z0-9_-]{1,63}$")


def parse_untrusted_xml(data: bytes) -> ET.Element:
    """Parse XML that came from a target (sitemaps, decoded APK files).

    Documents with a DTD are refused: none of the formats this toolkit reads
    needs one, and refusing it removes entity-expansion tricks without a
    third-party library. Raises ValueError or ET.ParseError.
    """
    if _DTD.search(data):
        raise ValueError("XML contains a DOCTYPE/ENTITY declaration; refusing to parse")
    return ET.fromstring(data)


class ScopeError(ValueError):
    """Raised when a target is not explicitly included in the supplied scope."""


class RequestError(RuntimeError):
    """Raised when an in-scope HTTP request fails (network, TLS, protocol, timeout)."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def load_json(path: str | Path) -> Any:
    with Path(path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def write_json(data: dict[str, Any], path: str | Path | None) -> None:
    rendered = json.dumps(data, indent=2)
    if path:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)


def _parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _normalise_host(host: str) -> str:
    """Lower-case, strip a trailing dot, IDNA-encode, and reject malformed names.

    Rejecting anything that is not a plain IP or a well-formed DNS name means
    odd inputs (backslashes, spaces, "host:port") fail closed instead of being
    compared as strings.
    """
    host = host.strip().rstrip(".").lower()
    address = _parse_ip(host)
    if address is not None:
        return str(address)
    try:
        encoded = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ScopeError(f"Invalid hostname: {host!r}") from exc
    if not encoded or not all(_LABEL.match(label) for label in encoded.split(".")):
        raise ScopeError(f"Invalid hostname: {host!r}")
    return encoded


class Scope:
    """Explicit allow-list for domains, IP ranges, and TCP ports.

    Example scope file:
      {"domains": ["example.test", "*.example.test"],
       "cidrs": ["192.0.2.0/24"], "ports": [80, 443]}

    Rules (all fail closed):
    - Unknown keys are rejected, so a typo such as "port" cannot silently
      disable the port allow-list.
    - "ports" is mandatory and non-empty; there is no "any port" default.
    - A wildcard is only allowed as a complete left-most label ("*.example.test")
      and needs at least two labels after it, so "*" or "*.com" are rejected.
      It matches subdomains, not the apex.
    - CIDRs are parsed strictly: "192.0.2.10/24" is an error (host bits set),
      not a silent widening to 192.0.2.0/24. "/0" networks are rejected.
    - IP addresses belong in "cidrs" (use /32 or /128 for a single host).
    """

    def __init__(self, config: dict[str, Any]):
        unknown = set(config) - SCOPE_KEYS
        if unknown:
            raise ValueError(f"Unknown scope key(s): {', '.join(sorted(unknown))}")
        raw_domains = config.get("domains", [])
        raw_cidrs = config.get("cidrs", [])
        raw_ports = config.get("ports", [])
        if not all(isinstance(v, list) for v in (raw_domains, raw_cidrs, raw_ports)):
            raise ValueError("domains, cidrs, and ports must be JSON arrays")
        if any(not isinstance(item, str) for item in raw_domains + raw_cidrs):
            raise ValueError("domain and CIDR entries must be strings")

        self.domains: set[str] = set()
        self.wildcards: set[str] = set()
        for entry in raw_domains:
            self._add_domain(entry)

        self.cidrs: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for entry in raw_cidrs:
            network = ipaddress.ip_network(entry.strip(), strict=True)  # ValueError if host bits set
            if network.prefixlen == 0:
                raise ValueError(f"CIDR {entry!r} covers the entire address space")
            self.cidrs.append(network)

        if not raw_ports:
            raise ValueError("Scope must list at least one permitted port")
        if any(isinstance(p, bool) or not isinstance(p, int) for p in raw_ports):
            raise ValueError("Scope ports must be JSON integers")
        if any(p < 1 or p > 65535 for p in raw_ports):
            raise ValueError("Scope ports must be between 1 and 65535")
        self.ports: set[int] = set(raw_ports)

    def _add_domain(self, entry: str) -> None:
        is_wildcard = entry.startswith("*.")
        base = entry[2:] if is_wildcard else entry
        if "*" in base:
            raise ValueError(f"Wildcard only allowed as the left-most label: {entry!r}")
        if _parse_ip(base.strip()) is not None:
            raise ValueError(f"IP address {entry!r} must be listed under 'cidrs'")
        normalised = _normalise_host(base)
        if is_wildcard:
            if normalised.count(".") < 1:
                raise ValueError(f"Wildcard {entry!r} is too broad")
            self.wildcards.add(normalised)
        else:
            self.domains.add(normalised)

    @classmethod
    def from_file(cls, path: str | Path) -> "Scope":
        config = load_json(path)
        if not isinstance(config, dict):
            raise ValueError("Scope file must contain a JSON object")
        if not (config.get("domains") or config.get("cidrs")):
            raise ValueError("Scope must define at least one domain or CIDR")
        return cls(config)

    def allows_host(self, host: str) -> bool:
        """Return True if the host is in scope. Raises ScopeError if malformed."""
        candidate = _normalise_host(host)
        address = _parse_ip(candidate)
        if address is not None:
            # Treat ::ffff:192.0.2.10 the same as 192.0.2.10.
            mapped = getattr(address, "ipv4_mapped", None)
            return any(address in net or (mapped is not None and mapped in net) for net in self.cidrs)
        if candidate in self.domains:
            return True
        return any(candidate.endswith("." + suffix) for suffix in self.wildcards)

    def check_host_port(self, host: str, port: int | None = None) -> None:
        """Raise ScopeError unless host (and port, if given) are in scope."""
        if port is not None and port not in self.ports:
            raise ScopeError(f"Port {port} is not included in the scope allow-list")
        if not self.allows_host(host):
            raise ScopeError(f"Host {host!r} is outside the authorised scope")

    def check_url(self, url: str) -> urllib.parse.SplitResult:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme not in {"http", "https"}:
            raise ScopeError("Only http:// and https:// URLs are supported")
        if not parsed.hostname:
            raise ScopeError("URL must contain a hostname")
        if parsed.username is not None or parsed.password is not None:
            raise ScopeError("URLs containing embedded credentials are not allowed")
        try:
            explicit_port = parsed.port
        except ValueError as exc:
            raise ScopeError("Invalid URL port") from exc
        # "is None" rather than "or": port 0 must not be silently treated as 443.
        port = explicit_port if explicit_port is not None else (443 if parsed.scheme == "https" else 80)
        self.check_host_port(parsed.hostname, port)
        return parsed


def check_target(scope: Scope, target: str) -> None:
    """Validate a URL, IP, or host[:port] string. Used by the offline scope checker."""
    if "://" in target:
        scope.check_url(target)
        return
    if _parse_ip(target) is not None:  # bare IPv4/IPv6, no port
        scope.check_host_port(target)
        return
    parsed = urllib.parse.urlsplit("//" + target)  # handles host:port and [v6]:port
    if not parsed.hostname or parsed.path or parsed.query or parsed.username is not None:
        raise ScopeError(f"Unrecognised target format: {target!r}")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ScopeError("Invalid port") from exc
    scope.check_host_port(parsed.hostname, port)


class HttpResult(NamedTuple):
    status: int
    headers: dict[str, str]
    body: bytes
    final_url: str
    truncated: bool
    redirect_chain: list[str]


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Disable automatic redirects so every redirect can be scope-checked.

    Returning None makes urllib raise HTTPError for the 3xx response, which
    safe_http_request treats as a normal response and inspects itself.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


def _collect_headers(message: Any) -> dict[str, str]:
    """Lower-case header names; join repeated headers instead of keeping only the last."""
    merged: dict[str, str] = {}
    for name in {key.lower() for key in message.keys()}:
        merged[name] = ", ".join(message.get_all(name) or [])
    return merged


def safe_http_request(
    url: str,
    scope: Scope,
    *,
    method: str = "GET",
    timeout: float = 8.0,
    max_redirects: int = 4,
    max_bytes: int = 1_000_000,
) -> HttpResult:
    """Make a bounded HTTP request, checking scope before every network hop.

    Raises ScopeError if the URL or any redirect target is out of scope and
    RequestError for network/TLS/protocol failures (including during the body
    read). TLS certificates are verified by urllib's default context. Proxy
    environment variables (e.g. HTTPS_PROXY for an intercepting proxy) are
    honoured; scope is still checked against the destination URL.
    """
    current = url
    chain: list[str] = []
    opener = urllib.request.build_opener(NoRedirectHandler())
    for _hop in range(max_redirects + 1):
        scope.check_url(current)  # before every connection, including redirects
        request = urllib.request.Request(
            current, method=method, headers={"User-Agent": USER_AGENT, "Accept": "*/*"}
        )
        try:
            try:
                response = opener.open(request, timeout=timeout)
            except urllib.error.HTTPError as exc:  # 3xx/4xx/5xx still carry headers
                response = exc
            with response:
                status = int(response.code)
                headers = _collect_headers(response.headers)
                is_redirect = status in {301, 302, 303, 307, 308} and "location" in headers
                body = b"" if is_redirect else response.read(max_bytes + 1)
        except (OSError, http.client.HTTPException) as exc:
            # OSError covers URLError, socket timeouts, resets and ssl.SSLError;
            # HTTPException covers malformed status lines and incomplete reads.
            raise RequestError(f"Request failed for {current}: {exc}") from exc

        if is_redirect:
            chain.append(current)
            current = urllib.parse.urljoin(current, headers["location"])
            continue  # the next iteration scope-checks the destination first
        truncated = len(body) > max_bytes
        return HttpResult(status, headers, body[:max_bytes], current, truncated, chain)
    raise RequestError(f"Maximum redirect count ({max_redirects}) exceeded")


def result_document(tool: str, target: str, findings: list[dict[str, Any]], **extra: Any) -> dict[str, Any]:
    return {
        "schema_version": "1.1",
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
    normalised = severity.upper()
    if normalised not in SEVERITIES:
        raise ValueError(f"Unknown severity {severity!r}; expected one of {SEVERITIES}")
    return {
        "title": title,
        "severity": normalised,
        "description": description,
        "evidence": evidence,
        "recommendation": recommendation,
        "source": source,
        "confidence": confidence,
    }
