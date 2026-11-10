"""Scope validation edge cases (pure logic, no network)."""
import pytest

from toolkit.common import Scope, ScopeError, check_target, make_finding


def sample_scope() -> Scope:
    return Scope({"domains": ["example.test", "*.example.test"],
                  "cidrs": ["192.0.2.0/24", "2001:db8::/64"], "ports": [80, 443]})


# --- host matching ---------------------------------------------------------

def test_exact_domain_is_allowed():
    assert sample_scope().allows_host("example.test")


def test_wildcard_matches_subdomain_not_apex():
    assert sample_scope().allows_host("app.example.test")
    assert sample_scope().allows_host("a.b.example.test")
    assert not Scope({"domains": ["*.example.test"], "ports": [443]}).allows_host("example.test")


@pytest.mark.parametrize("host", ["evilexample.test", "example.test.evil.test", "example.testing", "test"])
def test_suffix_lookalikes_are_rejected(host):
    assert not sample_scope().allows_host(host)


def test_case_and_trailing_dot_are_normalised():
    assert sample_scope().allows_host("APP.Example.Test.")


def test_cidr_membership_ipv4_ipv6_and_mapped():
    scope = sample_scope()
    assert scope.allows_host("192.0.2.10")
    assert not scope.allows_host("198.51.100.10")
    assert scope.allows_host("2001:db8::1")
    assert scope.allows_host("::ffff:192.0.2.10")  # IPv4-mapped form of an in-scope address


@pytest.mark.parametrize("host", ["exa mple.test", "example.test\\.evil.test", "a..example.test", "x" * 64 + ".example.test"])
def test_malformed_hostnames_raise(host):
    with pytest.raises(ScopeError):
        sample_scope().allows_host(host)


# --- URL checks ------------------------------------------------------------

def test_url_scheme_host_and_port_are_checked():
    scope = sample_scope()
    scope.check_url("https://app.example.test/path")
    for bad in ["ftp://app.example.test/file", "https://app.example.test:8443/", "https://outside.test/",
                "javascript:alert(1)", "https:///nohost"]:
        with pytest.raises(ScopeError):
            scope.check_url(bad)


def test_port_zero_is_not_treated_as_default():
    with pytest.raises(ScopeError):
        Scope({"domains": ["example.test"], "ports": [443]}).check_url("https://example.test:0/")


@pytest.mark.parametrize("url", ["https://example.test:99999/", "https://example.test:abc/"])
def test_invalid_ports_raise_scope_error(url):
    with pytest.raises(ScopeError):
        sample_scope().check_url(url)


@pytest.mark.parametrize("url", ["https://user:pass@example.test/", "https://user@example.test/",
                                 "https://evil.test\\@example.test/"])
def test_embedded_credentials_are_rejected(url):
    with pytest.raises(ScopeError):
        sample_scope().check_url(url)


# --- offline target strings (script 01) -------------------------------------

@pytest.mark.parametrize("target", ["example.test", "app.example.test:443", "192.0.2.5", "[2001:db8::1]:80",
                                    "2001:db8::1", "https://app.example.test"])
def test_check_target_accepts_supported_formats(target):
    check_target(sample_scope(), target)


@pytest.mark.parametrize("target", ["app.example.test:8443", "192.0.2.5:22", "example.test/path", "[::1"])
def test_check_target_rejects_bad_port_or_format(target):
    with pytest.raises(ValueError):
        check_target(sample_scope(), target)


# --- scope file validation (fail closed) ------------------------------------

@pytest.mark.parametrize("config, message", [
    ({"domains": ["example.test"], "port": [443]}, "Unknown scope key"),
    ({"domains": ["example.test"]}, "at least one permitted port"),
    ({"domains": ["example.test"], "ports": ["443"]}, "integers"),
    ({"domains": ["example.test"], "ports": [True]}, "integers"),
    ({"domains": ["example.test"], "ports": [0]}, "between 1 and 65535"),
    ({"cidrs": ["192.0.2.10/24"], "ports": [443]}, "host bits"),
    ({"cidrs": ["0.0.0.0/0"], "ports": [443]}, "entire address space"),
    ({"domains": ["*"], "ports": [443]}, "left-most label"),
    ({"domains": ["*.test"], "ports": [443]}, "too broad"),
    ({"domains": ["app*.example.test"], "ports": [443]}, "left-most label"),
    ({"domains": ["192.0.2.1"], "ports": [443]}, "cidrs"),
    ({"domains": "example.test", "ports": [443]}, "JSON arrays"),
])
def test_invalid_scope_configs_are_rejected(config, message):
    with pytest.raises(ValueError, match=message):
        Scope(config)


def test_scope_file_requires_object_and_targets(tmp_path):
    path = tmp_path / "scope.json"
    path.write_text("[]")
    with pytest.raises(ValueError, match="JSON object"):
        Scope.from_file(path)
    path.write_text('{"ports": [443]}')
    with pytest.raises(ValueError, match="at least one domain or CIDR"):
        Scope.from_file(path)


def test_make_finding_rejects_unknown_severity():
    with pytest.raises(ValueError):
        make_finding("t", "SEVERE", "d")
