import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
from toolkit.common import Scope, ScopeError


def sample_scope():
    return Scope({"domains": ["example.test", "*.example.test"],
                  "cidrs": ["192.0.2.0/24"], "ports": [80, 443]})


def test_exact_domain_is_allowed():
    assert sample_scope().allows_host("example.test")


def test_wildcard_matches_subdomain_not_apex():
    scope = sample_scope()
    assert scope.allows_host("app.example.test")
    assert not Scope({"domains": ["*.example.test"]}).allows_host("example.test")


def test_cidr_membership():
    scope = sample_scope()
    assert scope.allows_host("192.0.2.10")
    assert not scope.allows_host("198.51.100.10")


def test_url_scheme_host_and_port_are_checked():
    scope = sample_scope()
    scope.check_url("https://app.example.test/path")
    with pytest.raises(ScopeError):
        scope.check_url("ftp://app.example.test/file")
    with pytest.raises(ScopeError):
        scope.check_url("https://app.example.test:8443/")
    with pytest.raises(ScopeError):
        scope.check_url("https://outside.test/")


def test_embedded_credentials_are_rejected():
    with pytest.raises(ScopeError):
        sample_scope().check_url("https://user:pass@example.test/")
