"""safe_http_request against throwaway servers bound to 127.0.0.1 only.

These tests prove the scope check runs before each redirect hop: the
out-of-scope server records how many requests it received, and that number
must stay at zero.
"""
from __future__ import annotations

import http.server
import socket
import threading
import time

import pytest

from toolkit.common import RequestError, Scope, ScopeError, safe_http_request


class _Quiet(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):  # keep pytest output clean
        pass


def _start(handler_cls) -> http.server.HTTPServer:
    server = http.server.HTTPServer(("127.0.0.1", 0), handler_cls)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


@pytest.fixture
def servers():
    hits = {"outside": 0}

    class Outside(_Quiet):
        def do_GET(self):
            hits["outside"] += 1
            self.send_response(200)
            self.end_headers()

    outside = _start(Outside)

    class Inside(_Quiet):
        def do_GET(self):
            routes = {
                "/to-outside": f"http://127.0.0.1:{outside.server_port}/",
                "/to-other-host": "http://not-in-scope.test/",
                "/to-ftp": "ftp://127.0.0.1/",
                "/loop": "/loop",
                "/hop": "/final",
            }
            if self.path in routes:
                self.send_response(302)
                self.send_header("Location", routes[self.path])
                self.end_headers()
            elif self.path == "/dup-headers":
                self.send_response(200)
                self.send_header("Content-Security-Policy", "frame-ancestors 'none'")
                self.send_header("Content-Security-Policy", "default-src 'self'")
                self.end_headers()
            elif self.path == "/big":
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"x" * 5000)
            else:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

    inside = _start(Inside)
    # Only the "inside" server's port is in scope.
    scope = Scope({"cidrs": ["127.0.0.1/32"], "ports": [inside.server_port]})
    yield f"http://127.0.0.1:{inside.server_port}", scope, hits
    inside.shutdown()
    outside.shutdown()


@pytest.mark.parametrize("path", ["/to-outside", "/to-other-host", "/to-ftp"])
def test_out_of_scope_redirect_is_blocked_before_connecting(servers, path):
    base, scope, hits = servers
    with pytest.raises(ScopeError):
        safe_http_request(base + path, scope)
    assert hits["outside"] == 0


def test_in_scope_redirect_is_followed_and_recorded(servers):
    base, scope, _ = servers
    result = safe_http_request(base + "/hop", scope)
    assert result.status == 200 and result.final_url == base + "/final"
    assert result.redirect_chain == [base + "/hop"]


def test_redirect_loop_is_bounded(servers):
    base, scope, _ = servers
    with pytest.raises(RequestError, match="Maximum redirect"):
        safe_http_request(base + "/loop", scope, max_redirects=3)


def test_duplicate_headers_are_joined_not_overwritten(servers):
    base, scope, _ = servers
    csp = safe_http_request(base + "/dup-headers", scope).headers["content-security-policy"]
    assert "frame-ancestors" in csp and "default-src" in csp


def test_body_is_capped_and_flagged(servers):
    base, scope, _ = servers
    result = safe_http_request(base + "/big", scope, max_bytes=100)
    assert len(result.body) == 100 and result.truncated


def test_initial_url_out_of_scope_never_connects():
    scope = Scope({"cidrs": ["127.0.0.1/32"], "ports": [1]})
    with pytest.raises(ScopeError):
        safe_http_request("http://198.51.100.1/", scope)  # TEST-NET-2; rejected before any socket


def _raw_server(payload: bytes, linger: float = 0.0) -> int:
    """One-shot TCP server that sends raw bytes, used to simulate broken servers."""
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)

    def run():
        conn, _ = sock.accept()
        conn.recv(4096)
        conn.sendall(payload)
        time.sleep(linger)
        conn.close()
        sock.close()

    threading.Thread(target=run, daemon=True).start()
    return sock.getsockname()[1]


@pytest.mark.parametrize("payload, linger", [
    (b"NOT-HTTP garbage\r\n\r\n", 0.0),                               # malformed status line
    (b"HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\nab", 2.0),        # body stalls past timeout
])
def test_broken_servers_raise_request_error_not_crash(payload, linger):
    port = _raw_server(payload, linger)
    scope = Scope({"cidrs": ["127.0.0.1/32"], "ports": [port]})
    with pytest.raises(RequestError):
        safe_http_request(f"http://127.0.0.1:{port}/", scope, timeout=0.5)


def test_connection_refused_raises_request_error():
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()  # nothing listening now
    scope = Scope({"cidrs": ["127.0.0.1/32"], "ports": [port]})
    with pytest.raises(RequestError):
        safe_http_request(f"http://127.0.0.1:{port}/", scope, timeout=1)
