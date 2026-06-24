"""
Controlled HTTP test server for accuracy benchmarking.

Creates a lightweight thread-based HTTP server on a random port that returns
precisely configured headers, status codes, and per-path responses.

Usage:
    with mock_target(MockServerConfig(headers={"cf-ray": "abc"})) as url:
        result = detect_waf.func(url)

Requires AICS_BENCHMARK_MODE=1 to bypass the SSRF guard in tools that call
is_ssrf_blocked() before making requests to 127.0.0.1.
"""
from __future__ import annotations

import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Generator


@dataclass
class MockServerConfig:
    """
    Describes exactly what the mock HTTP server returns.

    Attributes:
        headers:       Response headers sent on every request (unless path override).
        status:        Default HTTP status code (used when path not in ``paths``).
        body:          Default response body.
        paths:         Per-path overrides: ``{"/path": (status_code, body_text)}``.
                       The match is on the path portion only (query string stripped).
        probe_keyword: If non-empty and this substring appears anywhere in the
                       raw request path (including query string), return
                       ``probe_status`` instead of the normal response.  Used to
                       simulate WAF probe blocking on ``?waf_probe=<xss>``.
        probe_status:  Status code returned when ``probe_keyword`` matches.
        probe_body:    Body returned when ``probe_keyword`` matches.
        extra_path_headers: Per-path extra headers overrides: ``{"/path": {headers}}``.
    """
    headers: dict[str, str] = field(default_factory=dict)
    status: int = 200
    body: str = "<html><body>Mock Target</body></html>"
    paths: dict[str, tuple[int, str]] = field(default_factory=dict)
    probe_keyword: str = ""
    probe_status: int = 403
    probe_body: str = "Access Denied"
    extra_path_headers: dict[str, dict[str, str]] = field(default_factory=dict)


def _make_handler(config: MockServerConfig) -> type:
    """Dynamically creates a request handler class bound to ``config``."""

    class _MockHandler(BaseHTTPRequestHandler):
        _cfg: MockServerConfig = config

        def _respond(self, status: int, hdrs: dict[str, str], body: str) -> None:
            body_bytes = body.encode("utf-8", errors="replace")
            self.send_response(status)
            for k, v in hdrs.items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(body_bytes)))
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body_bytes)

        def do_GET(self) -> None:
            cfg = type(self)._cfg

            # 1. Probe detection (for WAF tests: ?waf_probe=... → probe_status)
            if cfg.probe_keyword and cfg.probe_keyword in self.path:
                self._respond(cfg.probe_status, cfg.headers, cfg.probe_body)
                return

            # 2. Path-specific override (strip query string for matching)
            path_clean = self.path.split("?")[0].split("#")[0]
            if path_clean in cfg.paths:
                status, body = cfg.paths[path_clean]
                extra_hdrs = cfg.extra_path_headers.get(path_clean, {})
                merged = {**cfg.headers, **extra_hdrs}
                self._respond(status, merged, body)
                return

            # 3. Default response
            self._respond(cfg.status, cfg.headers, cfg.body)

        def do_HEAD(self) -> None:
            self.do_GET()

        def do_OPTIONS(self) -> None:
            self.do_GET()

        def do_POST(self) -> None:
            self.do_GET()

        def do_TRACE(self) -> None:
            # Reflect TRACE so the exposure checker can detect it via OPTIONS
            self._respond(200, cfg.headers, "TRACE response")

        def log_message(self, *args: object) -> None:
            pass  # silence access logs during tests

    # Bind config to class so every instance shares it without closure overhead
    _MockHandler._cfg = config
    return _MockHandler


@contextmanager
def mock_target(
    config: MockServerConfig,
    host: str = "127.0.0.1",
) -> Generator[str, None, None]:
    """
    Context manager that starts a mock HTTP server on a random OS-assigned port.

    Yields:
        Base URL of the mock server, e.g. ``"http://127.0.0.1:54321"``.

    Requires ``AICS_BENCHMARK_MODE=1`` environment variable to be set so that
    the scanning tools' SSRF guard allows requests to 127.0.0.1.
    """
    handler_cls = _make_handler(config)
    server = HTTPServer((host, 0), handler_cls)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()
