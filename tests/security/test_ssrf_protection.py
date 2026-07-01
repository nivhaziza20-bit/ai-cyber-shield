"""
tests/security/test_ssrf_protection.py — AI Cyber Shield v6

Extended SSRF protection tests beyond the standard private-IP checks.
Covers attack vectors that bypass naive IP validation:
  IPv4-mapped IPv6, DNS rebinding, file/FTP schemes, redirects with credentials.
"""

from __future__ import annotations

import socket
from unittest.mock import MagicMock, patch

import pytest

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from tools.http_utils import SSRFError, is_ssrf_blocked, safe_get


def _v6_addr(ip: str):
    return [(socket.AF_INET6, socket.SOCK_STREAM, 0, "", (ip, 0, 0, 0))]


def _v4_addr(ip: str):
    return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (ip, 0))]


class TestAdvancedSSRFVectors:
    """Brief 1 — tests/security/test_ssrf_protection.py (6 tests)."""

    def test_ipv4_mapped_ipv6_blocked(self):
        """::ffff:127.0.0.1 is the IPv6 representation of 127.0.0.1 — must block."""
        with patch("socket.getaddrinfo", return_value=_v6_addr("::ffff:127.0.0.1")):
            assert is_ssrf_blocked("::ffff:127.0.0.1") is True

    def test_dns_rebinding_protection(self):
        """If DNS resolves to a private IP, the request must be blocked."""
        with patch("socket.getaddrinfo", return_value=_v4_addr("10.0.0.1")):
            # Public-looking hostname that resolves to private IP
            assert is_ssrf_blocked("attacker-rebind.example.com") is True

    def test_file_scheme_blocked(self):
        """file:// is never HTTP — safe_get must reject it."""
        with pytest.raises(ValueError, match="Only http/https"):
            safe_get("file:///etc/passwd")

    def test_ftp_scheme_blocked(self):
        """ftp:// is not an allowed scheme."""
        with pytest.raises(ValueError, match="Only http/https"):
            safe_get("ftp://internal-server/data")

    def test_url_with_credentials_in_localhost_blocked(self):
        """http://user:pass@127.0.0.1 still resolves to loopback — must block."""
        with patch("socket.getaddrinfo", return_value=_v4_addr("127.0.0.1")):
            with pytest.raises(SSRFError):
                safe_get("http://user:pass@127.0.0.1/secret")

    def test_link_local_imds_blocked(self):
        """169.254.169.254 is the AWS/GCP/Azure IMDS endpoint — critical to block."""
        with patch("socket.getaddrinfo", return_value=_v4_addr("169.254.169.254")):
            assert is_ssrf_blocked("169.254.169.254") is True


class TestSchemeEnforcement:
    def test_only_http_and_https_allowed(self):
        for bad_scheme in ("gopher://x.com", "ldap://x.com", "dict://x.com", "ssh://x.com"):
            with pytest.raises(ValueError, match="Only http/https"):
                safe_get(bad_scheme)

    def test_https_scheme_accepted(self):
        """https:// should not raise ValueError for scheme check."""
        with patch("tools.http_utils.is_ssrf_blocked", return_value=False):
            with patch("requests.Session") as mock_sess_cls:
                sess = MagicMock()
                resp = MagicMock()
                resp.is_redirect = False
                resp.headers = {}
                resp.iter_content.return_value = iter([b"ok"])
                sess.get.return_value = resp
                mock_sess_cls.return_value = sess
                try:
                    safe_get("https://example.com")
                except ValueError as e:
                    if "Only http/https" in str(e):
                        pytest.fail("https:// was wrongly rejected as a scheme")
