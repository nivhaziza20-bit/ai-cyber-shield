"""
Tests for SSL/TLS Analyzer.
Run with: python -m pytest tests/test_ssl_analyzer.py -v
"""

import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from unittest.mock import patch, MagicMock
from tools.ssl_analyzer import analyze_ssl, _days_until_expiry, _is_self_signed, _score_cipher


# ─────────────────────────────────────────────────────────────────────────────
# Unit tests — pure functions
# ─────────────────────────────────────────────────────────────────────────────

class TestScoreCipher:

    def test_aes256_scores_100(self):
        score, _ = _score_cipher("TLS_AES_256_GCM_SHA384")
        assert score == 100

    def test_chacha20_scores_100(self):
        score, _ = _score_cipher("TLS_CHACHA20_POLY1305_SHA256")
        assert score == 100

    def test_aes128_scores_85_with_ecdhe(self):
        score, _ = _score_cipher("ECDHE-RSA-AES128-GCM-SHA256")
        assert score == 85  # AES-128 + ECDHE (PFS) = 85

    def test_rc4_scores_0(self):
        score, reason = _score_cipher("RC4-MD5")
        assert score == 0
        assert "Weak cipher" in reason

    def test_des_scores_0(self):
        score, _ = _score_cipher("DES-CBC-SHA")
        assert score == 0

    def test_null_cipher_scores_0(self):
        score, _ = _score_cipher("NULL-SHA")
        assert score == 0


class TestIsSelfSigned:

    def test_self_signed_detected(self):
        cert = {
            "subject": [(("commonName", "localhost"),)],
            "issuer":  [(("commonName", "localhost"),)],
        }
        assert _is_self_signed(cert) is True

    def test_ca_signed_not_flagged(self):
        cert = {
            "subject": [(("commonName", "example.com"),)],
            "issuer":  [(("commonName", "Let's Encrypt Authority X3"),)],
        }
        assert _is_self_signed(cert) is False


# ─────────────────────────────────────────────────────────────────────────────
# Integration-style tests — mock the TLS socket
# ─────────────────────────────────────────────────────────────────────────────

def _make_mock_cert(days_ahead: int = 90, self_signed: bool = False) -> dict:
    from datetime import datetime, timezone, timedelta
    expiry = datetime.now(timezone.utc) + timedelta(days=days_ahead)
    not_after = expiry.strftime("%b %d %H:%M:%S %Y GMT")
    issuer_cn = "example.com" if self_signed else "Let's Encrypt"
    return {
        "subject":        [(("commonName", "example.com"),)],
        "issuer":         [(("commonName", issuer_cn),), (("organizationName", issuer_cn),)],
        "notAfter":       not_after,
        "subjectAltName": [("DNS", "example.com"), ("DNS", "www.example.com")],
    }


class TestAnalyzeSsl:

    def test_http_url_returns_grade_f(self):
        result = json.loads(analyze_ssl.invoke({"url": "http://example.com"}))
        assert result["grade"] == "F"
        assert result["ssl_score"] == 0
        assert any("HTTP" in f for f in result["findings"])

    def test_good_tls13_scores_high(self):
        mock_cert = _make_mock_cert(days_ahead=90)
        mock_ssock = MagicMock()
        mock_ssock.version.return_value   = "TLSv1.3"
        mock_ssock.cipher.return_value    = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        mock_ssock.getpeercert.return_value = mock_cert
        mock_ssock.__enter__ = lambda s: s
        mock_ssock.__exit__  = MagicMock(return_value=False)

        mock_sock = MagicMock()
        mock_sock.__enter__ = lambda s: s
        mock_sock.__exit__  = MagicMock(return_value=False)

        with patch("tools.ssl_analyzer.socket.create_connection", return_value=mock_sock):
            with patch("tools.ssl_analyzer.ssl.create_default_context") as mock_ctx:
                mock_ctx.return_value.wrap_socket.return_value = mock_ssock
                result = json.loads(analyze_ssl.invoke({"url": "https://example.com"}))

        assert result["grade"] in ("A", "B")
        assert result["ssl_score"] >= 75
        assert result["tls_version"] == "TLSv1.3"

    def test_expired_cert_scores_0(self):
        mock_cert = _make_mock_cert(days_ahead=-5)
        mock_ssock = MagicMock()
        mock_ssock.version.return_value     = "TLSv1.3"
        mock_ssock.cipher.return_value      = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        mock_ssock.getpeercert.return_value = mock_cert
        mock_ssock.__enter__ = lambda s: s
        mock_ssock.__exit__  = MagicMock(return_value=False)

        mock_sock = MagicMock()
        mock_sock.__enter__ = lambda s: s
        mock_sock.__exit__  = MagicMock(return_value=False)

        with patch("tools.ssl_analyzer.socket.create_connection", return_value=mock_sock):
            with patch("tools.ssl_analyzer.ssl.create_default_context") as mock_ctx:
                mock_ctx.return_value.wrap_socket.return_value = mock_ssock
                result = json.loads(analyze_ssl.invoke({"url": "https://example.com"}))

        assert result["days_until_expiry"] < 0
        assert any("EXPIRED" in f for f in result["findings"])

    def test_self_signed_cert_flagged(self):
        mock_cert = _make_mock_cert(days_ahead=90, self_signed=True)
        mock_ssock = MagicMock()
        mock_ssock.version.return_value     = "TLSv1.3"
        mock_ssock.cipher.return_value      = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        mock_ssock.getpeercert.return_value = mock_cert
        mock_ssock.__enter__ = lambda s: s
        mock_ssock.__exit__  = MagicMock(return_value=False)

        mock_sock = MagicMock()
        mock_sock.__enter__ = lambda s: s
        mock_sock.__exit__  = MagicMock(return_value=False)

        with patch("tools.ssl_analyzer.socket.create_connection", return_value=mock_sock):
            with patch("tools.ssl_analyzer.ssl.create_default_context") as mock_ctx:
                mock_ctx.return_value.wrap_socket.return_value = mock_ssock
                result = json.loads(analyze_ssl.invoke({"url": "https://example.com"}))

        assert result["cert_self_signed"] is True
        assert any("Self-signed" in f for f in result["findings"])

    def test_weak_tls_version_flagged(self):
        mock_cert = _make_mock_cert(days_ahead=90)
        mock_ssock = MagicMock()
        mock_ssock.version.return_value     = "TLSv1"
        mock_ssock.cipher.return_value      = ("AES128-SHA", "TLSv1", 128)
        mock_ssock.getpeercert.return_value = mock_cert
        mock_ssock.__enter__ = lambda s: s
        mock_ssock.__exit__  = MagicMock(return_value=False)

        mock_sock = MagicMock()
        mock_sock.__enter__ = lambda s: s
        mock_sock.__exit__  = MagicMock(return_value=False)

        with patch("tools.ssl_analyzer.socket.create_connection", return_value=mock_sock):
            with patch("tools.ssl_analyzer.ssl.create_default_context") as mock_ctx:
                mock_ctx.return_value.wrap_socket.return_value = mock_ssock
                result = json.loads(analyze_ssl.invoke({"url": "https://example.com"}))

        assert result["grade"] == "F"
        assert any("deprecated" in f for f in result["findings"])
