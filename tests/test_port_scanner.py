"""
Tests for tools/port_scanner.py

Structure
─────────
  TestCheckPort          — async unit tests with mocked asyncio.open_connection
  TestAsyncScanCore      — async integration tests using _check_port mocking
  TestScanOpenPortsTool  — sync @tool wrapper, mocks _async_scan_core
"""

import asyncio
import json
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.port_scanner import (
    _PORTS,
    _async_scan_core,
    _check_port,
    scan_open_ports,
)


# ─────────────────────────────────────────────────────────────────────────────
# _check_port
# ─────────────────────────────────────────────────────────────────────────────

class TestCheckPort:
    @pytest.mark.asyncio
    async def test_open_port_returns_true(self):
        mock_writer = MagicMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock(return_value=None)

        with patch("asyncio.open_connection", new=AsyncMock(return_value=(MagicMock(), mock_writer))):
            result = await _check_port("example.com", 80)
        assert result is True

    @pytest.mark.asyncio
    async def test_connection_refused_returns_false(self):
        with patch("asyncio.open_connection", new=AsyncMock(side_effect=ConnectionRefusedError())):
            result = await _check_port("example.com", 3306)
        assert result is False

    @pytest.mark.asyncio
    async def test_timeout_returns_false(self):
        with patch("asyncio.open_connection", new=AsyncMock(side_effect=asyncio.TimeoutError())):
            result = await _check_port("example.com", 22)
        assert result is False

    @pytest.mark.asyncio
    async def test_os_error_returns_false(self):
        with patch("asyncio.open_connection", new=AsyncMock(side_effect=OSError("unreachable"))):
            result = await _check_port("example.com", 443)
        assert result is False

    @pytest.mark.asyncio
    async def test_wait_closed_error_still_returns_true(self):
        """writer.wait_closed() raising should not affect the open=True result."""
        mock_writer = MagicMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock(side_effect=Exception("closed unexpectedly"))

        with patch("asyncio.open_connection", new=AsyncMock(return_value=(MagicMock(), mock_writer))):
            result = await _check_port("example.com", 8080)
        assert result is True


# ─────────────────────────────────────────────────────────────────────────────
# _async_scan_core
# ─────────────────────────────────────────────────────────────────────────────

class TestAsyncScanCore:
    @pytest.mark.asyncio
    async def test_no_open_ports_returns_empty(self):
        with patch("tools.port_scanner._check_port", new=AsyncMock(return_value=False)):
            result = await _async_scan_core("example.com")
        assert result == []

    @pytest.mark.asyncio
    async def test_open_port_included_in_results(self):
        async def _mock_check(host, port):
            return port == 22  # only SSH open

        with patch("tools.port_scanner._check_port", side_effect=_mock_check):
            result = await _async_scan_core("example.com")

        assert len(result) == 1
        assert result[0]["port"] == 22
        assert result[0]["service"] == "SSH"

    @pytest.mark.asyncio
    async def test_critical_port_open_returns_high_risk(self):
        async def _mock_check(host, port):
            return port == 3306  # MySQL

        with patch("tools.port_scanner._check_port", side_effect=_mock_check):
            result = await _async_scan_core("example.com")

        assert result[0]["risk"] == 70

    @pytest.mark.asyncio
    async def test_results_sorted_by_port_number(self):
        async def _mock_check(host, port):
            return port in (3306, 22, 443)

        with patch("tools.port_scanner._check_port", side_effect=_mock_check):
            result = await _async_scan_core("example.com")

        ports = [r["port"] for r in result]
        assert ports == sorted(ports)

    @pytest.mark.asyncio
    async def test_all_catalogue_ports_are_probed(self):
        probed = []

        async def _capture(host, port):
            probed.append(port)
            return False

        with patch("tools.port_scanner._check_port", side_effect=_capture):
            await _async_scan_core("example.com")

        assert set(probed) == set(_PORTS.keys())

    @pytest.mark.asyncio
    async def test_exceptions_from_individual_probes_are_ignored(self):
        async def _mock_check(host, port):
            if port == 22:
                raise RuntimeError("unexpected")
            return port == 80

        with patch("tools.port_scanner._check_port", side_effect=_mock_check):
            result = await _async_scan_core("example.com")

        ports = [r["port"] for r in result]
        assert 80 in ports
        assert 22 not in ports


# ─────────────────────────────────────────────────────────────────────────────
# @tool scan_open_ports wrapper
# ─────────────────────────────────────────────────────────────────────────────

def _make_core_mock(open_ports: list[dict]):
    return AsyncMock(return_value=open_ports)


class TestScanOpenPortsTool:
    def _run(self, url: str, open_ports: list[dict]) -> dict:
        with patch("tools.port_scanner._async_scan_core", _make_core_mock(open_ports)):
            with patch("tools.port_scanner.is_ssrf_blocked", return_value=False):
                raw = scan_open_ports.invoke({"url": url})
        return json.loads(raw)

    def test_invalid_url_no_hostname(self):
        result = json.loads(scan_open_ports.invoke({"url": "notaurl"}))
        assert result["status"] == "invalid_url"

    def test_ssrf_blocked(self):
        with patch("tools.port_scanner.is_ssrf_blocked", return_value=True):
            result = json.loads(scan_open_ports.invoke({"url": "https://127.0.0.1"}))
        assert result["status"] == "ssrf_blocked"

    def test_no_open_ports_risk_zero(self):
        result = self._run("https://example.com", [])
        assert result["risk_score"] == 0
        assert result["open_count"] == 0

    def test_risk_sums_port_risks(self):
        open_ports = [
            {"port": 22, "service": "SSH", "description": "...", "risk": 10},
            {"port": 3306, "service": "MySQL", "description": "...", "risk": 70},
        ]
        result = self._run("https://example.com", open_ports)
        assert result["risk_score"] == 80

    def test_risk_capped_at_100(self):
        open_ports = [
            {"port": 3306, "service": "MySQL", "description": "...", "risk": 70},
            {"port": 5432, "service": "PostgreSQL", "description": "...", "risk": 70},
        ]
        result = self._run("https://example.com", open_ports)
        assert result["risk_score"] == 100

    def test_critical_port_generates_critical_recommendation(self):
        open_ports = [{"port": 3389, "service": "RDP", "description": "...", "risk": 80}]
        result = self._run("https://example.com", open_ports)
        recs = " ".join(result["recommendations"])
        assert "CRITICAL" in recs

    def test_no_findings_generates_clean_recommendation(self):
        result = self._run("https://example.com", [])
        recs = " ".join(result["recommendations"])
        assert "no" in recs.lower() or "strong" in recs.lower()

    def test_output_contains_required_keys(self):
        result = self._run("https://example.com", [])
        for key in ("tool", "status", "host", "ports_checked", "open_ports",
                    "open_count", "risk_score", "recommendations"):
            assert key in result, f"Missing key: {key}"

    def test_ports_checked_equals_catalogue_size(self):
        result = self._run("https://example.com", [])
        assert result["ports_checked"] == len(_PORTS)

    def test_host_extracted_from_url(self):
        result = self._run("https://target.example.com", [])
        assert result["host"] == "target.example.com"

    def test_status_completed_on_success(self):
        result = self._run("https://example.com", [])
        assert result["status"] == "completed"

    def test_backdoor_port_highest_risk(self):
        """Port 4444 (Metasploit) has risk=90 — should dominate score."""
        open_ports = [{"port": 4444, "service": "Backdoor", "description": "...", "risk": 90}]
        result = self._run("https://example.com", open_ports)
        assert result["risk_score"] == 90

    def test_http_and_https_open_zero_risk(self):
        """Standard web ports should not inflate the score."""
        open_ports = [
            {"port": 80,  "service": "HTTP",  "description": "...", "risk": 0},
            {"port": 443, "service": "HTTPS", "description": "...", "risk": 0},
        ]
        result = self._run("https://example.com", open_ports)
        assert result["risk_score"] == 0
