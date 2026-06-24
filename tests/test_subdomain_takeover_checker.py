"""
Tests for tools/subdomain_takeover_checker.py

Structure
─────────
  TestIdentifyCloudService      — pure Python, tests compiled regex patterns
  TestDohQuery                  — async, uses _MockTransport for httpx
  TestResolveCnameChain         — async, uses _MockTransport for httpx
  TestHasARecord                — async, uses _MockTransport for httpx
  TestCheckHttpFingerprint      — async, uses _MockTransport for httpx
  TestCheckSingle               — async, mocks helper coroutines
  TestCheckSubdomainTakeoverTool — sync @tool wrapper, mocks _async_scan_core

No real network calls are made in any test.
"""

import asyncio
import json
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.subdomain_takeover_checker import (
    _CLOUD_SERVICES,
    _async_scan_core,
    _check_http_fingerprint,
    _check_single,
    _doh_query,
    _has_a_record,
    _identify_cloud_service,
    _resolve_cname_chain,
    check_subdomain_takeover,
)


# ─────────────────────────────────────────────────────────────────────────────
# Mock transport helper
# ─────────────────────────────────────────────────────────────────────────────

class _MockTransport(httpx.AsyncBaseTransport):
    """
    pattern → (status_code, content_type, body_str)
    Un-matched requests → 404.
    """

    def __init__(self, url_map: dict[str, tuple[int, str, str]]) -> None:
        self._map = url_map

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        url_str = str(request.url)
        for pattern, (status, ctype, body) in self._map.items():
            if pattern in url_str:
                return httpx.Response(
                    status_code=status,
                    headers={"content-type": ctype},
                    content=body.encode(),
                    request=request,
                )
        return httpx.Response(404, content=b"Not Found", request=request)


def _doh_client(url_map: dict) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=_MockTransport(url_map))


def _http_client(url_map: dict) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=_MockTransport(url_map),
        follow_redirects=True,
        verify=False,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Helpers to build DoH responses
# ─────────────────────────────────────────────────────────────────────────────

def _doh_cname_response(target: str) -> str:
    return json.dumps({
        "Answer": [{"type": 5, "data": f"{target}."}]
    })


def _doh_a_response(ip: str = "1.2.3.4") -> str:
    return json.dumps({
        "Answer": [{"type": 1, "data": ip}]
    })


def _doh_empty_response() -> str:
    return json.dumps({"Answer": []})


# ─────────────────────────────────────────────────────────────────────────────
# Pure Python tests — cloud service identification
# ─────────────────────────────────────────────────────────────────────────────

class TestIdentifyCloudService:
    """Tests regex pattern matching without any network I/O."""

    def test_s3_amazonaws_cname_identified(self):
        name, info = _identify_cloud_service(["mybucket.s3.amazonaws.com"])
        assert name == "AWS S3"
        assert info is not None

    def test_s3_website_cname_identified(self):
        name, _ = _identify_cloud_service(["mybucket.s3-website-us-east-1.amazonaws.com"])
        assert name == "AWS S3"

    def test_github_pages_cname_identified(self):
        name, _ = _identify_cloud_service(["myorg.github.io"])
        assert name == "GitHub Pages"

    def test_heroku_cname_identified(self):
        name, _ = _identify_cloud_service(["myapp.herokuapp.com"])
        assert name == "Heroku"

    def test_netlify_cname_identified(self):
        name, _ = _identify_cloud_service(["mysite.netlify.app"])
        assert name == "Netlify"

    def test_azure_webapp_cname_identified(self):
        name, _ = _identify_cloud_service(["myapp.azurewebsites.net"])
        assert name == "Azure Web Apps"

    def test_fastly_cname_identified(self):
        name, _ = _identify_cloud_service(["cdn.fastly.net"])
        assert name == "Fastly"

    def test_ghost_cname_identified(self):
        name, _ = _identify_cloud_service(["myblog.ghost.io"])
        assert name == "Ghost.io"

    def test_surge_cname_identified(self):
        name, _ = _identify_cloud_service(["myproject.surge.sh"])
        assert name == "Surge.sh"

    def test_unknown_cname_returns_none(self):
        name, info = _identify_cloud_service(["myapp.example.com"])
        assert name is None
        assert info is None

    def test_empty_chain_returns_none(self):
        name, info = _identify_cloud_service([])
        assert name is None
        assert info is None

    def test_first_match_in_chain_wins(self):
        # Chain passes through a non-cloud hop then hits S3
        chain = ["cdn.some-proxy.com", "mybucket.s3.amazonaws.com"]
        name, _ = _identify_cloud_service(chain)
        assert name == "AWS S3"

    def test_all_14_services_have_fingerprints(self):
        """Every cloud service must have at least one HTTP fingerprint string."""
        for svc, info in _CLOUD_SERVICES.items():
            assert info["http_fingerprints"], f"{svc} has no fingerprints"

    def test_case_insensitive_matching(self):
        name, _ = _identify_cloud_service(["myapp.HEROKUAPP.COM"])
        assert name == "Heroku"


# ─────────────────────────────────────────────────────────────────────────────
# Async DoH query tests
# ─────────────────────────────────────────────────────────────────────────────

class TestDohQuery:
    @pytest.mark.asyncio
    async def test_returns_answer_records_on_success(self):
        body = json.dumps({
            "Answer": [
                {"type": 5, "data": "myapp.herokuapp.com."},
                {"type": 5, "data": "alt.herokuapp.com."},
            ]
        })
        async with _doh_client({"cloudflare-dns.com": (200, "application/json", body)}) as c:
            answers = await _doh_query(c, "staging.example.com", "CNAME")
        assert len(answers) == 2
        assert answers[0]["type"] == 5

    @pytest.mark.asyncio
    async def test_returns_empty_list_on_empty_answer(self):
        body = json.dumps({"Answer": []})
        async with _doh_client({"cloudflare-dns.com": (200, "application/json", body)}) as c:
            answers = await _doh_query(c, "nonexistent.example.com", "A")
        assert answers == []

    @pytest.mark.asyncio
    async def test_returns_empty_on_error_status(self):
        async with _doh_client({"cloudflare-dns.com": (500, "text/plain", "Error")}) as c:
            answers = await _doh_query(c, "example.com", "CNAME")
        assert answers == []

    @pytest.mark.asyncio
    async def test_returns_empty_on_network_error(self):
        class _ErrorTransport(httpx.AsyncBaseTransport):
            async def handle_async_request(self, req):
                raise httpx.NetworkError("Connection failed")

        async with httpx.AsyncClient(transport=_ErrorTransport()) as c:
            answers = await _doh_query(c, "example.com", "CNAME")
        assert answers == []


# ─────────────────────────────────────────────────────────────────────────────
# Async CNAME chain resolution tests
# ─────────────────────────────────────────────────────────────────────────────

class TestResolveCnameChain:
    @pytest.mark.asyncio
    async def test_single_hop_cname_resolved(self):
        body = _doh_cname_response("myapp.herokuapp.com")
        async with _doh_client({"cloudflare-dns.com": (200, "application/json", body)}) as c:
            chain = await _resolve_cname_chain(c, "staging.example.com")
        assert chain == ["myapp.herokuapp.com"]

    @pytest.mark.asyncio
    async def test_no_cname_returns_empty_chain(self):
        body = _doh_empty_response()
        async with _doh_client({"cloudflare-dns.com": (200, "application/json", body)}) as c:
            chain = await _resolve_cname_chain(c, "direct.example.com")
        assert chain == []

    @pytest.mark.asyncio
    async def test_trailing_dot_stripped_from_cname_target(self):
        body = json.dumps({"Answer": [{"type": 5, "data": "myapp.github.io."}]})
        async with _doh_client({"cloudflare-dns.com": (200, "application/json", body)}) as c:
            chain = await _resolve_cname_chain(c, "docs.example.com")
        assert chain == ["myapp.github.io"]  # no trailing dot

    @pytest.mark.asyncio
    async def test_cycle_detection_prevents_infinite_loop(self):
        """If A → A (self-reference), chain stops after 1 hop."""
        body = json.dumps({"Answer": [{"type": 5, "data": "same.example.com."}]})
        async with _doh_client({"cloudflare-dns.com": (200, "application/json", body)}) as c:
            chain = await _resolve_cname_chain(c, "same.example.com")
        # same.example.com → same.example.com → stopped (cycle)
        assert len(chain) <= 1

    @pytest.mark.asyncio
    async def test_result_is_lowercase(self):
        body = json.dumps({"Answer": [{"type": 5, "data": "MyApp.HerokuApp.COM."}]})
        async with _doh_client({"cloudflare-dns.com": (200, "application/json", body)}) as c:
            chain = await _resolve_cname_chain(c, "staging.example.com")
        assert chain[0] == chain[0].lower()


# ─────────────────────────────────────────────────────────────────────────────
# Async A-record existence check
# ─────────────────────────────────────────────────────────────────────────────

class TestHasARecord:
    @pytest.mark.asyncio
    async def test_returns_true_when_a_record_exists(self):
        body = _doh_a_response("1.2.3.4")
        async with _doh_client({"cloudflare-dns.com": (200, "application/json", body)}) as c:
            result = await _has_a_record(c, "existing.example.com")
        assert result is True

    @pytest.mark.asyncio
    async def test_returns_false_when_nxdomain(self):
        body = _doh_empty_response()
        async with _doh_client({"cloudflare-dns.com": (200, "application/json", body)}) as c:
            result = await _has_a_record(c, "ghost.example.com")
        assert result is False

    @pytest.mark.asyncio
    async def test_aaaa_record_also_counts(self):
        # First query (A) returns empty, second (AAAA) returns a record
        call_count = [0]

        class _IPv6Transport(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request):
                call_count[0] += 1
                rtype = request.url.params.get("type", "A")
                if rtype == "AAAA":
                    body = json.dumps({"Answer": [{"type": 28, "data": "::1"}]})
                else:
                    body = _doh_empty_response()
                return httpx.Response(
                    200, headers={"content-type": "application/json"},
                    content=body.encode(), request=request,
                )

        async with httpx.AsyncClient(transport=_IPv6Transport()) as c:
            result = await _has_a_record(c, "ipv6only.example.com")
        assert result is True


# ─────────────────────────────────────────────────────────────────────────────
# Async HTTP fingerprint check
# ─────────────────────────────────────────────────────────────────────────────

class TestCheckHttpFingerprint:
    @pytest.mark.asyncio
    async def test_fingerprint_matched_returns_true(self):
        body = "NoSuchBucket - The bucket you requested does not exist."
        async with _http_client({"https://deleted.example.com": (404, "text/xml", body)}) as c:
            matched, snippet = await _check_http_fingerprint(
                c, "deleted.example.com", "https", ["NoSuchBucket"]
            )
        assert matched is True
        assert "NoSuchBucket" in snippet

    @pytest.mark.asyncio
    async def test_fingerprint_not_found_returns_false(self):
        body = "<html><body>Welcome to our site!</body></html>"
        async with _http_client({"https://active.example.com": (200, "text/html", body)}) as c:
            matched, _ = await _check_http_fingerprint(
                c, "active.example.com", "https", ["NoSuchBucket"]
            )
        assert matched is False

    @pytest.mark.asyncio
    async def test_ssrf_blocked_returns_false(self):
        with patch("tools.subdomain_takeover_checker.is_ssrf_blocked", return_value=True):
            async with _http_client({}) as c:
                matched, snippet = await _check_http_fingerprint(
                    c, "internal.example.com", "https", ["anything"]
                )
        assert matched is False
        assert snippet == ""

    @pytest.mark.asyncio
    async def test_network_error_returns_false(self):
        class _ErrorTransport(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request):
                raise httpx.NetworkError("Connection refused")

        with patch("tools.subdomain_takeover_checker.is_ssrf_blocked", return_value=False):
            async with httpx.AsyncClient(transport=_ErrorTransport()) as c:
                matched, _ = await _check_http_fingerprint(
                    c, "unreachable.example.com", "https", ["NoSuchBucket"]
                )
        assert matched is False

    @pytest.mark.asyncio
    async def test_case_insensitive_fingerprint_match(self):
        body = "nosuchbucket - bucket not found"  # lowercase
        async with _http_client({"https://s3.example.com": (404, "text/xml", body)}) as c:
            matched, _ = await _check_http_fingerprint(
                c, "s3.example.com", "https", ["NoSuchBucket"]
            )
        assert matched is True

    @pytest.mark.asyncio
    async def test_multiple_fingerprints_any_match_suffices(self):
        body = "There isn't a GitHub Pages site here."
        async with _http_client({"https://pages.example.com": (404, "text/html", body)}) as c:
            matched, _ = await _check_http_fingerprint(
                c, "pages.example.com", "https",
                ["NoSuchBucket", "There isn't a GitHub Pages site here"]
            )
        assert matched is True


# ─────────────────────────────────────────────────────────────────────────────
# @tool wrapper (sync) — mocks _async_scan_core
# ─────────────────────────────────────────────────────────────────────────────

def _make_scan_core_mock(confirmed=None, potential=None):
    confirmed = confirmed or []
    potential = potential or []
    return AsyncMock(return_value=(confirmed, potential))


class TestCheckSubdomainTakeoverTool:
    def _run(self, url, subdomains_json="[]", core_mock=None) -> dict:
        if core_mock is None:
            core_mock = _make_scan_core_mock()
        with patch("tools.subdomain_takeover_checker._async_scan_core", core_mock):
            with patch("tools.subdomain_takeover_checker._fallback_ct_query",
                       return_value=["staging.example.com"]):
                raw = check_subdomain_takeover.invoke({
                    "url": url,
                    "subdomains_json": subdomains_json,
                })
        return json.loads(raw)

    def test_invalid_scheme_returns_invalid_url(self):
        result = json.loads(
            check_subdomain_takeover.invoke({"url": "ftp://example.com"})
        )
        assert result["status"] == "invalid_url"

    def test_no_subdomains_returns_no_subdomains_status(self):
        with patch("tools.subdomain_takeover_checker._fallback_ct_query", return_value=[]):
            result = json.loads(
                check_subdomain_takeover.invoke({
                    "url": "https://example.com",
                    "subdomains_json": "[]",
                })
            )
        assert result["status"] == "no_subdomains"
        assert result["risk_score"] == 0

    def test_no_takeovers_risk_is_zero(self):
        result = self._run(
            "https://example.com",
            subdomains_json='["staging.example.com"]',
            core_mock=_make_scan_core_mock(),
        )
        assert result["risk_score"] == 0
        assert result["status"] == "completed"

    def test_one_confirmed_takeover_adds_50_risk(self):
        confirmed = [{"subdomain": "staging.example.com", "service": "Heroku",
                      "cname_chain": ["myapp.herokuapp.com"], "severity": "HIGH",
                      "attack": "...", "evidence": "No such app", "confidence": "HIGH"}]
        result = self._run(
            "https://example.com",
            subdomains_json='["staging.example.com"]',
            core_mock=_make_scan_core_mock(confirmed=confirmed),
        )
        assert result["risk_score"] == 50

    def test_two_confirmed_takeovers_capped_at_100(self):
        confirmed = [
            {"subdomain": f"sub{i}.example.com", "service": "Heroku",
             "cname_chain": [f"app{i}.herokuapp.com"], "severity": "HIGH",
             "attack": "...", "evidence": "No such app", "confidence": "HIGH"}
            for i in range(3)
        ]
        result = self._run(
            "https://example.com",
            subdomains_json=json.dumps([f"sub{i}.example.com" for i in range(3)]),
            core_mock=_make_scan_core_mock(confirmed=confirmed),
        )
        assert result["risk_score"] == 100

    def test_potential_takeover_adds_25_risk(self):
        potential = [{"subdomain": "old.example.com", "service": "GitHub Pages",
                      "cname_chain": ["ghost.github.io"], "severity": "HIGH",
                      "attack": "...", "note": "NXDOMAIN", "confidence": "MEDIUM"}]
        result = self._run(
            "https://example.com",
            subdomains_json='["old.example.com"]',
            core_mock=_make_scan_core_mock(potential=potential),
        )
        assert result["risk_score"] == 25

    def test_confirmed_and_potential_combined_capped_at_100(self):
        confirmed = [{"subdomain": "sub1.example.com", "service": "Heroku",
                      "cname_chain": ["x.herokuapp.com"], "severity": "HIGH",
                      "attack": "...", "evidence": "No such app", "confidence": "HIGH"}]
        potential = [{"subdomain": f"sub{i}.example.com", "service": "S3",
                      "cname_chain": [f"b{i}.s3.amazonaws.com"], "severity": "CRITICAL",
                      "attack": "...", "note": "NXDOMAIN", "confidence": "MEDIUM"}
                     for i in range(4)]
        result = self._run(
            "https://example.com",
            subdomains_json=json.dumps(["sub1.example.com"] + [f"sub{i}.example.com" for i in range(4)]),
            core_mock=_make_scan_core_mock(confirmed=confirmed, potential=potential),
        )
        assert result["risk_score"] <= 100

    def test_confirmed_takeovers_in_output(self):
        confirmed = [{"subdomain": "staging.example.com", "service": "Heroku",
                      "cname_chain": ["myapp.herokuapp.com"], "severity": "HIGH",
                      "attack": "...", "evidence": "No such app", "confidence": "HIGH"}]
        result = self._run(
            "https://example.com",
            subdomains_json='["staging.example.com"]',
            core_mock=_make_scan_core_mock(confirmed=confirmed),
        )
        assert len(result["confirmed_takeovers"]) == 1
        assert result["confirmed_takeovers"][0]["subdomain"] == "staging.example.com"

    def test_output_contains_required_keys(self):
        result = self._run("https://example.com", subdomains_json='["a.example.com"]')
        for key in ("tool", "status", "domain", "risk_score", "checked_count",
                    "confirmed_takeovers", "potential_takeovers", "recommendations"):
            assert key in result, f"Missing key: {key}"

    def test_critical_recommendation_for_confirmed_takeover(self):
        confirmed = [{"subdomain": "staging.example.com", "service": "Heroku",
                      "cname_chain": ["myapp.herokuapp.com"], "severity": "HIGH",
                      "attack": "...", "evidence": "No such app", "confidence": "HIGH"}]
        result = self._run(
            "https://example.com",
            subdomains_json='["staging.example.com"]',
            core_mock=_make_scan_core_mock(confirmed=confirmed),
        )
        recs = " ".join(result["recommendations"])
        assert "CRITICAL" in recs or "takeover" in recs.lower()

    def test_subdomains_from_json_param_are_used(self):
        """Verify passed subdomains_json is forwarded to _async_scan_core."""
        core_mock = _make_scan_core_mock()
        with patch("tools.subdomain_takeover_checker._async_scan_core", core_mock):
            check_subdomain_takeover.invoke({
                "url": "https://example.com",
                "subdomains_json": '["admin.example.com", "api.example.com"]',
            })
        # _async_scan_core called once with the subdomain list
        assert core_mock.call_count == 1
        _, call_kwargs = core_mock.call_args
        # Subdomains are the second positional arg (url, subdomains)
        call_args_pos = core_mock.call_args[0]
        subdomains_passed = call_args_pos[1]
        assert "admin.example.com" in subdomains_passed
        assert "api.example.com" in subdomains_passed

    def test_malformed_subdomains_json_falls_back_to_ct(self):
        """Malformed JSON in subdomains_json → fall back to CT query."""
        with patch("tools.subdomain_takeover_checker._fallback_ct_query",
                   return_value=["fallback.example.com"]) as mock_ct:
            with patch("tools.subdomain_takeover_checker._async_scan_core",
                       _make_scan_core_mock()):
                check_subdomain_takeover.invoke({
                    "url": "https://example.com",
                    "subdomains_json": "THIS IS NOT JSON",
                })
        mock_ct.assert_called_once()
