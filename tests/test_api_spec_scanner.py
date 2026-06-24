"""
Tests for tools/api_spec_scanner.py

Structure
─────────
  TestValidateJsonSpec       — pure Python, no network
  TestValidateYamlSpec       — pure Python
  TestValidateSwaggerUi      — pure Python
  TestValidateDocsUi         — pure Python
  TestCountOpenApiOperations — pure Python
  TestGetAuthSchemes         — pure Python
  TestProbeSingle            — async, uses _MockTransport for httpx
  TestAsyncScanCore          — async, uses _MockTransport for httpx
  TestScanApiSpecTool        — sync @tool wrapper, mocks _async_scan_core

No real network calls are made in any test.
"""

import asyncio
import json
import sys
from pathlib import Path
from typing import Callable
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.api_spec_scanner import (
    _API_SPEC_ENDPOINTS,
    _async_scan_core,
    _count_openapi_operations,
    _get_auth_schemes,
    _probe_single,
    _validate_docs_ui,
    _validate_json_spec,
    _validate_swagger_ui,
    _validate_yaml_spec,
    scan_api_spec,
)


# ─────────────────────────────────────────────────────────────────────────────
# httpx mock transport helper
# ─────────────────────────────────────────────────────────────────────────────

class _MockTransport(httpx.AsyncBaseTransport):
    """
    Minimal async httpx transport for tests.
    url_map: {url_substring: (status_code, content_type, body_str)}
    Missing URLs → 404.
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


def _client_with(url_map: dict) -> httpx.AsyncClient:
    """Return an httpx.AsyncClient wired to a _MockTransport."""
    return httpx.AsyncClient(transport=_MockTransport(url_map))


_OPENAPI3_SPEC = json.dumps({
    "openapi": "3.0.0",
    "info":    {"title": "Test API", "version": "1.0.0"},
    "paths": {
        "/users":         {"get": {}, "post": {}},
        "/users/{id}":    {"get": {}, "put": {}, "delete": {}},
        "/health":        {"get": {}},
    },
    "components": {
        "securitySchemes": {
            "bearerAuth": {"type": "http", "scheme": "bearer"},
            "apiKey":     {"type": "apiKey", "in": "header", "name": "X-API-Key"},
        }
    },
})

_SWAGGER2_SPEC = json.dumps({
    "swagger": "2.0",
    "info":    {"title": "Legacy API", "version": "2.0.0"},
    "paths":   {"/items": {"get": {}}},
    "securityDefinitions": {"basicAuth": {"type": "basic"}},
})

_GQL_INTROSPECTION_RESPONSE = json.dumps({
    "data": {
        "__schema": {
            "queryType": {"name": "Query"},
            "types": [
                {"name": "Query"}, {"name": "User"}, {"name": "Product"},
                {"name": "String"}, {"name": "Boolean"}, {"name": "__Schema"},
            ],
        }
    }
})

_SWAGGER_UI_HTML = """
<!DOCTYPE html>
<html><head><title>Swagger UI</title></head>
<body>
  <div id="swagger-ui"></div>
  <script src="/swagger-ui-bundle.js"></script>
  <script>const ui = SwaggerUIBundle({url: "/openapi.json"});</script>
</body>
</html>
"""

_REDOC_HTML = """
<!DOCTYPE html>
<html><head><title>ReDoc</title></head>
<body>
  <redoc spec-url="/openapi.json"></redoc>
  <script src="/redoc.standalone.js"></script>
</body>
</html>
"""


# ─────────────────────────────────────────────────────────────────────────────
# Pure Python validation tests
# ─────────────────────────────────────────────────────────────────────────────

class TestValidateJsonSpec:
    def test_openapi3_dict_is_valid(self):
        valid, parsed = _validate_json_spec(_OPENAPI3_SPEC)
        assert valid
        assert parsed.get("openapi") == "3.0.0"

    def test_swagger2_dict_is_valid(self):
        valid, parsed = _validate_json_spec(_SWAGGER2_SPEC)
        assert valid
        assert "swagger" in parsed

    def test_spec_with_only_paths_key_is_valid(self):
        body = json.dumps({"paths": {"/ping": {"get": {}}}})
        valid, _ = _validate_json_spec(body)
        assert valid

    def test_spec_with_only_info_key_is_valid(self):
        body = json.dumps({"info": {"title": "x", "version": "1"}})
        valid, _ = _validate_json_spec(body)
        assert valid

    def test_generic_json_dict_without_openapi_keys_is_invalid(self):
        body = json.dumps({"foo": "bar", "count": 42})
        valid, _ = _validate_json_spec(body)
        assert not valid

    def test_json_array_is_invalid(self):
        valid, _ = _validate_json_spec(json.dumps([1, 2, 3]))
        assert not valid

    def test_html_body_is_invalid(self):
        valid, _ = _validate_json_spec("<html><body>Not found</body></html>")
        assert not valid

    def test_plain_text_is_invalid(self):
        valid, _ = _validate_json_spec("This is a plain text error page")
        assert not valid

    def test_empty_string_is_invalid(self):
        valid, _ = _validate_json_spec("")
        assert not valid

    def test_returns_parsed_dict_on_valid(self):
        valid, parsed = _validate_json_spec(_OPENAPI3_SPEC)
        assert valid
        assert isinstance(parsed, dict)

    def test_returns_empty_dict_on_invalid(self):
        _, parsed = _validate_json_spec("not json")
        assert parsed == {}


class TestValidateYamlSpec:
    def test_openapi_yaml_keyword_detected(self):
        assert _validate_yaml_spec("openapi: 3.0.0\ninfo:\n  title: Test")

    def test_swagger_yaml_keyword_detected(self):
        assert _validate_yaml_spec("swagger: '2.0'\ninfo:\n  title: Old API")

    def test_paths_keyword_detected(self):
        assert _validate_yaml_spec("paths:\n  /users:\n    get: {}")

    def test_info_keyword_detected(self):
        assert _validate_yaml_spec("info:\n  title: My Service\n  version: 1.0")

    def test_html_page_not_detected(self):
        assert not _validate_yaml_spec("<html><body>Page not found</body></html>")

    def test_plain_json_not_detected_as_yaml(self):
        # JSON that's not YAML-spec-like
        assert not _validate_yaml_spec('{"message": "hello"}')

    def test_keyword_must_be_at_line_start(self):
        # Indented (not a top-level YAML key)
        body = "    openapi: 3.0.0"
        # The regex uses MULTILINE so ^ matches start of any line — this should match
        # regardless of leading spaces? No, ^ in MULTILINE matches start of line, not
        # start of content. "    openapi:" starts with spaces, so ^ won't match.
        # Actually the regex is: r"^(swagger|openapi|info|paths)\s*:"
        # "    openapi: 3.0.0" — ^ does NOT match because there are leading spaces
        # → should be False
        assert not _validate_yaml_spec(body)


class TestValidateSwaggerUi:
    def test_swagger_ui_class_detected(self):
        assert _validate_swagger_ui(_SWAGGER_UI_HTML)

    def test_swaggerui_bundle_script_detected(self):
        html = '<script src="swagger-ui-bundle.js"></script>'
        assert _validate_swagger_ui(html)

    def test_swaggeruibundle_camelcase_detected(self):
        html = "<script>const SwaggerUIBundle = window.SwaggerUIBundle;</script>"
        assert _validate_swagger_ui(html)

    def test_regular_html_not_detected(self):
        html = "<html><head><title>Home</title></head><body>Welcome</body></html>"
        assert not _validate_swagger_ui(html)

    def test_empty_body_not_detected(self):
        assert not _validate_swagger_ui("")

    def test_case_insensitive(self):
        assert _validate_swagger_ui("<div class='SWAGGER-UI'>...</div>")


class TestValidateDocsUi:
    def test_redoc_html_detected(self):
        assert _validate_docs_ui(_REDOC_HTML)

    def test_fastapi_docs_detected(self):
        html = "<html><body>FastAPI - Swagger UI</body></html>"
        assert _validate_docs_ui(html)

    def test_api_documentation_phrase_detected(self):
        html = "<html><body><h1>API Documentation</h1></body></html>"
        assert _validate_docs_ui(html)

    def test_plain_page_not_detected(self):
        html = "<html><body>Welcome to our website</body></html>"
        assert not _validate_docs_ui(html)


class TestCountOpenApiOperations:
    def test_counts_standard_methods(self):
        spec = {
            "paths": {
                "/users":      {"get": {}, "post": {}},
                "/users/{id}": {"get": {}, "put": {}, "delete": {}},
                "/health":     {"get": {}},
            }
        }
        assert _count_openapi_operations(spec) == 6

    def test_empty_paths_returns_zero(self):
        assert _count_openapi_operations({"paths": {}}) == 0

    def test_no_paths_key_returns_zero(self):
        assert _count_openapi_operations({}) == 0

    def test_ignores_non_http_keys_like_summary(self):
        spec = {
            "paths": {
                "/users": {
                    "get":     {},
                    "summary": "User resource",  # not an HTTP method
                    "x-tags":  ["users"],        # extension
                }
            }
        }
        assert _count_openapi_operations(spec) == 1

    def test_patch_method_counted(self):
        spec = {"paths": {"/items/{id}": {"patch": {}}}}
        assert _count_openapi_operations(spec) == 1

    def test_case_insensitive_method_counting(self):
        spec = {"paths": {"/items": {"GET": {}, "POST": {}}}}
        assert _count_openapi_operations(spec) == 2


class TestGetAuthSchemes:
    def test_openapi3_security_schemes_extracted(self):
        spec = json.loads(_OPENAPI3_SPEC)
        schemes = _get_auth_schemes(spec)
        assert "bearerAuth" in schemes
        assert "apiKey" in schemes

    def test_swagger2_security_definitions_extracted(self):
        spec = json.loads(_SWAGGER2_SPEC)
        schemes = _get_auth_schemes(spec)
        assert "basicAuth" in schemes

    def test_empty_spec_returns_empty(self):
        assert _get_auth_schemes({}) == []

    def test_caps_at_six(self):
        spec = {
            "components": {
                "securitySchemes": {f"scheme{i}": {} for i in range(10)}
            }
        }
        assert len(_get_auth_schemes(spec)) <= 6


# ─────────────────────────────────────────────────────────────────────────────
# Async probe tests (mock httpx transport)
# ─────────────────────────────────────────────────────────────────────────────

class TestProbeSingle:
    BASE = "https://example.com"

    @pytest.mark.asyncio
    async def test_json_spec_found_on_200(self):
        async with _client_with({"/swagger.json": (200, "application/json", _OPENAPI3_SPEC)}) as c:
            result = await _probe_single(
                c, self.BASE, "/swagger.json", "Swagger JSON", 35, "json_spec"
            )
        assert result is not None
        assert result["path"] == "/swagger.json"
        assert result["category"] == "json_spec"
        assert result["operations"] == 6

    @pytest.mark.asyncio
    async def test_non_200_returns_none(self):
        async with _client_with({"/swagger.json": (404, "text/html", "Not Found")}) as c:
            result = await _probe_single(
                c, self.BASE, "/swagger.json", "Swagger JSON", 35, "json_spec"
            )
        assert result is None

    @pytest.mark.asyncio
    async def test_200_with_html_body_returns_none(self):
        # Custom 404 page returning 200 with HTML
        async with _client_with({"/swagger.json": (200, "text/html", "<html>Not found</html>")}) as c:
            result = await _probe_single(
                c, self.BASE, "/swagger.json", "Swagger JSON", 35, "json_spec"
            )
        assert result is None

    @pytest.mark.asyncio
    async def test_swagger_ui_html_detected(self):
        async with _client_with({"/swagger-ui.html": (200, "text/html", _SWAGGER_UI_HTML)}) as c:
            result = await _probe_single(
                c, self.BASE, "/swagger-ui.html", "Swagger UI", 45, "swagger_ui"
            )
        assert result is not None
        assert result["category"] == "swagger_ui"
        assert result["risk"] == 45

    @pytest.mark.asyncio
    async def test_graphql_introspection_returns_gql_flag(self):
        async with _client_with({"/graphql": (200, "application/json", _GQL_INTROSPECTION_RESPONSE)}) as c:
            result = await _probe_single(
                c, self.BASE, "/graphql", "GraphQL endpoint", 0, "graphql"
            )
        assert result is not None
        assert result.get("_gql") is True
        assert result["type_count"] == 6

    @pytest.mark.asyncio
    async def test_graphql_endpoint_returning_404_returns_none(self):
        async with _client_with({}) as c:  # all → 404
            result = await _probe_single(
                c, self.BASE, "/graphql", "GraphQL endpoint", 0, "graphql"
            )
        assert result is None

    @pytest.mark.asyncio
    async def test_yaml_spec_detected(self):
        yaml_body = "openapi: 3.0.0\ninfo:\n  title: Test\npaths:\n  /ping:\n    get: {}"
        async with _client_with({"/openapi.yaml": (200, "text/yaml", yaml_body)}) as c:
            result = await _probe_single(
                c, self.BASE, "/openapi.yaml", "OpenAPI YAML", 35, "yaml_spec"
            )
        assert result is not None
        assert result["category"] == "yaml_spec"

    @pytest.mark.asyncio
    async def test_network_error_returns_none(self):
        class _ErrorTransport(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request):
                raise httpx.NetworkError("Connection refused")

        async with httpx.AsyncClient(transport=_ErrorTransport()) as c:
            result = await _probe_single(
                c, self.BASE, "/swagger.json", "Swagger JSON", 35, "json_spec"
            )
        assert result is None


class TestAsyncScanCore:
    BASE_URL = "https://example.com"

    @pytest.mark.asyncio
    async def test_no_exposed_specs_returns_empty_lists(self):
        # All requests → 404
        with patch("tools.api_spec_scanner.httpx.AsyncClient") as MockClient:
            mock_instance = AsyncMock()
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=None)
            MockClient.return_value = mock_instance

            # _probe_single will get a client whose .get/.post all return 404
            resp_mock = MagicMock()
            resp_mock.status_code = 404
            resp_mock.text = "Not Found"
            mock_instance.get = AsyncMock(return_value=resp_mock)
            mock_instance.post = AsyncMock(return_value=resp_mock)

            exposed, gql, ops, auth = await _async_scan_core(self.BASE_URL)

        assert exposed == []
        assert gql == []
        assert ops == 0
        assert auth == []

    @pytest.mark.asyncio
    async def test_probe_single_results_aggregated(self):
        """Verify that _async_scan_core correctly separates GQL from regular specs."""
        # We mock _probe_single to return controlled data
        spec_result = {
            "path": "/swagger.json", "description": "Swagger JSON",
            "category": "json_spec", "risk": 35,
            "operations": 10, "auth_schemes": ["bearerAuth"], "_gql": False,
        }
        gql_result = {
            "path": "/graphql", "description": "GraphQL",
            "category": "graphql", "type_count": 4, "risk": 40, "_gql": True,
        }
        # Alternate results: half return None, one returns spec, one returns gql
        call_count = [0]

        async def mock_probe(client, base_url, path, desc, risk, cat):
            call_count[0] += 1
            if path == "/swagger.json":
                return spec_result
            if path == "/graphql":
                return gql_result
            return None

        with patch("tools.api_spec_scanner._probe_single", side_effect=mock_probe):
            with patch("tools.api_spec_scanner.httpx.AsyncClient") as MockClient:
                mock_instance = AsyncMock()
                mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
                mock_instance.__aexit__ = AsyncMock(return_value=None)
                MockClient.return_value = mock_instance

                exposed, gql, ops, auth = await _async_scan_core(self.BASE_URL)

        assert len(exposed) == 1
        assert exposed[0]["path"] == "/swagger.json"
        assert "_gql" not in exposed[0]  # sentinel stripped
        assert len(gql) == 1
        assert gql[0]["path"] == "/graphql"
        assert "_gql" not in gql[0]
        assert ops == 10
        assert "bearerAuth" in auth


# ─────────────────────────────────────────────────────────────────────────────
# @tool wrapper (sync) — mocks _async_scan_core
# ─────────────────────────────────────────────────────────────────────────────

def _make_scan_core_mock(
    exposed: list = None,
    gql: list = None,
    ops: int = 0,
    auth: list = None,
):
    """Return an AsyncMock for _async_scan_core with controlled results."""
    exposed = exposed or []
    gql     = gql or []
    auth    = auth or []
    mock    = AsyncMock(return_value=(exposed, gql, ops, auth))
    return mock


class TestScanApiSpecTool:
    def _run(self, url: str, core_mock: AsyncMock) -> dict:
        with patch("tools.api_spec_scanner._async_scan_core", core_mock):
            with patch("tools.api_spec_scanner.is_ssrf_blocked", return_value=False):
                raw = scan_api_spec.invoke({"url": url})
        return json.loads(raw)

    def test_invalid_scheme_returns_invalid_url(self):
        result = json.loads(scan_api_spec.invoke({"url": "ftp://example.com"}))
        assert result["status"] == "invalid_url"

    def test_ssrf_blocked_returns_ssrf_blocked(self):
        with patch("tools.api_spec_scanner.is_ssrf_blocked", return_value=True):
            result = json.loads(scan_api_spec.invoke({"url": "https://127.0.0.1"}))
        assert result["status"] == "ssrf_blocked"

    def test_no_findings_risk_zero(self):
        result = self._run("https://example.com", _make_scan_core_mock())
        assert result["risk_score"] == 0
        assert result["status"] == "completed"

    def test_swagger_ui_adds_45_risk(self):
        exposed = [{"path": "/swagger-ui.html", "description": "Swagger UI",
                    "category": "swagger_ui", "risk": 45, "operations": 0, "auth_schemes": []}]
        result = self._run("https://example.com", _make_scan_core_mock(exposed=exposed))
        assert result["risk_score"] == 45

    def test_graphql_introspection_adds_40_risk(self):
        gql = [{"path": "/graphql", "description": "GraphQL introspection",
                "category": "graphql", "type_count": 10, "risk": 40}]
        result = self._run("https://example.com", _make_scan_core_mock(gql=gql))
        assert result["risk_score"] == 40

    def test_risk_capped_at_80(self):
        exposed = [
            {"path": f"/spec{i}", "description": "Spec", "category": "swagger_ui",
             "risk": 45, "operations": 0, "auth_schemes": []}
            for i in range(5)   # 5 * 45 = 225 → must cap at 80
        ]
        result = self._run("https://example.com", _make_scan_core_mock(exposed=exposed))
        assert result["risk_score"] <= 80

    def test_operation_count_bonus_added(self):
        exposed = [{"path": "/api-docs", "description": "JSON spec", "category": "json_spec",
                    "risk": 35, "operations": 50, "auth_schemes": []}]
        result = self._run(
            "https://example.com",
            _make_scan_core_mock(exposed=exposed, ops=50),
        )
        # base risk 35 + bonus 10 (50//25 * 5 = 10)
        assert result["risk_score"] == 45

    def test_total_operations_in_output(self):
        result = self._run(
            "https://example.com",
            _make_scan_core_mock(ops=32),
        )
        assert result["total_operations"] == 32

    def test_auth_schemes_deduplicated(self):
        result = self._run(
            "https://example.com",
            _make_scan_core_mock(auth=["bearerAuth", "bearerAuth", "apiKey"]),
        )
        assert result["auth_schemes_disclosed"].count("bearerAuth") == 1

    def test_output_contains_required_keys(self):
        result = self._run("https://example.com", _make_scan_core_mock())
        for key in ("tool", "status", "url", "risk_score", "exposed_specs",
                    "graphql_introspection", "total_operations",
                    "auth_schemes_disclosed", "endpoints_probed", "recommendations"):
            assert key in result, f"Missing key: {key}"

    def test_endpoints_probed_count_correct(self):
        result = self._run("https://example.com", _make_scan_core_mock())
        assert result["endpoints_probed"] == len(_API_SPEC_ENDPOINTS)

    def test_swagger_ui_recommendation_present(self):
        exposed = [{"path": "/swagger-ui.html", "description": "Swagger UI",
                    "category": "swagger_ui", "risk": 45, "operations": 0, "auth_schemes": []}]
        result = self._run("https://example.com", _make_scan_core_mock(exposed=exposed))
        recs = " ".join(result["recommendations"])
        assert "swagger" in recs.lower() or "CRITICAL" in recs

    def test_graphql_recommendation_present(self):
        gql = [{"path": "/graphql", "description": "GraphQL introspection",
                "category": "graphql", "type_count": 5, "risk": 40}]
        result = self._run("https://example.com", _make_scan_core_mock(gql=gql))
        recs = " ".join(result["recommendations"])
        assert "graphql" in recs.lower() or "introspection" in recs.lower()

    def test_no_findings_clean_recommendation(self):
        result = self._run("https://example.com", _make_scan_core_mock())
        assert len(result["recommendations"]) >= 1
        # Should be a positive "clean" message
        assert any("not" in r.lower() or "no " in r.lower()
                   for r in result["recommendations"])
