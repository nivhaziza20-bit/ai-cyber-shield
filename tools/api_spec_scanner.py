"""
API Specification Scanner

Discovers publicly accessible API documentation — Swagger/OpenAPI specs,
interactive Swagger UI / ReDoc pages, and GraphQL introspection endpoints —
that expose the complete API surface area to unauthenticated clients.

Performance design
──────────────────
Uses httpx.AsyncClient to fire all path probes CONCURRENTLY within one tool
invocation. The outer pipeline (ThreadPoolExecutor) calls this @tool
synchronously; asyncio.run() creates a new event loop inside the worker
thread to run the async fan-out. This is safe because ThreadPoolExecutor
threads have no running event loop by default.

  Sequential (requests.Session): 32 paths × 6s = up to 192s worst case
  Parallel   (httpx.AsyncClient): 32 paths ≈ 6s total (one RTT)

Why it matters
──────────────
Exposed specs enumerate every endpoint, parameter, data schema, and
authentication method. Attackers use them to:
  • Map the full attack surface in minutes (no fuzzing needed)
  • Discover hidden /admin, /debug, /internal endpoints
  • Use Swagger "Try it out" to invoke the API directly in a browser
  • Extract embedded auth tokens / API keys from example payloads

Risk scoring (capped at 80):
  Interactive Swagger UI / GraphiQL  +45  live API console in browser
  Raw OpenAPI / Swagger JSON/YAML    +35  full endpoint enumeration
  GraphQL introspection enabled      +40  complete schema disclosed
  ReDoc / docs UI                    +30  read-only spec exposure
  +5 per additional 25 operations    bonus for larger attack surfaces

SSRF protection:
  is_ssrf_blocked() is checked for the base host before any request is sent.
"""

from __future__ import annotations

import asyncio
import json
import re
from urllib.parse import urljoin, urlparse

import httpx
from langchain_core.tools import tool

from tools.http_utils import is_ssrf_blocked

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

_UA = "AICyberShield-Scanner/1.0 (security audit — authorized use only)"

# Minimal GraphQL introspection query — read-only, asks only for type names
_GQL_QUERY = json.dumps(
    {"query": "{ __schema { queryType { name } types { name } } }"}
)

_YAML_SPEC_RE = re.compile(
    r"^(swagger|openapi|info|paths)\s*:", re.MULTILINE | re.IGNORECASE
)

_HTTP_METHODS = frozenset(
    {"get", "post", "put", "delete", "patch", "options", "head"}
)

# Each entry: (path, description, risk_points, category)
# Categories: json_spec | yaml_spec | swagger_ui | docs_ui | graphql | graphql_ui
_API_SPEC_ENDPOINTS: list[tuple[str, str, int, str]] = [
    # ── Raw JSON / YAML specs ─────────────────────────────────────────────────
    ("/swagger.json",           "Swagger 2.0 JSON spec",              35, "json_spec"),
    ("/openapi.json",           "OpenAPI 3.x JSON spec",              35, "json_spec"),
    ("/api-docs",               "SpringDoc / Springfox JSON",         35, "json_spec"),
    ("/api-docs.json",          "Swagger JSON (alternate)",           35, "json_spec"),
    ("/v1/api-docs",            "Versioned API docs v1",              35, "json_spec"),
    ("/v2/api-docs",            "Versioned API docs v2",              35, "json_spec"),
    ("/v3/api-docs",            "Versioned API docs v3",              35, "json_spec"),
    ("/api/swagger.json",       "Namespaced Swagger JSON",            35, "json_spec"),
    ("/api/openapi.json",       "Namespaced OpenAPI JSON",            35, "json_spec"),
    ("/api/v1/swagger.json",    "API v1 Swagger JSON",                35, "json_spec"),
    ("/api/v2/swagger.json",    "API v2 Swagger JSON",                35, "json_spec"),
    ("/apispec.json",           "Flask-APISpec JSON",                 35, "json_spec"),
    ("/spec",                   "Generic spec endpoint",              30, "json_spec"),
    ("/swagger.yaml",           "Swagger 2.0 YAML spec",             35, "yaml_spec"),
    ("/swagger.yml",            "Swagger 2.0 YAML (short)",          35, "yaml_spec"),
    ("/openapi.yaml",           "OpenAPI 3.x YAML spec",             35, "yaml_spec"),
    ("/openapi.yml",            "OpenAPI 3.x YAML (short)",          35, "yaml_spec"),
    ("/api/openapi.yaml",       "Namespaced OpenAPI YAML",           35, "yaml_spec"),
    # ── Interactive UIs (try-it-out lets attackers invoke endpoints) ──────────
    ("/swagger-ui.html",        "Swagger UI (live API console)",      45, "swagger_ui"),
    ("/swagger-ui/",            "Swagger UI root",                    45, "swagger_ui"),
    ("/swagger-ui/index.html",  "Swagger UI index",                   45, "swagger_ui"),
    ("/swagger/",               "Swagger UI directory",               45, "swagger_ui"),
    ("/swagger/index.html",     "Swagger UI (alternate path)",        45, "swagger_ui"),
    ("/api/swagger-ui.html",    "Namespaced Swagger UI",              45, "swagger_ui"),
    ("/docs",                   "FastAPI / DRF interactive docs",     30, "docs_ui"),
    ("/docs/",                  "FastAPI / DRF interactive docs",     30, "docs_ui"),
    ("/redoc",                  "ReDoc documentation UI",             30, "docs_ui"),
    ("/redoc/",                 "ReDoc documentation UI",             30, "docs_ui"),
    ("/api/docs",               "Namespaced API docs UI",             30, "docs_ui"),
    # ── GraphQL (zero base risk — conditional on introspection success) ───────
    ("/graphql",                "GraphQL endpoint",                    0, "graphql"),
    ("/api/graphql",            "GraphQL endpoint (namespaced)",       0, "graphql"),
    ("/graphiql",               "GraphiQL interactive IDE",           40, "graphql_ui"),
    ("/api/graphiql",           "GraphiQL IDE (namespaced)",          40, "graphql_ui"),
]


# ─────────────────────────────────────────────────────────────────────────────
# Body validation helpers (pure Python — tested independently)
# ─────────────────────────────────────────────────────────────────────────────

def _validate_json_spec(body: str) -> tuple[bool, dict]:
    """Check if body is a genuine OpenAPI/Swagger JSON object."""
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return False, {}
    if not isinstance(data, dict):
        return False, {}
    if any(k in data for k in ("swagger", "openapi", "paths", "info", "components")):
        return True, data
    return False, {}


def _validate_yaml_spec(body: str) -> bool:
    """Heuristic: body starts with OpenAPI / Swagger YAML top-level keys."""
    return bool(_YAML_SPEC_RE.search(body[:600]))


def _validate_swagger_ui(body: str) -> bool:
    """Detect Swagger UI by well-known marker strings."""
    lower = body.lower()
    return "swagger-ui" in lower or "swaggerui" in lower


def _validate_docs_ui(body: str) -> bool:
    """Detect FastAPI / DRF / ReDoc UI."""
    lower = body.lower()
    return (
        "redoc" in lower
        or "rapidoc" in lower
        or "fastapi" in lower
        or ("api" in lower and "documentation" in lower)
    )


def _count_openapi_operations(spec: dict) -> int:
    """Count total HTTP operations declared in an OpenAPI paths object."""
    total = 0
    for path_item in spec.get("paths", {}).values():
        if isinstance(path_item, dict):
            total += sum(1 for k in path_item if k.lower() in _HTTP_METHODS)
    return total


def _get_auth_schemes(spec: dict) -> list[str]:
    """Extract security scheme names from OpenAPI 2/3 spec."""
    schemes: list[str] = []
    schemes.extend((spec.get("components") or {}).get("securitySchemes", {}).keys())
    schemes.extend(spec.get("securityDefinitions", {}).keys())
    return schemes[:6]


# ─────────────────────────────────────────────────────────────────────────────
# Async probe workers
# ─────────────────────────────────────────────────────────────────────────────

async def _probe_single(
    client: httpx.AsyncClient,
    base_url: str,
    path: str,
    description: str,
    base_risk: int,
    category: str,
) -> dict | None:
    """
    Probe one path.  Returns a result dict or None if nothing found.
    The dict includes a "_gql" boolean to separate GraphQL findings.
    """
    probe_url = urljoin(base_url, path)

    try:
        if category == "graphql":
            # POST minimal introspection — read-only, does not mutate data
            r = await client.post(
                probe_url,
                content=_GQL_QUERY.encode(),
                headers={"Content-Type": "application/json"},
            )
            if r.status_code not in (200, 201):
                return None
            try:
                data   = r.json()
                schema = (data.get("data") or {}).get("__schema") or {}
                types  = schema.get("types") or []
                if schema.get("queryType") or types:
                    return {
                        "path":        path,
                        "description": "GraphQL introspection enabled",
                        "category":    "graphql",
                        "type_count":  len(types),
                        "risk":        40,
                        "_gql":        True,
                    }
            except Exception:
                pass
            return None

        # Regular GET probe
        r = await client.get(probe_url)

        if r.status_code not in (200, 206):
            return None

        body = r.text[:30_000]

        valid     = False
        spec_data: dict = {}

        if category == "json_spec":
            valid, spec_data = _validate_json_spec(body)
        elif category == "yaml_spec":
            valid = _validate_yaml_spec(body)
        elif category == "swagger_ui":
            valid = _validate_swagger_ui(body)
        elif category == "docs_ui":
            valid = _validate_docs_ui(body)
        elif category == "graphql_ui":
            valid = "graphiql" in body.lower() or "graphql" in body.lower()

        if not valid:
            return None

        return {
            "path":        path,
            "description": description,
            "category":    category,
            "risk":        base_risk,
            "operations":  _count_openapi_operations(spec_data) if spec_data else 0,
            "auth_schemes": _get_auth_schemes(spec_data) if spec_data else [],
            "_gql":        False,
        }

    except (httpx.TimeoutException, httpx.NetworkError, httpx.HTTPStatusError):
        return None
    except Exception:
        return None


_MAX_CONCURRENT = 10  # max simultaneous HTTP probes per scan — avoids triggering WAF rate-limits

async def _async_scan_core(
    base_url: str,
) -> tuple[list[dict], list[dict], int, list[str]]:
    """
    Fire every spec-path probe concurrently with httpx.AsyncClient.

    Returns
    ────────
    (exposed_specs, graphql_endpoints, total_operations, all_auth_schemes)

    Exposed as a module-level coroutine so tests can call it directly
    with a mocked httpx transport without going through asyncio.run().
    """
    limits  = httpx.Limits(max_connections=_MAX_CONCURRENT + 2, max_keepalive_connections=5)
    timeout = httpx.Timeout(8.0, connect=5.0)

    # Semaphore caps concurrent in-flight requests without changing _probe_single's signature.
    sem = asyncio.Semaphore(_MAX_CONCURRENT)

    async def _bounded(client, path, desc, risk, cat):
        async with sem:
            return await _probe_single(client, base_url, path, desc, risk, cat)

    async with httpx.AsyncClient(
        headers={"User-Agent": _UA},
        timeout=timeout,
        limits=limits,
        follow_redirects=False,
        verify=False,   # target cert may be self-signed or expired — document only
    ) as client:
        tasks = [
            _bounded(client, path, desc, risk, cat)
            for path, desc, risk, cat in _API_SPEC_ENDPOINTS
        ]
        raw = await asyncio.gather(*tasks, return_exceptions=True)

    exposed_specs:    list[dict] = []
    graphql_endpoints: list[dict] = []
    total_operations  = 0
    all_auth_schemes: list[str]  = []

    for item in raw:
        if not isinstance(item, dict):
            continue
        if item.get("_gql"):
            graphql_endpoints.append({k: v for k, v in item.items() if k != "_gql"})
        else:
            cleaned = {k: v for k, v in item.items() if k != "_gql"}
            exposed_specs.append(cleaned)
            total_operations += cleaned.get("operations", 0) or 0
            all_auth_schemes.extend(cleaned.get("auth_schemes") or [])

    return exposed_specs, graphql_endpoints, total_operations, all_auth_schemes


# ─────────────────────────────────────────────────────────────────────────────
# Tool
# ─────────────────────────────────────────────────────────────────────────────

@tool
def scan_api_spec(url: str) -> str:
    """
    Probes a website for publicly accessible API documentation endpoints
    (Swagger/OpenAPI specs, interactive UIs, GraphQL introspection).

    Uses httpx.AsyncClient to probe all 33 known paths CONCURRENTLY —
    the scan takes ~6s regardless of path count instead of up to 3 minutes
    sequential. Fires all probes from within a single event loop created
    by asyncio.run(); safe to call from ThreadPoolExecutor worker threads.

    Args:
        url: Target HTTP or HTTPS URL.

    Returns:
        JSON with exposed_specs, graphql_introspection, total_operations,
        auth_schemes_disclosed, endpoints_probed, risk_score (0–80),
        and recommendations.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return json.dumps({"tool": "api_spec", "status": "invalid_url"})

    if is_ssrf_blocked(parsed.hostname or ""):
        return json.dumps({"tool": "api_spec", "status": "ssrf_blocked"})

    base_url = f"{parsed.scheme}://{parsed.netloc}"

    try:
        exposed_specs, graphql_endpoints, total_operations, all_auth_schemes = (
            asyncio.run(_async_scan_core(base_url))
        )
    except RuntimeError as exc:
        return json.dumps({"tool": "api_spec", "status": "error", "error": str(exc)})

    # ── Risk scoring ──────────────────────────────────────────────────────────
    risk_score = 0
    for spec in exposed_specs:
        risk_score += spec.get("risk", 0)
    for gql in graphql_endpoints:
        risk_score += gql.get("risk", 40)
    if total_operations > 0:
        risk_score += min((total_operations // 25) * 5, 15)
    risk_score = min(risk_score, 80)

    # Deduplicate auth schemes (preserving first-seen order)
    seen: set[str] = set()
    unique_auth: list[str] = []
    for s in all_auth_schemes:
        if s not in seen:
            seen.add(s)
            unique_auth.append(s)

    # ── Recommendations ───────────────────────────────────────────────────────
    recommendations: list[str] = []

    uis = [s for s in exposed_specs if s["category"] == "swagger_ui"]
    if uis:
        paths = ", ".join(s["path"] for s in uis[:3])
        recommendations.append(
            f"CRITICAL: Swagger UI accessible at {paths}. "
            "Restrict to authenticated users or block at the reverse proxy. "
            "nginx: `location ~* /swagger { deny all; }`"
        )

    raw_specs = [s for s in exposed_specs if s["category"] in ("json_spec", "yaml_spec")]
    if raw_specs:
        paths = ", ".join(s["path"] for s in raw_specs[:3])
        ops   = f"{total_operations} operation(s) enumerable" if total_operations else "endpoints enumerable"
        recommendations.append(
            f"API spec exposed at {paths} — {ops}. "
            "Remove raw spec endpoints from production or gate with authentication. "
            "FastAPI: set `docs_url=None, redoc_url=None, openapi_url=None`."
        )

    if graphql_endpoints:
        gql_paths = ", ".join(g["path"] for g in graphql_endpoints[:2])
        recommendations.append(
            f"GraphQL introspection ENABLED at {gql_paths}. Disable it: "
            "Apollo Server → `introspection: process.env.NODE_ENV !== 'production'`. "
            "Introspection exposes your full schema including internal types."
        )

    docs_uis = [s for s in exposed_specs if s["category"] == "docs_ui"]
    if docs_uis:
        paths = ", ".join(s["path"] for s in docs_uis[:2])
        recommendations.append(
            f"Documentation UI at {paths}. Gate with authentication middleware. "
            "FastAPI: add an `HTTPBearer` dependency to the docs routes."
        )

    if not exposed_specs and not graphql_endpoints:
        recommendations.append(
            "No API spec or documentation endpoints publicly accessible. "
            "Periodically re-audit after framework upgrades — many default to enabling docs."
        )

    return json.dumps({
        "tool":                   "api_spec",
        "status":                 "completed",
        "url":                    url,
        "risk_score":             risk_score,
        "exposed_specs":          exposed_specs,
        "graphql_introspection":  graphql_endpoints,
        "total_operations":       total_operations,
        "auth_schemes_disclosed": unique_auth,
        "endpoints_probed":       len(_API_SPEC_ENDPOINTS),
        "recommendations":        recommendations,
    }, indent=2)
