"""
tools/tool_registry.py — AI Cyber Shield v6

Central registry of all 17 scanning tools with metadata.

Usage:
    from tools.tool_registry import TOOL_REGISTRY, get_tool, list_tools

Each entry provides:
  - function    : callable — the LangChain tool
  - display_name: str — human-readable label
  - weight      : int — scoring weight (all 17 sum to 100)
  - timeout_seconds: int — per-tool execution cap
"""

from __future__ import annotations

from tools.api_spec_scanner           import scan_api_spec
from tools.cert_transparency          import scan_certificate_transparency
from tools.cookie_security            import scan_cookie_security
from tools.cors_csp_checker           import check_cors_csp
from tools.deep_js_crawler            import crawl_spa
from tools.dns_scanner                import scan_dns_security
from tools.exposure_checker           import check_exposure
from tools.hsts_preload               import check_hsts_preload
from tools.html_scanner               import scan_html
from tools.open_redirect              import scan_open_redirects
from tools.port_scanner               import scan_open_ports
from tools.ssl_analyzer               import analyze_ssl
from tools.subdomain_takeover_checker import check_subdomain_takeover
from tools.tech_fingerprinter         import fingerprint_technologies
from tools.waf_detector               import detect_waf
from tools.web_crawler                import crawl_website
from tools.web_tools                  import check_security_headers

TOOL_REGISTRY: dict[str, dict] = {
    "ssl": {
        "function":        analyze_ssl,
        "display_name":    "SSL/TLS Analysis",
        "weight":          13,
        "timeout_seconds": 30,
        "invoke_args":     lambda url: {"url": url},
    },
    "headers": {
        "function":        check_security_headers,
        "display_name":    "Security Headers",
        "weight":          9,
        "timeout_seconds": 15,
        "invoke_args":     lambda url: {"url": url},
    },
    "html": {
        "function":        scan_html,
        "display_name":    "HTML Analysis",
        "weight":          9,
        "timeout_seconds": 20,
        "invoke_args":     lambda url: {"url": url},
    },
    "tech": {
        "function":        fingerprint_technologies,
        "display_name":    "Technology Fingerprinting",
        "weight":          5,
        "timeout_seconds": 20,
        "invoke_args":     lambda url: {"url": url},
    },
    "crawler": {
        "function":        crawl_website,
        "display_name":    "Web Crawler",
        "weight":          7,
        "timeout_seconds": 60,
        "invoke_args":     lambda url: {"url": url, "max_pages": 15},
    },
    "cors_csp": {
        "function":        check_cors_csp,
        "display_name":    "CORS & CSP Checker",
        "weight":          6,
        "timeout_seconds": 15,
        "invoke_args":     lambda url: {"url": url},
    },
    "dns": {
        "function":        scan_dns_security,
        "display_name":    "DNS Security",
        "weight":          6,
        "timeout_seconds": 20,
        "invoke_args":     lambda url: {"url": url},
    },
    "exposure": {
        "function":        check_exposure,
        "display_name":    "Exposure Checker",
        "weight":          6,
        "timeout_seconds": 30,
        "invoke_args":     lambda url: {"url": url},
    },
    "waf": {
        "function":        detect_waf,
        "display_name":    "WAF Detection",
        "weight":          3,
        "timeout_seconds": 15,
        "invoke_args":     lambda url: {"url": url},
    },
    "cert_transparency": {
        "function":        scan_certificate_transparency,
        "display_name":    "Certificate Transparency",
        "weight":          1,
        "timeout_seconds": 30,
        "invoke_args":     lambda url: {"url": url},
    },
    "hsts_preload": {
        "function":        check_hsts_preload,
        "display_name":    "HSTS Preload",
        "weight":          5,
        "timeout_seconds": 15,
        "invoke_args":     lambda url: {"url": url},
    },
    "open_redirect": {
        "function":        scan_open_redirects,
        "display_name":    "Open Redirect Scanner",
        "weight":          5,
        "timeout_seconds": 30,
        "invoke_args":     lambda url: {"url": url},
    },
    "api_spec": {
        "function":        scan_api_spec,
        "display_name":    "API Spec Scanner",
        "weight":          5,
        "timeout_seconds": 20,
        "invoke_args":     lambda url: {"url": url},
    },
    "port_scanner": {
        "function":        scan_open_ports,
        "display_name":    "Port Scanner",
        "weight":          5,
        "timeout_seconds": 45,
        "invoke_args":     lambda url: {"url": url},
    },
    "cookie_security": {
        "function":        scan_cookie_security,
        "display_name":    "Cookie Security",
        "weight":          5,
        "timeout_seconds": 15,
        "invoke_args":     lambda url: {"url": url},
    },
    "deep_js_crawler": {
        "function":        crawl_spa,
        "display_name":    "Deep JS Crawler",
        "weight":          4,
        "timeout_seconds": 60,
        "invoke_args":     lambda url: {"url": url},
    },
    "subdomain_takeover": {
        "function":        check_subdomain_takeover,
        "display_name":    "Subdomain Takeover Check",
        "weight":          6,
        "timeout_seconds": 45,
        "invoke_args":     lambda url: {"url": url, "subdomains_json": "[]"},
    },
}


def get_tool(tool_name: str) -> dict:
    """Return tool config dict. Raises KeyError if not registered."""
    return TOOL_REGISTRY[tool_name]


def list_tools() -> list[str]:
    """Return all registered tool names."""
    return list(TOOL_REGISTRY.keys())
