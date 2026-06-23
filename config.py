"""
Central configuration loaded once at startup.
All tools and agents import from here — never os.getenv() directly.
"""

import ipaddress
from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, field_validator


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8-sig",
        case_sensitive=False,
        extra="ignore",
    )

    # Database — Supabase (differential scan history)
    supabase_url: str = Field("", description="Supabase project URL")
    supabase_key: str = Field("", description="Supabase anon / service-role key")

    # Alerting channels (optional)
    slack_webhook_url: str = Field("", description="Slack Incoming Webhook URL")
    alert_webhook_url: str = Field("", description="Generic SIEM / DevOps webhook URL")

    # LLM — Groq (primary), others optional
    groq_api_key: str = Field(..., description="Groq API key")
    google_api_key: str = Field("", description="Google AI Studio API key (optional)")
    anthropic_api_key: str = Field("", description="Anthropic API key (optional)")

    # Threat intel
    virustotal_api_key: str = Field("", description="VirusTotal API key (optional at import time)")
    google_safe_browsing_api_key: str = Field("", description="GSB key (optional)")

    # CVE Intelligence (all optional — free tier works without keys, keys raise rate limits)
    nvd_api_key: str = Field(
        "", description="NVD API key — increases rate limit from 5 to 50 req/30s. Free: nvd.nist.gov/developers/request-an-api-key"
    )
    github_token: str = Field(
        "", description="GitHub token — increases Advisory rate limit from 60 to 5000 req/hour. Never stored as module-level global."
    )

    # Multi-tenancy + Billing (Stripe)
    stripe_secret_key: str = Field(
        "", description="Stripe secret key (sk_live_... or sk_test_...). Never commit to source control."
    )
    stripe_webhook_secret: str = Field(
        "", description="Stripe webhook signing secret (whsec_...). Found in Stripe Dashboard → Webhooks."
    )
    stripe_price_starter: str = Field(
        "", description="Stripe Price ID for Starter tier ($49/mo). Create in Stripe Dashboard → Products."
    )
    stripe_price_professional: str = Field(
        "", description="Stripe Price ID for Professional tier ($149/mo)."
    )

    # Scanner behaviour
    sast_timeout_seconds: int = Field(60, ge=10, le=300)
    semgrep_ruleset: str = Field("p/owasp-top-ten")

    # SSRF guard — parsed into ipaddress network objects
    blocked_cidr_ranges: str = Field(
        "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8,169.254.0.0/16"
    )

    @field_validator("semgrep_ruleset")
    @classmethod
    def validate_ruleset(cls, v: str) -> str:
        allowed = {"auto", "p/owasp-top-ten", "p/security-audit", "p/python", "p/javascript"}
        if v not in allowed:
            raise ValueError(f"semgrep_ruleset must be one of {allowed}")
        return v

    def get_blocked_networks(self) -> list[ipaddress.IPv4Network]:
        networks = []
        for cidr in self.blocked_cidr_ranges.split(","):
            cidr = cidr.strip()
            if cidr:
                networks.append(ipaddress.IPv4Network(cidr, strict=False))
        return networks


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]


def is_benchmark_mode() -> bool:
    """
    Returns True when the accuracy benchmark test suite is running.
    Set AICS_BENCHMARK_MODE=1 to enable — allows loopback addresses for mock servers.
    Never set this in production.
    """
    import os
    return os.environ.get("AICS_BENCHMARK_MODE") == "1"
