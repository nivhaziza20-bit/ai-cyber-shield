"""
tenancy/api_key_manager.py — AI Cyber Shield v6

API key lifecycle management.

Security design:
  - Keys generated with secrets.token_hex(32) — 256 bits of entropy
  - Only the SHA-256 hash is stored in the DB — never the plaintext key
  - First 16 characters used as a lookup prefix (avoids full-table hash scan)
  - Keys are prefixed with "aics_" for easy identification in logs/config
  - Rotation invalidates the old key immediately — no grace period

Key format:  aics_{slug}_{64-hex-chars}
             └─ 5 ─┘  └─ var ─┘  └──── 64 ────┘
Example:     aics_acme-corp_a3f2...e9b1

Why not JWT for API keys?
  JWTs for API keys create stateless trust — a leaked key cannot be instantly
  revoked without a denylist. We store a hash, so rotation = instant revocation.
"""

from __future__ import annotations

import hashlib
import secrets
import re


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

_KEY_PREFIX_LEN = 16   # chars stored for DB lookup
_PREFIX = "aics_"


def generate_api_key(tenant_slug: str) -> tuple[str, str, str]:
    """
    Generate a new API key for a tenant.

    Returns:
        (full_key, key_hash, key_prefix)
        - full_key:   shown to the user exactly once — store it nowhere
        - key_hash:   SHA-256 hex — store this in DB
        - key_prefix: first _KEY_PREFIX_LEN chars — stored for lookup

    The caller is responsible for storing key_hash + key_prefix.
    """
    random_part = secrets.token_hex(32)   # 64 hex chars = 256 bits
    safe_slug = re.sub(r"[^a-z0-9-]", "", tenant_slug.lower())[:20]
    full_key = f"{_PREFIX}{safe_slug}_{random_part}"
    key_hash = _sha256(full_key)
    key_prefix = full_key[:_KEY_PREFIX_LEN]
    return full_key, key_hash, key_prefix


def verify_api_key(full_key: str, stored_hash: str) -> bool:
    """
    Return True if SHA-256(full_key) == stored_hash.
    Uses constant-time comparison to prevent timing attacks.
    """
    if not full_key or not stored_hash:
        return False
    computed = _sha256(full_key)
    return secrets.compare_digest(computed, stored_hash)


def extract_prefix(full_key: str) -> str:
    """Return the lookup prefix from a full API key."""
    return full_key[:_KEY_PREFIX_LEN]


def mask_api_key(full_key: str) -> str:
    """
    Return a display-safe version: 'aics_slug_a3f2****e9b1'.
    Shows first 4 and last 4 chars of the random part.
    Safe to log and display in UI.
    """
    if not full_key or len(full_key) < _KEY_PREFIX_LEN + 8:
        return "aics_****"
    # Find the underscore after "aics_slug_"
    parts = full_key.split("_", 2)   # ["aics", slug, random64]
    if len(parts) < 3:
        return f"{full_key[:8]}****"
    random = parts[2]
    masked_random = f"{random[:4]}{'*' * (len(random) - 8)}{random[-4:]}"
    return f"{_PREFIX}{parts[1]}_{masked_random}"


def is_valid_key_format(key: str) -> bool:
    """Quick format check — does not verify against DB."""
    return bool(re.match(r"^aics_[a-z0-9-]{1,20}_[0-9a-f]{64}$", key))


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
