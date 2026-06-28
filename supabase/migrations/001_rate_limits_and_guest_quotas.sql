-- ─────────────────────────────────────────────────────────────────────────────
-- Migration 001: Rate limits + Guest quotas
-- Run once in Supabase SQL editor (or via supabase db push)
-- ─────────────────────────────────────────────────────────────────────────────

-- ── Rate limits table ─────────────────────────────────────────────────────────
-- Stores sliding-window request counters, keyed by "ip:action".
-- One row per (IP, action type). Updated via upsert on every request.

CREATE TABLE IF NOT EXISTS rate_limits (
  key          TEXT        PRIMARY KEY,           -- e.g. "1.2.3.4:scan"
  count        INTEGER     NOT NULL DEFAULT 1,
  window_start TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Auto-vacuum old entries (rows older than 2 minutes are never checked again)
-- This is a lightweight cleanup index — not required for correctness.
CREATE INDEX IF NOT EXISTS rate_limits_updated_at_idx ON rate_limits (updated_at);

-- ── Guest quotas table ────────────────────────────────────────────────────────
-- Tracks daily guest scan usage per IP address.
-- Resets automatically each calendar day (UTC) via date comparison in app code.

CREATE TABLE IF NOT EXISTS guest_quotas (
  ip_key      TEXT    PRIMARY KEY,    -- e.g. "1.2.3.4:guest"
  count       INTEGER NOT NULL DEFAULT 1,
  quota_day   DATE    NOT NULL DEFAULT CURRENT_DATE,
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS guest_quotas_day_idx ON guest_quotas (quota_day);

-- ── Audit logs table (if not already created) ────────────────────────────────
-- Referenced in audit_log.py — create here if missing.

CREATE TABLE IF NOT EXISTS audit_logs (
  id          UUID        DEFAULT gen_random_uuid() PRIMARY KEY,
  created_at  TIMESTAMPTZ DEFAULT NOW(),
  user_id     UUID        REFERENCES auth.users(id) ON DELETE SET NULL,
  user_email  TEXT,
  action      TEXT        NOT NULL,
  target      TEXT,
  details     JSONB       DEFAULT '{}',
  severity    TEXT        DEFAULT 'info'
);

CREATE INDEX IF NOT EXISTS audit_logs_created_at_idx  ON audit_logs (created_at DESC);
CREATE INDEX IF NOT EXISTS audit_logs_user_id_idx     ON audit_logs (user_id);
CREATE INDEX IF NOT EXISTS audit_logs_action_idx      ON audit_logs (action);

-- ── Profiles table (if not already created) ───────────────────────────────────
-- Stores per-user metadata: role, quota, PT approval, subscription tier.

CREATE TABLE IF NOT EXISTS profiles (
  id                 UUID        PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  email              TEXT,
  role               TEXT        DEFAULT 'user',
  pt_approved        BOOLEAN     DEFAULT FALSE,
  subscription_tier  TEXT        DEFAULT 'free',
  stripe_customer_id TEXT,
  scans_today        INTEGER     DEFAULT 0,
  scans_today_reset  DATE        DEFAULT CURRENT_DATE,
  created_at         TIMESTAMPTZ DEFAULT NOW()
);

-- ── Row Level Security ────────────────────────────────────────────────────────
-- rate_limits and guest_quotas are written by the service-role key only.
-- Never expose them via anon key.

ALTER TABLE rate_limits  ENABLE ROW LEVEL SECURITY;
ALTER TABLE guest_quotas ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs   ENABLE ROW LEVEL SECURITY;

-- Service role bypasses RLS automatically — no explicit policy needed.
-- Anon users get no access (no SELECT / INSERT policy = deny all).

-- ── Make admin easy ──────────────────────────────────────────────────────────
-- Set your account to admin (replace with your real email):
-- UPDATE profiles SET role = 'admin' WHERE email = 'nivhaziza20@gmail.com';
