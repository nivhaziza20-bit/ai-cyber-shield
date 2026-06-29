-- ─────────────────────────────────────────────────────────────────────────────
-- Migration 002: Scan History table
-- Run in Supabase SQL editor after 001_rate_limits_and_guest_quotas.sql
-- ─────────────────────────────────────────────────────────────────────────────

-- ── Scan history ─────────────────────────────────────────────────────────────
-- Stores every scan result (URL scanner + Legal scanner).
-- Referenced by: scan_history_store._SupabaseStore

CREATE TABLE IF NOT EXISTS scan_history (
  id               UUID        DEFAULT gen_random_uuid() PRIMARY KEY,
  scan_id          TEXT        NOT NULL UNIQUE,            -- app-generated UUID
  user_id          UUID        REFERENCES auth.users(id) ON DELETE CASCADE,
  url              TEXT        NOT NULL,
  scan_timestamp   TIMESTAMPTZ DEFAULT NOW(),
  overall_score    INTEGER     DEFAULT 0,
  overall_grade    TEXT        DEFAULT 'F',
  category_scores  JSONB       DEFAULT '{}',
  critical_findings JSONB      DEFAULT '[]',
  created_at       TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS scan_history_user_id_idx     ON scan_history (user_id);
CREATE INDEX IF NOT EXISTS scan_history_url_idx         ON scan_history (url);
CREATE INDEX IF NOT EXISTS scan_history_timestamp_idx   ON scan_history (scan_timestamp DESC);

-- ── Row Level Security ────────────────────────────────────────────────────────
ALTER TABLE scan_history ENABLE ROW LEVEL SECURITY;

-- Users can only see their own scan history
CREATE POLICY "scan_history_select_own"
  ON scan_history FOR SELECT
  USING (auth.uid() = user_id);

-- Users can only insert their own scans
CREATE POLICY "scan_history_insert_own"
  ON scan_history FOR INSERT
  WITH CHECK (auth.uid() = user_id);

-- Users can delete their own scans
CREATE POLICY "scan_history_delete_own"
  ON scan_history FOR DELETE
  USING (auth.uid() = user_id);

-- Service role bypasses RLS (for admin queries)

-- ── Set your account to admin ─────────────────────────────────────────────────
-- Run this ONCE after first login to grant yourself admin access:
-- UPDATE profiles SET role = 'admin' WHERE email = 'nivhaziza20@gmail.com';
