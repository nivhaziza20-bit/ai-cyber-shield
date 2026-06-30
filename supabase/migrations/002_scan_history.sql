-- ─────────────────────────────────────────────────────────────────────────────
-- Migration 002: Scan History table
-- Run in Supabase SQL editor after 001_rate_limits_and_guest_quotas.sql
--
-- NOTE (corrected 2026-06-30): the table is written by TWO different modules
-- with two different column sets:
--   scan_history.py          — target_url, findings_count, critical_count,
--                               high_count, scan_mode, scan_duration_s, report_md
--   scan_history_store.py    — scan_id, url, scan_timestamp, critical_findings
-- This migration is additive (CREATE ... IF NOT EXISTS / ADD COLUMN IF NOT
-- EXISTS) so it is safe to run whether the table already exists with one of
-- the two schemas, the other, or neither — it always converges on the union
-- of both, which is what both modules need.
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS scan_history (
  id                 UUID        DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id            UUID        REFERENCES auth.users(id) ON DELETE CASCADE,
  created_at         TIMESTAMPTZ DEFAULT NOW()
);

-- ── Columns used by scan_history.py (the "rich" store) ────────────────────────
ALTER TABLE scan_history
  ADD COLUMN IF NOT EXISTS target_url        TEXT,
  ADD COLUMN IF NOT EXISTS overall_grade     TEXT        DEFAULT 'F',
  ADD COLUMN IF NOT EXISTS overall_score     INTEGER     DEFAULT 0,
  ADD COLUMN IF NOT EXISTS category_scores   JSONB       DEFAULT '{}',
  ADD COLUMN IF NOT EXISTS findings_count    INTEGER,
  ADD COLUMN IF NOT EXISTS critical_count    INTEGER,
  ADD COLUMN IF NOT EXISTS high_count        INTEGER,
  ADD COLUMN IF NOT EXISTS scan_mode         TEXT,
  ADD COLUMN IF NOT EXISTS scan_duration_s   DOUBLE PRECISION,
  ADD COLUMN IF NOT EXISTS report_md         TEXT;

-- ── Columns used by scan_history_store.py (_SupabaseStore) ────────────────────
ALTER TABLE scan_history
  ADD COLUMN IF NOT EXISTS scan_id           TEXT,
  ADD COLUMN IF NOT EXISTS url               TEXT,
  ADD COLUMN IF NOT EXISTS scan_timestamp    TIMESTAMPTZ DEFAULT NOW(),
  ADD COLUMN IF NOT EXISTS critical_findings JSONB       DEFAULT '[]';

-- No NOT NULL / UNIQUE constraints are added retroactively — existing rows
-- written by either module will have NULLs in the other module's columns,
-- and that's fine, neither module requires the other's columns to be set.

CREATE INDEX IF NOT EXISTS scan_history_user_id_idx     ON scan_history (user_id);
CREATE INDEX IF NOT EXISTS scan_history_url_idx         ON scan_history (url);
CREATE INDEX IF NOT EXISTS scan_history_target_url_idx  ON scan_history (target_url);
CREATE INDEX IF NOT EXISTS scan_history_timestamp_idx   ON scan_history (scan_timestamp DESC);
CREATE INDEX IF NOT EXISTS scan_history_created_at_idx  ON scan_history (created_at DESC);

-- ── Row Level Security ────────────────────────────────────────────────────────
ALTER TABLE scan_history ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "scan_history_select_own" ON scan_history;
CREATE POLICY "scan_history_select_own"
  ON scan_history FOR SELECT
  USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "scan_history_insert_own" ON scan_history;
CREATE POLICY "scan_history_insert_own"
  ON scan_history FOR INSERT
  WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "scan_history_delete_own" ON scan_history;
CREATE POLICY "scan_history_delete_own"
  ON scan_history FOR DELETE
  USING (auth.uid() = user_id);

-- Service role bypasses RLS (for admin queries)

-- ── Set your account to admin ─────────────────────────────────────────────────
-- Run this ONCE after first login to grant yourself admin access:
-- UPDATE profiles SET role = 'admin' WHERE email = 'nivhaziza20@gmail.com';
