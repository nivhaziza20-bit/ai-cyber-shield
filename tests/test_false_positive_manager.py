"""
tests/test_false_positive_manager.py — AI Cyber Shield v6

Test suite for reports/false_positive_manager.py.

Tests cover:
  • FindingState enum values
  • compute_fingerprint: deterministic, different inputs → different outputs
  • InvalidTransitionError raised for forbidden transitions
  • All allowed transitions from each state
  • All disallowed transitions from each state
  • FalsePositiveManager:
    - register_finding creates OPEN record
    - register_finding is idempotent (second call same fingerprint)
    - register_finding on FIXED → OPEN regression
    - confirm_finding OPEN → CONFIRMED
    - mark_false_positive OPEN → FALSE_POS
    - mark_false_positive CONFIRMED → FALSE_POS
    - suppress FALSE_POS → SUPPRESSED
    - unmark_false_positive FALSE_POS → OPEN
    - lift_suppression SUPPRESSED → OPEN
    - mark_fixed OPEN → FIXED
    - mark_fixed CONFIRMED → FIXED
    - audit trail grows with each transition
    - is_suppressed / is_false_positive
    - get_suppressed_fingerprints
    - get_open_fingerprints
    - stats()
    - mark_all_false_positive bulk operation
    - mark_all_false_positive skips invalid transitions
    - process_rescan: new findings registered
    - process_rescan: disappeared OPEN → FIXED
    - process_rescan: disappeared CONFIRMED → FIXED
    - process_rescan: FIXED re-appears → OPEN (regression)
    - process_rescan: FALSE_POS disappeared → unchanged
    - process_rescan: SUPPRESSED disappeared → unchanged
    - JSON persistence: save and reload
    - export_json roundtrip
    - Thread safety: concurrent transitions don't corrupt state
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
from pathlib import Path

import pytest

from reports.false_positive_manager import (
    FindingState,
    FindingRecord,
    AuditEntry,
    FalsePositiveManager,
    InvalidTransitionError,
    compute_fingerprint,
    _transition,
    _ALLOWED_TRANSITIONS,
)


# ─────────────────────────────────────────────────────────────────────────────
# TestFindingState
# ─────────────────────────────────────────────────────────────────────────────

class TestFindingState:
    def test_enum_values(self):
        assert FindingState.OPEN.value       == "OPEN"
        assert FindingState.CONFIRMED.value  == "CONFIRMED"
        assert FindingState.FALSE_POS.value  == "FALSE_POS"
        assert FindingState.SUPPRESSED.value == "SUPPRESSED"
        assert FindingState.FIXED.value      == "FIXED"

    def test_is_string_enum(self):
        assert isinstance(FindingState.OPEN, str)

    def test_all_five_states_exist(self):
        assert len(FindingState) == 5


# ─────────────────────────────────────────────────────────────────────────────
# TestComputeFingerprint
# ─────────────────────────────────────────────────────────────────────────────

class TestComputeFingerprint:
    def test_deterministic(self):
        fp1 = compute_fingerprint("xss", "https://example.com/search", "q")
        fp2 = compute_fingerprint("xss", "https://example.com/search", "q")
        assert fp1 == fp2

    def test_different_type_different_fingerprint(self):
        fp1 = compute_fingerprint("xss",   "https://example.com", "q")
        fp2 = compute_fingerprint("sqli",  "https://example.com", "q")
        assert fp1 != fp2

    def test_different_endpoint_different_fingerprint(self):
        fp1 = compute_fingerprint("xss", "https://a.com/path", "q")
        fp2 = compute_fingerprint("xss", "https://b.com/path", "q")
        assert fp1 != fp2

    def test_different_parameter_different_fingerprint(self):
        fp1 = compute_fingerprint("xss", "https://example.com", "q")
        fp2 = compute_fingerprint("xss", "https://example.com", "name")
        assert fp1 != fp2

    def test_returns_32_char_hex(self):
        fp = compute_fingerprint("xss", "https://example.com", "q")
        assert len(fp) == 32
        int(fp, 16)   # should not raise

    def test_trailing_slash_normalised(self):
        fp1 = compute_fingerprint("xss", "https://example.com/",  "q")
        fp2 = compute_fingerprint("xss", "https://example.com",   "q")
        assert fp1 == fp2

    def test_empty_parameter(self):
        fp = compute_fingerprint("cors", "https://example.com/api")
        assert len(fp) == 32


# ─────────────────────────────────────────────────────────────────────────────
# TestAllowedTransitions
# ─────────────────────────────────────────────────────────────────────────────

class TestAllowedTransitions:
    """Verify the transition table is correct."""

    def _make_record(self, state: FindingState) -> FindingRecord:
        rec = FindingRecord(fingerprint="test", state=state)
        return rec

    # OPEN → *
    def test_open_to_confirmed_allowed(self):
        rec = self._make_record(FindingState.OPEN)
        _transition(rec, FindingState.CONFIRMED, "analyst")
        assert rec.state == FindingState.CONFIRMED

    def test_open_to_false_pos_allowed(self):
        rec = self._make_record(FindingState.OPEN)
        _transition(rec, FindingState.FALSE_POS, "analyst")
        assert rec.state == FindingState.FALSE_POS

    def test_open_to_fixed_allowed(self):
        rec = self._make_record(FindingState.OPEN)
        _transition(rec, FindingState.FIXED, "ci-bot")
        assert rec.state == FindingState.FIXED

    def test_open_to_suppressed_forbidden(self):
        rec = self._make_record(FindingState.OPEN)
        with pytest.raises(InvalidTransitionError):
            _transition(rec, FindingState.SUPPRESSED, "analyst")

    def test_open_to_open_forbidden(self):
        rec = self._make_record(FindingState.OPEN)
        with pytest.raises(InvalidTransitionError):
            _transition(rec, FindingState.OPEN, "analyst")

    # CONFIRMED → *
    def test_confirmed_to_fixed_allowed(self):
        rec = self._make_record(FindingState.CONFIRMED)
        _transition(rec, FindingState.FIXED, "ci-bot")
        assert rec.state == FindingState.FIXED

    def test_confirmed_to_false_pos_allowed(self):
        rec = self._make_record(FindingState.CONFIRMED)
        _transition(rec, FindingState.FALSE_POS, "analyst")
        assert rec.state == FindingState.FALSE_POS

    def test_confirmed_to_open_forbidden(self):
        rec = self._make_record(FindingState.CONFIRMED)
        with pytest.raises(InvalidTransitionError):
            _transition(rec, FindingState.OPEN, "analyst")

    # FALSE_POS → *
    def test_false_pos_to_open_allowed(self):
        rec = self._make_record(FindingState.FALSE_POS)
        _transition(rec, FindingState.OPEN, "analyst")
        assert rec.state == FindingState.OPEN

    def test_false_pos_to_suppressed_allowed(self):
        rec = self._make_record(FindingState.FALSE_POS)
        _transition(rec, FindingState.SUPPRESSED, "analyst")
        assert rec.state == FindingState.SUPPRESSED

    def test_false_pos_to_confirmed_forbidden(self):
        rec = self._make_record(FindingState.FALSE_POS)
        with pytest.raises(InvalidTransitionError):
            _transition(rec, FindingState.CONFIRMED, "analyst")

    def test_false_pos_to_fixed_forbidden(self):
        rec = self._make_record(FindingState.FALSE_POS)
        with pytest.raises(InvalidTransitionError):
            _transition(rec, FindingState.FIXED, "ci-bot")

    # SUPPRESSED → *
    def test_suppressed_to_open_allowed(self):
        rec = self._make_record(FindingState.SUPPRESSED)
        _transition(rec, FindingState.OPEN, "analyst")
        assert rec.state == FindingState.OPEN

    def test_suppressed_to_confirmed_forbidden(self):
        rec = self._make_record(FindingState.SUPPRESSED)
        with pytest.raises(InvalidTransitionError):
            _transition(rec, FindingState.CONFIRMED, "analyst")

    def test_suppressed_to_false_pos_forbidden(self):
        rec = self._make_record(FindingState.SUPPRESSED)
        with pytest.raises(InvalidTransitionError):
            _transition(rec, FindingState.FALSE_POS, "analyst")

    # FIXED → *
    def test_fixed_to_open_allowed(self):
        rec = self._make_record(FindingState.FIXED)
        _transition(rec, FindingState.OPEN, "ci-bot")
        assert rec.state == FindingState.OPEN

    def test_fixed_to_confirmed_forbidden(self):
        rec = self._make_record(FindingState.FIXED)
        with pytest.raises(InvalidTransitionError):
            _transition(rec, FindingState.CONFIRMED, "analyst")

    def test_fixed_to_suppressed_forbidden(self):
        rec = self._make_record(FindingState.FIXED)
        with pytest.raises(InvalidTransitionError):
            _transition(rec, FindingState.SUPPRESSED, "analyst")


# ─────────────────────────────────────────────────────────────────────────────
# TestAuditTrail
# ─────────────────────────────────────────────────────────────────────────────

class TestAuditTrail:
    def test_transition_adds_audit_entry(self):
        rec = FindingRecord(fingerprint="fp", state=FindingState.OPEN)
        _transition(rec, FindingState.CONFIRMED, "alice@test.com", "verified")
        assert len(rec.audit_trail) == 1
        entry = rec.audit_trail[0]
        assert entry.from_state == "OPEN"
        assert entry.to_state   == "CONFIRMED"
        assert entry.analyst    == "alice@test.com"
        assert entry.reason     == "verified"

    def test_multiple_transitions_build_trail(self):
        rec = FindingRecord(fingerprint="fp", state=FindingState.OPEN)
        _transition(rec, FindingState.CONFIRMED, "alice")
        _transition(rec, FindingState.FALSE_POS, "bob")
        _transition(rec, FindingState.OPEN, "alice", "re-verified")
        assert len(rec.audit_trail) == 3

    def test_audit_entry_has_timestamp(self):
        rec = FindingRecord(fingerprint="fp", state=FindingState.OPEN)
        _transition(rec, FindingState.CONFIRMED, "alice")
        assert "T" in rec.audit_trail[0].timestamp  # ISO timestamp


# ─────────────────────────────────────────────────────────────────────────────
# TestFalsePositiveManager
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def mgr():
    """In-memory manager (no persistence)."""
    return FalsePositiveManager()


class TestFalsePositiveManagerBasic:
    def test_register_creates_open_record(self, mgr):
        rec = mgr.register_finding("fp-001", "f-001", "XSS Finding")
        assert rec.state == FindingState.OPEN

    def test_register_idempotent(self, mgr):
        mgr.register_finding("fp-001", "f-001")
        mgr.register_finding("fp-001", "f-001")   # second call
        assert len(mgr.all_records()) == 1

    def test_register_fixed_causes_regression(self, mgr):
        mgr.register_finding("fp-001")
        mgr.mark_fixed("fp-001", "ci-bot")
        # Now register again (rescan found it again)
        rec = mgr.register_finding("fp-001", analyst="ci-bot")
        assert rec.state == FindingState.OPEN

    def test_get_state_returns_none_for_unknown(self, mgr):
        assert mgr.get_state("unknown-fp") is None

    def test_get_state_after_register(self, mgr):
        mgr.register_finding("fp-001")
        assert mgr.get_state("fp-001") == FindingState.OPEN

    def test_confirm_finding(self, mgr):
        mgr.register_finding("fp-001")
        rec = mgr.confirm_finding("fp-001", "analyst")
        assert rec.state == FindingState.CONFIRMED

    def test_mark_false_positive_from_open(self, mgr):
        mgr.register_finding("fp-001")
        rec = mgr.mark_false_positive("fp-001", "analyst", "Test artifact")
        assert rec.state == FindingState.FALSE_POS

    def test_mark_false_positive_from_confirmed(self, mgr):
        mgr.register_finding("fp-001")
        mgr.confirm_finding("fp-001", "alice")
        rec = mgr.mark_false_positive("fp-001", "bob", "Re-reviewed")
        assert rec.state == FindingState.FALSE_POS

    def test_suppress(self, mgr):
        mgr.register_finding("fp-001")
        mgr.mark_false_positive("fp-001", "analyst")
        rec = mgr.suppress("fp-001", "analyst", "Global suppression")
        assert rec.state == FindingState.SUPPRESSED
        assert rec.suppression_reason == "Global suppression"

    def test_unmark_false_positive(self, mgr):
        mgr.register_finding("fp-001")
        mgr.mark_false_positive("fp-001", "analyst")
        rec = mgr.unmark_false_positive("fp-001", "analyst", "Re-opened")
        assert rec.state == FindingState.OPEN

    def test_lift_suppression(self, mgr):
        mgr.register_finding("fp-001")
        mgr.mark_false_positive("fp-001", "analyst")
        mgr.suppress("fp-001", "analyst")
        rec = mgr.lift_suppression("fp-001", "analyst", "Suppression lifted")
        assert rec.state == FindingState.OPEN
        assert rec.suppression_reason == ""

    def test_mark_fixed_from_open(self, mgr):
        mgr.register_finding("fp-001")
        rec = mgr.mark_fixed("fp-001", "ci-bot", "Not found in rescan")
        assert rec.state == FindingState.FIXED

    def test_mark_fixed_from_confirmed(self, mgr):
        mgr.register_finding("fp-001")
        mgr.confirm_finding("fp-001", "alice")
        rec = mgr.mark_fixed("fp-001", "ci-bot")
        assert rec.state == FindingState.FIXED

    def test_invalid_transition_raises(self, mgr):
        mgr.register_finding("fp-001")
        mgr.mark_fixed("fp-001", "ci-bot")
        with pytest.raises(InvalidTransitionError):
            mgr.confirm_finding("fp-001", "analyst")

    def test_audit_trail_recorded(self, mgr):
        mgr.register_finding("fp-001")
        mgr.confirm_finding("fp-001", "alice", "Verified in lab")
        mgr.mark_fixed("fp-001", "ci-bot")
        rec = mgr.get_record("fp-001")
        assert len(rec.audit_trail) == 2
        assert rec.audit_trail[0].analyst == "alice"
        assert rec.audit_trail[1].analyst == "ci-bot"


# ─────────────────────────────────────────────────────────────────────────────
# TestQueryHelpers
# ─────────────────────────────────────────────────────────────────────────────

class TestQueryHelpers:
    def test_is_suppressed_true(self, mgr):
        mgr.register_finding("fp-001")
        mgr.mark_false_positive("fp-001", "analyst")
        mgr.suppress("fp-001", "analyst")
        assert mgr.is_suppressed("fp-001") is True

    def test_is_suppressed_false_for_open(self, mgr):
        mgr.register_finding("fp-001")
        assert mgr.is_suppressed("fp-001") is False

    def test_is_suppressed_false_for_unknown(self, mgr):
        assert mgr.is_suppressed("unknown") is False

    def test_is_false_positive_true(self, mgr):
        mgr.register_finding("fp-001")
        mgr.mark_false_positive("fp-001", "analyst")
        assert mgr.is_false_positive("fp-001") is True

    def test_is_false_positive_false_for_open(self, mgr):
        mgr.register_finding("fp-001")
        assert mgr.is_false_positive("fp-001") is False

    def test_get_suppressed_fingerprints(self, mgr):
        mgr.register_finding("fp-001")
        mgr.register_finding("fp-002")
        mgr.mark_false_positive("fp-001", "analyst")
        mgr.suppress("fp-001", "analyst")
        supp = mgr.get_suppressed_fingerprints()
        assert "fp-001" in supp
        assert "fp-002" not in supp

    def test_get_open_fingerprints(self, mgr):
        mgr.register_finding("fp-001")
        mgr.register_finding("fp-002")
        mgr.mark_false_positive("fp-001", "analyst")
        open_fps = mgr.get_open_fingerprints()
        assert "fp-002" in open_fps
        assert "fp-001" not in open_fps

    def test_stats(self, mgr):
        mgr.register_finding("fp-001")
        mgr.register_finding("fp-002")
        mgr.mark_false_positive("fp-001", "analyst")
        s = mgr.stats()
        assert s["OPEN"]      == 1
        assert s["FALSE_POS"] == 1
        assert s["CONFIRMED"] == 0

    def test_all_records(self, mgr):
        mgr.register_finding("fp-001")
        mgr.register_finding("fp-002")
        assert len(mgr.all_records()) == 2


# ─────────────────────────────────────────────────────────────────────────────
# TestBulkOperations
# ─────────────────────────────────────────────────────────────────────────────

class TestBulkOperations:
    def test_mark_all_false_positive_success(self, mgr):
        for fp in ["fp-001", "fp-002", "fp-003"]:
            mgr.register_finding(fp)
        results = mgr.mark_all_false_positive(
            ["fp-001", "fp-002", "fp-003"], "analyst", "Bulk mark"
        )
        assert all(results.values())
        for fp in ["fp-001", "fp-002", "fp-003"]:
            assert mgr.get_state(fp) == FindingState.FALSE_POS

    def test_mark_all_false_positive_skips_invalid(self, mgr):
        mgr.register_finding("fp-001")
        mgr.mark_false_positive("fp-001", "analyst")
        mgr.suppress("fp-001", "analyst")  # now SUPPRESSED
        # Can't mark SUPPRESSED as FALSE_POS
        results = mgr.mark_all_false_positive(["fp-001"], "analyst")
        assert results["fp-001"] is False

    def test_mark_all_false_positive_mixed_results(self, mgr):
        mgr.register_finding("fp-001")   # OPEN → can transition
        mgr.register_finding("fp-002")
        mgr.mark_false_positive("fp-002", "analyst")
        mgr.suppress("fp-002", "analyst")  # SUPPRESSED → can't
        results = mgr.mark_all_false_positive(["fp-001", "fp-002"], "analyst")
        assert results["fp-001"] is True
        assert results["fp-002"] is False


# ─────────────────────────────────────────────────────────────────────────────
# TestProcessRescan
# ─────────────────────────────────────────────────────────────────────────────

class TestProcessRescan:
    def test_new_findings_registered(self, mgr):
        result = mgr.process_rescan(
            previous_fingerprints = set(),
            current_fingerprints  = {"fp-new"},
            analyst = "ci-bot",
        )
        assert "fp-new" in result["new"]
        assert mgr.get_state("fp-new") == FindingState.OPEN

    def test_disappeared_open_becomes_fixed(self, mgr):
        mgr.register_finding("fp-001")
        result = mgr.process_rescan(
            previous_fingerprints = {"fp-001"},
            current_fingerprints  = set(),
            analyst = "ci-bot",
        )
        assert "fp-001" in result["fixed"]
        assert mgr.get_state("fp-001") == FindingState.FIXED

    def test_disappeared_confirmed_becomes_fixed(self, mgr):
        mgr.register_finding("fp-001")
        mgr.confirm_finding("fp-001", "alice")
        mgr.process_rescan(
            previous_fingerprints = {"fp-001"},
            current_fingerprints  = set(),
            analyst = "ci-bot",
        )
        assert mgr.get_state("fp-001") == FindingState.FIXED

    def test_regression_fixed_to_open(self, mgr):
        mgr.register_finding("fp-001")
        mgr.mark_fixed("fp-001", "ci-bot")
        result = mgr.process_rescan(
            previous_fingerprints = {"fp-001"},
            current_fingerprints  = {"fp-001"},
            analyst = "ci-bot",
        )
        assert "fp-001" in result["regressed"]
        assert mgr.get_state("fp-001") == FindingState.OPEN

    def test_false_pos_disappeared_unchanged(self, mgr):
        mgr.register_finding("fp-001")
        mgr.mark_false_positive("fp-001", "analyst")
        result = mgr.process_rescan(
            previous_fingerprints = {"fp-001"},
            current_fingerprints  = set(),
            analyst = "ci-bot",
        )
        assert "fp-001" in result["unchanged"]
        assert mgr.get_state("fp-001") == FindingState.FALSE_POS

    def test_suppressed_disappeared_unchanged(self, mgr):
        mgr.register_finding("fp-001")
        mgr.mark_false_positive("fp-001", "analyst")
        mgr.suppress("fp-001", "analyst")
        result = mgr.process_rescan(
            previous_fingerprints = {"fp-001"},
            current_fingerprints  = set(),
            analyst = "ci-bot",
        )
        assert "fp-001" in result["unchanged"]
        assert mgr.get_state("fp-001") == FindingState.SUPPRESSED


# ─────────────────────────────────────────────────────────────────────────────
# TestPersistence
# ─────────────────────────────────────────────────────────────────────────────

class TestPersistence:
    def test_save_and_reload(self, tmp_path):
        store_path = str(tmp_path / "fp_store.json")
        mgr1 = FalsePositiveManager(store_path)
        mgr1.register_finding("fp-001", "f-001", "XSS Finding")
        mgr1.mark_false_positive("fp-001", "alice", "Test artifact")

        mgr2 = FalsePositiveManager(store_path)
        assert mgr2.get_state("fp-001") == FindingState.FALSE_POS
        rec = mgr2.get_record("fp-001")
        assert rec.title == "XSS Finding"
        assert len(rec.audit_trail) == 1

    def test_audit_trail_persisted(self, tmp_path):
        store_path = str(tmp_path / "fp_store.json")
        mgr1 = FalsePositiveManager(store_path)
        mgr1.register_finding("fp-001")
        mgr1.confirm_finding("fp-001", "alice", "Verified")

        mgr2 = FalsePositiveManager(store_path)
        rec = mgr2.get_record("fp-001")
        assert len(rec.audit_trail) == 1
        assert rec.audit_trail[0].analyst == "alice"

    def test_suppression_reason_persisted(self, tmp_path):
        store_path = str(tmp_path / "fp_store.json")
        mgr1 = FalsePositiveManager(store_path)
        mgr1.register_finding("fp-001")
        mgr1.mark_false_positive("fp-001", "alice")
        mgr1.suppress("fp-001", "alice", "Network scanner artifact")

        mgr2 = FalsePositiveManager(store_path)
        rec = mgr2.get_record("fp-001")
        assert rec.suppression_reason == "Network scanner artifact"

    def test_export_json_roundtrip(self, mgr):
        mgr.register_finding("fp-001", "f-001", "XSS in login")
        mgr.confirm_finding("fp-001", "alice")
        json_str = mgr.export_json()
        data = json.loads(json_str)
        assert "fp-001" in data
        assert data["fp-001"]["state"] == "CONFIRMED"
        assert data["fp-001"]["title"] == "XSS in login"

    def test_no_persistence_without_store_path(self):
        # Should not crash or write files
        mgr = FalsePositiveManager()
        mgr.register_finding("fp-001")
        mgr.mark_false_positive("fp-001", "analyst")
        # No file written — just verify no crash


# ─────────────────────────────────────────────────────────────────────────────
# TestThreadSafety
# ─────────────────────────────────────────────────────────────────────────────

class TestThreadSafety:
    def test_concurrent_register_no_duplicate(self):
        """10 threads all register the same fingerprint — should be idempotent."""
        mgr = FalsePositiveManager()
        errors = []

        def register():
            try:
                mgr.register_finding("shared-fp", "f-001", "Shared")
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=register) for _ in range(10)]
        for t in threads: t.start()
        for t in threads: t.join()

        assert not errors
        assert len(mgr.all_records()) == 1

    def test_concurrent_mark_different_fingerprints(self):
        """Each thread marks its own distinct fingerprint → no interference."""
        mgr = FalsePositiveManager()
        for i in range(20):
            mgr.register_finding(f"fp-{i:03d}")

        errors = []
        def mark(i):
            try:
                mgr.mark_false_positive(f"fp-{i:03d}", "analyst")
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=mark, args=(i,)) for i in range(20)]
        for t in threads: t.start()
        for t in threads: t.join()

        assert not errors
        s = mgr.stats()
        assert s["FALSE_POS"] == 20
