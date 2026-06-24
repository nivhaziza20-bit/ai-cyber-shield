"""
Accuracy scorer for AI Cyber Shield benchmark results.

Computes per-tool and overall metrics from a BenchmarkRun:
  - Precision  = TP / (TP + FP)   — how accurate are detections?
  - Recall     = TP / (TP + FN)   — what fraction of real issues are found?
  - F1 Score   = harmonic mean of Precision and Recall
  - Specificity= TN / (TN + FP)   — true negative rate
  - Bootstrap 95% confidence intervals (2000 resamples, percentile method)

Industry context:
  Detectify / Invicti target ~95% precision and ~85% recall on OWASP Top 10.
  Any tool scoring < 80% precision is generating too many false positives to
  be production-usable. Any tool scoring < 70% recall is missing real issues.
"""
from __future__ import annotations

import random
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Literal

from benchmark.runner import BenchmarkRun, CheckResult

Outcome = Literal["TP", "FP", "TN", "FN", "ERROR", "SKIP"]

# Thresholds used for the CI pass/fail gate
PRECISION_GATE = 0.80   # at least 80% precision overall
RECALL_GATE    = 0.70   # at least 70% recall overall

_BOOTSTRAP_N   = 2000   # number of resamples for CI
_CI_ALPHA      = 0.05   # 95% confidence interval


# ─────────────────────────────────────────────────────────────────────────────
# Per-metric result types
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class MetricSet:
    """Accuracy metrics for a single tool (or "overall")."""
    name:         str
    tp:           int = 0
    fp:           int = 0
    tn:           int = 0
    fn:           int = 0
    errors:       int = 0
    skips:        int = 0

    @property
    def precision(self) -> float | None:
        denom = self.tp + self.fp
        return self.tp / denom if denom else None

    @property
    def recall(self) -> float | None:
        denom = self.tp + self.fn
        return self.tp / denom if denom else None

    @property
    def specificity(self) -> float | None:
        denom = self.tn + self.fp
        return self.tn / denom if denom else None

    @property
    def f1(self) -> float | None:
        p, r = self.precision, self.recall
        if p is None or r is None or (p + r) == 0:
            return None
        return 2 * p * r / (p + r)

    @property
    def total_evaluated(self) -> int:
        return self.tp + self.fp + self.tn + self.fn

    def grade(self) -> str:
        """Human-readable grade: A / B / C / D / F based on F1."""
        f1 = self.f1
        if f1 is None:
            return "N/A"
        if f1 >= 0.95:
            return "A"
        if f1 >= 0.85:
            return "B"
        if f1 >= 0.70:
            return "C"
        if f1 >= 0.55:
            return "D"
        return "F"


@dataclass
class ConfidenceInterval:
    lower: float
    upper: float

    def __str__(self) -> str:
        return f"[{self.lower:.1%} – {self.upper:.1%}]"


@dataclass
class ScorerReport:
    """Full scored output from a BenchmarkRun."""
    overall:       MetricSet
    by_tool:       dict[str, MetricSet] = field(default_factory=dict)
    precision_ci:  ConfidenceInterval | None = None
    recall_ci:     ConfidenceInterval | None = None
    f1_ci:         ConfidenceInterval | None = None
    gate_passed:   bool = False
    worst_tools:   list[str] = field(default_factory=list)   # tools with F1 < 0.70


# ─────────────────────────────────────────────────────────────────────────────
# Core computation
# ─────────────────────────────────────────────────────────────────────────────

def _count_into(metric: MetricSet, result: CheckResult) -> None:
    """Accumulates one CheckResult into a MetricSet."""
    o = result.outcome
    if   o == "TP":    metric.tp     += 1
    elif o == "FP":    metric.fp     += 1
    elif o == "TN":    metric.tn     += 1
    elif o == "FN":    metric.fn     += 1
    elif o == "ERROR": metric.errors += 1
    elif o == "SKIP":  metric.skips  += 1


def _bootstrap_metric(
    values: list[int],
    n_resamples: int = _BOOTSTRAP_N,
) -> ConfidenceInterval:
    """
    Percentile bootstrap CI for a fraction.

    ``values`` is a list of 0/1 integers (1 = event occurred).
    Returns the 95% percentile-bootstrap CI.
    """
    if not values:
        return ConfidenceInterval(0.0, 1.0)

    rng = random.Random(42)  # deterministic seed
    totals: list[float] = []
    n = len(values)
    for _ in range(n_resamples):
        sample = [rng.choice(values) for _ in range(n)]
        totals.append(sum(sample) / n)
    totals.sort()
    lo = totals[int(n_resamples * _CI_ALPHA / 2)]
    hi = totals[int(n_resamples * (1 - _CI_ALPHA / 2))]
    return ConfidenceInterval(lo, hi)


def score(run: BenchmarkRun) -> ScorerReport:
    """
    Compute full accuracy metrics from a BenchmarkRun.

    Returns a ScorerReport with per-tool breakdowns and bootstrap CIs.
    """
    overall = MetricSet(name="overall")
    by_tool: dict[str, MetricSet] = {}

    for result in run.results:
        tool_key = result.tool
        if tool_key not in by_tool:
            by_tool[tool_key] = MetricSet(name=tool_key)
        _count_into(overall, result)
        _count_into(by_tool[tool_key], result)

    # ── Bootstrap confidence intervals on precision and recall ─────────────────
    precision_values: list[int] = []
    recall_values:    list[int] = []
    f1_values_raw:    list[float] = []

    for result in run.results:
        o = result.outcome
        if o in ("TP", "FP"):
            precision_values.append(1 if o == "TP" else 0)
        if o in ("TP", "FN"):
            recall_values.append(1 if o == "TP" else 0)

    precision_ci = _bootstrap_metric(precision_values) if precision_values else None
    recall_ci    = _bootstrap_metric(recall_values)    if recall_values    else None

    # F1 bootstrap: resample (precision_values, recall_values) jointly
    f1_ci: ConfidenceInterval | None = None
    if precision_values and recall_values:
        rng = random.Random(42)
        n_p, n_r = len(precision_values), len(recall_values)
        f1s: list[float] = []
        for _ in range(_BOOTSTRAP_N):
            sp = [rng.choice(precision_values) for _ in range(n_p)]
            sr = [rng.choice(recall_values)    for _ in range(n_r)]
            p_hat = sum(sp) / n_p
            r_hat = sum(sr) / n_r
            if p_hat + r_hat > 0:
                f1s.append(2 * p_hat * r_hat / (p_hat + r_hat))
        if f1s:
            f1s.sort()
            f1_ci = ConfidenceInterval(
                f1s[int(_BOOTSTRAP_N * _CI_ALPHA / 2)],
                f1s[int(_BOOTSTRAP_N * (1 - _CI_ALPHA / 2))],
            )

    # ── Gate check ─────────────────────────────────────────────────────────────
    prec   = overall.precision
    rec    = overall.recall
    passed = (prec is not None and prec >= PRECISION_GATE) and \
             (rec  is not None and rec  >= RECALL_GATE)

    # ── Worst performers ───────────────────────────────────────────────────────
    worst = [
        m.name for m in by_tool.values()
        if (m.f1 is not None and m.f1 < 0.70) or (m.total_evaluated > 0 and m.precision is None)
    ]

    return ScorerReport(
        overall=overall,
        by_tool=by_tool,
        precision_ci=precision_ci,
        recall_ci=recall_ci,
        f1_ci=f1_ci,
        gate_passed=passed,
        worst_tools=sorted(worst),
    )
