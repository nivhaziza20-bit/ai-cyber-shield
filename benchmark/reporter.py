"""
Benchmark reporter — generates human and machine-readable accuracy reports.

Outputs:
  1. Console  — coloured ASCII table (no external deps)
  2. JSON     — machine-readable, suitable for CI gate checks
  3. HTML     — self-contained dashboard with per-tool breakdowns
"""
from __future__ import annotations

import json
from pathlib import Path

from benchmark.runner import BenchmarkRun
from benchmark.scorer import PRECISION_GATE, RECALL_GATE, ScorerReport, score


# ─────────────────────────────────────────────────────────────────────────────
# Console report
# ─────────────────────────────────────────────────────────────────────────────

_ANSI = {
    "red":    "\033[31m",
    "green":  "\033[32m",
    "yellow": "\033[33m",
    "cyan":   "\033[36m",
    "bold":   "\033[1m",
    "reset":  "\033[0m",
}


def _c(text: str, colour: str) -> str:
    return f"{_ANSI.get(colour, '')}{text}{_ANSI['reset']}"


def _pct(v: float | None) -> str:
    if v is None:
        return "  N/A  "
    colour = "green" if v >= 0.85 else ("yellow" if v >= 0.70 else "red")
    return _c(f"{v:6.1%}", colour)


def print_report(run: BenchmarkRun, report: ScorerReport | None = None) -> None:
    """Print a coloured ASCII accuracy report to stdout."""
    if report is None:
        report = score(run)

    o = report.overall
    sep = "─" * 72
    print()
    print(_c("═" * 72, "bold"))
    print(_c("  AI CYBER SHIELD — ACCURACY BENCHMARK", "bold"))
    print(_c(f"  {run.timestamp}", "cyan"))
    print(_c(f"  Total cases: {run.total_cases}  ·  Results: {len(run.results)}  ·  Errors: {run.errors}", "cyan"))
    print(_c("═" * 72, "bold"))

    print()
    print(_c("  OVERALL METRICS", "bold"))
    print(sep)
    print(f"  {'Precision':<14} {_pct(o.precision)}"
          + (f"  CI {report.precision_ci}" if report.precision_ci else ""))
    print(f"  {'Recall':<14} {_pct(o.recall)}"
          + (f"  CI {report.recall_ci}"    if report.recall_ci    else ""))
    print(f"  {'F1 Score':<14} {_pct(o.f1)}"
          + (f"  CI {report.f1_ci}"        if report.f1_ci        else ""))
    print(f"  {'Specificity':<14} {_pct(o.specificity)}")
    print(f"  {'TP/FP/TN/FN':<14} {o.tp}/{o.fp}/{o.tn}/{o.fn}  "
          f"(Errors: {o.errors}  Skips: {o.skips})")
    gate_str = _c("PASSED ✓", "green") if report.gate_passed else _c("FAILED ✗", "red")
    print(f"  {'CI Gate':<14} {gate_str}  "
          f"(thresholds: P≥{PRECISION_GATE:.0%} R≥{RECALL_GATE:.0%})")

    print()
    print(_c("  PER-TOOL BREAKDOWN", "bold"))
    print(sep)
    print(f"  {'Tool':<20} {'Precision':>10} {'Recall':>10} {'F1':>10} "
          f"{'Grade':>6}  TP  FP  TN  FN")
    print(sep)
    for tool_name, m in sorted(report.by_tool.items()):
        grade_colour = {"A": "green", "B": "green", "C": "yellow",
                        "D": "yellow", "F": "red"}.get(m.grade(), "reset")
        print(
            f"  {tool_name:<20} {_pct(m.precision):>17} {_pct(m.recall):>17} "
            f"{_pct(m.f1):>17} {_c(m.grade():>6, grade_colour)}  "
            f"{m.tp:>2}  {m.fp:>2}  {m.tn:>2}  {m.fn:>2}"
        )

    if report.worst_tools:
        print()
        print(_c("  NEEDS IMPROVEMENT (F1 < 70%)", "yellow"))
        for t in report.worst_tools:
            print(f"    • {t}")

    print()
    print(_c("  CASE DETAILS", "bold"))
    print(sep)
    for r in run.results:
        icon = {"TP": "✓", "TN": "✓", "FP": "✗", "FN": "✗",
                "ERROR": "!", "SKIP": "-"}.get(r.outcome, "?")
        colour = {"TP": "green", "TN": "green", "FP": "red",
                  "FN": "red", "ERROR": "yellow"}.get(r.outcome, "reset")
        label = _c(f"[{r.outcome:5s}]", colour)
        err   = f"  ERROR: {r.error_msg}" if r.error_msg else ""
        print(f"  {icon} {label} {r.case_name:<30} {r.tool:<20} {r.duration_ms:5.0f}ms{err}")

    print()


# ─────────────────────────────────────────────────────────────────────────────
# JSON report (for CI gate integration)
# ─────────────────────────────────────────────────────────────────────────────

def to_json(run: BenchmarkRun, report: ScorerReport | None = None) -> dict:
    """Returns a JSON-serialisable dict — suitable for CI gate checks."""
    if report is None:
        report = score(run)
    o = report.overall

    def _m(m) -> dict:
        return {
            "precision":   round(m.precision,   4) if m.precision   is not None else None,
            "recall":      round(m.recall,       4) if m.recall      is not None else None,
            "f1":          round(m.f1,           4) if m.f1          is not None else None,
            "specificity": round(m.specificity,  4) if m.specificity is not None else None,
            "grade":       m.grade(),
            "tp": m.tp, "fp": m.fp, "tn": m.tn, "fn": m.fn,
            "errors": m.errors, "skips": m.skips,
        }

    cases = []
    for r in run.results:
        cases.append({
            "case":     r.case_name,
            "tool":     r.tool,
            "category": r.category,
            "outcome":  r.outcome,
            "ms":       round(r.duration_ms, 1),
            "error":    r.error_msg,
        })

    return {
        "timestamp":   run.timestamp,
        "total_cases": run.total_cases,
        "errors":      run.errors,
        "overall":     _m(o),
        "precision_ci": {
            "lower": round(report.precision_ci.lower, 4),
            "upper": round(report.precision_ci.upper, 4),
        } if report.precision_ci else None,
        "recall_ci": {
            "lower": round(report.recall_ci.lower, 4),
            "upper": round(report.recall_ci.upper, 4),
        } if report.recall_ci else None,
        "f1_ci": {
            "lower": round(report.f1_ci.lower, 4),
            "upper": round(report.f1_ci.upper, 4),
        } if report.f1_ci else None,
        "gate": {
            "precision_threshold": PRECISION_GATE,
            "recall_threshold":    RECALL_GATE,
            "passed":              report.gate_passed,
        },
        "by_tool":      {k: _m(v) for k, v in report.by_tool.items()},
        "worst_tools":  report.worst_tools,
        "cases":        cases,
    }


def save_json(run: BenchmarkRun, path: str | Path) -> None:
    data = to_json(run)
    Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")


# ─────────────────────────────────────────────────────────────────────────────
# HTML report (self-contained, dark-mode)
# ─────────────────────────────────────────────────────────────────────────────

def _grade_colour(grade: str) -> str:
    return {"A": "#22c55e", "B": "#86efac", "C": "#facc15",
            "D": "#fb923c", "F": "#ef4444"}.get(grade, "#94a3b8")


def _outcome_colour(outcome: str) -> str:
    return {"TP": "#22c55e", "TN": "#22c55e",
            "FP": "#ef4444", "FN": "#f97316",
            "ERROR": "#facc15", "SKIP": "#94a3b8"}.get(outcome, "#94a3b8")


def to_html(run: BenchmarkRun, report: ScorerReport | None = None) -> str:
    """Returns a self-contained HTML accuracy dashboard."""
    if report is None:
        report = score(run)
    o = report.overall

    def pct(v: float | None) -> str:
        return f"{v:.1%}" if v is not None else "N/A"

    # ── Tool rows ──────────────────────────────────────────────────────────────
    tool_rows = ""
    for tool_name, m in sorted(report.by_tool.items()):
        g = m.grade()
        tool_rows += f"""
        <tr>
          <td>{tool_name}</td>
          <td>{pct(m.precision)}</td>
          <td>{pct(m.recall)}</td>
          <td>{pct(m.f1)}</td>
          <td style="color:{_grade_colour(g)};font-weight:700">{g}</td>
          <td><span style="color:#22c55e">{m.tp}</span>/
              <span style="color:#ef4444">{m.fp}</span>/
              <span style="color:#22c55e">{m.tn}</span>/
              <span style="color:#f97316">{m.fn}</span></td>
          <td>{m.errors}</td>
        </tr>"""

    # ── Case rows ──────────────────────────────────────────────────────────────
    case_rows = ""
    for r in run.results:
        oc = r.outcome
        colour = _outcome_colour(oc)
        err_cell = f'<span style="color:#facc15;font-size:0.8em">{r.error_msg or ""}</span>'
        case_rows += f"""
        <tr>
          <td style="color:{colour};font-weight:700">{oc}</td>
          <td>{r.case_name}</td>
          <td>{r.tool}</td>
          <td style="color:#94a3b8">{r.category}</td>
          <td>{r.duration_ms:.0f}ms</td>
          <td>{err_cell}</td>
        </tr>"""

    gate_colour = "#22c55e" if report.gate_passed else "#ef4444"
    gate_text   = "PASSED ✓" if report.gate_passed else "FAILED ✗"

    ci_text = ""
    if report.precision_ci:
        ci_text += f"<li>Precision 95% CI: {report.precision_ci}</li>"
    if report.recall_ci:
        ci_text += f"<li>Recall 95% CI: {report.recall_ci}</li>"
    if report.f1_ci:
        ci_text += f"<li>F1 95% CI: {report.f1_ci}</li>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AI Cyber Shield — Accuracy Benchmark</title>
<style>
  body{{background:#0f172a;color:#e2e8f0;font-family:system-ui,sans-serif;margin:0;padding:2rem}}
  h1{{color:#38bdf8;font-size:1.6rem;margin:0 0 0.25rem}}
  h2{{color:#7dd3fc;font-size:1.1rem;margin:2rem 0 0.5rem;border-bottom:1px solid #1e3a5f;padding-bottom:0.3rem}}
  .meta{{color:#64748b;font-size:0.85rem;margin-bottom:2rem}}
  .metrics{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:1rem;margin-bottom:2rem}}
  .card{{background:#1e293b;border:1px solid #334155;border-radius:8px;padding:1rem;text-align:center}}
  .card .val{{font-size:2rem;font-weight:700;margin:0.25rem 0}}
  .card .lbl{{font-size:0.75rem;color:#64748b;text-transform:uppercase;letter-spacing:.05em}}
  table{{width:100%;border-collapse:collapse;font-size:0.85rem}}
  th{{background:#1e293b;color:#94a3b8;font-weight:500;padding:0.6rem 0.8rem;text-align:left;border-bottom:1px solid #334155}}
  td{{padding:0.5rem 0.8rem;border-bottom:1px solid #1e293b}}
  tr:hover td{{background:#1e293b}}
  .gate{{display:inline-block;padding:0.4rem 1rem;border-radius:999px;font-weight:700;
          background:{gate_colour}22;color:{gate_colour};border:1px solid {gate_colour}44}}
  .ci-list{{background:#1e293b;border-radius:6px;padding:0.75rem 1.25rem;list-style:none;
            font-size:0.82rem;color:#94a3b8;display:inline-block;margin:0.5rem 0}}
  .ci-list li{{margin:0.15rem 0}}
  .worst{{color:#f97316;background:#f9731611;border:1px solid #f9731644;
          border-radius:6px;padding:0.5rem 1rem;display:inline-block;margin:0.25rem 0.25rem 0 0}}
</style>
</head>
<body>
<h1>AI Cyber Shield — Accuracy Benchmark</h1>
<div class="meta">Generated: {run.timestamp} &nbsp;·&nbsp;
     Cases: {run.total_cases} &nbsp;·&nbsp; Results: {len(run.results)} &nbsp;·&nbsp;
     Errors: {run.errors}</div>

<div class="metrics">
  <div class="card">
    <div class="lbl">Precision</div>
    <div class="val" style="color:{'#22c55e' if (o.precision or 0)>=0.85 else ('#facc15' if (o.precision or 0)>=0.70 else '#ef4444')}">{pct(o.precision)}</div>
  </div>
  <div class="card">
    <div class="lbl">Recall</div>
    <div class="val" style="color:{'#22c55e' if (o.recall or 0)>=0.85 else ('#facc15' if (o.recall or 0)>=0.70 else '#ef4444')}">{pct(o.recall)}</div>
  </div>
  <div class="card">
    <div class="lbl">F1 Score</div>
    <div class="val" style="color:{'#22c55e' if (o.f1 or 0)>=0.85 else ('#facc15' if (o.f1 or 0)>=0.70 else '#ef4444')}">{pct(o.f1)}</div>
  </div>
  <div class="card">
    <div class="lbl">Specificity</div>
    <div class="val">{pct(o.specificity)}</div>
  </div>
  <div class="card">
    <div class="lbl">CI Gate</div>
    <div class="val" style="color:{gate_colour};font-size:1.2rem">{gate_text}</div>
  </div>
</div>

<ul class="ci-list">{ci_text}</ul>

<h2>Per-Tool Breakdown</h2>
<table>
<thead><tr>
  <th>Tool</th><th>Precision</th><th>Recall</th><th>F1</th>
  <th>Grade</th><th>TP/FP/TN/FN</th><th>Errors</th>
</tr></thead>
<tbody>{tool_rows}</tbody>
</table>

{'<h2>Needs Improvement (F1 &lt; 70%)</h2>' + "".join(f'<span class="worst">{t}</span>' for t in report.worst_tools) if report.worst_tools else ""}

<h2>Case Details</h2>
<table>
<thead><tr>
  <th>Outcome</th><th>Case</th><th>Tool</th><th>Category</th><th>Duration</th><th>Error</th>
</tr></thead>
<tbody>{case_rows}</tbody>
</table>
</body></html>"""


def save_html(run: BenchmarkRun, path: str | Path) -> None:
    Path(path).write_text(to_html(run), encoding="utf-8")


# ─────────────────────────────────────────────────────────────────────────────
# Convenience: run + report in one call
# ─────────────────────────────────────────────────────────────────────────────

def run_and_report(
    output_dir: str | Path | None = None,
    verbose: bool = True,
) -> ScorerReport:
    """
    Run the full benchmark, print console output, and optionally save files.

    Args:
        output_dir: If given, saves ``benchmark_results.json`` and
                    ``benchmark_report.html`` into this directory.
        verbose:    Print case names as they run.

    Returns:
        ScorerReport (also prints to stdout).
    """
    from benchmark.runner import run_benchmark

    print("Running AI Cyber Shield accuracy benchmark...")
    brun   = run_benchmark(verbose=verbose)
    report = score(brun)
    print_report(brun, report)

    if output_dir:
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        save_json(brun,  out / "benchmark_results.json")
        save_html(brun,  out / "benchmark_report.html")
        print(f"  Reports saved to {out.resolve()}")

    return report
