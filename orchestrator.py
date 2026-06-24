"""
Security Pipeline Orchestrator — Phase 3

Wires Scanner → Analyst → Remediation into a single, observable pipeline.

Design principles:
  - Each stage is isolated: a failure in Stage N skips N+1 and N+2 but still
    returns a PipelineResult with partial data, never raises to the caller.
  - Timing is captured per-stage and for the full run.
  - Rich is used for progress display; all console output is silenceable.
  - Results are structured Pydantic models — easy to serialise for reports.
"""

import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Literal

from pydantic import BaseModel
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.rule import Rule
from rich.text import Text

from agents import run_analyst, run_remediation, run_scanner


# ─────────────────────────────────────────────────────────────────────────────
# Result models
# ─────────────────────────────────────────────────────────────────────────────

class StageResult(BaseModel):
    status: Literal["success", "failed", "skipped"]
    output: str = ""
    duration_seconds: float = 0.0
    error: str | None = None


class PipelineResult(BaseModel):
    target_description: str
    started_at: str           # ISO 8601
    completed_at: str
    total_duration_seconds: float
    scanner:     StageResult
    analyst:     StageResult
    remediation: StageResult
    overall_status: Literal["success", "partial", "failed"]

    def is_success(self) -> bool:
        return self.overall_status == "success"

    def save_reports(self, output_dir: str | Path = "./reports") -> dict[str, Path]:
        """
        Persists each stage's output to timestamped files.
        Returns a dict mapping stage name → saved file path.
        """
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        stamp = datetime.fromisoformat(self.started_at).strftime("%Y%m%d_%H%M%S")
        saved: dict[str, Path] = {}

        if self.scanner.status == "success":
            p = out / f"{stamp}_1_scanner.json"
            p.write_text(self.scanner.output, encoding="utf-8")
            saved["scanner"] = p

        if self.analyst.status == "success":
            p = out / f"{stamp}_2_analyst.md"
            p.write_text(self.analyst.output, encoding="utf-8")
            saved["analyst"] = p

        if self.remediation.status == "success":
            p = out / f"{stamp}_3_remediation.md"
            p.write_text(self.remediation.output, encoding="utf-8")
            saved["remediation"] = p

        # Always write a JSON summary
        import json
        p = out / f"{stamp}_summary.json"
        p.write_text(
            json.dumps(self.model_dump(exclude={"scanner", "analyst", "remediation"}), indent=2),
            encoding="utf-8",
        )
        saved["summary"] = p

        return saved


# ─────────────────────────────────────────────────────────────────────────────
# Pipeline
# ─────────────────────────────────────────────────────────────────────────────

class SecurityPipeline:
    """
    Orchestrates the three-agent security analysis pipeline.

    Usage:
        pipeline = SecurityPipeline()
        result   = pipeline.run("Scan this Python code: <code>")
        saved    = result.save_reports("./reports")
    """

    def __init__(self, verbose: bool = True):
        self._console = Console(highlight=False) if verbose else Console(quiet=True)
        self._verbose = verbose

    # ── Public API ────────────────────────────────────────────────────────────

    def run(self, target: str, scanner_only: bool = False) -> PipelineResult:
        """
        Executes the full Scanner → Analyst → Remediation pipeline.

        Args:
            target:       Raw input string describing what to scan.
                          Include the code inline or a URL; the Scanner Agent
                          decides which tools to invoke.
            scanner_only: If True, stop after the Scanner stage and return a
                          partial result (useful for quick pre-checks).

        Returns:
            PipelineResult with all stage outputs and timing data.
        """
        started_at    = datetime.now(timezone.utc)
        pipeline_start = time.perf_counter()

        self._print_header(target)

        # ── Stage 1: Scanner ─────────────────────────────────────────────────
        scanner_result = self._run_stage(
            stage_number=1,
            name="Scanner Agent",
            description="Dispatching security tools (Bandit · Semgrep · VirusTotal · Headers)…",
            fn=lambda: run_scanner(target),
            # run_scanner returns {"output": str, "intermediate_steps": list}
            post_process=lambda r: r["output"],
        )

        if scanner_result.status == "failed":
            return self._build_result(
                target, started_at, pipeline_start,
                scanner_result,
                StageResult(status="skipped", error="Skipped: Scanner stage failed."),
                StageResult(status="skipped", error="Skipped: Scanner stage failed."),
            )

        if scanner_only:
            self._console.print("\n[yellow]-- Scanner-only mode: stopping here --[/yellow]")
            return self._build_result(
                target, started_at, pipeline_start,
                scanner_result,
                StageResult(status="skipped", error="Skipped: scanner_only=True"),
                StageResult(status="skipped", error="Skipped: scanner_only=True"),
            )

        # ── Stage 2: Analyst ─────────────────────────────────────────────────
        analyst_result = self._run_stage(
            stage_number=2,
            name="Analyst Agent",
            description="Triaging findings · mapping OWASP · calculating CVSS scores…",
            fn=lambda: run_analyst(scanner_result.output),
        )

        # ── Stage 3: Remediation ─────────────────────────────────────────────
        remediation_result = self._run_stage(
            stage_number=3,
            name="Remediation Agent",
            description="Generating production-ready patches and hardening steps…",
            fn=lambda: run_remediation(analyst_result.output),
            skip_if=(analyst_result.status != "success"),
            skip_reason="Skipped: Analyst stage did not succeed.",
        )

        result = self._build_result(
            target, started_at, pipeline_start,
            scanner_result, analyst_result, remediation_result,
        )

        self._print_footer(result)
        return result

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _run_stage(
        self,
        stage_number: int,
        name: str,
        description: str,
        fn: Callable,
        post_process: Callable | None = None,
        skip_if: bool = False,
        skip_reason: str = "Skipped.",
    ) -> StageResult:
        if skip_if:
            self._console.print(f"\n  [dim]Stage {stage_number} · {name}: SKIPPED[/dim]")
            return StageResult(status="skipped", error=skip_reason)

        self._console.print()
        self._console.print(
            Rule(f"[bold cyan]Stage {stage_number} — {name}[/bold cyan]", style="cyan")
        )
        self._console.print(f"  [dim]{description}[/dim]")

        t0 = time.perf_counter()
        try:
            raw    = fn()
            output = post_process(raw) if post_process else raw
            dur    = round(time.perf_counter() - t0, 2)
            self._console.print(f"  [green]✓  Done in {dur}s[/green]")
            return StageResult(status="success", output=str(output), duration_seconds=dur)

        except Exception as exc:
            dur = round(time.perf_counter() - t0, 2)
            self._console.print(f"  [red]✗  Failed after {dur}s[/red]")
            self._console.print(f"  [red]   {exc}[/red]")
            return StageResult(status="failed", error=str(exc), duration_seconds=dur)

    @staticmethod
    def _build_result(
        target: str,
        started_at: datetime,
        pipeline_start: float,
        scanner: StageResult,
        analyst: StageResult,
        remediation: StageResult,
    ) -> PipelineResult:
        completed_at = datetime.now(timezone.utc)
        total        = round(time.perf_counter() - pipeline_start, 2)

        statuses = [scanner.status, analyst.status, remediation.status]

        if all(s == "success" for s in statuses):
            overall: Literal["success", "partial", "failed"] = "success"
        elif "failed" in statuses and not any(s == "success" for s in statuses):
            # Only scanner ran and it failed — whole pipeline down
            overall = "failed"
        else:
            # Mix of success/failed/skipped (scanner_only, mid-pipeline failure, etc.)
            overall = "partial"

        return PipelineResult(
            target_description=target[:200],
            started_at=started_at.isoformat(),
            completed_at=completed_at.isoformat(),
            total_duration_seconds=total,
            scanner=scanner,
            analyst=analyst,
            remediation=remediation,
            overall_status=overall,
        )

    def _print_header(self, target: str) -> None:
        preview = target[:100].replace("\n", " ")
        self._console.print(
            Panel.fit(
                f"[bold white]Multi-Agent Security Pipeline[/bold white]\n"
                f"[dim]Target: {preview}{'…' if len(target) > 100 else ''}[/dim]",
                border_style="blue",
                padding=(0, 2),
            )
        )

    def _print_footer(self, result: PipelineResult) -> None:
        colour = {"success": "green", "partial": "yellow", "failed": "red"}[result.overall_status]
        icon   = {"success": "✓", "partial": "⚠", "failed": "✗"}[result.overall_status]

        rows = [
            f"  Scanner     [{result.scanner.status}]  {result.scanner.duration_seconds}s",
            f"  Analyst     [{result.analyst.status}]  {result.analyst.duration_seconds}s",
            f"  Remediation [{result.remediation.status}]  {result.remediation.duration_seconds}s",
            f"  Total                   {result.total_duration_seconds}s",
        ]
        self._console.print()
        self._console.print(
            Panel(
                "\n".join(rows),
                title=f"[{colour}]{icon} Pipeline {result.overall_status.upper()}[/{colour}]",
                border_style=colour,
                padding=(0, 2),
            )
        )
