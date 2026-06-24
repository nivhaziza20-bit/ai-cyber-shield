#!/usr/bin/env python3
"""
Phase 4 Demo — Simulated full pipeline execution on samples/vulnerable_app.py

Two modes
---------
  (default) Mock mode:  Uses pre-authored responses to show the exact pipeline
                        output without needing API keys. Runs instantly.

  --live               Uses the real pipeline with live LLM + tools.
                        Requires ANTHROPIC_API_KEY in .env and installed
                        Bandit / Semgrep binaries.

Usage
-----
  cd c:\\Users\\PC\\Documents\\cyber
  python samples/phase4_demo.py            # mock mode (no keys needed)
  python samples/phase4_demo.py --live     # live mode (needs .env)
  python samples/phase4_demo.py --save     # mock mode + save reports to ./reports/
"""

import argparse
import sys
import time
from pathlib import Path

# ── Make project root importable when run as a script ────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.rule import Rule
from rich.text import Text

console = Console(highlight=False)

VULNERABLE_FILE = Path(__file__).parent / "vulnerable_app.py"


# ─────────────────────────────────────────────────────────────────────────────
# Mock mode
# ─────────────────────────────────────────────────────────────────────────────

def run_mock(save: bool) -> None:
    from samples.mock_responses import SCANNER_JSON, ANALYST_MARKDOWN, REMEDIATION_MARKDOWN
    from orchestrator import PipelineResult, StageResult
    from datetime import datetime, timezone

    console.print()
    console.print(
        Panel.fit(
            "[bold white]Multi-Agent Security Pipeline[/bold white]  [dim](DEMO — mock mode)[/dim]\n"
            f"[dim]Target: {VULNERABLE_FILE.name} — 5 planted vulnerabilities[/dim]",
            border_style="blue",
            padding=(0, 2),
        )
    )

    # ── Stage 1 ───────────────────────────────────────────────────────────────
    console.print()
    console.print(Rule("[bold cyan]Stage 1 — Scanner Agent[/bold cyan]", style="cyan"))
    console.print("  [dim]Dispatching security tools (Bandit · Semgrep · VirusTotal · Headers)…[/dim]")
    _fake_progress(1.8)
    console.print("  [green]✓  Done in 1.8s[/green]")

    # ── Stage 2 ───────────────────────────────────────────────────────────────
    console.print()
    console.print(Rule("[bold cyan]Stage 2 — Analyst Agent[/bold cyan]", style="cyan"))
    console.print("  [dim]Triaging findings · mapping OWASP · calculating CVSS scores…[/dim]")
    _fake_progress(3.1)
    console.print("  [green]✓  Done in 3.1s[/green]")

    # ── Stage 3 ───────────────────────────────────────────────────────────────
    console.print()
    console.print(Rule("[bold cyan]Stage 3 — Remediation Agent[/bold cyan]", style="cyan"))
    console.print("  [dim]Generating production-ready patches and hardening steps…[/dim]")
    _fake_progress(4.5)
    console.print("  [green]✓  Done in 4.5s[/green]")

    # ── Summary panel ─────────────────────────────────────────────────────────
    console.print()
    console.print(
        Panel(
            "  Scanner     [success]  1.8s\n"
            "  Analyst     [success]  3.1s\n"
            "  Remediation [success]  4.5s\n"
            "  Total                  9.4s",
            title="[green]✓ Pipeline SUCCESS[/green]",
            border_style="green",
            padding=(0, 2),
        )
    )

    # ── Print analyst report ──────────────────────────────────────────────────
    console.print()
    console.print(Rule("[bold]Vulnerability Report[/bold]", style="blue"))
    console.print(Markdown(ANALYST_MARKDOWN))

    # ── Print remediation playbook ────────────────────────────────────────────
    console.print()
    console.print(Rule("[bold]Remediation Playbook[/bold]", style="green"))
    console.print(Markdown(REMEDIATION_MARKDOWN))

    # ── Optionally save ───────────────────────────────────────────────────────
    if save:
        now = datetime.now(timezone.utc)
        result = PipelineResult(
            target_description=str(VULNERABLE_FILE),
            started_at=now.isoformat(),
            completed_at=now.isoformat(),
            total_duration_seconds=9.4,
            scanner=StageResult(status="success", output=SCANNER_JSON, duration_seconds=1.8),
            analyst=StageResult(status="success", output=ANALYST_MARKDOWN, duration_seconds=3.1),
            remediation=StageResult(status="success", output=REMEDIATION_MARKDOWN, duration_seconds=4.5),
            overall_status="success",
        )
        saved = result.save_reports(PROJECT_ROOT / "reports")
        console.print()
        console.print("[dim]Reports saved:[/dim]")
        for stage, path in saved.items():
            console.print(f"  [dim]{stage:12s} → {path.relative_to(PROJECT_ROOT)}[/dim]")


def _fake_progress(duration: float) -> None:
    """Tiny spinner so mock mode doesn't feel instantaneous."""
    steps = 12
    delay = duration / steps
    frames = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
    for i in range(steps):
        console.print(f"  [dim]{frames[i % len(frames)]}[/dim]", end="\r")
        time.sleep(delay)
    console.print(" " * 6, end="\r")  # clear spinner line


# ─────────────────────────────────────────────────────────────────────────────
# Live mode
# ─────────────────────────────────────────────────────────────────────────────

def run_live(save: bool) -> None:
    from dotenv import load_dotenv
    load_dotenv(PROJECT_ROOT / ".env", override=False)

    code = VULNERABLE_FILE.read_text(encoding="utf-8")
    target = (
        f"Scan the following Python source code for security vulnerabilities:\n\n"
        f"```python\n{code}\n```"
    )

    from orchestrator import SecurityPipeline
    from rich.markdown import Markdown

    pipeline = SecurityPipeline(verbose=True)
    result   = pipeline.run(target, scanner_only=False)

    if result.analyst.status == "success":
        console.print()
        console.print(Rule("[bold]Vulnerability Report[/bold]", style="blue"))
        console.print(Markdown(result.analyst.output))

    if result.remediation.status == "success":
        console.print()
        console.print(Rule("[bold]Remediation Playbook[/bold]", style="green"))
        console.print(Markdown(result.remediation.output))

    if save:
        saved = result.save_reports(PROJECT_ROOT / "reports")
        console.print()
        console.print("[dim]Reports saved:[/dim]")
        for stage, path in saved.items():
            console.print(f"  [dim]{stage:12s} → {path.relative_to(PROJECT_ROOT)}[/dim]")


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Phase 4 demo — runs pipeline on vulnerable_app.py",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Use the real LLM pipeline (requires ANTHROPIC_API_KEY in .env).",
    )
    parser.add_argument(
        "--save",
        action="store_true",
        help="Save all stage outputs to ./reports/",
    )
    args = parser.parse_args()

    if args.live:
        run_live(save=args.save)
    else:
        run_mock(save=args.save)

    return 0


if __name__ == "__main__":
    sys.exit(main())
