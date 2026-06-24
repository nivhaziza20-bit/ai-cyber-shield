#!/usr/bin/env python3
"""
main.py — CLI entry point for the Multi-Agent Security Pipeline.

Examples
--------
# Scan a Python file
python main.py --code path/to/app.py

# Scan raw code snippet passed inline
python main.py --code "import os; os.system(input('cmd> '))"

# Scan a URL
python main.py --url https://example.com

# Scan both code and a URL in one pipeline run
python main.py --code path/to/app.py --url https://example.com

# Only run the Scanner stage (skip Analyst + Remediation)
python main.py --code app.py --scanner-only

# Save all reports to a specific directory
python main.py --code app.py --output-dir ./reports/run1

# Suppress verbose stage output (only print final report)
python main.py --code app.py --quiet
"""

import argparse
import json
import sys
from pathlib import Path

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.rule import Rule

console = Console()


# ─────────────────────────────────────────────────────────────────────────────
# Argument parsing
# ─────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="main.py",
        description="Multi-Agent AI Security Scanner — defensive analysis only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument(
        "--code",
        metavar="FILE_OR_STRING",
        help="Path to a source file OR a raw code string. If this looks like an "
             "existing file path it is read from disk; otherwise treated as inline code.",
    )
    p.add_argument(
        "--url",
        metavar="URL",
        help="HTTP/HTTPS URL to audit (VirusTotal + security headers).",
    )
    p.add_argument(
        "--scanner-only",
        action="store_true",
        default=False,
        help="Stop after the Scanner stage. Useful for a quick raw-data dump.",
    )
    p.add_argument(
        "--output-dir",
        metavar="DIR",
        default="./reports",
        help="Directory to save per-stage reports (default: ./reports).",
    )
    p.add_argument(
        "--no-save",
        action="store_true",
        default=False,
        help="Do not write report files to disk.",
    )
    p.add_argument(
        "--quiet",
        action="store_true",
        default=False,
        help="Suppress stage-by-stage verbose output.",
    )
    p.add_argument(
        "--show-scanner-json",
        action="store_true",
        default=False,
        help="Print the raw Scanner JSON output after the pipeline completes.",
    )
    return p


# ─────────────────────────────────────────────────────────────────────────────
# Input assembly
# ─────────────────────────────────────────────────────────────────────────────

def build_target_string(code: str | None, url: str | None) -> str:
    """
    Constructs the natural-language prompt handed to the Scanner Agent.
    The Scanner's system prompt tells it how to parse this.
    """
    parts: list[str] = []

    if code:
        code_path = Path(code)
        if code_path.is_file():
            source = code_path.read_text(encoding="utf-8", errors="replace")
            lang   = _ext_to_lang(code_path.suffix)
            console.print(f"[dim]Reading file: {code_path} ({len(source)} chars, language={lang})[/dim]")
        else:
            source = code
            lang   = "python"  # default assumption for inline snippets
        parts.append(
            f"Scan the following {lang} source code for security vulnerabilities:\n\n"
            f"```{lang}\n{source}\n```"
        )

    if url:
        parts.append(f"Also audit this URL for reputation and security headers: {url}")

    if not parts:
        console.print("[red]Error: provide --code and/or --url[/red]")
        sys.exit(1)

    return "\n\n".join(parts)


def _ext_to_lang(suffix: str) -> str:
    return {
        ".py": "python", ".js": "javascript", ".ts": "typescript",
        ".java": "java",  ".go": "go",         ".rb": "ruby",
        ".php": "php",    ".c": "c",            ".cpp": "cpp",
        ".rs": "rust",
    }.get(suffix.lower(), "python")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = build_parser()
    args   = parser.parse_args()

    if not args.code and not args.url:
        parser.print_help()
        return 1

    # Lazy import so .env is loaded before any agent/config module resolves
    from dotenv import load_dotenv
    load_dotenv(override=False)

    from orchestrator import SecurityPipeline

    target   = build_target_string(args.code, args.url)
    pipeline = SecurityPipeline(verbose=not args.quiet)
    result   = pipeline.run(target, scanner_only=args.scanner_only)

    # ── Optional: print scanner JSON ──────────────────────────────────────────
    if args.show_scanner_json and result.scanner.status == "success":
        console.print()
        console.print(Rule("[dim]Raw Scanner Output[/dim]", style="dim"))
        try:
            parsed = json.loads(result.scanner.output)
            console.print_json(json.dumps(parsed))
        except json.JSONDecodeError:
            console.print(result.scanner.output)

    # ── Print analyst report ──────────────────────────────────────────────────
    if result.analyst.status == "success":
        console.print()
        console.print(Rule("[bold]Vulnerability Report[/bold]", style="blue"))
        console.print(Markdown(result.analyst.output))

    # ── Print remediation playbook ────────────────────────────────────────────
    if result.remediation.status == "success":
        console.print()
        console.print(Rule("[bold]Remediation Playbook[/bold]", style="green"))
        console.print(Markdown(result.remediation.output))

    # ── Save reports ──────────────────────────────────────────────────────────
    if not args.no_save:
        saved = result.save_reports(args.output_dir)
        if saved:
            console.print()
            console.print("[dim]Reports saved:[/dim]")
            for stage, path in saved.items():
                console.print(f"  [dim]{stage:12s} → {path}[/dim]")

    return 0 if result.overall_status in ("success", "partial") else 1


if __name__ == "__main__":
    sys.exit(main())
