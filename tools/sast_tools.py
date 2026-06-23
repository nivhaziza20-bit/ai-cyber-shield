"""
SAST Tools — Phase 1
Wraps Bandit and Semgrep as LangChain tools.

Security contract:
  - Code is written to a temp file and passed as a PATH argument.
  - subprocess is NEVER called with shell=True.
  - The temp file is always deleted in a finally block.
  - The agent receives structured findings, not raw shell output,
    so it cannot be tricked into re-executing code found inside the scan.
"""

import json
import os
import subprocess
import tempfile
from typing import Literal

from langchain_core.tools import tool

from config import get_settings

# ─────────────────────────────────────────────────────────────────────────────
# Language → file extension map
# ─────────────────────────────────────────────────────────────────────────────
_EXT_MAP: dict[str, str] = {
    "python": ".py",
    "javascript": ".js",
    "typescript": ".ts",
    "java": ".java",
    "go": ".go",
    "ruby": ".rb",
    "php": ".php",
    "c": ".c",
    "cpp": ".cpp",
    "rust": ".rs",
}


# ─────────────────────────────────────────────────────────────────────────────
# Bandit
# ─────────────────────────────────────────────────────────────────────────────

@tool
def run_bandit_scan(code: str) -> str:
    """
    Performs static security analysis on Python source code using Bandit.

    Bandit checks for common Python security issues: SQL injection via string
    formatting, use of dangerous functions (eval/exec/pickle), hardcoded
    secrets, weak cryptography, insecure subprocess calls, and more.

    Args:
        code: Raw Python source code to analyse. Treated as untrusted data —
              it is written to disk and passed to the tool, never executed.

    Returns:
        JSON string with fields:
          tool, status, total_findings, severity_summary {high/medium/low},
          findings [{id, name, severity, confidence, cwe, description,
                     line_number, code_snippet, more_info}]
    """
    settings = get_settings()

    with tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".py",
        delete=False,
        prefix="bandit_scan_",
        encoding="utf-8",
    ) as tmp:
        tmp.write(code)
        tmp_path = tmp.name

    try:
        proc = subprocess.run(
            [
                "bandit",
                "--format", "json",
                "--level",      # include LOW severity
                "--confidence", # include LOW confidence
                tmp_path,
            ],
            capture_output=True,
            text=True,
            timeout=settings.sast_timeout_seconds,
            shell=False,  # CRITICAL: no shell interpolation
        )
        # Bandit exits 1 when findings exist — that is expected behaviour.
        raw_output = proc.stdout or proc.stderr
        try:
            raw = json.loads(raw_output)
        except json.JSONDecodeError:
            return json.dumps({
                "tool": "bandit",
                "status": "parse_error",
                "raw_stderr": proc.stderr[:1000],
            })

        return json.dumps(_normalise_bandit(raw), indent=2)

    except subprocess.TimeoutExpired:
        return json.dumps({"tool": "bandit", "status": "timeout",
                           "error": f"Scan aborted after {settings.sast_timeout_seconds}s"})
    except FileNotFoundError:
        return json.dumps({"tool": "bandit", "status": "not_installed",
                           "error": "Bandit binary not found. Run: pip install bandit"})
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


def _normalise_bandit(raw: dict) -> dict:
    if raw.get("errors"):
        return {"tool": "bandit", "status": "error", "errors": raw["errors"]}

    results = raw.get("results", [])
    findings = [
        {
            "id": r.get("test_id"),
            "name": r.get("test_name"),
            "severity": r.get("issue_severity", "UNKNOWN"),   # LOW / MEDIUM / HIGH
            "confidence": r.get("issue_confidence", "UNKNOWN"),
            "cwe": r.get("issue_cwe", {}),
            "description": r.get("issue_text", ""),
            "line_number": r.get("line_number"),
            "line_range": r.get("line_range", []),
            "code_snippet": r.get("code", "").strip(),
            "more_info": r.get("more_info", ""),
        }
        for r in results
    ]

    return {
        "tool": "bandit",
        "status": "completed",
        "total_findings": len(findings),
        "severity_summary": {
            "high":   sum(1 for f in findings if f["severity"] == "HIGH"),
            "medium": sum(1 for f in findings if f["severity"] == "MEDIUM"),
            "low":    sum(1 for f in findings if f["severity"] == "LOW"),
        },
        "findings": findings,
        "metrics": raw.get("metrics", {}),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Semgrep
# ─────────────────────────────────────────────────────────────────────────────

@tool
def run_semgrep_scan(code: str, language: str = "python") -> str:
    """
    Performs multi-language SAST using Semgrep with the OWASP Top-10 ruleset.

    Semgrep pattern-matches against curated security rules and maps each
    finding to CWE identifiers and OWASP categories. Supports Python,
    JavaScript, TypeScript, Java, Go, Ruby, PHP, C, C++, and Rust.

    Args:
        code: Source code to analyse (treated as untrusted data).
        language: Language hint so the correct file extension is used.
                  One of: python, javascript, typescript, java, go, ruby,
                  php, c, cpp, rust.  Defaults to 'python'.

    Returns:
        JSON string with fields:
          tool, status, total_findings, severity_summary {error/warning/info},
          findings [{rule_id, severity, message, line_start, line_end,
                     code_snippet, cwe, owasp, references, autofix}]
    """
    settings = get_settings()
    ext = _EXT_MAP.get(language.lower(), ".py")

    with tempfile.NamedTemporaryFile(
        mode="w",
        suffix=ext,
        delete=False,
        prefix="semgrep_scan_",
        encoding="utf-8",
    ) as tmp:
        tmp.write(code)
        tmp_path = tmp.name

    try:
        proc = subprocess.run(
            [
                "semgrep",
                "--json",
                "--no-git-ignore",
                "--config", settings.semgrep_ruleset,
                "--timeout", str(settings.sast_timeout_seconds),
                tmp_path,
            ],
            capture_output=True,
            text=True,
            timeout=settings.sast_timeout_seconds + 10,  # outer guard
            shell=False,
        )

        try:
            raw = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return json.dumps({
                "tool": "semgrep",
                "status": "parse_error",
                "raw_stderr": proc.stderr[:1000],
            })

        return json.dumps(_normalise_semgrep(raw), indent=2)

    except subprocess.TimeoutExpired:
        return json.dumps({"tool": "semgrep", "status": "timeout",
                           "error": f"Scan aborted after {settings.sast_timeout_seconds}s"})
    except FileNotFoundError:
        return json.dumps({"tool": "semgrep", "status": "not_installed",
                           "error": "Semgrep not found. Run: pip install semgrep"})
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


def _normalise_semgrep(raw: dict) -> dict:
    results = raw.get("results", [])
    errors  = raw.get("errors", [])

    findings = []
    for r in results:
        extra = r.get("extra", {})
        meta  = extra.get("metadata", {})
        findings.append({
            "rule_id":      r.get("check_id", ""),
            "severity":     extra.get("severity", "INFO").upper(),
            "message":      extra.get("message", ""),
            "line_start":   r.get("start", {}).get("line"),
            "line_end":     r.get("end", {}).get("line"),
            "code_snippet": extra.get("lines", "").strip(),
            "cwe":          meta.get("cwe", []),
            "owasp":        meta.get("owasp", []),
            "references":   meta.get("references", []),
            "autofix":      extra.get("fix"),  # populated when Semgrep has a suggested fix
        })

    return {
        "tool": "semgrep",
        "status": "completed",
        "total_findings": len(findings),
        "severity_summary": {
            "error":   sum(1 for f in findings if f["severity"] == "ERROR"),
            "warning": sum(1 for f in findings if f["severity"] == "WARNING"),
            "info":    sum(1 for f in findings if f["severity"] == "INFO"),
        },
        "findings": findings,
        "scan_errors": errors,
    }
