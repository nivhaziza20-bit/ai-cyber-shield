"""
samples/vulnerable_app.py
--------------------------
INTENTIONALLY VULNERABLE — for pipeline demonstration only.
DO NOT deploy this code.  It contains five real, exploitable weaknesses.

Vulnerabilities planted:
  1. SQL Injection        — string-concatenated query (B608 / CWE-89)
  2. eval() Usage         — arbitrary code execution (B307 / CWE-95)
  3. Shell Injection      — subprocess with shell=True (B602 / CWE-78)
  4. Weak Hashing         — MD5 used for passwords (B303 / CWE-327)
  5. Hardcoded Credential — secret key in source (B105 / CWE-798)
"""

import hashlib
import os
import sqlite3
import subprocess

# ── Vulnerability 5: Hardcoded credential (CWE-798) ──────────────────────────
SECRET_KEY  = "super-secret-key-do-not-share"   # B105
DB_PASSWORD = "admin123"                         # B105


# ── Vulnerability 1: SQL Injection (CWE-89) ──────────────────────────────────
def get_user(username: str) -> tuple | None:
    """Fetch a user record by username."""
    conn   = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # UNSAFE: username is interpolated directly into the query.
    # Attacker input: ' OR '1'='1  →  returns every row.
    query  = "SELECT id, username, role FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()


def update_email(user_id: int, new_email: str) -> None:
    """Update the email address for a given user."""
    conn   = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # UNSAFE: same injection pattern, different operation.
    cursor.execute(
        "UPDATE users SET email = '" + new_email + "' WHERE id = " + str(user_id)
    )
    conn.commit()


# ── Vulnerability 4: Weak Password Hashing (CWE-327) ─────────────────────────
def hash_password(plaintext: str) -> str:
    """Hash a password before storing it in the database."""
    # UNSAFE: MD5 is cryptographically broken and has no salt.
    # Precomputed rainbow tables can reverse common passwords in milliseconds.
    return hashlib.md5(plaintext.encode()).hexdigest()


def verify_password(plaintext: str, stored_hash: str) -> bool:
    return hash_password(plaintext) == stored_hash


# ── Vulnerability 3: Shell Injection (CWE-78) ─────────────────────────────────
def run_report(report_name: str) -> str:
    """Run a named report script and return its output."""
    # UNSAFE: report_name is passed to a shell.
    # Attacker input: "quarterly; rm -rf /"
    result = subprocess.run(
        f"python reports/{report_name}.py",
        shell=True,               # B602
        capture_output=True,
        text=True,
    )
    return result.stdout


# ── Vulnerability 2: eval() / Arbitrary Code Execution (CWE-95) ──────────────
def calculate(expression: str) -> float:
    """Evaluate a user-supplied mathematical expression."""
    # UNSAFE: eval() executes arbitrary Python, not just math.
    # Attacker input: "__import__('os').system('whoami')"
    return eval(expression)    # B307
