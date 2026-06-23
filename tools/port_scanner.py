"""
Port Scanner

Checks a target host for commonly exposed and dangerous TCP ports using
asyncio TCP connect probes. No data is sent — the scanner only attempts to
open a TCP connection, then immediately closes it.

Why this matters
────────────────
Many breach investigations reveal that public cloud VMs have wide-open
firewall rules left over from development (the "open everything and forget"
pattern). Exposed database ports (3306, 5432, 27017), remote desktop (3389),
and unauthenticated caches (6379 Redis) are among the most frequently abused
services on the internet.

Performance design
──────────────────
All port probes run concurrently via asyncio.gather() with a short per-port
timeout (3s). Maximum concurrent probes is capped by a semaphore so the scan
doesn't generate a SYN-flood-like burst that triggers upstream rate-limiting
or IDS alerts.

SSRF protection
───────────────
The target hostname is validated with is_ssrf_blocked() before any connection
attempt. This prevents the scanner from being used to probe internal networks
(169.254.x.x, 10.x.x.x, 192.168.x.x, etc.).
"""

from __future__ import annotations

import asyncio
import json
from urllib.parse import urlparse

from langchain_core.tools import tool

from tools.http_utils import is_ssrf_blocked

# ─────────────────────────────────────────────────────────────────────────────
# Port catalogue
# (port: (service_name, short_description, risk_score))
# risk_score is the ADDITIVE contribution per open port to the final risk score.
# A database port open to the internet is a much bigger deal than an open SSH.
# ─────────────────────────────────────────────────────────────────────────────

_PORTS: dict[int, tuple[str, str, int]] = {
    21:    ("FTP",         "File Transfer Protocol — often allows anonymous or brute-forced access", 30),
    22:    ("SSH",         "Secure Shell — brute-force target; restrict to known IPs", 10),
    23:    ("Telnet",      "Cleartext remote shell — credentials sent in plaintext", 60),
    25:    ("SMTP",        "Mail submission — check for open relay misconfiguration", 15),
    80:    ("HTTP",        "Plaintext web traffic — expected; verify HTTPS redirect works", 0),
    443:   ("HTTPS",       "Encrypted web — expected", 0),
    445:   ("SMB",         "Windows file sharing — common ransomware entry point", 75),
    3000:  ("Dev-HTTP",    "Node.js/Rails dev server — likely exposed accidentally", 40),
    3306:  ("MySQL",       "Database exposed to internet — critical data breach risk", 70),
    3389:  ("RDP",         "Windows Remote Desktop — critical; brute-force and BlueKeep target", 80),
    4444:  ("Backdoor",    "Common shell/C2 port (Metasploit default) — investigate immediately", 90),
    5432:  ("PostgreSQL",  "Database exposed to internet — critical data breach risk", 70),
    5900:  ("VNC",         "Remote desktop — often runs without authentication by default", 75),
    6379:  ("Redis",       "Cache/message broker — commonly unauthenticated by default", 75),
    8080:  ("Alt-HTTP",    "Alternative HTTP — check for admin panel or dev proxy", 25),
    8443:  ("Alt-HTTPS",   "Alternative HTTPS — check for admin panel", 20),
    8888:  ("Jupyter",     "Jupyter Notebook — may expose a token-free code execution environment", 70),
    27017: ("MongoDB",     "Database exposed to internet — critical data breach risk", 70),
}

_CONNECT_TIMEOUT = 3.0   # seconds per probe — long enough for slow hosts, short enough to be fast
_MAX_CONCURRENT  = 12    # semaphore cap — avoids a SYN burst that could trigger IDS/WAF


# ─────────────────────────────────────────────────────────────────────────────
# Async core (exposed for direct testing without going through asyncio.run)
# ─────────────────────────────────────────────────────────────────────────────

async def _check_port(hostname: str, port: int) -> bool:
    """
    Attempt a TCP connection to hostname:port.
    Returns True if the port accepted the connection, False otherwise.
    Exposed for direct unit testing.
    """
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(hostname, port),
            timeout=_CONNECT_TIMEOUT,
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return False


async def _async_scan_core(hostname: str) -> list[dict]:
    """
    Probe all ports in _PORTS concurrently with a semaphore-bounded gather.

    Returns a list of open-port dicts — only ports that accepted a TCP
    connection are included.
    Exposed at module level so tests can call it directly.
    """
    sem = asyncio.Semaphore(_MAX_CONCURRENT)

    async def _bounded(port: int) -> tuple[int, bool]:
        async with sem:
            open_ = await _check_port(hostname, port)
            return port, open_

    results = await asyncio.gather(
        *[_bounded(p) for p in _PORTS],
        return_exceptions=True,
    )

    open_ports: list[dict] = []
    for item in results:
        if isinstance(item, Exception):
            continue
        port, is_open = item
        if not is_open:
            continue
        name, desc, risk = _PORTS[port]
        open_ports.append({
            "port":        port,
            "service":     name,
            "description": desc,
            "risk":        risk,
        })

    return sorted(open_ports, key=lambda p: p["port"])


# ─────────────────────────────────────────────────────────────────────────────
# @tool
# ─────────────────────────────────────────────────────────────────────────────

@tool
def scan_open_ports(url: str) -> str:
    """
    Probes a target host for commonly dangerous open TCP ports.

    Uses asyncio TCP-connect probes (no data sent) with a short 3-second
    per-port timeout. All ports are tested concurrently. SSRF protection
    blocks scans of private/loopback networks.

    Checks 18 ports including databases (MySQL, PostgreSQL, MongoDB, Redis),
    remote access (SSH, RDP, VNC, Telnet), and common dev/admin surfaces.

    Args:
        url: Target URL — the hostname is extracted and probed.

    Returns:
        JSON with open_ports list, risk_score (0-100), and recommendations.
    """
    parsed   = urlparse(url)
    hostname = parsed.hostname or ""

    if not hostname:
        return json.dumps({"tool": "port_scanner", "status": "invalid_url"})

    if is_ssrf_blocked(hostname):
        return json.dumps({"tool": "port_scanner", "status": "ssrf_blocked"})

    try:
        open_ports = asyncio.run(_async_scan_core(hostname))
    except RuntimeError as exc:
        return json.dumps({"tool": "port_scanner", "status": "error", "error": str(exc)})

    # ── Risk scoring ──────────────────────────────────────────────────────────
    # Sum individual port risks; cap at 100.
    risk_score = min(sum(p["risk"] for p in open_ports), 100)

    # ── Recommendations ───────────────────────────────────────────────────────
    recommendations: list[str] = []

    critical = [p for p in open_ports if p["risk"] >= 60]
    for p in critical[:4]:
        recommendations.append(
            f"CRITICAL: Port {p['port']} ({p['service']}) is reachable from the internet — "
            f"{p['description']}. "
            f"Restrict immediately with firewall rules: "
            f"`iptables -A INPUT -p tcp --dport {p['port']} -j DROP` or cloud security group."
        )

    medium = [p for p in open_ports if 10 <= p["risk"] < 60]
    for p in medium[:3]:
        recommendations.append(
            f"Port {p['port']} ({p['service']}) is exposed — {p['description']}. "
            "Restrict access to known IP ranges only."
        )

    if not open_ports:
        recommendations.append(
            "No commonly dangerous ports are reachable from the internet — strong firewall posture."
        )
    elif not critical:
        recommendations.append(
            "No critical ports open. Only standard web ports (80/443) and low-risk services detected."
        )

    return json.dumps({
        "tool":           "port_scanner",
        "status":         "completed",
        "host":           hostname,
        "ports_checked":  len(_PORTS),
        "open_ports":     open_ports,
        "open_count":     len(open_ports),
        "risk_score":     risk_score,
        "recommendations": recommendations,
    }, indent=2)
