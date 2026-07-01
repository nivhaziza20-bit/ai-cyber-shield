"""
AI Cyber Shield — GitHub Action scan runner.
Uses only Python stdlib (no pip install required).
"""
import json
import os
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import urlencode

# ── Config from environment ────────────────────────────────────────────────────
TARGET_URL     = os.environ.get("INPUT_TARGET_URL", "").strip()
API_KEY        = os.environ.get("INPUT_API_KEY", "").strip()
API_ENDPOINT   = os.environ.get("INPUT_API_ENDPOINT", "https://your-api-url.com").rstrip("/")
FAIL_ON_GRADE  = os.environ.get("INPUT_FAIL_ON_GRADE", "D").upper()
FAIL_ON_CRIT   = os.environ.get("INPUT_FAIL_ON_CRITICAL", "true").lower() == "true"
TIMEOUT_MINS   = int(os.environ.get("INPUT_TIMEOUT_MINUTES", "5"))
UPLOAD_SARIF   = os.environ.get("INPUT_UPLOAD_SARIF", "true").lower() == "true"
GITHUB_TOKEN   = os.environ.get("GITHUB_TOKEN", "")
GITHUB_OUTPUT  = os.environ.get("GITHUB_OUTPUT", "")
GITHUB_REPO    = os.environ.get("GITHUB_REPOSITORY", "")
GITHUB_SHA     = os.environ.get("GITHUB_SHA", "")
GITHUB_STEP_SUMMARY = os.environ.get("GITHUB_STEP_SUMMARY", "")

GRADE_ORDER = ["A", "B", "C", "D", "F"]
SARIF_FILE  = "scan-results.sarif"


def _mask(text: str) -> str:
    """Replace API key with *** in log output."""
    if API_KEY:
        text = text.replace(API_KEY, "***")
    return text


def log(msg: str) -> None:
    print(_mask(msg), flush=True)


def _api_request(method: str, path: str, body: dict | None = None, retries: int = 3) -> dict:
    url = f"{API_ENDPOINT}{path}"
    data = json.dumps(body).encode() if body else None
    headers = {
        "X-API-Key": API_KEY,
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "AI-Cyber-Shield-GitHub-Action/1.0",
    }
    last_err = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, data=data, headers=headers, method=method)
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            body_text = e.read().decode("utf-8", errors="replace")
            if e.code == 401:
                print(f"::error::Authentication failed. Check that INPUT_API_KEY is correct.")
                sys.exit(1)
            if e.code == 429:
                wait = 30 * (attempt + 1)
                log(f"Rate limited. Waiting {wait}s before retry {attempt + 1}/{retries}…")
                time.sleep(wait)
                last_err = e
                continue
            if e.code == 422:
                print(f"::error::Invalid request: {body_text}")
                sys.exit(1)
            last_err = e
        except Exception as e:
            last_err = e
            if attempt < retries - 1:
                wait = 2 ** attempt
                log(f"Request failed ({e}). Retrying in {wait}s…")
                time.sleep(wait)
    raise RuntimeError(f"API request failed after {retries} attempts: {last_err}")


def _set_output(name: str, value: str) -> None:
    if GITHUB_OUTPUT:
        with open(GITHUB_OUTPUT, "a") as f:
            f.write(f"{name}={value}\n")


def _write_summary(scan: dict, sarif_path: str | None = None) -> None:
    if not GITHUB_STEP_SUMMARY:
        return
    grade    = scan.get("overall_grade", "?")
    score    = scan.get("overall_score", 0)
    findings = scan.get("findings", [])
    counts   = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "INFO")
        counts[sev] = counts.get(sev, 0) + 1

    top_highs = [f for f in findings if f.get("severity") in ("CRITICAL", "HIGH")][:3]
    lines = [
        "## 🛡 AI Cyber Shield Scan Results\n",
        f"| Score | Grade | URL |",
        f"|-------|-------|-----|",
        f"| {score}/100 | {grade} | {scan.get('url', TARGET_URL)} |",
        "",
        "### Findings",
        f"| 🔴 Critical | 🟠 High | 🟡 Medium | 🟢 Low | ℹ️ Info |",
        f"|------------|--------|----------|--------|------|",
        f"| {counts['CRITICAL']} | {counts['HIGH']} | {counts['MEDIUM']} | {counts['LOW']} | {counts['INFO']} |",
    ]
    if top_highs:
        lines += ["", "### Top findings"]
        for f in top_highs:
            lines.append(f"- **[{f.get('severity')}]** {f.get('title', 'Unknown')}")
    if sarif_path:
        lines.append(f"\n_SARIF report saved to `{sarif_path}`_")

    with open(GITHUB_STEP_SUMMARY, "a") as f:
        f.write("\n".join(lines) + "\n")


def _grade_fails(grade: str, threshold: str) -> bool:
    if grade not in GRADE_ORDER or threshold not in GRADE_ORDER:
        return False
    return GRADE_ORDER.index(grade) > GRADE_ORDER.index(threshold)


def _generate_sarif(scan: dict) -> dict:
    findings = scan.get("findings", [])
    results = []
    rules   = {}

    for f in findings:
        rule_id = f.get("id", "unknown")
        sev     = f.get("severity", "INFO").upper()
        level_map = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}
        level = level_map.get(sev, "note")

        rules[rule_id] = {
            "id": rule_id,
            "name": f.get("title", rule_id),
            "shortDescription": {"text": f.get("title", rule_id)},
            "fullDescription": {"text": f.get("description", "")},
            "defaultConfiguration": {"level": level},
            "properties": {
                "tags": [sev, "security"],
                "security-severity": str(f.get("cvss_score", _sev_to_cvss(sev))),
            },
        }

        results.append({
            "ruleId": rule_id,
            "level": level,
            "message": {"text": f.get("description", f.get("title", ""))},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": scan.get("url", TARGET_URL), "uriBaseId": "%SRCROOT%"},
                }
            }],
        })

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "AI Cyber Shield",
                    "version": "6.0",
                    "informationUri": "https://aicybershield.com",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
            "properties": {
                "overall_score": scan.get("overall_score"),
                "overall_grade": scan.get("overall_grade"),
            },
        }],
    }


def _sev_to_cvss(sev: str) -> float:
    return {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.5, "INFO": 0.0}.get(sev, 0.0)


def _upload_sarif_to_github(sarif_path: str) -> bool:
    if not GITHUB_TOKEN or not GITHUB_REPO or not GITHUB_SHA:
        log("Skipping SARIF upload — GITHUB_TOKEN/REPOSITORY/SHA not available")
        return False
    try:
        import base64
        import gzip
        with open(sarif_path, "rb") as f:
            compressed = gzip.compress(f.read())
        encoded = base64.b64encode(compressed).decode()

        upload_url = f"https://api.github.com/repos/{GITHUB_REPO}/code-scanning/sarifs"
        payload = {
            "commit_sha": GITHUB_SHA,
            "ref": os.environ.get("GITHUB_REF", "refs/heads/main"),
            "sarif": encoded,
            "tool_name": "AI Cyber Shield",
        }
        req = urllib.request.Request(
            upload_url,
            data=json.dumps(payload).encode(),
            headers={
                "Authorization": f"Bearer {GITHUB_TOKEN}",
                "Accept": "application/vnd.github+json",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            log(f"SARIF uploaded to GitHub Code Scanning (status {resp.status})")
            return True
    except Exception as e:
        log(f"::warning::SARIF upload failed: {e}")
        return False


def main() -> None:
    if not TARGET_URL:
        print("::error::INPUT_TARGET_URL is required")
        sys.exit(1)
    if not API_KEY:
        print("::error::INPUT_API_KEY is required")
        sys.exit(1)

    # ── Trigger scan ─────────────────────────────────────────────────────────
    log(f"::group::AI Cyber Shield — Scanning {TARGET_URL}")
    log(f"Triggering scan of {TARGET_URL}…")
    try:
        resp = _api_request("POST", "/api/v1/scans", {"url": TARGET_URL, "mode": "standard"})
    except Exception as e:
        print(f"::error::Failed to start scan: {e}")
        sys.exit(1)

    scan_id = resp.get("scan_id")
    if not scan_id:
        print(f"::error::No scan_id in response: {resp}")
        sys.exit(1)
    log(f"Scan started: {scan_id}")

    # ── Poll for completion ──────────────────────────────────────────────────
    deadline   = time.time() + TIMEOUT_MINS * 60
    poll_delay = 10
    scan       = None

    while time.time() < deadline:
        time.sleep(poll_delay)
        try:
            scan = _api_request("GET", f"/api/v1/scans/{scan_id}")
        except Exception as e:
            log(f"Poll error (will retry): {e}")
            continue

        status = scan.get("status", "")
        log(f"  Status: {status}")
        if status == "completed":
            break
        if status == "failed":
            err = scan.get("error_message", "Unknown error")
            print(f"::error::Scan failed: {err}")
            sys.exit(1)
    else:
        print(f"::error::Scan timed out after {TIMEOUT_MINS} minute(s). Scan ID: {scan_id}")
        sys.exit(1)

    # ── Extract results ──────────────────────────────────────────────────────
    grade    = (scan.get("overall_grade") or "F").upper()
    score    = scan.get("overall_score") or 0
    findings = scan.get("findings") or []
    counts   = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = (f.get("severity") or "INFO").upper()
        counts[sev] = counts.get(sev, 0) + 1

    scan_url = f"{API_ENDPOINT}/dashboard/scans/{scan_id}"

    # ── Print results ─────────────────────────────────────────────────────────
    log(f"")
    log(f"🛡  Security Score: {score}/100 (Grade: {grade})")
    log(f"")
    log(f"Findings:")
    log(f"  🔴 Critical: {counts['CRITICAL']}")
    log(f"  🟠 High:     {counts['HIGH']}")
    log(f"  🟡 Medium:   {counts['MEDIUM']}")
    log(f"  🟢 Low:      {counts['LOW']}")
    log(f"  ℹ  Info:     {counts['INFO']}")
    log(f"")
    top = [f for f in findings if f.get("severity") in ("CRITICAL", "HIGH")][:3]
    if top:
        log("Top findings:")
        for f in top:
            log(f"  [{f.get('severity')}] {f.get('title', 'Unknown')}")
        log("")
    log(f"Full results: {scan_url}")
    log("::endgroup::")

    # ── Set GitHub outputs ───────────────────────────────────────────────────
    _set_output("overall_score",    str(score))
    _set_output("overall_grade",    grade)
    _set_output("findings_critical", str(counts["CRITICAL"]))
    _set_output("findings_high",     str(counts["HIGH"]))
    _set_output("findings_total",    str(sum(counts.values())))
    _set_output("scan_url",          scan_url)

    # ── SARIF export ─────────────────────────────────────────────────────────
    sarif_path = None
    if UPLOAD_SARIF:
        sarif = _generate_sarif(scan)
        with open(SARIF_FILE, "w") as f:
            json.dump(sarif, f, indent=2)
        sarif_path = SARIF_FILE
        _set_output("sarif_file", SARIF_FILE)
        log(f"SARIF report written to {SARIF_FILE}")
        _upload_sarif_to_github(SARIF_FILE)

    _write_summary(scan, sarif_path)

    # ── Pass / fail evaluation ────────────────────────────────────────────────
    fail_reasons = []
    if _grade_fails(grade, FAIL_ON_GRADE):
        fail_reasons.append(f"Grade {grade} is below threshold {FAIL_ON_GRADE}")
    if FAIL_ON_CRIT and counts["CRITICAL"] > 0:
        fail_reasons.append(f"{counts['CRITICAL']} CRITICAL finding(s) detected")

    if fail_reasons:
        reason = ". ".join(fail_reasons) + "."
        print(f"::error::Security scan failed: {reason}")
        sys.exit(1)

    log("✅ Security scan passed.")


if __name__ == "__main__":
    main()
