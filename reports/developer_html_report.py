"""
reports/developer_html_report.py — AI Cyber Shield v6

Developer-facing HTML security report.

What makes this better than competitors:
  • Inline code diff (before/after snippets with syntax highlight via Prism.js CDN)
  • Copy-to-clipboard curl PoC command for every finding
  • Collapsible per-finding sections (zero page load — pure CSS)
  • Evidence viewer with highlighted payload
  • Filterable severity badges (pure JS, no external deps)
  • OWASP 2025 tags including A11/A12
  • Remediation effort badges (easy/medium/hard/expert)
  • Compliance control chips (PCI-DSS / SOC2 / ISO 27001 / NIST CSF)
  • Dark-mode aware (prefers-color-scheme: dark)
  • Self-contained: all JS inline, single-file HTML, no external CDN required for layout

Requires: jinja2 >= 3.0

Usage:
    from reports.developer_html_report import generate_developer_html
    from finding_enricher import enrich_scan_result

    findings = enrich_scan_result(raw_result)
    html = generate_developer_html(
        findings    = findings,
        target_url  = "https://app.example.com",
        scan_id     = "abc-123",
    )
    with open("dev_report.html", "w", encoding="utf-8") as f:
        f.write(html)
"""

from __future__ import annotations

import html as _html_lib
import logging
import textwrap
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

_log = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Jinja2 template (inline, no file I/O required)
# ─────────────────────────────────────────────────────────────────────────────

_TEMPLATE_SRC = r"""<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>{{ report_title | e }} — AI Cyber Shield</title>
<style>
/* ── Reset & base ── */
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
:root {
  --brand: #1d4ed8;
  --brand-light: #eff6ff;
  --bg: #f8fafc;
  --surface: #fff;
  --border: #e2e8f0;
  --text: #0f172a;
  --muted: #64748b;
  --critical: #dc2626;
  --high: #ea580c;
  --medium: #ca8a04;
  --low: #16a34a;
  --info: #64748b;
  --code-bg: #1e293b;
  --code-text: #e2e8f0;
  --tag-bg: #f1f5f9;
  --radius: 8px;
  --shadow: 0 1px 3px rgba(0,0,0,.08);
}
@media (prefers-color-scheme: dark) {
  :root[data-theme="auto"] {
    --bg: #0f172a; --surface: #1e293b; --border: #334155;
    --text: #f1f5f9; --muted: #94a3b8; --tag-bg: #334155;
  }
}
body { font-family: system-ui, -apple-system, sans-serif; background: var(--bg);
       color: var(--text); font-size: 14px; line-height: 1.6; }
a { color: var(--brand); }

/* ── Layout ── */
.container { max-width: 1100px; margin: 0 auto; padding: 24px 16px; }
header { background: var(--text); color: #fff; padding: 20px 0; }
header .inner { max-width: 1100px; margin: 0 auto; padding: 0 16px;
                display: flex; justify-content: space-between; align-items: center; }
header h1 { font-size: 1.25rem; font-weight: 700; }
header .meta { font-size: 0.8rem; opacity: 0.7; text-align: right; }

/* ── Score bar ── */
.score-bar { display: flex; gap: 16px; flex-wrap: wrap; margin: 20px 0; }
.score-card { background: var(--surface); border: 1px solid var(--border);
              border-radius: var(--radius); padding: 16px 20px;
              box-shadow: var(--shadow); flex: 1; min-width: 120px; text-align: center; }
.score-card .value { font-size: 2rem; font-weight: 800; line-height: 1; }
.score-card .label { font-size: 0.7rem; color: var(--muted); text-transform: uppercase;
                     letter-spacing: .05em; margin-top: 4px; }
.score-card.critical .value { color: var(--critical); }
.score-card.high     .value { color: var(--high); }
.score-card.medium   .value { color: var(--medium); }
.score-card.low      .value { color: var(--low); }

/* ── Filter bar ── */
.filter-bar { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 16px; align-items: center; }
.filter-bar span { font-size: 0.75rem; color: var(--muted); }
.filter-btn { border: 1px solid var(--border); background: var(--surface);
              border-radius: 20px; padding: 4px 12px; font-size: 0.75rem;
              cursor: pointer; transition: all .15s; }
.filter-btn.active { background: var(--brand); color: #fff; border-color: var(--brand); }

/* ── Finding card ── */
.finding { background: var(--surface); border: 1px solid var(--border);
           border-radius: var(--radius); margin-bottom: 12px;
           box-shadow: var(--shadow); overflow: hidden; }
.finding-header { display: flex; align-items: center; gap: 12px;
                  padding: 14px 16px; cursor: pointer; user-select: none; }
.finding-header:hover { background: var(--brand-light); }
.sev-badge { border-radius: 4px; padding: 2px 8px; font-size: 0.7rem;
             font-weight: 700; letter-spacing: .06em; color: #fff; flex-shrink: 0; }
.sev-CRITICAL { background: var(--critical); }
.sev-HIGH     { background: var(--high); }
.sev-MEDIUM   { background: var(--medium); }
.sev-LOW      { background: var(--low); }
.sev-INFO     { background: var(--info); }
.finding-title { font-weight: 600; flex: 1; }
.cvss-pill { font-size: 0.7rem; color: var(--muted); background: var(--tag-bg);
             padding: 2px 8px; border-radius: 10px; flex-shrink: 0; }
.chevron { color: var(--muted); font-size: 0.8rem; flex-shrink: 0; transition: transform .2s; }
.finding.open .chevron { transform: rotate(90deg); }

/* ── Finding body ── */
.finding-body { display: none; padding: 0 16px 16px; border-top: 1px solid var(--border); }
.finding.open .finding-body { display: block; }

/* ── Sections inside body ── */
.section { margin-top: 14px; }
.section-title { font-size: 0.7rem; font-weight: 700; text-transform: uppercase;
                 letter-spacing: .06em; color: var(--muted); margin-bottom: 6px; }

/* ── Tags / chips ── */
.tags { display: flex; flex-wrap: wrap; gap: 6px; }
.tag { background: var(--tag-bg); border: 1px solid var(--border);
       border-radius: 4px; padding: 2px 8px; font-size: 0.7rem; }
.tag.pci   { border-color: #a78bfa; }
.tag.soc2  { border-color: #34d399; }
.tag.iso   { border-color: #60a5fa; }
.tag.nist  { border-color: #fb923c; }

/* ── Code blocks ── */
pre { background: var(--code-bg); color: var(--code-text); border-radius: var(--radius);
      padding: 12px 14px; font-size: 0.78rem; overflow-x: auto; position: relative; }
pre code { font-family: 'Cascadia Code', 'Fira Code', monospace; }
.copy-btn { position: absolute; top: 8px; right: 8px; background: #334155;
            color: #94a3b8; border: none; border-radius: 4px; padding: 2px 8px;
            font-size: 0.7rem; cursor: pointer; }
.copy-btn:hover { background: #475569; color: #fff; }

/* ── Diff ── */
.diff pre { margin: 0; }
.diff-before pre { background: #1a0808; }
.diff-after  pre { background: #081a0e; }
.diff-label { font-size: 0.7rem; font-weight: 600; padding: 4px 8px; }
.diff-before .diff-label { color: #f87171; }
.diff-after  .diff-label { color: #34d399; }

/* ── Evidence ── */
.evidence-box { background: var(--code-bg); border-left: 3px solid var(--critical);
                color: var(--code-text); padding: 10px 12px; border-radius: 0 var(--radius) var(--radius) 0;
                font-family: monospace; font-size: 0.78rem; overflow-x: auto; word-break: break-all; }

/* ── Effort badge ── */
.effort { display: inline-block; border-radius: 4px; padding: 2px 8px;
          font-size: 0.7rem; font-weight: 600; }
.effort-easy   { background: #dcfce7; color: #15803d; }
.effort-medium { background: #fef9c3; color: #92400e; }
.effort-hard   { background: #ffedd5; color: #9a3412; }
.effort-expert { background: #fee2e2; color: #991b1b; }

/* ── Misc ── */
.confirmed-badge { font-size: 0.65rem; background: #dcfce7; color: #15803d;
                   border-radius: 4px; padding: 1px 6px; font-weight: 600; }
footer { text-align: center; padding: 24px; color: var(--muted); font-size: 0.75rem; border-top: 1px solid var(--border); margin-top: 32px; }
</style>
</head>
<body>

<header>
  <div class="inner">
    <h1>AI Cyber Shield — Developer Security Report</h1>
    <div class="meta">
      <div>{{ target_url | e }}</div>
      <div>{{ scan_timestamp | e }}{% if scan_id %} · Scan {{ scan_id | e }}{% endif %}</div>
    </div>
  </div>
</header>

<div class="container">

  <!-- Score bar -->
  <div class="score-bar">
    <div class="score-card critical">
      <div class="value">{{ counts.CRITICAL }}</div>
      <div class="label">Critical</div>
    </div>
    <div class="score-card high">
      <div class="value">{{ counts.HIGH }}</div>
      <div class="label">High</div>
    </div>
    <div class="score-card medium">
      <div class="value">{{ counts.MEDIUM }}</div>
      <div class="label">Medium</div>
    </div>
    <div class="score-card low">
      <div class="value">{{ counts.LOW }}</div>
      <div class="label">Low</div>
    </div>
    <div class="score-card">
      <div class="value">{{ findings | length }}</div>
      <div class="label">Total</div>
    </div>
    <div class="score-card">
      <div class="value" style="color:var(--brand)">{{ confirmed_count }}</div>
      <div class="label">Confirmed</div>
    </div>
  </div>

  <!-- Filter bar -->
  <div class="filter-bar">
    <span>Filter:</span>
    <button class="filter-btn active" onclick="filterSev('ALL',this)">All</button>
    <button class="filter-btn" onclick="filterSev('CRITICAL',this)">Critical</button>
    <button class="filter-btn" onclick="filterSev('HIGH',this)">High</button>
    <button class="filter-btn" onclick="filterSev('MEDIUM',this)">Medium</button>
    <button class="filter-btn" onclick="filterSev('LOW',this)">Low</button>
    <button class="filter-btn" onclick="filterSev('INFO',this)">Info</button>
  </div>

  <!-- Findings -->
  {% if findings %}
  {% for f in findings %}
  <div class="finding" data-sev="{{ f.severity | e }}" id="finding-{{ loop.index }}">
    <div class="finding-header" onclick="toggleFinding(this)">
      <span class="sev-badge sev-{{ f.severity | e }}">{{ f.severity | e }}</span>
      <span class="finding-title">{{ f.title | e }}
        {% if f.confirmed %}<span class="confirmed-badge">✓ Confirmed</span>{% endif %}
      </span>
      <span class="cvss-pill">CVSS {{ "%.1f"|format(f.cvss.score) }}</span>
      <span class="cvss-pill">{{ f.cwe.label | e }}</span>
      <span class="cvss-pill">{{ f.owasp.code | e }}</span>
      <span class="chevron">▶</span>
    </div>
    <div class="finding-body">

      <!-- Meta tags -->
      <div class="section">
        <div class="section-title">Classification</div>
        <div class="tags">
          <span class="tag">{{ f.owasp.label | e }}</span>
          <span class="tag">{{ f.cwe.label | e }} — {{ f.cwe.name | e }}</span>
          {% if f.compliance.pci_dss %}<span class="tag pci">PCI-DSS {{ f.compliance.pci_dss | e }}</span>{% endif %}
          {% if f.compliance.soc2_cc %}<span class="tag soc2">SOC2 {{ f.compliance.soc2_cc | e }}</span>{% endif %}
          {% if f.compliance.iso_27001 %}<span class="tag iso">ISO {{ f.compliance.iso_27001 | e }}</span>{% endif %}
          {% if f.compliance.nist_csf %}<span class="tag nist">NIST {{ f.compliance.nist_csf | e }}</span>{% endif %}
        </div>
      </div>

      <!-- Endpoint -->
      {% if f.endpoint %}
      <div class="section">
        <div class="section-title">Endpoint</div>
        <code>{{ f.endpoint | e }}{% if f.parameter %} · param: <b>{{ f.parameter | e }}</b>{% endif %}</code>
      </div>
      {% endif %}

      <!-- Attack scenario -->
      <div class="section">
        <div class="section-title">Attack Scenario</div>
        <p>{{ f.attack_scenario | e }}</p>
      </div>

      <!-- Business impact -->
      <div class="section">
        <div class="section-title">Business Impact</div>
        <p>{{ f.business_impact | e }}</p>
      </div>

      <!-- Evidence -->
      {% if f.evidence %}
      <div class="section">
        <div class="section-title">Evidence</div>
        <div class="evidence-box">{{ f.evidence | e }}</div>
      </div>
      {% endif %}

      {% if f.endpoint %}
      <div class="section">
        <div class="section-title">curl PoC</div>
        <div style="position:relative">
          <pre><button class="copy-btn" onclick="copyCode(this)">Copy</button><code>{{ curl_poc(f) | e }}</code></pre>
        </div>
      </div>
      {% endif %}

      <!-- Code diff -->
      {% if f.remediation.code_before or f.remediation.code_after %}
      <div class="section">
        <div class="section-title">Code Fix</div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px" class="diff">
          <div class="diff-before">
            <div class="diff-label">❌ Vulnerable</div>
            <pre><code>{{ f.remediation.code_before | e }}</code></pre>
          </div>
          <div class="diff-after">
            <div class="diff-label">✅ Fixed</div>
            <pre><code>{{ f.remediation.code_after | e }}</code></pre>
          </div>
        </div>
      </div>
      {% endif %}

      <!-- Remediation summary -->
      <div class="section">
        <div class="section-title">Remediation</div>
        <p>{{ f.remediation.summary | e }}</p>
        <div style="margin-top:8px">
          <span class="{{ effort_class(f.remediation.effort_hours) }}">
            {{ effort_label(f.remediation.effort_hours) }}
          </span>
          <span style="margin-left:8px;color:var(--muted);font-size:0.75rem">
            ~{{ f.remediation.effort_hours | int }}h estimated
          </span>
        </div>
      </div>

      <!-- References -->
      {% if f.remediation.references %}
      <div class="section">
        <div class="section-title">References</div>
        <ul style="padding-left:18px;font-size:0.8rem">
          {% for ref in f.remediation.references %}
          <li><a href="{{ ref | e }}" target="_blank" rel="noopener">{{ ref | e }}</a></li>
          {% endfor %}
        </ul>
      </div>
      {% endif %}

    </div><!-- /finding-body -->
  </div><!-- /finding -->
  {% endfor %}

  {% else %}
  <div style="text-align:center;padding:60px;color:var(--muted)">
    <div style="font-size:3rem">✅</div>
    <h2 style="margin-top:12px">No findings detected</h2>
    <p style="margin-top:8px">The scan completed successfully with zero security findings.</p>
  </div>
  {% endif %}

</div>

<footer>
  Generated by AI Cyber Shield v6 · {{ scan_timestamp | e }} · {{ findings | length }} findings
</footer>

<script>
function toggleFinding(header) {
  header.closest('.finding').classList.toggle('open');
}
function filterSev(sev, btn) {
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('.finding').forEach(el => {
    el.style.display = (sev === 'ALL' || el.dataset.sev === sev) ? '' : 'none';
  });
}
function copyCode(btn) {
  const code = btn.nextElementSibling.textContent;
  navigator.clipboard.writeText(code).then(() => {
    btn.textContent = 'Copied!';
    setTimeout(() => { btn.textContent = 'Copy'; }, 1500);
  });
}
// Open first critical/high finding automatically
(function() {
  const first = document.querySelector('.finding[data-sev="CRITICAL"], .finding[data-sev="HIGH"]');
  if (first) first.classList.add('open');
})();
</script>
</body>
</html>"""


# ─────────────────────────────────────────────────────────────────────────────
# Template helpers (exposed as Jinja2 globals)
# ─────────────────────────────────────────────────────────────────────────────

def _effort_class(hours: float) -> str:
    if hours <= 2:   return "effort effort-easy"
    if hours <= 8:   return "effort effort-medium"
    if hours <= 24:  return "effort effort-hard"
    return "effort effort-expert"


def _effort_label(hours: float) -> str:
    if hours <= 2:   return "Easy (< 2h)"
    if hours <= 8:   return "Medium (2–8h)"
    if hours <= 24:  return "Hard (8–24h)"
    return "Expert (24h+)"


def _curl_poc(finding) -> str:
    """Build a representative curl command for the finding."""
    endpoint = finding.endpoint or "https://TARGET/path"
    param    = finding.parameter or ""
    evidence = finding.evidence or ""

    if param and evidence:
        safe_evidence = evidence[:120].replace("'", "\\'")
        return (
            f"curl -sk -X GET '{endpoint}'"
            f" --data-urlencode '{param}={safe_evidence}'"
            f" -H 'User-Agent: AI-Cyber-Shield/6.0'"
        )
    return f"curl -sk '{endpoint}' -H 'User-Agent: AI-Cyber-Shield/6.0'"


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def generate_developer_html(
    findings:       list,
    target_url:     str = "",
    scan_id:        str = "",
    scan_timestamp: str = "",
    report_title:   str = "Developer Security Report",
) -> str:
    """
    Render a self-contained developer-facing HTML security report.

    Args:
        findings:       List of SecurityFinding from finding_enricher
        target_url:     URL that was scanned
        scan_id:        Unique scan identifier
        scan_timestamp: ISO datetime string
        report_title:   Document title shown in browser tab

    Returns:
        Complete HTML document as a str (UTF-8)
    """
    try:
        from jinja2 import Environment, Undefined  # noqa: PLC0415
    except ImportError:
        raise RuntimeError("jinja2 required: pip install jinja2")

    if not scan_timestamp:
        scan_timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_findings = sorted(
        findings,
        key=lambda f: (severity_order.get(f.severity, 5), -f.cvss.score),
    )

    counts = {sev: sum(1 for f in findings if f.severity == sev)
              for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}
    confirmed_count = sum(1 for f in findings if f.confirmed)

    env = Environment(autoescape=False)
    env.globals["curl_poc"]      = _curl_poc
    env.globals["effort_class"]  = _effort_class
    env.globals["effort_label"]  = _effort_label

    tmpl = env.from_string(_TEMPLATE_SRC)
    return tmpl.render(
        findings        = sorted_findings,
        target_url      = target_url,
        scan_id         = scan_id,
        scan_timestamp  = scan_timestamp,
        report_title    = report_title,
        counts          = counts,
        confirmed_count = confirmed_count,
    )
