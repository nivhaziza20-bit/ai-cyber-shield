// Supabase Edge Function — Send scan-complete email via Resend
// Deploy: supabase functions deploy send-scan-email
// Set secrets: supabase secrets set RESEND_API_KEY=re_...

import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const RESEND_URL = "https://api.resend.com/emails";
const FROM_EMAIL = "noreply@ai-cyber-shield.com";

interface ScanEmailPayload {
  to:           string;
  target_url:   string;
  overall_grade: string;
  overall_score: number;
  critical_count: number;
  high_count:    number;
  scan_duration_s: number;
}

serve(async (req) => {
  if (req.method !== "POST") {
    return new Response("Method not allowed", { status: 405 });
  }

  const apiKey = Deno.env.get("RESEND_API_KEY");
  if (!apiKey) {
    return new Response(JSON.stringify({ error: "RESEND_API_KEY not configured" }), { status: 500 });
  }

  let payload: ScanEmailPayload;
  try {
    payload = await req.json();
  } catch {
    return new Response(JSON.stringify({ error: "Invalid JSON" }), { status: 400 });
  }

  const {
    to, target_url, overall_grade, overall_score,
    critical_count, high_count, scan_duration_s
  } = payload;

  if (!to || !target_url) {
    return new Response(JSON.stringify({ error: "Missing required fields" }), { status: 400 });
  }

  const gradeColor = overall_grade === "A" || overall_grade === "A+" ? "#10b981"
    : overall_grade === "B" ? "#3b82f6"
    : overall_grade === "C" ? "#f59e0b"
    : "#ef4444";

  const html = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Scan Complete — AI Cyber Shield</title>
</head>
<body style="margin:0;padding:0;background:#0a0e1a;font-family:'Segoe UI',Arial,sans-serif;color:#c9d1d9;">
  <table width="100%" cellpadding="0" cellspacing="0" border="0">
    <tr>
      <td align="center" style="padding:40px 16px;">
        <table width="600" cellpadding="0" cellspacing="0" border="0"
               style="background:#0d1117;border:1px solid #1f2d3d;border-radius:16px;overflow:hidden;max-width:600px;">

          <!-- Header -->
          <tr>
            <td style="background:#0d1117;border-bottom:1px solid #1f2d3d;padding:32px 40px;text-align:center;">
              <div style="font-size:2.5rem;">🛡</div>
              <div style="font-size:1.5rem;font-weight:900;color:#10b981;font-family:monospace;letter-spacing:-0.04em;margin:8px 0 4px;">
                AI Cyber Shield
              </div>
              <div style="font-size:0.7rem;color:#475569;letter-spacing:0.18em;text-transform:uppercase;">
                Security Scan Complete
              </div>
            </td>
          </tr>

          <!-- Grade -->
          <tr>
            <td style="padding:32px 40px;text-align:center;">
              <div style="font-size:0.8rem;color:#475569;letter-spacing:0.1em;text-transform:uppercase;margin-bottom:16px;">
                Overall Security Grade
              </div>
              <div style="display:inline-block;width:80px;height:80px;border-radius:50%;
                          background:${gradeColor}22;border:3px solid ${gradeColor};
                          line-height:80px;font-size:2rem;font-weight:900;color:${gradeColor};">
                ${overall_grade}
              </div>
              <div style="font-size:1.1rem;color:#c9d1d9;margin-top:12px;">
                Score: <strong>${overall_score}/100</strong>
              </div>
            </td>
          </tr>

          <!-- Target -->
          <tr>
            <td style="padding:0 40px 24px;">
              <div style="background:#0a0e1a;border:1px solid #1f2d3d;border-radius:8px;padding:16px;">
                <div style="font-size:0.7rem;color:#475569;letter-spacing:0.1em;text-transform:uppercase;margin-bottom:6px;">
                  Scanned Target
                </div>
                <div style="color:#10b981;font-family:monospace;word-break:break-all;font-size:0.9rem;">
                  ${target_url}
                </div>
              </div>
            </td>
          </tr>

          <!-- Findings -->
          <tr>
            <td style="padding:0 40px 32px;">
              <table width="100%" cellpadding="0" cellspacing="8" border="0">
                <tr>
                  <td width="50%" style="background:#4a1111;border:1px solid #991b1b;border-radius:8px;padding:16px;text-align:center;">
                    <div style="font-size:0.65rem;color:#fca5a5;letter-spacing:0.1em;text-transform:uppercase;">
                      Critical Findings
                    </div>
                    <div style="font-size:2rem;font-weight:900;color:#ef4444;margin-top:4px;">
                      ${critical_count}
                    </div>
                  </td>
                  <td width="50%" style="background:#3d2a00;border:1px solid #92400e;border-radius:8px;padding:16px;text-align:center;">
                    <div style="font-size:0.65rem;color:#fcd34d;letter-spacing:0.1em;text-transform:uppercase;">
                      High Findings
                    </div>
                    <div style="font-size:2rem;font-weight:900;color:#f59e0b;margin-top:4px;">
                      ${high_count}
                    </div>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- CTA -->
          <tr>
            <td style="padding:0 40px 40px;text-align:center;">
              <a href="https://ai-cyber-shield-jzpg7w9bqviznsazbtbfgg.streamlit.app"
                 style="display:inline-block;background:#10b981;color:#fff;font-weight:700;
                        text-decoration:none;border-radius:8px;padding:14px 32px;font-size:0.9rem;">
                View Full Report →
              </a>
              <div style="margin-top:16px;font-size:0.75rem;color:#475569;">
                Scan completed in ${scan_duration_s.toFixed(1)}s
              </div>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="border-top:1px solid #1f2d3d;padding:20px 40px;text-align:center;">
              <div style="font-size:0.7rem;color:#475569;line-height:1.6;">
                AI Cyber Shield — Authorized security scanning<br>
                You received this because you have notifications enabled.
                <a href="#" style="color:#475569;">Unsubscribe</a>
              </div>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>
`;

  const text = `
AI Cyber Shield — Scan Complete

Target: ${target_url}
Grade: ${overall_grade} (${overall_score}/100)
Critical findings: ${critical_count}
High findings: ${high_count}
Scan duration: ${scan_duration_s.toFixed(1)}s

View full report: https://ai-cyber-shield-jzpg7w9bqviznsazbtbfgg.streamlit.app
`;

  try {
    const res = await fetch(RESEND_URL, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        from: `AI Cyber Shield <${FROM_EMAIL}>`,
        to: [to],
        subject: `🛡 Scan Complete: ${overall_grade} grade for ${new URL(target_url).hostname}`,
        html,
        text,
      }),
    });

    if (!res.ok) {
      const err = await res.text();
      console.error("Resend error:", err);
      return new Response(JSON.stringify({ error: `Resend API error: ${err}` }), { status: 500 });
    }

    const result = await res.json();
    return new Response(JSON.stringify({ sent: true, id: result.id }), { status: 200 });
  } catch (exc) {
    console.error("Send email failed:", exc);
    return new Response(JSON.stringify({ error: String(exc) }), { status: 500 });
  }
});
