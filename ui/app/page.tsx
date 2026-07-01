"use client";

import { useState, useEffect, useRef } from "react";
import { useRouter } from "next/navigation";

/* ─── Tool grid data ──────────────────────────────────────────────────────── */
const TOOLS = [
  { name: "SSL/TLS",        icon: "🔒", desc: "Certificate & protocol analysis" },
  { name: "Headers",        icon: "📋", desc: "OWASP security header audit" },
  { name: "DNS Security",   icon: "🌐", desc: "SPF, DMARC, DNSSEC validation" },
  { name: "CORS & CSP",     icon: "🛡",  desc: "Cross-origin & content policy" },
  { name: "HTML Analysis",  icon: "📄", desc: "Client-side injection surface" },
  { name: "Tech Stack",     icon: "⚙️", desc: "CVE-matched fingerprinting" },
  { name: "Web Crawler",    icon: "🕷",  desc: "Link & form enumeration" },
  { name: "Exposure Check", icon: "🗂",  desc: ".git, .env, backup detection" },
  { name: "WAF Detection",  icon: "🔥", desc: "Firewall presence analysis" },
  { name: "Cert Transparency", icon: "📜", desc: "CT log subdomain discovery" },
  { name: "HSTS Preload",   icon: "⚡", desc: "Strict-Transport-Security" },
  { name: "Open Redirect",  icon: "↩️", desc: "Redirect chain analysis" },
  { name: "API Spec",       icon: "📡", desc: "OpenAPI/Swagger endpoint scan" },
  { name: "Port Scanner",   icon: "🔍", desc: "Common port reachability" },
  { name: "Cookie Security",icon: "🍪", desc: "Secure/HttpOnly/SameSite flags" },
  { name: "Deep JS",        icon: "🧠", desc: "JS secret & endpoint extraction" },
  { name: "Subdomain Takeover", icon: "🎯", desc: "Dangling DNS record detection" },
];

/* ─── Pricing plans ──────────────────────────────────────────────────────── */
const PLANS = [
  {
    name: "Free",
    price: "€0",
    period: "",
    scans: "5 scans / month",
    users: "1 user",
    features: ["All 17 scanning tools", "HTML report", "Email notifications"],
    missing:  ["API access", "CI/CD integration", "PDF reports", "Hebrew/compliance"],
    cta: "Start Free",
    highlight: false,
  },
  {
    name: "Starter",
    price: "€20",
    period: "/mo",
    scans: "50 scans / month",
    users: "3 users",
    features: ["All 17 tools", "API access", "CI/CD GitHub Action", "CVE intel feed", "Scan history"],
    missing:  ["PT mode", "PDF CISO reports", "Hebrew compliance"],
    cta: "Get Started",
    highlight: false,
  },
  {
    name: "Pro",
    price: "€50",
    period: "/mo",
    scans: "200 scans / month",
    users: "10 users",
    features: ["All 17 tools", "API access", "CI/CD GitHub Action", "PT mode", "PDF CISO reports", "Israeli compliance", "Hebrew reports", "SARIF export"],
    missing:  ["SSO", "Dedicated support", "SLA"],
    cta: "Get Started",
    highlight: true,
  },
  {
    name: "Enterprise",
    price: "Custom",
    period: "",
    scans: "Unlimited scans",
    users: "Unlimited users",
    features: ["Everything in Pro", "SSO / SAML", "On-premise option", "Dedicated support", "SLA 99.9%", "Custom compliance frameworks"],
    missing:  [],
    cta: "Contact Us",
    highlight: false,
  },
];

const STATS = [
  { label: "Scanning Tools",        value: "17" },
  { label: "CVSS 3.1 Scoring",      value: "✓" },
  { label: "AI Pipeline Stages",    value: "3" },
  { label: "Tests Passing",         value: "131+" },
  { label: "SARIF Export",          value: "✓" },
  { label: "OWASP Top 10",          value: "2025" },
  { label: "Compliance Frameworks", value: "5" },
  { label: "Languages",             value: "EN + HE" },
];

const DIFFERENTIATORS = [
  {
    icon: "🤖",
    title: "AI Remediation",
    body: "Other scanners tell you what's wrong. We give you the code to fix it — before and after, ready to paste into your codebase.",
  },
  {
    icon: "🔗",
    title: "Attack Path Simulation",
    body: "See how individual findings combine into exploitable chains. Not just a list of issues — a story of how an attacker would use them together.",
  },
  {
    icon: "🇮🇱",
    title: "Israeli Compliance",
    body: "Built-in mapping to Amendment 13 (Privacy Protection Law). Hebrew reports. RTL support. No other international scanner offers this.",
  },
  {
    icon: "📊",
    title: "CISO-Grade Reports",
    body: "PDF reports with risk gauges, CVSS tables, compliance matrices, and trend tracking. Ready for board presentations.",
  },
];

/* ─── Hero mock result component ─────────────────────────────────────────── */
function HeroMockResult() {
  return (
    <div style={{
      background: "rgba(8,12,24,0.85)",
      border: "1px solid rgba(34,211,238,0.15)",
      borderRadius: "16px",
      padding: "20px 24px",
      backdropFilter: "blur(12px)",
      maxWidth: "560px",
      margin: "0 auto",
      boxShadow: "0 0 60px rgba(34,211,238,0.08)",
    }}>
      <div style={{ display: "flex", alignItems: "center", gap: "20px", marginBottom: "16px" }}>
        {/* Score ring */}
        <div style={{ position: "relative", flexShrink: 0 }}>
          <svg width="80" height="80" viewBox="0 0 80 80">
            <circle cx="40" cy="40" r="33" fill="none" stroke="#1a2236" strokeWidth="7"/>
            <circle cx="40" cy="40" r="33" fill="none" stroke="#22d3ee" strokeWidth="7"
              strokeLinecap="round" strokeDasharray="184 207"
              transform="rotate(-90 40 40)" opacity="0.9"/>
          </svg>
          <div style={{ position: "absolute", inset: 0, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center" }}>
            <div style={{ color: "#22d3ee", fontWeight: 900, fontSize: "1.3rem", fontFamily: "JetBrains Mono, monospace", lineHeight: 1 }}>85</div>
            <div style={{ color: "#64748b", fontSize: "0.6rem", letterSpacing: "0.08em" }}>SCORE</div>
          </div>
        </div>
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "4px" }}>
            <div style={{
              width: "34px", height: "34px", borderRadius: "50%",
              border: "2px solid #3b82f6", background: "rgba(59,130,246,0.12)",
              display: "flex", alignItems: "center", justifyContent: "center",
              color: "#3b82f6", fontWeight: 900, fontSize: "1rem",
              fontFamily: "JetBrains Mono, monospace",
            }}>B</div>
            <div>
              <div style={{ color: "#f1f5f9", fontWeight: 700, fontSize: "0.9rem" }}>Good security posture</div>
              <div style={{ color: "#64748b", fontSize: "0.72rem", fontFamily: "JetBrains Mono, monospace" }}>example.com · 17/17 tools · 34s</div>
            </div>
          </div>
        </div>
      </div>
      {/* Mini tool results */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: "6px" }}>
        {[
          { n: "SSL", s: 95, ok: true },
          { n: "Headers", s: 70, ok: false },
          { n: "DNS", s: 88, ok: true },
          { n: "CORS", s: 90, ok: true },
          { n: "Exposure", s: 100, ok: true },
          { n: "Cookies", s: 60, ok: false },
          { n: "Tech Stack", s: 82, ok: true },
          { n: "WAF", s: 75, ok: true },
        ].map((t) => (
          <div key={t.n} style={{
            background: "#0a0f1e",
            border: `1px solid ${t.ok ? "rgba(34,211,238,0.1)" : "rgba(239,68,68,0.15)"}`,
            borderRadius: "8px",
            padding: "7px 8px",
          }}>
            <div style={{ color: t.ok ? "#22d3ee" : "#ef4444", fontSize: "0.62rem", fontFamily: "JetBrains Mono, monospace", fontWeight: 700 }}>
              {t.ok ? "✓" : "⚠"} {t.n}
            </div>
            <div style={{ color: t.ok ? "#94a3b8" : "#f87171", fontSize: "0.7rem", fontWeight: 800, fontFamily: "JetBrains Mono, monospace" }}>{t.s}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ─── Section wrapper ─────────────────────────────────────────────────────── */
function Section({ children, id, style }: { children: React.ReactNode; id?: string; style?: React.CSSProperties }) {
  return (
    <section
      id={id}
      style={{
        padding: "80px 24px",
        maxWidth: "1100px",
        margin: "0 auto",
        ...style,
      }}
    >
      {children}
    </section>
  );
}

/* ─── Main landing page ───────────────────────────────────────────────────── */
export default function LandingPage() {
  const router = useRouter();
  const [heroUrl, setHeroUrl] = useState("");
  const [scrolled, setScrolled] = useState(false);
  const heroRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 40);
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  const handleFreeScan = () => {
    const url = heroUrl.trim();
    if (!url) { heroRef.current?.focus(); return; }
    router.push(`/dashboard?url=${encodeURIComponent(url)}`);
  };

  return (
    <div style={{ background: "linear-gradient(180deg, #0a0f1e 0%, #0d1117 100%)", minHeight: "100vh", color: "#e2e8f0" }}>

      {/* ── Top nav ──────────────────────────────────────────────────────── */}
      <nav style={{
        position: "sticky",
        top: 0,
        zIndex: 100,
        padding: "0 24px",
        height: "60px",
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        background: scrolled ? "rgba(10,15,30,0.92)" : "transparent",
        backdropFilter: scrolled ? "blur(12px)" : "none",
        borderBottom: scrolled ? "1px solid rgba(30,41,59,0.7)" : "none",
        transition: "all 200ms ease",
      }}>
        <span style={{ fontWeight: 800, fontSize: "1rem", color: "#f1f5f9", letterSpacing: "0.02em" }}>
          <span style={{ color: "#22d3ee" }}>AI</span> Cyber Shield
        </span>
        <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
          <a href="#pricing" style={{ color: "#94a3b8", fontSize: "0.85rem", textDecoration: "none", padding: "6px 12px" }}>Pricing</a>
          <a href="#tools" style={{ color: "#94a3b8", fontSize: "0.85rem", textDecoration: "none", padding: "6px 12px" }}>Tools</a>
          <button
            onClick={() => router.push("/dashboard")}
            style={{
              padding: "7px 18px",
              borderRadius: "8px",
              background: "rgba(34,211,238,0.1)",
              border: "1px solid rgba(34,211,238,0.25)",
              color: "#22d3ee",
              fontSize: "0.82rem",
              fontWeight: 700,
              cursor: "pointer",
              transition: "all 150ms ease",
            }}
            onMouseEnter={(e) => { e.currentTarget.style.background = "rgba(34,211,238,0.18)"; }}
            onMouseLeave={(e) => { e.currentTarget.style.background = "rgba(34,211,238,0.1)"; }}
          >
            Dashboard →
          </button>
        </div>
      </nav>

      {/* ── SECTION 1: Hero ──────────────────────────────────────────────── */}
      <section style={{ padding: "100px 24px 80px", maxWidth: "1100px", margin: "0 auto", textAlign: "center" }}>

        {/* Badge */}
        <div style={{
          display: "inline-flex",
          alignItems: "center",
          gap: "8px",
          padding: "5px 14px",
          borderRadius: "999px",
          background: "rgba(34,211,238,0.06)",
          border: "1px solid rgba(34,211,238,0.2)",
          color: "#22d3ee",
          fontSize: "0.75rem",
          fontWeight: 700,
          fontFamily: "JetBrains Mono, monospace",
          letterSpacing: "0.08em",
          marginBottom: "28px",
        }}>
          🛡 17 SECURITY TOOLS · AI-POWERED · REAL REMEDIATION CODE
        </div>

        <h1 style={{
          fontSize: "clamp(2rem, 5vw, 3.6rem)",
          fontWeight: 800,
          lineHeight: 1.1,
          color: "#f1f5f9",
          margin: "0 0 20px",
          letterSpacing: "-0.02em",
        }}>
          Know your security score<br />
          <span style={{
            background: "linear-gradient(90deg, #22d3ee, #6366f1)",
            WebkitBackgroundClip: "text",
            WebkitTextFillColor: "transparent",
          }}>in 60 seconds.</span>
        </h1>

        <p style={{ color: "#94a3b8", fontSize: "1.05rem", lineHeight: 1.7, margin: "0 0 40px", maxWidth: "600px", marginInline: "auto" }}>
          17 security tools. AI-powered analysis. Real remediation code.
          <br />No agent to install. No setup required.
        </p>

        {/* Hero scan input */}
        <div style={{
          display: "flex",
          gap: "10px",
          maxWidth: "580px",
          margin: "0 auto 14px",
          flexWrap: "wrap",
          justifyContent: "center",
        }}>
          <input
            ref={heroRef}
            type="url"
            value={heroUrl}
            onChange={(e) => setHeroUrl(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleFreeScan()}
            placeholder="https://yoursite.com"
            style={{
              flex: 1,
              minWidth: "240px",
              padding: "13px 16px",
              background: "rgba(8,12,24,0.9)",
              border: "1px solid rgba(34,211,238,0.2)",
              borderRadius: "10px",
              color: "#f1f5f9",
              fontSize: "1rem",
              fontFamily: "JetBrains Mono, monospace",
              outline: "none",
              boxShadow: "0 0 0 0 rgba(34,211,238,0)",
              transition: "border-color 150ms, box-shadow 150ms",
            }}
            onFocus={(e) => {
              e.target.style.borderColor = "rgba(34,211,238,0.5)";
              e.target.style.boxShadow = "0 0 0 3px rgba(34,211,238,0.08)";
            }}
            onBlur={(e) => {
              e.target.style.borderColor = "rgba(34,211,238,0.2)";
              e.target.style.boxShadow = "none";
            }}
          />
          <button
            onClick={handleFreeScan}
            style={{
              padding: "13px 28px",
              borderRadius: "10px",
              background: "linear-gradient(135deg, #22d3ee, #0891b2)",
              color: "#000d1a",
              fontWeight: 800,
              fontSize: "0.95rem",
              border: "none",
              cursor: "pointer",
              boxShadow: "0 0 24px rgba(34,211,238,0.3)",
              transition: "all 200ms ease",
              whiteSpace: "nowrap",
            }}
            onMouseEnter={(e) => { e.currentTarget.style.transform = "translateY(-2px)"; e.currentTarget.style.boxShadow = "0 8px 32px rgba(34,211,238,0.45)"; }}
            onMouseLeave={(e) => { e.currentTarget.style.transform = ""; e.currentTarget.style.boxShadow = "0 0 24px rgba(34,211,238,0.3)"; }}
          >
            Free Scan →
          </button>
        </div>
        <div style={{ color: "#64748b", fontSize: "0.8rem" }}>No signup required for your first scan.</div>

        {/* Hero mock result */}
        <div style={{ marginTop: "56px" }}>
          <HeroMockResult />
        </div>
      </section>

      {/* ── SECTION 2: How it works ───────────────────────────────────────── */}
      <Section style={{ textAlign: "center" }}>
        <h2 style={{ fontSize: "2rem", fontWeight: 800, color: "#f1f5f9", marginBottom: "12px" }}>How it works</h2>
        <p style={{ color: "#64748b", marginBottom: "56px" }}>Three steps from URL to security roadmap.</p>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", gap: "20px" }}>
          {[
            {
              num: "1",
              title: "Enter your URL",
              body: "Paste any public URL. We scan it from the outside — nothing installed on your server.",
            },
            {
              num: "2",
              title: "17 tools analyze your security",
              body: "SSL, headers, DNS, CORS, cookies, exposed files, WAF detection, and 10 more — all in parallel, in under 90 seconds.",
            },
            {
              num: "3",
              title: "Get your score + AI remediation plan",
              body: "A letter grade (A–F), prioritized findings with CVSS scores, and actual code patches to fix each issue.",
            },
          ].map((step) => (
            <div key={step.num} style={{
              background: "rgba(12,17,32,0.7)",
              border: "1px solid #1a2236",
              borderRadius: "14px",
              padding: "28px 24px",
              textAlign: "start",
              position: "relative",
              overflow: "hidden",
            }}>
              <div style={{
                position: "absolute",
                top: "16px",
                right: "16px",
                fontFamily: "JetBrains Mono, monospace",
                fontSize: "3rem",
                fontWeight: 900,
                color: "rgba(34,211,238,0.06)",
                lineHeight: 1,
              }}>
                {step.num}
              </div>
              <div style={{
                width: "36px", height: "36px",
                borderRadius: "9px",
                background: "rgba(34,211,238,0.1)",
                border: "1px solid rgba(34,211,238,0.2)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                fontFamily: "JetBrains Mono, monospace",
                fontWeight: 900,
                color: "#22d3ee",
                fontSize: "1rem",
                marginBottom: "16px",
              }}>
                {step.num}
              </div>
              <h3 style={{ color: "#f1f5f9", fontSize: "1.05rem", fontWeight: 700, margin: "0 0 10px" }}>{step.title}</h3>
              <p style={{ color: "#64748b", fontSize: "0.88rem", lineHeight: 1.65, margin: 0 }}>{step.body}</p>
            </div>
          ))}
        </div>
      </Section>

      {/* ── SECTION 3: 17 tools grid ──────────────────────────────────────── */}
      <Section id="tools" style={{ textAlign: "center" }}>
        <h2 style={{ fontSize: "2rem", fontWeight: 800, color: "#f1f5f9", marginBottom: "12px" }}>
          17 security categories, one scan
        </h2>
        <p style={{ color: "#64748b", marginBottom: "48px" }}>Every dimension of your site's attack surface, covered automatically.</p>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(150px, 1fr))", gap: "8px" }}>
          {TOOLS.map((tool) => (
            <div
              key={tool.name}
              style={{
                background: "rgba(12,17,32,0.7)",
                border: "1px solid #1a2236",
                borderRadius: "10px",
                padding: "16px 12px",
                textAlign: "center",
                cursor: "default",
                transition: "all 150ms ease",
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.borderColor = "rgba(34,211,238,0.2)";
                e.currentTarget.style.background = "rgba(16,22,40,0.9)";
                e.currentTarget.style.transform = "translateY(-2px)";
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.borderColor = "#1a2236";
                e.currentTarget.style.background = "rgba(12,17,32,0.7)";
                e.currentTarget.style.transform = "";
              }}
            >
              <div style={{ fontSize: "1.4rem", marginBottom: "6px" }}>{tool.icon}</div>
              <div style={{ color: "#e2e8f0", fontSize: "0.78rem", fontWeight: 600, marginBottom: "4px" }}>{tool.name}</div>
              <div style={{ color: "#64748b", fontSize: "0.65rem", lineHeight: 1.4 }}>{tool.desc}</div>
            </div>
          ))}
        </div>
      </Section>

      {/* ── SECTION 4: Differentiators ────────────────────────────────────── */}
      <Section style={{ textAlign: "center" }}>
        <h2 style={{ fontSize: "2rem", fontWeight: 800, color: "#f1f5f9", marginBottom: "12px" }}>Not just another scanner</h2>
        <p style={{ color: "#64748b", marginBottom: "48px" }}>Features designed for teams who actually fix things.</p>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))", gap: "16px" }}>
          {DIFFERENTIATORS.map((d) => (
            <div key={d.title} style={{
              background: "rgba(12,17,32,0.7)",
              border: "1px solid #1a2236",
              borderRadius: "14px",
              padding: "28px 24px",
              textAlign: "start",
            }}>
              <div style={{ fontSize: "2rem", marginBottom: "14px" }}>{d.icon}</div>
              <h3 style={{ color: "#f1f5f9", fontSize: "1rem", fontWeight: 700, margin: "0 0 10px" }}>{d.title}</h3>
              <p style={{ color: "#64748b", fontSize: "0.85rem", lineHeight: 1.65, margin: 0 }}>{d.body}</p>
            </div>
          ))}
        </div>
      </Section>

      {/* ── SECTION 5: Pricing ────────────────────────────────────────────── */}
      <Section id="pricing" style={{ textAlign: "center" }}>
        <h2 style={{ fontSize: "2rem", fontWeight: 800, color: "#f1f5f9", marginBottom: "12px" }}>Pricing</h2>
        <p style={{ color: "#64748b", marginBottom: "48px" }}>Start free. Scale as you grow.</p>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: "12px" }}>
          {PLANS.map((plan) => (
            <div key={plan.name} style={{
              background: plan.highlight ? "rgba(16,22,46,0.95)" : "rgba(12,17,32,0.7)",
              border: `1px solid ${plan.highlight ? "rgba(34,211,238,0.3)" : "#1a2236"}`,
              borderRadius: "16px",
              padding: "28px 20px",
              position: "relative",
              boxShadow: plan.highlight ? "0 0 40px rgba(34,211,238,0.08)" : "none",
              textAlign: "start",
            }}>
              {plan.highlight && (
                <div style={{
                  position: "absolute",
                  top: "-1px",
                  left: "50%",
                  transform: "translateX(-50%)",
                  background: "linear-gradient(135deg, #22d3ee, #0891b2)",
                  color: "#000d1a",
                  fontSize: "0.65rem",
                  fontWeight: 800,
                  padding: "3px 12px",
                  borderRadius: "0 0 8px 8px",
                  letterSpacing: "0.1em",
                }}>
                  RECOMMENDED
                </div>
              )}
              <div style={{ color: plan.highlight ? "#22d3ee" : "#94a3b8", fontWeight: 700, fontSize: "0.9rem", marginBottom: "8px" }}>{plan.name}</div>
              <div style={{ marginBottom: "4px" }}>
                <span style={{ color: "#f1f5f9", fontSize: "2rem", fontWeight: 900, fontFamily: "JetBrains Mono, monospace" }}>{plan.price}</span>
                <span style={{ color: "#64748b", fontSize: "0.85rem" }}>{plan.period}</span>
              </div>
              <div style={{ color: "#64748b", fontSize: "0.75rem", marginBottom: "20px", fontFamily: "JetBrains Mono, monospace" }}>
                {plan.scans} · {plan.users}
              </div>
              <div style={{ marginBottom: "20px" }}>
                {plan.features.map((f) => (
                  <div key={f} style={{ display: "flex", alignItems: "center", gap: "8px", color: "#94a3b8", fontSize: "0.8rem", padding: "4px 0" }}>
                    <span style={{ color: "#22c55e", flexShrink: 0 }}>✓</span> {f}
                  </div>
                ))}
                {plan.missing.map((f) => (
                  <div key={f} style={{ display: "flex", alignItems: "center", gap: "8px", color: "#374151", fontSize: "0.8rem", padding: "4px 0" }}>
                    <span style={{ flexShrink: 0 }}>✗</span> {f}
                  </div>
                ))}
              </div>
              <button
                onClick={() => router.push("/dashboard")}
                style={{
                  width: "100%",
                  padding: "10px",
                  borderRadius: "8px",
                  background: plan.highlight ? "linear-gradient(135deg, #22d3ee, #0891b2)" : "transparent",
                  border: plan.highlight ? "none" : "1px solid #1a2236",
                  color: plan.highlight ? "#000d1a" : "#94a3b8",
                  fontWeight: 700,
                  fontSize: "0.85rem",
                  cursor: "pointer",
                  transition: "all 150ms ease",
                }}
                onMouseEnter={(e) => {
                  if (!plan.highlight) { e.currentTarget.style.borderColor = "rgba(34,211,238,0.2)"; e.currentTarget.style.color = "#22d3ee"; }
                }}
                onMouseLeave={(e) => {
                  if (!plan.highlight) { e.currentTarget.style.borderColor = "#1a2236"; e.currentTarget.style.color = "#94a3b8"; }
                }}
              >
                {plan.cta}
              </button>
            </div>
          ))}
        </div>
      </Section>

      {/* ── SECTION 6: Stats ─────────────────────────────────────────────── */}
      <Section style={{ textAlign: "center" }}>
        <h2 style={{ fontSize: "2rem", fontWeight: 800, color: "#f1f5f9", marginBottom: "40px" }}>Built for real security</h2>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(180px, 1fr))", gap: "12px" }}>
          {STATS.map((s) => (
            <div key={s.label} style={{
              background: "rgba(12,17,32,0.7)",
              border: "1px solid #1a2236",
              borderRadius: "12px",
              padding: "20px",
              display: "flex",
              flexDirection: "column",
              alignItems: "center",
              gap: "6px",
            }}>
              <div style={{ color: "#22d3ee", fontFamily: "JetBrains Mono, monospace", fontWeight: 900, fontSize: "1.5rem" }}>{s.value}</div>
              <div style={{ color: "#64748b", fontSize: "0.78rem" }}>{s.label}</div>
            </div>
          ))}
        </div>
      </Section>

      {/* ── SECTION 7: CTA ───────────────────────────────────────────────── */}
      <Section style={{ textAlign: "center", padding: "60px 24px 80px" }}>
        <h2 style={{ fontSize: "2rem", fontWeight: 800, color: "#f1f5f9", marginBottom: "12px" }}>
          Ready to know your security score?
        </h2>
        <p style={{ color: "#64748b", marginBottom: "32px" }}>Your first scan is free. No credit card required.</p>
        <div style={{ display: "flex", gap: "10px", justifyContent: "center", flexWrap: "wrap" }}>
          <input
            type="url"
            placeholder="https://yoursite.com"
            onChange={(e) => setHeroUrl(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleFreeScan()}
            style={{
              padding: "12px 16px",
              background: "rgba(8,12,24,0.9)",
              border: "1px solid rgba(34,211,238,0.2)",
              borderRadius: "10px",
              color: "#f1f5f9",
              fontSize: "0.95rem",
              fontFamily: "JetBrains Mono, monospace",
              outline: "none",
              width: "280px",
            }}
          />
          <button
            onClick={handleFreeScan}
            style={{
              padding: "12px 28px",
              borderRadius: "10px",
              background: "linear-gradient(135deg, #22d3ee, #0891b2)",
              color: "#000d1a",
              fontWeight: 800,
              fontSize: "0.95rem",
              border: "none",
              cursor: "pointer",
              boxShadow: "0 0 24px rgba(34,211,238,0.3)",
            }}
          >
            Scan Now — Free
          </button>
        </div>
      </Section>

      {/* ── Footer ───────────────────────────────────────────────────────── */}
      <footer style={{
        borderTop: "1px solid #1a2236",
        padding: "40px 24px",
      }}>
        <div style={{ maxWidth: "1100px", margin: "0 auto", display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))", gap: "32px" }}>
          <div>
            <div style={{ fontWeight: 800, color: "#f1f5f9", marginBottom: "10px" }}>
              <span style={{ color: "#22d3ee" }}>AI</span> Cyber Shield
            </div>
            <div style={{ color: "#64748b", fontSize: "0.8rem", lineHeight: 1.6 }}>
              Security scanning platform.<br />17 tools. AI analysis. Real fixes.
            </div>
            <div style={{ color: "#374151", fontSize: "0.72rem", marginTop: "12px" }}>© 2026 AI Cyber Shield</div>
          </div>
          <div>
            <div style={{ color: "#94a3b8", fontWeight: 700, fontSize: "0.8rem", marginBottom: "10px", textTransform: "uppercase", letterSpacing: "0.1em" }}>Product</div>
            {["Features", "Pricing", "API Docs", "GitHub"].map((l) => (
              <div key={l} style={{ color: "#64748b", fontSize: "0.82rem", padding: "4px 0", cursor: "pointer" }}
                onMouseEnter={(e) => { (e.target as HTMLElement).style.color = "#94a3b8"; }}
                onMouseLeave={(e) => { (e.target as HTMLElement).style.color = "#64748b"; }}
              >{l}</div>
            ))}
          </div>
          <div>
            <div style={{ color: "#94a3b8", fontWeight: 700, fontSize: "0.8rem", marginBottom: "10px", textTransform: "uppercase", letterSpacing: "0.1em" }}>Legal</div>
            {["Terms", "Privacy", "GDPR", "Contact"].map((l) => (
              <div key={l} style={{ color: "#64748b", fontSize: "0.82rem", padding: "4px 0", cursor: "pointer" }}
                onMouseEnter={(e) => { (e.target as HTMLElement).style.color = "#94a3b8"; }}
                onMouseLeave={(e) => { (e.target as HTMLElement).style.color = "#64748b"; }}
              >{l}</div>
            ))}
          </div>
        </div>
      </footer>
    </div>
  );
}
