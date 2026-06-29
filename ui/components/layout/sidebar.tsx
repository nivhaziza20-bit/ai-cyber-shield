"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useLang } from "@/contexts/language-context";
import type { TranslationKey } from "@/lib/i18n";

interface NavItem {
  href:  string;
  icon:  React.ReactNode;
  label: TranslationKey;
  badge?: string;
}

function ShieldIcon() {
  return (
    <svg width="28" height="32" viewBox="0 0 28 32" fill="none" aria-hidden="true"
         style={{ filter: "drop-shadow(0 0 14px rgba(34,211,238,0.65))", flexShrink: 0 }}>
      <path d="M14 1.5L2 6.5V15.5C2 23.2 7.4 30.1 14 32C20.6 30.1 26 23.2 26 15.5V6.5L14 1.5Z"
            fill="#090d1a" stroke="#22d3ee" strokeWidth="1.3"/>
      <path d="M9 16l4 4 7-7" stroke="#22d3ee" strokeWidth="1.9"
            strokeLinecap="round" strokeLinejoin="round"/>
    </svg>
  );
}

function LiveDot() {
  return (
    <span style={{ position: "relative", display: "inline-flex", width: "7px", height: "7px" }}>
      <span style={{
        position: "absolute", inset: 0, borderRadius: "50%",
        background: "#10b981",
        animation: "pingDot 1.8s ease-in-out infinite",
        opacity: 0.6,
      }} />
      <span style={{
        position: "relative", width: "7px", height: "7px",
        borderRadius: "50%", background: "#10b981",
        boxShadow: "0 0 6px #10b981",
      }} />
      <style>{`
        @keyframes pingDot {
          0%,100% { transform: scale(1); opacity: 0.6; }
          50% { transform: scale(2.2); opacity: 0; }
        }
      `}</style>
    </span>
  );
}

const NAV_ITEMS: { group: TranslationKey | null; groupPrefix?: string; items: NavItem[] }[] = [
  {
    group: null,
    items: [
      {
        href: "/dashboard",
        label: "nav_dashboard",
        icon: (
          <svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true">
            <rect x="1" y="1" width="6" height="6" rx="1.2" stroke="currentColor" strokeWidth="1.4"/>
            <rect x="9" y="1" width="6" height="6" rx="1.2" stroke="currentColor" strokeWidth="1.4"/>
            <rect x="1" y="9" width="6" height="6" rx="1.2" stroke="currentColor" strokeWidth="1.4"/>
            <rect x="9" y="9" width="6" height="6" rx="1.2" stroke="currentColor" strokeWidth="1.4"/>
          </svg>
        ),
      },
      {
        href: "/dashboard/history",
        label: "nav_history",
        icon: (
          <svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true">
            <circle cx="8" cy="8" r="6.5" stroke="currentColor" strokeWidth="1.4"/>
            <path d="M8 4.5V8L10.5 10" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round"/>
          </svg>
        ),
      },
      {
        href: "/dashboard/scheduled",
        label: "nav_scheduled",
        icon: (
          <svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true">
            <rect x="2" y="2.5" width="12" height="12" rx="2" stroke="currentColor" strokeWidth="1.4"/>
            <path d="M5 1v3M11 1v3" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round"/>
            <path d="M2 6.5h12" stroke="currentColor" strokeWidth="1.4"/>
          </svg>
        ),
      },
    ],
  },
  {
    group: "nav_compliance",
    groupPrefix: "//",
    items: [
      {
        href: "/dashboard/compliance",
        label: "nav_compliance",
        badge: "NEW",
        icon: (
          <svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true">
            <path d="M8 1L2 3.5V8C2 11.7 4.7 15 8 16C11.3 15 14 11.7 14 8V3.5L8 1Z"
                  stroke="currentColor" strokeWidth="1.4" strokeLinejoin="round"/>
            <path d="M5.5 8l2 2 4-4" stroke="currentColor" strokeWidth="1.4"
                  strokeLinecap="round" strokeLinejoin="round"/>
          </svg>
        ),
      },
    ],
  },
  {
    group: "nav_settings",
    groupPrefix: "//",
    items: [
      {
        href: "/dashboard/settings",
        label: "nav_settings",
        icon: (
          <svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true">
            <circle cx="8" cy="8" r="2.5" stroke="currentColor" strokeWidth="1.4"/>
            <path d="M8 1.5v2M8 12.5v2M1.5 8h2M12.5 8h2M3.6 3.6l1.4 1.4M11 11l1.4 1.4M3.6 12.4l1.4-1.4M11 5l1.4-1.4"
                  stroke="currentColor" strokeWidth="1.4" strokeLinecap="round"/>
          </svg>
        ),
      },
    ],
  },
];

export function Sidebar() {
  const { t, toggle, lang, isRTL } = useLang();
  const pathname = usePathname();

  const isActive = (href: string) =>
    href === "/dashboard" ? pathname === "/dashboard" : pathname.startsWith(href);

  return (
    <aside
      style={{
        width: "224px",
        flexShrink: 0,
        background: "linear-gradient(180deg, rgba(8,11,22,0.98) 0%, rgba(6,9,18,0.98) 100%)",
        borderRight: isRTL ? "none" : "1px solid rgba(34,211,238,0.08)",
        borderLeft:  isRTL ? "1px solid rgba(34,211,238,0.08)" : "none",
        backdropFilter: "blur(24px)",
        WebkitBackdropFilter: "blur(24px)",
        display: "flex",
        flexDirection: "column",
        height: "100dvh",
        position: "sticky",
        top: 0,
        overflowY: "auto",
        boxShadow: isRTL
          ? "-4px 0 40px rgba(0,0,0,0.4)"
          : "4px 0 40px rgba(0,0,0,0.4)",
      }}
    >
      {/* ── Logo area ─────────────────────────────────────────────── */}
      <div style={{
        padding: "20px 16px 18px",
        borderBottom: "1px solid rgba(255,255,255,0.04)",
        display: "flex",
        alignItems: "center",
        gap: "12px",
        position: "relative",
      }}>
        {/* Ambient glow behind logo */}
        <div style={{
          position: "absolute",
          top: 0, left: 0,
          width: "100%", height: "100%",
          background: "radial-gradient(ellipse 140px 60px at 30px 30px, rgba(34,211,238,0.06) 0%, transparent 70%)",
          pointerEvents: "none",
        }} />
        <ShieldIcon />
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{
            fontFamily: "var(--font-jetbrains, JetBrains Mono, monospace)",
            fontSize: "0.88rem",
            fontWeight: 900,
            letterSpacing: "-0.02em",
            lineHeight: 1.15,
          }}>
            <span style={{ color: "#f1f5f9" }}>AI CYBER </span>
            <span className="text-gradient-cyber">SHIELD</span>
          </div>
          <div style={{
            fontSize: "0.58rem",
            color: "#5a7084",
            letterSpacing: "0.14em",
            textTransform: "uppercase",
            fontFamily: "var(--font-jetbrains, monospace)",
            marginTop: "4px",
          }}>
            {t("sidebar_tools")}
          </div>
        </div>
        {/* Live indicator */}
        <LiveDot />
      </div>

      {/* ── Navigation ──────────────────────────────────────────────── */}
      <nav style={{ flex: 1, padding: "10px 8px", overflowY: "auto" }}>
        {NAV_ITEMS.map((group, gi) => (
          <div key={gi} style={{ marginBottom: "4px" }}>
            {group.group && (
              <div style={{
                display: "flex",
                alignItems: "center",
                gap: "6px",
                fontSize: "0.56rem",
                fontWeight: 700,
                color: "#374151",
                textTransform: "uppercase",
                letterSpacing: "0.2em",
                padding: "10px 10px 5px",
                fontFamily: "var(--font-jetbrains, monospace)",
              }}>
                <span style={{ color: "#22d3ee44", fontWeight: 900 }}>
                  {group.groupPrefix ?? "//"}
                </span>
                <span>{t(group.group as TranslationKey)}</span>
                <span style={{
                  flex: 1, height: "1px",
                  background: "linear-gradient(90deg, #1a2236 0%, transparent 100%)",
                }} />
              </div>
            )}
            {group.items.map((item) => {
              const active = isActive(item.href);
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "10px",
                    padding: "8px 10px",
                    borderRadius: "9px",
                    marginBottom: "2px",
                    color: active ? "#22d3ee" : "#64748b",
                    background: active
                      ? "linear-gradient(90deg, rgba(34,211,238,0.10) 0%, rgba(34,211,238,0.04) 100%)"
                      : "transparent",
                    borderLeft: (!isRTL && active)
                      ? "2px solid #22d3ee"
                      : (!isRTL ? "2px solid transparent" : "none"),
                    borderRight: (isRTL && active)
                      ? "2px solid #22d3ee"
                      : (isRTL ? "2px solid transparent" : "none"),
                    fontWeight: active ? 600 : 400,
                    fontSize: "0.84rem",
                    textDecoration: "none",
                    transition: "all 140ms ease",
                    boxShadow: active
                      ? "inset 0 0 20px rgba(34,211,238,0.05)"
                      : "none",
                  }}
                  onMouseEnter={(e) => {
                    if (!active) {
                      e.currentTarget.style.color = "#94a3b8";
                      e.currentTarget.style.background = "rgba(34,211,238,0.04)";
                    }
                  }}
                  onMouseLeave={(e) => {
                    if (!active) {
                      e.currentTarget.style.color = "#64748b";
                      e.currentTarget.style.background = "transparent";
                    }
                  }}
                >
                  <span style={{
                    flexShrink: 0,
                    opacity: active ? 1 : 0.55,
                    filter: active ? `drop-shadow(0 0 4px #22d3ee66)` : "none",
                    transition: "all 140ms ease",
                  }}>
                    {item.icon}
                  </span>
                  <span style={{ flex: 1, letterSpacing: active ? "0" : "0" }}>
                    {t(item.label)}
                  </span>
                  {item.badge && (
                    <span style={{
                      fontSize: "0.50rem",
                      fontWeight: 800,
                      color: "#22d3ee",
                      background: "rgba(34,211,238,0.10)",
                      border: "1px solid rgba(34,211,238,0.28)",
                      borderRadius: "4px",
                      padding: "1px 5px",
                      fontFamily: "var(--font-jetbrains, monospace)",
                      letterSpacing: "0.08em",
                      animation: "badgePulse 2s ease-in-out infinite",
                    }}>
                      {item.badge}
                    </span>
                  )}
                </Link>
              );
            })}
          </div>
        ))}
      </nav>

      {/* ── Footer ──────────────────────────────────────────────────── */}
      <div style={{
        padding: "12px 12px 14px",
        borderTop: "1px solid rgba(255,255,255,0.04)",
        display: "flex",
        flexDirection: "column",
        gap: "8px",
      }}>
        {/* Language toggle */}
        <button
          onClick={toggle}
          style={{
            display: "flex",
            alignItems: "center",
            gap: "8px",
            padding: "7px 10px",
            borderRadius: "8px",
            background: "rgba(34,211,238,0.03)",
            border: "1px solid rgba(255,255,255,0.06)",
            color: "#64748b",
            fontSize: "0.78rem",
            fontWeight: 600,
            cursor: "pointer",
            transition: "all 140ms ease",
            width: "100%",
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.borderColor = "rgba(34,211,238,0.25)";
            e.currentTarget.style.color = "#22d3ee";
            e.currentTarget.style.background = "rgba(34,211,238,0.06)";
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.borderColor = "rgba(255,255,255,0.06)";
            e.currentTarget.style.color = "#64748b";
            e.currentTarget.style.background = "rgba(34,211,238,0.03)";
          }}
        >
          <span style={{ fontSize: "0.85rem" }}>{lang === "he" ? "🇺🇸" : "🇮🇱"}</span>
          <span>{t("toggle_lang")}</span>
        </button>

        {/* Terminal version prompt */}
        <div style={{
          fontSize: "0.57rem",
          color: "#374151",
          fontFamily: "var(--font-jetbrains, monospace)",
          letterSpacing: "0.06em",
          textAlign: isRTL ? "right" : "left",
          padding: "2px 4px",
        }}>
          <span style={{ color: "#22d3ee33" }}>$ </span>
          aics --version 6.0 --mode defensive
        </div>
      </div>

      <style>{`
        @keyframes badgePulse {
          0%,100% { box-shadow: 0 0 0 0 rgba(34,211,238,0.3); }
          50% { box-shadow: 0 0 0 3px rgba(34,211,238,0); }
        }
      `}</style>
    </aside>
  );
}
