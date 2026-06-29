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
         style={{ filter: "drop-shadow(0 0 10px rgba(34,211,238,0.5))" }}>
      <path d="M14 1.5L2 6.5V15.5C2 23.2 7.4 30.1 14 32C20.6 30.1 26 23.2 26 15.5V6.5L14 1.5Z"
            fill="#090d1a" stroke="#22d3ee" strokeWidth="1.2"/>
      <path d="M9 16l4 4 7-7" stroke="#22d3ee" strokeWidth="1.8"
            strokeLinecap="round" strokeLinejoin="round"/>
    </svg>
  );
}

const NAV_ITEMS: { group: TranslationKey | null; items: NavItem[] }[] = [
  {
    group: null,
    items: [
      {
        href: "/dashboard",
        label: "nav_dashboard",
        icon: (
          <svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true">
            <rect x="1" y="1" width="6" height="6" rx="1" stroke="currentColor" strokeWidth="1.4"/>
            <rect x="9" y="1" width="6" height="6" rx="1" stroke="currentColor" strokeWidth="1.4"/>
            <rect x="1" y="9" width="6" height="6" rx="1" stroke="currentColor" strokeWidth="1.4"/>
            <rect x="9" y="9" width="6" height="6" rx="1" stroke="currentColor" strokeWidth="1.4"/>
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
        width: "220px",
        flexShrink: 0,
        background: "rgba(9,13,26,0.95)",
        borderRight: isRTL ? "none" : "1px solid #1a2236",
        borderLeft:  isRTL ? "1px solid #1a2236" : "none",
        backdropFilter: "blur(20px)",
        WebkitBackdropFilter: "blur(20px)",
        display: "flex",
        flexDirection: "column",
        height: "100dvh",
        position: "sticky",
        top: 0,
        overflowY: "auto",
      }}
    >
      {/* Logo */}
      <div style={{
        padding: "20px 16px 16px",
        borderBottom: "1px solid #1a2236",
        display: "flex",
        alignItems: "center",
        gap: "10px",
      }}>
        <ShieldIcon />
        <div>
          <div style={{
            fontFamily: "var(--font-jetbrains, JetBrains Mono, monospace)",
            fontSize: "0.9rem",
            fontWeight: 900,
            letterSpacing: "-0.02em",
            lineHeight: 1,
          }}>
            <span style={{ color: "#f1f5f9" }}>AI CYBER </span>
            <span className="text-gradient-cyber">SHIELD</span>
          </div>
          <div style={{
            fontSize: "0.6rem",
            color: "#3d4f6e",
            letterSpacing: "0.14em",
            textTransform: "uppercase",
            fontFamily: "var(--font-jetbrains, monospace)",
            marginTop: "3px",
          }}>
            {t("sidebar_tools")}
          </div>
        </div>
      </div>

      {/* Navigation */}
      <nav style={{ flex: 1, padding: "12px 8px", overflowY: "auto" }}>
        {NAV_ITEMS.map((group, gi) => (
          <div key={gi} style={{ marginBottom: "8px" }}>
            {group.group && (
              <div style={{
                fontSize: "0.58rem",
                fontWeight: 700,
                color: "#2d3a52",
                textTransform: "uppercase",
                letterSpacing: "0.18em",
                padding: "8px 8px 4px",
                fontFamily: "var(--font-jetbrains, monospace)",
              }}>
                {t(group.group as TranslationKey)}
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
                    borderRadius: "8px",
                    marginBottom: "2px",
                    color: active ? "#22d3ee" : "#4a5568",
                    background: active ? "rgba(34,211,238,0.07)" : "transparent",
                    borderLeft: (!isRTL && active) ? "2px solid #22d3ee" : (!isRTL ? "2px solid transparent" : "none"),
                    borderRight: (isRTL && active) ? "2px solid #22d3ee" : (isRTL ? "2px solid transparent" : "none"),
                    fontWeight: active ? 600 : 400,
                    fontSize: "0.84rem",
                    textDecoration: "none",
                    transition: "all 150ms ease",
                    position: "relative",
                  }}
                  onMouseEnter={(e) => {
                    if (!active) {
                      e.currentTarget.style.color = "#94a3b8";
                      e.currentTarget.style.background = "rgba(34,211,238,0.03)";
                    }
                  }}
                  onMouseLeave={(e) => {
                    if (!active) {
                      e.currentTarget.style.color = "#4a5568";
                      e.currentTarget.style.background = "transparent";
                    }
                  }}
                >
                  <span style={{ flexShrink: 0, opacity: active ? 1 : 0.6 }}>
                    {item.icon}
                  </span>
                  <span style={{ flex: 1 }}>{t(item.label)}</span>
                  {item.badge && (
                    <span style={{
                      fontSize: "0.52rem",
                      fontWeight: 800,
                      color: "#22d3ee",
                      background: "rgba(34,211,238,0.1)",
                      border: "1px solid rgba(34,211,238,0.25)",
                      borderRadius: "4px",
                      padding: "1px 5px",
                      fontFamily: "var(--font-jetbrains, monospace)",
                      letterSpacing: "0.06em",
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

      {/* Footer */}
      <div style={{
        padding: "12px 16px",
        borderTop: "1px solid #1a2236",
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
            background: "rgba(34,211,238,0.04)",
            border: "1px solid #1a2236",
            color: "#4a5568",
            fontSize: "0.78rem",
            fontWeight: 600,
            cursor: "pointer",
            transition: "all 150ms ease",
            width: "100%",
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.borderColor = "rgba(34,211,238,0.3)";
            e.currentTarget.style.color = "#22d3ee";
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.borderColor = "#1a2236";
            e.currentTarget.style.color = "#4a5568";
          }}
        >
          <span style={{ fontSize: "0.9rem" }}>{lang === "he" ? "🇺🇸" : "🇮🇱"}</span>
          <span>{t("toggle_lang")}</span>
        </button>

        {/* Version */}
        <div style={{
          fontSize: "0.6rem",
          color: "#2d3a52",
          fontFamily: "var(--font-jetbrains, monospace)",
          letterSpacing: "0.1em",
          textAlign: "center",
        }}>
          AI CYBER SHIELD · {t("sidebar_version")} · DEFENSIVE USE ONLY
        </div>
      </div>
    </aside>
  );
}
