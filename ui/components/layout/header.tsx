"use client";

import { useLang } from "@/contexts/language-context";

interface HeaderProps {
  title?: string;
  onNewScan?: () => void;
}

export function Header({ title, onNewScan }: HeaderProps) {
  const { t, isRTL } = useLang();

  return (
    <header style={{
      height: "56px",
      borderBottom: "1px solid #1a2236",
      background: "rgba(9,13,26,0.85)",
      backdropFilter: "blur(16px)",
      WebkitBackdropFilter: "blur(16px)",
      display: "flex",
      alignItems: "center",
      padding: "0 24px",
      gap: "16px",
      position: "sticky",
      top: 0,
      zIndex: 50,
      flexShrink: 0,
    }}>
      {/* Page title */}
      <div style={{ flex: 1, minWidth: 0 }}>
        {title && (
          <h1 style={{
            fontSize: "0.92rem",
            fontWeight: 600,
            color: "#f1f5f9",
            margin: 0,
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
          }}>
            {title}
          </h1>
        )}
      </div>

      {/* Right-side actions */}
      <div style={{
        display: "flex",
        alignItems: "center",
        gap: "10px",
        flexShrink: 0,
        flexDirection: isRTL ? "row-reverse" : "row",
      }}>
        {/* Status badge */}
        <div style={{
          display: "flex",
          alignItems: "center",
          gap: "5px",
          padding: "4px 10px",
          borderRadius: "999px",
          background: "rgba(16,185,129,0.07)",
          border: "1px solid rgba(16,185,129,0.2)",
        }}>
          <span style={{
            width: "6px", height: "6px",
            borderRadius: "50%",
            background: "#10b981",
            boxShadow: "0 0 6px #10b981",
            display: "inline-block",
          }} />
          <span style={{
            fontSize: "0.65rem",
            color: "#10b981",
            fontWeight: 700,
            fontFamily: "var(--font-jetbrains, monospace)",
            letterSpacing: "0.08em",
          }}>
            LIVE
          </span>
        </div>

        {/* New scan CTA */}
        {onNewScan && (
          <button
            onClick={onNewScan}
            style={{
              display: "flex",
              alignItems: "center",
              gap: "6px",
              padding: "7px 14px",
              borderRadius: "8px",
              background: "linear-gradient(135deg, #22d3ee 0%, #0891b2 100%)",
              color: "#000d1a",
              fontWeight: 800,
              fontSize: "0.8rem",
              border: "none",
              cursor: "pointer",
              letterSpacing: "0.02em",
              boxShadow: "0 0 16px rgba(34,211,238,0.2), inset 0 1px 0 rgba(255,255,255,0.15)",
              transition: "all 200ms cubic-bezier(0.16,1,0.3,1)",
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.transform = "translateY(-1px)";
              e.currentTarget.style.boxShadow = "0 6px 24px rgba(34,211,238,0.45), inset 0 1px 0 rgba(255,255,255,0.2)";
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.transform = "";
              e.currentTarget.style.boxShadow = "0 0 16px rgba(34,211,238,0.2), inset 0 1px 0 rgba(255,255,255,0.15)";
            }}
            onMouseDown={(e) => {
              e.currentTarget.style.transform = "scale(0.97)";
            }}
            onMouseUp={(e) => {
              e.currentTarget.style.transform = "translateY(-1px)";
            }}
          >
            <svg width="13" height="13" viewBox="0 0 13 13" fill="none" aria-hidden="true">
              <path d="M6.5 1.5v10M1.5 6.5h10" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
            </svg>
            {t("new_scan")}
          </button>
        )}
      </div>
    </header>
  );
}
