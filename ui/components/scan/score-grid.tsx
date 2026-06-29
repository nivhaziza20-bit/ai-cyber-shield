"use client";

import { scoreColor, categoryIcon } from "@/lib/api";
import { useLang } from "@/contexts/language-context";

interface ScoreGridProps {
  scores: Record<string, number>;
}

function ScoreCard({ name, score }: { name: string; score: number }) {
  const color = scoreColor(score);
  const icon  = categoryIcon(name);

  return (
    <div
      className="glass-card animate-fade-up"
      style={{
        padding: "14px 16px",
        cursor: "default",
        transition: "transform 200ms cubic-bezier(0.16,1,0.3,1), box-shadow 200ms ease, border-color 200ms ease",
      }}
      onMouseEnter={(e) => {
        e.currentTarget.style.transform = "translateY(-2px)";
        e.currentTarget.style.boxShadow = "0 8px 28px rgba(0,0,0,0.45), 0 0 0 1px #243049";
        e.currentTarget.style.borderColor = "#243049";
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.transform = "";
        e.currentTarget.style.boxShadow = "";
        e.currentTarget.style.borderColor = "";
      }}
    >
      {/* Label row */}
      <div style={{
        display: "flex",
        alignItems: "center",
        gap: "6px",
        marginBottom: "8px",
      }}>
        <span style={{ fontSize: "0.9rem" }}>{icon}</span>
        <span style={{
          color: "#64748b",
          fontSize: "0.66rem",
          textTransform: "uppercase",
          letterSpacing: "0.12em",
          fontFamily: "JetBrains Mono, monospace",
          flex: 1,
        }}>
          {name}
        </span>
      </div>

      {/* Score */}
      <div style={{
        color,
        fontSize: "1.6rem",
        fontWeight: 800,
        fontFamily: "JetBrains Mono, Courier New, monospace",
        lineHeight: 1,
        marginBottom: "8px",
      }}>
        {score}
        <span style={{ fontSize: "0.85rem", color: "#64748b", fontWeight: 400 }}>/100</span>
      </div>

      {/* Mini bar */}
      <div style={{ background: "#1a2236", borderRadius: "3px", height: "3px", overflow: "hidden" }}>
        <div
          className="score-bar-fill"
          style={{
            height: "3px",
            width: `${score}%`,
            borderRadius: "3px",
            background: `linear-gradient(90deg, ${color}, ${color}90)`,
          }}
        />
      </div>
    </div>
  );
}

export function ScoreGrid({ scores }: ScoreGridProps) {
  const { t } = useLang();
  const entries = Object.entries(scores);

  if (!entries.length) return null;

  return (
    <div style={{ marginBottom: "24px" }}>
      <div style={{
        color: "#64748b",
        fontSize: "0.65rem",
        textTransform: "uppercase",
        letterSpacing: "0.18em",
        fontFamily: "JetBrains Mono, monospace",
        paddingBottom: "8px",
        borderBottom: "1px solid #1a2236",
        marginBottom: "12px",
      }}>
        {t("scores_title")}
      </div>
      <div style={{
        display: "grid",
        gridTemplateColumns: "repeat(auto-fill, minmax(160px, 1fr))",
        gap: "8px",
      }}>
        {entries.map(([name, score]) => (
          <ScoreCard key={name} name={name} score={score} />
        ))}
      </div>
    </div>
  );
}
