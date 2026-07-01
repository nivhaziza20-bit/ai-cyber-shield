"use client";

/**
 * SecurityCopilot — conversational AI assistant for scan results.
 * Calls POST /api/v1/scans/{scanId}/chat.
 *
 * Features:
 *  - Chat interface with message history (managed client-side)
 *  - 3 suggested follow-up chips after each assistant response
 *  - Hebrew / English language support via useLang()
 *  - Skeleton loading state while LLM processes
 *  - Graceful error banner
 */

import { useState, useRef, useEffect, useCallback } from "react";
import { useLang } from "@/contexts/language-context";

interface ChatMessage {
  role:    "user" | "assistant";
  content: string;
}

interface CopilotResponse {
  response:            string;
  suggested_followups: string[];
  scan_id:             string;
}

interface Props {
  scanId:   string;
  apiKey?:  string;
  disabled?: boolean;
}

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";
const _CYAN = "#22d3ee";
const _DARK = "rgba(6,11,20,0.96)";

/* ── Skeleton loader ────────────────────────────────────────────────────────── */
function TypingIndicator() {
  return (
    <div style={{ display: "flex", gap: "5px", padding: "12px 16px", alignItems: "center" }}>
      {[0, 1, 2].map((i) => (
        <span
          key={i}
          style={{
            width: "7px", height: "7px", borderRadius: "50%",
            background: _CYAN, opacity: 0.6,
            animation: `copilotDot 1.2s ${i * 0.2}s infinite ease-in-out`,
          }}
        />
      ))}
      <style>{`
        @keyframes copilotDot {
          0%, 80%, 100% { transform: scale(0.6); opacity: 0.4; }
          40% { transform: scale(1.1); opacity: 1; }
        }
      `}</style>
    </div>
  );
}

/* ── Message bubble ─────────────────────────────────────────────────────────── */
function Bubble({ msg }: { msg: ChatMessage }) {
  const isUser = msg.role === "user";
  return (
    <div style={{
      display: "flex",
      justifyContent: isUser ? "flex-end" : "flex-start",
      marginBottom: "12px",
    }}>
      {!isUser && (
        <div style={{
          width: "28px", height: "28px", borderRadius: "50%",
          background: `${_CYAN}18`, border: `1px solid ${_CYAN}33`,
          display: "flex", alignItems: "center", justifyContent: "center",
          fontSize: "13px", flexShrink: 0, marginRight: "8px", marginTop: "2px",
        }}>🛡</div>
      )}
      <div style={{
        maxWidth: "80%",
        padding: "10px 14px",
        borderRadius: isUser ? "14px 14px 4px 14px" : "14px 14px 14px 4px",
        background: isUser
          ? `linear-gradient(135deg, ${_CYAN}22 0%, ${_CYAN}10 100%)`
          : "rgba(13,20,33,0.9)",
        border: `1px solid ${isUser ? _CYAN + "33" : "#1a2236"}`,
        color: "#e2e8f0",
        fontSize: "0.855rem",
        lineHeight: 1.65,
        whiteSpace: "pre-wrap",
        wordBreak: "break-word",
      }}>
        {msg.content}
      </div>
    </div>
  );
}

/* ── Main component ─────────────────────────────────────────────────────────── */
export default function SecurityCopilot({ scanId, apiKey, disabled }: Props) {
  const { lang } = useLang();
  const isHe = lang === "he";
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput]       = useState("");
  const [loading, setLoading]   = useState(false);
  const [followups, setFollowups] = useState<string[]>([]);
  const [error, setError]       = useState<string | null>(null);
  const bottomRef = useRef<HTMLDivElement>(null);

  const placeholder = isHe
    ? "שאל על הממצאים, בקש תיקונים, צור כרטיס Jira…"
    : "Ask about findings, request fixes, generate a Jira ticket…";

  const scrollToBottom = useCallback(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, []);

  useEffect(() => { scrollToBottom(); }, [messages, loading, scrollToBottom]);

  const sendMessage = useCallback(async (text: string) => {
    if (!text.trim() || loading || disabled) return;
    setError(null);
    const userMsg: ChatMessage = { role: "user", content: text };
    setMessages((prev) => [...prev, userMsg]);
    setInput("");
    setFollowups([]);
    setLoading(true);

    const history = messages.slice(-18);

    try {
      const key = apiKey ?? process.env.NEXT_PUBLIC_AICS_API_KEY ?? "aics-dev-key-DO-NOT-USE-IN-PRODUCTION";
      const res = await fetch(`${API_BASE}/api/v1/scans/${scanId}/chat`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-API-Key":    key,
        },
        body: JSON.stringify({
          message:              text,
          conversation_history: history,
          language:             lang,
        }),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err?.detail?.error ?? `HTTP ${res.status}`);
      }

      const data: CopilotResponse = await res.json();
      setMessages((prev) => [...prev, { role: "assistant", content: data.response }]);
      setFollowups(data.suggested_followups ?? []);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      setError(isHe ? `שגיאה: ${msg}` : `Error: ${msg}`);
    } finally {
      setLoading(false);
    }
  }, [messages, loading, disabled, scanId, apiKey, lang, isHe]);

  const handleKey = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      sendMessage(input);
    }
  };

  const isEmpty = messages.length === 0;
  const greeting = isHe
    ? "שלום! אני יכול לעזור לך להבין את ממצאי הסריקה, לתעדף תיקונים ולצור כרטיסי Jira."
    : "Hello! I can help you understand scan findings, prioritize fixes, and generate Jira tickets.";

  const starters = isHe
    ? ["מה הבעיות הדחופות ביותר?", "כיצד אגיע לדרגת A?", "צור כרטיס Jira לממצא הקריטי"]
    : ["What are the most urgent issues?", "How do I reach Grade A?", "Generate a Jira ticket for the critical finding"];

  return (
    <div style={{
      display: "flex", flexDirection: "column",
      height: "540px",
      background: _DARK,
      border: "1px solid #1a2236",
      borderRadius: "14px",
      overflow: "hidden",
    }}>
      {/* Header */}
      <div style={{
        display: "flex", alignItems: "center", gap: "10px",
        padding: "12px 16px",
        background: "rgba(13,20,33,0.8)",
        borderBottom: "1px solid #1a2236",
        flexShrink: 0,
      }}>
        <div style={{
          width: "32px", height: "32px", borderRadius: "50%",
          background: `${_CYAN}15`,
          border: `1px solid ${_CYAN}40`,
          display: "flex", alignItems: "center", justifyContent: "center",
          fontSize: "15px",
        }}>🤖</div>
        <div>
          <div style={{ color: _CYAN, fontWeight: 700, fontSize: "0.88rem" }}>
            {isHe ? "Security Copilot" : "Security Copilot"}
          </div>
          <div style={{ color: "#64748b", fontSize: "0.72rem" }}>
            {isHe ? "מערכת שאלות ותשובות על ממצאי הסריקה" : "AI-powered findings Q&A · powered by Claude"}
          </div>
        </div>
        {disabled && (
          <div style={{
            marginLeft: "auto", padding: "3px 10px",
            borderRadius: "6px", background: "rgba(251,146,60,0.12)",
            border: "1px solid rgba(251,146,60,0.25)",
            color: "#fb923c", fontSize: "0.72rem", fontWeight: 600,
          }}>
            {isHe ? "סריקה טרם הושלמה" : "Scan not complete"}
          </div>
        )}
      </div>

      {/* Message area */}
      <div style={{
        flex: 1, overflowY: "auto", padding: "16px 14px",
        direction: isHe ? "rtl" : "ltr",
      }}>
        {isEmpty && (
          <div style={{ textAlign: "center", paddingTop: "24px" }}>
            <div style={{ fontSize: "2.2rem", marginBottom: "12px" }}>🛡</div>
            <div style={{ color: "#94a3b8", fontSize: "0.85rem", lineHeight: 1.7, marginBottom: "20px" }}>
              {greeting}
            </div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: "8px", justifyContent: "center" }}>
              {starters.map((s) => (
                <button
                  key={s}
                  onClick={() => sendMessage(s)}
                  disabled={disabled || loading}
                  style={{
                    padding: "7px 14px",
                    borderRadius: "20px",
                    border: `1px solid ${_CYAN}33`,
                    background: `${_CYAN}0a`,
                    color: _CYAN,
                    fontSize: "0.78rem",
                    cursor: "pointer",
                    transition: "all 150ms ease",
                  }}
                  onMouseEnter={(e) => { e.currentTarget.style.background = `${_CYAN}18`; }}
                  onMouseLeave={(e) => { e.currentTarget.style.background = `${_CYAN}0a`; }}
                >
                  {s}
                </button>
              ))}
            </div>
          </div>
        )}

        {messages.map((msg, i) => <Bubble key={i} msg={msg} />)}
        {loading && <TypingIndicator />}
        <div ref={bottomRef} />
      </div>

      {/* Follow-up chips */}
      {followups.length > 0 && !loading && (
        <div style={{
          padding: "6px 14px 0",
          display: "flex", gap: "7px", flexWrap: "wrap",
          direction: isHe ? "rtl" : "ltr",
        }}>
          {followups.map((f, i) => (
            <button
              key={i}
              onClick={() => sendMessage(f)}
              style={{
                padding: "5px 12px",
                borderRadius: "16px",
                border: "1px solid #1e3052",
                background: "rgba(30,48,82,0.4)",
                color: "#94a3b8",
                fontSize: "0.75rem",
                cursor: "pointer",
                transition: "all 150ms ease",
              }}
              onMouseEnter={(e) => { e.currentTarget.style.borderColor = `${_CYAN}55`; e.currentTarget.style.color = _CYAN; }}
              onMouseLeave={(e) => { e.currentTarget.style.borderColor = "#1e3052"; e.currentTarget.style.color = "#94a3b8"; }}
            >
              {f}
            </button>
          ))}
        </div>
      )}

      {/* Error banner */}
      {error && (
        <div style={{
          margin: "6px 14px 0",
          padding: "8px 12px",
          borderRadius: "8px",
          background: "rgba(239,68,68,0.1)",
          border: "1px solid rgba(239,68,68,0.25)",
          color: "#fca5a5", fontSize: "0.78rem",
        }}>
          {error}
        </div>
      )}

      {/* Input row */}
      <div style={{
        padding: "10px 14px 12px",
        borderTop: "1px solid #1a2236",
        display: "flex", gap: "8px", alignItems: "flex-end",
        flexShrink: 0,
        direction: isHe ? "rtl" : "ltr",
      }}>
        <textarea
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={handleKey}
          placeholder={placeholder}
          rows={2}
          disabled={disabled || loading}
          style={{
            flex: 1,
            padding: "9px 12px",
            background: "rgba(13,20,33,0.8)",
            border: "1px solid #1a2236",
            borderRadius: "10px",
            color: "#e2e8f0",
            fontSize: "0.85rem",
            resize: "none",
            outline: "none",
            fontFamily: "inherit",
            lineHeight: 1.5,
            direction: "inherit",
          }}
          onFocus={(e) => { e.target.style.borderColor = `${_CYAN}66`; }}
          onBlur={(e)  => { e.target.style.borderColor = "#1a2236"; }}
        />
        <button
          onClick={() => sendMessage(input)}
          disabled={!input.trim() || loading || disabled}
          style={{
            width: "38px", height: "38px",
            borderRadius: "10px",
            border: "none",
            background: input.trim() && !loading && !disabled
              ? `linear-gradient(135deg, ${_CYAN} 0%, ${_CYAN}80 100%)`
              : "#1a2236",
            color: input.trim() && !loading && !disabled ? "#000d1a" : "#334155",
            display: "flex", alignItems: "center", justifyContent: "center",
            cursor: input.trim() && !loading && !disabled ? "pointer" : "not-allowed",
            transition: "all 200ms ease",
            flexShrink: 0,
          }}
        >
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none"
               style={{ transform: isHe ? "rotate(180deg)" : "none" }}>
            <path d="M5 12h14M12 5l7 7-7 7" stroke="currentColor"
                  strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
          </svg>
        </button>
      </div>
    </div>
  );
}
