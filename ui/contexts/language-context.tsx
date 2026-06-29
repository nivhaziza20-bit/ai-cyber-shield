"use client";

import React, { createContext, useCallback, useContext, useEffect, useState } from "react";
import type { Lang } from "@/lib/i18n";
import { tr, type TranslationKey } from "@/lib/i18n";

interface LanguageContextValue {
  lang: Lang;
  isRTL: boolean;
  toggle: () => void;
  t: (key: TranslationKey) => string;
}

const LanguageContext = createContext<LanguageContextValue>({
  lang: "he",
  isRTL: true,
  toggle: () => {},
  t: (k) => tr(k, "he"),
});

export function LanguageProvider({ children }: { children: React.ReactNode }) {
  const [lang, setLang] = useState<Lang>("he");

  // Apply dir + font to <html> on every lang change
  useEffect(() => {
    const html = document.documentElement;
    html.lang = lang;
    html.dir  = lang === "he" ? "rtl" : "ltr";
    html.setAttribute("data-font", lang === "he" ? "heebo" : "inter");
    try { localStorage.setItem("aics-lang", lang); } catch {}
  }, [lang]);

  // Restore from localStorage on mount
  useEffect(() => {
    try {
      const saved = localStorage.getItem("aics-lang") as Lang | null;
      if (saved === "en" || saved === "he") setLang(saved);
    } catch {}
  }, []);

  const toggle = useCallback(() => {
    setLang((prev) => (prev === "he" ? "en" : "he"));
  }, []);

  const translate = useCallback((key: TranslationKey) => tr(key, lang), [lang]);

  return (
    <LanguageContext.Provider value={{ lang, isRTL: lang === "he", toggle, t: translate }}>
      {children}
    </LanguageContext.Provider>
  );
}

export function useLang() {
  return useContext(LanguageContext);
}
