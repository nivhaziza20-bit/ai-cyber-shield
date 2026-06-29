import type { Metadata, Viewport } from "next";
import { Inter, JetBrains_Mono, Heebo } from "next/font/google";
import { LanguageProvider } from "@/contexts/language-context";
import "./globals.css";

const inter = Inter({
  subsets: ["latin"],
  variable: "--font-inter",
  display: "optional",
});

const jetbrainsMono = JetBrains_Mono({
  subsets: ["latin"],
  variable: "--font-jetbrains",
  display: "optional",
});

const heebo = Heebo({
  subsets: ["hebrew", "latin"],
  variable: "--font-heebo",
  display: "optional",
});

export const metadata: Metadata = {
  title: "AI Cyber Shield — Web Security Intelligence",
  description: "Professional web application security analysis using 18 OSINT tools. Scan any domain for vulnerabilities, misconfigurations, and compliance issues.",
  keywords: ["security scanner", "OSINT", "web security", "vulnerability scanner", "GDPR compliance"],
  openGraph: {
    title: "AI Cyber Shield",
    description: "18-tool web security scanner. Grade A–F. Actionable remediation.",
    type: "website",
  },
};

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  themeColor: "#050810",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    /* Default: Hebrew RTL — LanguageProvider will adjust based on user preference */
    <html lang="he" dir="rtl" data-font="heebo" suppressHydrationWarning>
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="" />
      </head>
      <body className={`${inter.variable} ${jetbrainsMono.variable} ${heebo.variable} antialiased`}>
        <LanguageProvider>
          {children}
        </LanguageProvider>
      </body>
    </html>
  );
}
