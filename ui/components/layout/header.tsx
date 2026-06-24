"use client";

import { Bell, Moon, Sun, Search, Plus } from "lucide-react";
import { useTheme } from "next-themes";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

interface HeaderProps {
  title:    string;
  subtitle?: string;
}

export function Header({ title, subtitle }: HeaderProps) {
  const { resolvedTheme, setTheme } = useTheme();
  const isDark = resolvedTheme === "dark";

  return (
    <header className="flex h-16 items-center border-b bg-card/50 px-6 backdrop-blur-sm">
      {/* Title */}
      <div className="flex-1">
        <h1 className="text-lg font-semibold leading-none">{title}</h1>
        {subtitle && (
          <p className="mt-0.5 text-xs text-muted-foreground">{subtitle}</p>
        )}
      </div>

      {/* Actions */}
      <div className="flex items-center gap-2">
        {/* Search */}
        <Button variant="outline" size="sm" className="gap-2 text-muted-foreground">
          <Search className="h-3.5 w-3.5" />
          <span className="text-xs">Search</span>
          <kbd className="pointer-events-none ml-2 hidden select-none rounded border bg-muted px-1.5 font-mono text-[10px] opacity-100 sm:inline-flex">
            ⌘K
          </kbd>
        </Button>

        {/* New Scan */}
        <Button size="sm" className="gap-1.5">
          <Plus className="h-3.5 w-3.5" />
          New Scan
        </Button>

        {/* Notifications */}
        <Button variant="ghost" size="icon" className="relative">
          <Bell className="h-4 w-4" />
          <Badge
            variant="destructive"
            className="absolute -right-1 -top-1 h-4 w-4 rounded-full p-0 text-[10px] flex items-center justify-center"
          >
            3
          </Badge>
        </Button>

        {/* Theme toggle */}
        <Button
          variant="ghost"
          size="icon"
          onClick={() => setTheme(isDark ? "light" : "dark")}
        >
          {isDark ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
        </Button>
      </div>
    </header>
  );
}
