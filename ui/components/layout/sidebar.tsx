"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Shield,
  LayoutDashboard,
  Scan,
  Bug,
  BarChart3,
  Settings,
  Database,
  Users,
  Zap,
  ChevronRight,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Badge } from "@/components/ui/badge";

interface NavItem {
  href:    string;
  label:   string;
  icon:    React.ComponentType<{ className?: string }>;
  badge?:  string | number;
  exact?:  boolean;
}

const navItems: NavItem[] = [
  { href: "/",          label: "Dashboard",   icon: LayoutDashboard, exact: true },
  { href: "/scans",     label: "Scans",       icon: Scan },
  { href: "/findings",  label: "Findings",    icon: Bug },
  { href: "/assets",    label: "Assets",      icon: Database },
  { href: "/analytics", label: "Analytics",   icon: BarChart3 },
  { href: "/team",      label: "Team",        icon: Users },
  { href: "/settings",  label: "Settings",    icon: Settings },
];

export function Sidebar() {
  const pathname = usePathname();

  const isActive = (item: NavItem) =>
    item.exact ? pathname === item.href : pathname.startsWith(item.href);

  return (
    <aside className="flex h-screen w-64 flex-col border-r bg-card">
      {/* Logo */}
      <div className="flex h-16 items-center gap-3 border-b px-6">
        <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-primary/10 ring-1 ring-primary/20">
          <Shield className="h-5 w-5 text-primary" />
        </div>
        <div>
          <p className="text-sm font-semibold leading-none">AI Cyber Shield</p>
          <p className="mt-0.5 text-[10px] text-muted-foreground uppercase tracking-wider">v6 Pro</p>
        </div>
      </div>

      {/* Nav */}
      <ScrollArea className="flex-1 px-3 py-4">
        <nav className="space-y-1">
          {navItems.map((item) => {
            const active = isActive(item);
            return (
              <Link
                key={item.href}
                href={item.href}
                className={cn(
                  "group flex items-center gap-3 rounded-md px-3 py-2.5 text-sm font-medium transition-colors",
                  active
                    ? "bg-primary/10 text-primary"
                    : "text-muted-foreground hover:bg-accent hover:text-foreground"
                )}
              >
                <item.icon
                  className={cn(
                    "h-4 w-4 shrink-0 transition-colors",
                    active ? "text-primary" : "text-muted-foreground group-hover:text-foreground"
                  )}
                />
                <span className="flex-1">{item.label}</span>
                {item.badge != null && (
                  <Badge variant="secondary" className="text-[10px] h-4 px-1.5">
                    {item.badge}
                  </Badge>
                )}
                {active && (
                  <ChevronRight className="h-3 w-3 text-primary" />
                )}
              </Link>
            );
          })}
        </nav>
      </ScrollArea>

      {/* Footer */}
      <div className="border-t p-4">
        <div className="flex items-center gap-3 rounded-md px-2 py-2">
          <div className="flex h-8 w-8 items-center justify-center rounded-full bg-primary/10 ring-1 ring-primary/20">
            <Zap className="h-4 w-4 text-primary" />
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-xs font-medium truncate">Enterprise</p>
            <p className="text-[10px] text-muted-foreground">All features active</p>
          </div>
        </div>
      </div>
    </aside>
  );
}
