"use client";

import { useState, useMemo } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Database, Globe, Tag, AlertTriangle, Clock, Plus,
  ArrowUpDown, ArrowUp, ArrowDown, Search,
} from "lucide-react";
import { cn, formatRelative } from "@/lib/utils";
import type { Asset } from "@/types";

const DEMO_ASSETS: Asset[] = [
  { id: "a-001", domain: "app.example.com",       ip: "34.102.10.1",  tags: ["prod", "web"],         last_scan: new Date(Date.now() - 1000 * 60 * 15).toISOString(),  risk_score: 72, open_findings: 31 },
  { id: "a-002", domain: "api.example.com",       ip: "34.102.10.2",  tags: ["prod", "api"],         last_scan: new Date(Date.now() - 1000 * 60 * 5).toISOString(),   risk_score: 24, open_findings:  4 },
  { id: "a-003", domain: "staging.example.com",   ip: "35.190.10.5",  tags: ["staging"],             last_scan: new Date(Date.now() - 1000 * 60 * 110).toISOString(), risk_score: 18, open_findings: 12 },
  { id: "a-004", domain: "admin.example.com",     ip: "34.102.10.3",  tags: ["prod", "admin"],       last_scan: new Date(Date.now() - 1000 * 3600 * 24).toISOString(),risk_score: 85, open_findings: 47 },
  { id: "a-005", domain: "auth.example.com",      ip: "34.102.10.4",  tags: ["prod", "auth"],        last_scan: null,                                                   risk_score:  0, open_findings:  0 },
  { id: "a-006", domain: "cdn.example.com",       ip: "151.101.1.57", tags: ["prod", "cdn"],         last_scan: new Date(Date.now() - 1000 * 3600 * 48).toISOString(), risk_score:  5, open_findings:  1 },
  { id: "a-007", domain: "payments.example.com",  ip: "34.102.10.6",  tags: ["prod", "pci"],         last_scan: new Date(Date.now() - 1000 * 3600 * 2).toISOString(),  risk_score: 61, open_findings: 22 },
  { id: "a-008", domain: "mobile-api.example.com",ip: null,           tags: ["prod", "api", "v2"],   last_scan: new Date(Date.now() - 1000 * 3600 * 6).toISOString(),  risk_score: 33, open_findings:  8 },
];

type SortKey = "domain" | "risk_score" | "open_findings" | "last_scan";

function riskColor(score: number): string {
  if (score >= 70) return "text-critical";
  if (score >= 40) return "text-high";
  if (score >= 20) return "text-medium";
  return "text-low";
}

function riskBarColor(score: number): string {
  if (score >= 70) return "bg-critical";
  if (score >= 40) return "bg-high";
  if (score >= 20) return "bg-medium";
  return "bg-low";
}

export function AssetInventory() {
  const [sortKey, setSortKey] = useState<SortKey>("risk_score");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");
  const [search, setSearch]   = useState("");
  const [tagFilter, setTagFilter] = useState<string | null>(null);

  const allTags = useMemo(() => {
    const tags = new Set<string>();
    DEMO_ASSETS.forEach((a) => a.tags.forEach((t) => tags.add(t)));
    return [...tags].sort();
  }, []);

  const filtered = useMemo(() => {
    return DEMO_ASSETS.filter((a) => {
      if (search && !a.domain.toLowerCase().includes(search.toLowerCase())) return false;
      if (tagFilter && !a.tags.includes(tagFilter)) return false;
      return true;
    });
  }, [search, tagFilter]);

  const sorted = useMemo(() => {
    return [...filtered].sort((a, b) => {
      let cmp = 0;
      switch (sortKey) {
        case "domain":        cmp = a.domain.localeCompare(b.domain); break;
        case "risk_score":    cmp = a.risk_score - b.risk_score; break;
        case "open_findings": cmp = a.open_findings - b.open_findings; break;
        case "last_scan":
          cmp = (a.last_scan ? +new Date(a.last_scan) : 0) -
                (b.last_scan ? +new Date(b.last_scan) : 0);
          break;
      }
      return sortDir === "asc" ? cmp : -cmp;
    });
  }, [filtered, sortKey, sortDir]);

  const handleSort = (key: SortKey) => {
    if (sortKey === key) setSortDir((d) => d === "asc" ? "desc" : "asc");
    else { setSortKey(key); setSortDir("desc"); }
  };

  const SortIcon = ({ k }: { k: SortKey }) =>
    sortKey === k
      ? sortDir === "asc" ? <ArrowUp className="h-3 w-3" /> : <ArrowDown className="h-3 w-3" />
      : <ArrowUpDown className="h-3 w-3 opacity-30" />;

  return (
    <div className="space-y-4">
      {/* Summary cards */}
      <div className="grid grid-cols-3 gap-4">
        <SummaryCard
          icon={<Database className="h-4 w-4 text-primary" />}
          label="Total Assets"
          value={String(DEMO_ASSETS.length)}
        />
        <SummaryCard
          icon={<AlertTriangle className="h-4 w-4 text-critical" />}
          label="High Risk (≥70)"
          value={String(DEMO_ASSETS.filter((a) => a.risk_score >= 70).length)}
          color="text-critical"
        />
        <SummaryCard
          icon={<Clock className="h-4 w-4 text-medium" />}
          label="Never Scanned"
          value={String(DEMO_ASSETS.filter((a) => !a.last_scan).length)}
          color="text-medium"
        />
      </div>

      {/* Main table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>Asset Inventory</CardTitle>
              <CardDescription>{sorted.length} assets</CardDescription>
            </div>
            <Button size="sm" className="gap-1.5">
              <Plus className="h-3.5 w-3.5" /> Add Asset
            </Button>
          </div>

          {/* Filters */}
          <div className="flex flex-wrap items-center gap-3 mt-3">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
              <input
                type="text"
                placeholder="Search domains…"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="h-8 w-52 rounded-md border bg-input pl-8 pr-3 text-xs placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-ring"
              />
            </div>

            <div className="flex items-center gap-1.5">
              <Tag className="h-3.5 w-3.5 text-muted-foreground" />
              {allTags.map((tag) => (
                <button
                  key={tag}
                  onClick={() => setTagFilter((t) => (t === tag ? null : tag))}
                  className={cn(
                    "rounded-full border px-2.5 py-0.5 text-[10px] font-medium transition-all",
                    tagFilter === tag
                      ? "bg-primary/20 border-primary/40 text-primary"
                      : "bg-muted/50 border-muted text-muted-foreground hover:text-foreground"
                  )}
                >
                  {tag}
                </button>
              ))}
            </div>
          </div>
        </CardHeader>

        <CardContent className="p-0">
          <ScrollArea className="h-[460px]">
            <table className="w-full text-sm">
              <thead className="sticky top-0 bg-card border-b z-10">
                <tr>
                  <th
                    className="px-4 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider cursor-pointer hover:text-foreground"
                    onClick={() => handleSort("domain")}
                  >
                    <span className="flex items-center gap-1.5">Domain <SortIcon k="domain" /></span>
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">Tags</th>
                  <th
                    className="px-4 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider cursor-pointer hover:text-foreground w-36"
                    onClick={() => handleSort("risk_score")}
                  >
                    <span className="flex items-center gap-1.5">Risk <SortIcon k="risk_score" /></span>
                  </th>
                  <th
                    className="px-4 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider cursor-pointer hover:text-foreground w-28"
                    onClick={() => handleSort("open_findings")}
                  >
                    <span className="flex items-center gap-1.5">Findings <SortIcon k="open_findings" /></span>
                  </th>
                  <th
                    className="px-4 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider cursor-pointer hover:text-foreground w-32"
                    onClick={() => handleSort("last_scan")}
                  >
                    <span className="flex items-center gap-1.5">Last Scan <SortIcon k="last_scan" /></span>
                  </th>
                  <th className="w-20 px-4 py-3 text-xs text-muted-foreground">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y">
                {sorted.map((asset) => (
                  <tr key={asset.id} className="hover:bg-accent/40 transition-colors">
                    {/* Domain */}
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <Globe className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                        <div>
                          <p className="font-medium text-xs">{asset.domain}</p>
                          {asset.ip && (
                            <p className="text-[10px] font-mono text-muted-foreground">{asset.ip}</p>
                          )}
                        </div>
                      </div>
                    </td>

                    {/* Tags */}
                    <td className="px-4 py-3">
                      <div className="flex flex-wrap gap-1">
                        {asset.tags.map((t) => (
                          <span
                            key={t}
                            className="rounded-full bg-muted px-2 py-0.5 text-[10px] text-muted-foreground"
                          >
                            {t}
                          </span>
                        ))}
                      </div>
                    </td>

                    {/* Risk */}
                    <td className="px-4 py-3">
                      <div className="space-y-1">
                        <div className="flex items-center justify-between">
                          <span className={cn("text-xs font-black tabular-nums", riskColor(asset.risk_score))}>
                            {asset.risk_score}
                          </span>
                        </div>
                        <div className="h-1 w-full overflow-hidden rounded-full bg-muted">
                          <div
                            className={cn("h-full rounded-full transition-all", riskBarColor(asset.risk_score))}
                            style={{ width: `${asset.risk_score}%` }}
                          />
                        </div>
                      </div>
                    </td>

                    {/* Findings */}
                    <td className="px-4 py-3">
                      <span className={cn(
                        "text-sm font-bold tabular-nums",
                        asset.open_findings > 20 ? "text-critical" :
                        asset.open_findings > 5  ? "text-high"     : "text-foreground"
                      )}>
                        {asset.open_findings}
                      </span>
                    </td>

                    {/* Last scan */}
                    <td className="px-4 py-3 text-xs text-muted-foreground">
                      {asset.last_scan ? formatRelative(asset.last_scan) : (
                        <span className="text-medium font-medium">Never</span>
                      )}
                    </td>

                    {/* Actions */}
                    <td className="px-4 py-3">
                      <Button variant="ghost" size="sm" className="h-7 text-xs gap-1">
                        Scan now
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </ScrollArea>
        </CardContent>
      </Card>
    </div>
  );
}

function SummaryCard({
  icon, label, value, color = "text-foreground",
}: {
  icon: React.ReactNode; label: string; value: string; color?: string;
}) {
  return (
    <Card>
      <CardContent className="flex items-center gap-4 p-5">
        <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-muted">
          {icon}
        </div>
        <div>
          <p className="text-xs text-muted-foreground">{label}</p>
          <p className={cn("text-2xl font-black tabular-nums", color)}>{value}</p>
        </div>
      </CardContent>
    </Card>
  );
}
