"use client";

import { Header } from "@/components/layout/header";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { hasRole, canManageTeam } from "@/lib/auth";
import { UserPlus, Shield, Eye, PenSquare, Wrench } from "lucide-react";
import { cn, formatRelative } from "@/lib/utils";
import type { TeamMember, Workspace } from "@/types";

// Demo data
const CURRENT_USER_ROLE: Workspace["role"] = "owner";

const DEMO_MEMBERS: TeamMember[] = [
  { id: "u-001", email: "alice@example.com", name: "Alice Chen",    role: "owner",   last_active: new Date(Date.now() - 1000 * 60).toISOString() },
  { id: "u-002", email: "bob@example.com",   name: "Bob Martinez",  role: "admin",   last_active: new Date(Date.now() - 1000 * 3600).toISOString() },
  { id: "u-003", email: "carol@example.com", name: "Carol Smith",   role: "analyst", last_active: new Date(Date.now() - 1000 * 3600 * 4).toISOString() },
  { id: "u-004", email: "dan@example.com",   name: "Dan Williams",  role: "analyst", last_active: new Date(Date.now() - 1000 * 3600 * 24).toISOString() },
  { id: "u-005", email: "eve@example.com",   name: "Eve Johnson",   role: "viewer",  last_active: new Date(Date.now() - 1000 * 3600 * 48).toISOString() },
];

const ROLE_ICON: Record<Workspace["role"], React.ReactNode> = {
  owner:   <Shield     className="h-3.5 w-3.5 text-primary"  />,
  admin:   <Wrench     className="h-3.5 w-3.5 text-high"     />,
  analyst: <PenSquare  className="h-3.5 w-3.5 text-medium"   />,
  viewer:  <Eye        className="h-3.5 w-3.5 text-low"      />,
};

const ROLE_DESCRIPTION: Record<Workspace["role"], string> = {
  owner:   "Full access + billing + workspace deletion",
  admin:   "Full access except billing + workspace",
  analyst: "Start scans, suppress findings, export reports",
  viewer:  "Read-only access to findings and reports",
};

export default function TeamPage() {
  const canManage = canManageTeam(CURRENT_USER_ROLE);

  return (
    <>
      <Header title="Team" subtitle="Manage workspace members and roles" />
      <div className="flex-1 overflow-auto p-6 space-y-6 scrollbar-thin">
        {/* Role legend */}
        <div className="grid grid-cols-2 gap-4 xl:grid-cols-4">
          {(["owner", "admin", "analyst", "viewer"] as const).map((role) => (
            <Card key={role}>
              <CardContent className="flex items-start gap-3 p-4">
                <div className="mt-0.5">{ROLE_ICON[role]}</div>
                <div>
                  <p className="text-sm font-semibold capitalize">{role}</p>
                  <p className="text-[11px] text-muted-foreground mt-0.5">
                    {ROLE_DESCRIPTION[role]}
                  </p>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>

        {/* Members table */}
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <div>
                <CardTitle>Members</CardTitle>
                <CardDescription>{DEMO_MEMBERS.length} members in this workspace</CardDescription>
              </div>
              {canManage && (
                <Button size="sm" className="gap-1.5">
                  <UserPlus className="h-3.5 w-3.5" /> Invite
                </Button>
              )}
            </div>
          </CardHeader>
          <CardContent className="p-0">
            <div className="divide-y">
              {DEMO_MEMBERS.map((m) => (
                <div key={m.id} className="flex items-center gap-4 px-6 py-4">
                  {/* Avatar */}
                  <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-primary/10 text-sm font-bold text-primary uppercase">
                    {m.name.charAt(0)}
                  </div>

                  {/* Info */}
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium">{m.name}</p>
                    <p className="text-xs text-muted-foreground">{m.email}</p>
                  </div>

                  {/* Role */}
                  <div className="flex items-center gap-1.5">
                    {ROLE_ICON[m.role]}
                    <span className="text-xs font-medium capitalize">{m.role}</span>
                  </div>

                  {/* Last active */}
                  <span className="text-xs text-muted-foreground shrink-0">
                    {formatRelative(m.last_active)}
                  </span>

                  {/* Actions */}
                  {canManage && m.role !== "owner" && (
                    <Button variant="ghost" size="sm" className="h-7 text-xs shrink-0">
                      Edit
                    </Button>
                  )}
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>
    </>
  );
}
