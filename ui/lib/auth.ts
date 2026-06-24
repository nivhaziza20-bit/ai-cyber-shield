/**
 * lib/auth.ts — Multi-tenant workspace auth utilities
 *
 * Uses Auth0 / Clerk patterns. Replace AUTH_PROVIDER with your chosen provider.
 * All role checks are centralised here to avoid scattering permission logic.
 */

import type { Workspace, TeamMember } from "@/types";

export type Role = Workspace["role"];

// Role hierarchy: owner > admin > analyst > viewer
const ROLE_RANK: Record<Role, number> = {
  owner:   4,
  admin:   3,
  analyst: 2,
  viewer:  1,
};

export function hasRole(userRole: Role, required: Role): boolean {
  return ROLE_RANK[userRole] >= ROLE_RANK[required];
}

export function canStartScan(role: Role):      boolean { return hasRole(role, "analyst"); }
export function canManageTeam(role: Role):     boolean { return hasRole(role, "admin");   }
export function canDeleteScans(role: Role):    boolean { return hasRole(role, "admin");   }
export function canViewFindings(role: Role):   boolean { return hasRole(role, "viewer");  }
export function canSuppressFindings(role: Role): boolean { return hasRole(role, "analyst"); }
export function canExportReports(role: Role):  boolean { return hasRole(role, "analyst"); }
export function canManageProfiles(role: Role): boolean { return hasRole(role, "admin");   }
export function canDeleteWorkspace(role: Role): boolean { return role === "owner";         }

// Workspace switcher state (client-side; replace with server session in production)
export function getWorkspaceFromSlug(
  workspaces: Workspace[],
  slug: string
): Workspace | undefined {
  return workspaces.find((w) => w.slug === slug);
}

// JWT claims shape (from Auth0/Clerk)
export interface AuthClaims {
  sub:      string;
  email:    string;
  name:     string;
  picture?: string;
  // Custom claim namespaced to avoid collisions
  "https://aics.io/workspaces": Array<{
    id:   string;
    slug: string;
    role: Role;
  }>;
}

export function claimsToWorkspaces(claims: AuthClaims): Workspace[] {
  return (claims["https://aics.io/workspaces"] ?? []).map((w) => ({
    id:   w.id,
    name: w.slug,
    slug: w.slug,
    plan: "enterprise" as const,
    role: w.role,
  }));
}
