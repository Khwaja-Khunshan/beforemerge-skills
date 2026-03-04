---
title: Missing Service Layer
description: "Business logic belongs in service classes, not in route handlers, server actions, or components. Use the ServiceResult<T> pattern."
impact: HIGH
impact_description: Business logic scattered across handlers and actions is untestable, duplicated, and impossible to reuse across entry points
tags: [architecture, service-layer, single-responsibility, solid]
cwe: ["CWE-1086"]
detection_grep: "ServiceResult"
---

## Missing Service Layer

**Impact: HIGH (Business logic scattered across handlers and actions is untestable, duplicated, and impossible to reuse across entry points)**

Route handlers and server actions are entry points, not business logic containers. When validation rules, authorization checks, data transformations, or orchestration logic lives inside a `POST` handler or `"use server"` function, that logic cannot be unit tested without simulating HTTP requests, cannot be reused when a second entry point (webhook, cron job, CLI) needs the same behavior, and becomes invisible to developers who assume thin controllers.

Services should return a discriminated union `ServiceResult<T>` rather than throwing exceptions or returning raw data. This forces callers to handle both success and failure paths explicitly and keeps HTTP status code decisions in the controller where they belong.

```typescript
// The ServiceResult pattern — define once, use everywhere
type ServiceResult<T> =
  | { success: true; data: T }
  | { success: false; error: string; code?: string };
```

**Incorrect (fat server action with business logic, validation, and data access mixed together):**

```typescript
// ❌ app/actions/team.ts
"use server";

import { createClient } from "@/lib/supabase/server";
import { revalidatePath } from "next/cache";

export async function inviteTeamMember(formData: FormData) {
  const supabase = await createClient();

  const email = formData.get("email") as string;
  const teamId = formData.get("teamId") as string;
  const role = formData.get("role") as string;

  // ❌ Validation logic embedded in the server action
  if (!email || !email.includes("@")) {
    return { error: "Valid email is required" };
  }
  if (!["admin", "member", "viewer"].includes(role)) {
    return { error: "Invalid role" };
  }

  // ❌ Authorization logic in the server action
  const { data: currentUser } = await supabase.auth.getUser();
  const { data: membership } = await supabase
    .from("team_members")
    .select("role")
    .eq("team_id", teamId)
    .eq("user_id", currentUser.user?.id)
    .single();

  if (membership?.role !== "admin") {
    return { error: "Only admins can invite members" };
  }

  // ❌ Business rule (duplicate check) in the server action
  const { data: existing } = await supabase
    .from("team_invitations")
    .select("id")
    .eq("team_id", teamId)
    .eq("email", email)
    .eq("status", "pending")
    .single();

  if (existing) {
    return { error: "Invitation already pending for this email" };
  }

  // ❌ Data mutation directly in the server action
  const { error } = await supabase.from("team_invitations").insert({
    team_id: teamId,
    email,
    role,
    invited_by: currentUser.user?.id,
    expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
  });

  if (error) {
    return { error: "Failed to send invitation" };
  }

  // ❌ Side effects (email sending) mixed in with everything else
  await fetch(`${process.env.NEXT_PUBLIC_APP_URL}/api/email/send`, {
    method: "POST",
    body: JSON.stringify({
      to: email,
      template: "team-invite",
      data: { teamId, role },
    }),
  });

  revalidatePath(`/dashboard/teams/${teamId}`);
  return { success: true };
}
```

**Correct (thin server action delegating to a service that returns ServiceResult):**

```typescript
// ✅ lib/domain/types/team.ts
export interface TeamInvitation {
  id: string;
  teamId: string;
  email: string;
  role: "admin" | "member" | "viewer";
  invitedBy: string;
  status: "pending" | "accepted" | "expired";
  expiresAt: Date;
}

export interface InviteMemberInput {
  teamId: string;
  email: string;
  role: "admin" | "member" | "viewer";
  invitedByUserId: string;
}
```

```typescript
// ✅ lib/services/team-service.ts
import type { TeamInvitation, InviteMemberInput } from "@/lib/domain/types/team";
import type { TeamRepository } from "@/lib/repositories/team-repository";
import type { EmailService } from "@/lib/services/email-service";

export type ServiceResult<T> =
  | { success: true; data: T }
  | { success: false; error: string; code?: string };

const VALID_ROLES = ["admin", "member", "viewer"] as const;
const INVITATION_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

export class TeamService {
  constructor(
    private readonly teamRepo: TeamRepository,
    private readonly emailService: EmailService
  ) {}

  // ✅ All business logic in one testable method
  async inviteMember(input: InviteMemberInput): Promise<ServiceResult<TeamInvitation>> {
    // ✅ Validation
    if (!input.email || !input.email.includes("@")) {
      return { success: false, error: "Valid email is required", code: "INVALID_EMAIL" };
    }
    if (!VALID_ROLES.includes(input.role as (typeof VALID_ROLES)[number])) {
      return { success: false, error: "Invalid role", code: "INVALID_ROLE" };
    }

    // ✅ Authorization check via repository
    const membership = await this.teamRepo.getMembership(input.teamId, input.invitedByUserId);
    if (membership?.role !== "admin") {
      return { success: false, error: "Only admins can invite members", code: "FORBIDDEN" };
    }

    // ✅ Business rule: prevent duplicate invitations
    const existingInvite = await this.teamRepo.findPendingInvitation(input.teamId, input.email);
    if (existingInvite) {
      return { success: false, error: "Invitation already pending for this email", code: "DUPLICATE" };
    }

    // ✅ Create invitation through repository
    const invitation = await this.teamRepo.createInvitation({
      teamId: input.teamId,
      email: input.email,
      role: input.role,
      invitedBy: input.invitedByUserId,
      expiresAt: new Date(Date.now() + INVITATION_TTL_MS),
    });

    // ✅ Side effect handled by a dedicated service
    await this.emailService.sendTeamInvitation(input.email, {
      teamId: input.teamId,
      role: input.role,
      invitationId: invitation.id,
    });

    return { success: true, data: invitation };
  }
}
```

```typescript
// ✅ app/actions/team.ts — thin server action, only wiring and response mapping
"use server";

import { createClient } from "@/lib/supabase/server";
import { ServiceFactory } from "@/lib/factories/service-factory";
import { revalidatePath } from "next/cache";

export async function inviteTeamMember(formData: FormData) {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();

  if (!user) {
    return { error: "Not authenticated" };
  }

  const teamService = ServiceFactory.createTeamService();

  // ✅ Server action only extracts input and delegates
  const result = await teamService.inviteMember({
    teamId: formData.get("teamId") as string,
    email: formData.get("email") as string,
    role: formData.get("role") as "admin" | "member" | "viewer",
    invitedByUserId: user.id,
  });

  if (!result.success) {
    return { error: result.error };
  }

  revalidatePath(`/dashboard/teams/${result.data.teamId}`);
  return { success: true, data: { id: result.data.id } };
}
```

Reference: [Patterns of Enterprise Application Architecture - Service Layer](https://martinfowler.com/eaaCatalog/serviceLayer.html)
