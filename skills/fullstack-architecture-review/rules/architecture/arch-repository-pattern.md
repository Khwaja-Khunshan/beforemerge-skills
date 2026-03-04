---
title: Missing Repository Abstraction
description: "Database access belongs in repository classes, not in services or route handlers. Repositories abstract the data source behind a typed interface."
impact: HIGH
impact_description: Direct database calls in services tightly couple business logic to the data layer, preventing testing and making data source migrations costly
tags: [architecture, repository, abstraction, solid, data-access]
cwe: ["CWE-1057"]
detection_grep: "Repository"
---

## Missing Repository Abstraction

**Impact: HIGH (Direct database calls in services tightly couple business logic to the data layer, preventing testing and making data source migrations costly)**

The Repository pattern places a typed abstraction between business logic and data persistence. When a service calls `supabase.from("users").select("*")` directly, that service is coupled to Supabase's query API, its column naming conventions, and its error structure. You cannot unit test the service without a live database or an elaborate mock of the Supabase client. If you later need to read users from a cache, a different database, or an external API, every service that touches that table must change.

Repositories own the mapping between database rows and domain types, handle query construction and error translation, and expose a small surface area of typed methods (`findById`, `create`, `update`) that services consume.

**Incorrect (Supabase queries scattered directly in the service layer):**

```typescript
// ❌ lib/services/project-service.ts
import { createClient } from "@/lib/supabase/server";

export class ProjectService {
  async getProjectWithMembers(projectId: string, userId: string) {
    const supabase = await createClient();

    // ❌ Raw Supabase query in the service — coupled to table schema
    const { data: project, error: projectError } = await supabase
      .from("projects")
      .select("id, name, description, created_at, owner_id")
      .eq("id", projectId)
      .single();

    if (projectError) {
      throw new Error("Project not found");
    }

    // ❌ Second query in the service — service knows about join tables
    const { data: members } = await supabase
      .from("project_members")
      .select(`
        user_id,
        role,
        users (id, full_name, avatar_url, email)
      `)
      .eq("project_id", projectId);

    // ❌ Authorization check uses raw query — logic is untestable
    const isMember = members?.some((m) => m.user_id === userId);
    if (!isMember) {
      throw new Error("Not a project member");
    }

    // ❌ Manual mapping from snake_case DB columns — duplicated everywhere
    return {
      id: project.id,
      name: project.name,
      description: project.description,
      createdAt: project.created_at,
      ownerId: project.owner_id,
      members: members?.map((m) => ({
        userId: m.user_id,
        role: m.role,
        name: (m.users as any).full_name,
        avatarUrl: (m.users as any).avatar_url,
        email: (m.users as any).email,
      })),
    };
  }

  async archiveProject(projectId: string) {
    const supabase = await createClient();

    // ❌ Another raw query — if the column name changes, every service breaks
    const { error } = await supabase
      .from("projects")
      .update({ archived_at: new Date().toISOString(), status: "archived" })
      .eq("id", projectId);

    if (error) {
      throw new Error("Failed to archive project");
    }
  }
}
```

**Correct (repository abstracts all data access behind typed methods):**

```typescript
// ✅ lib/domain/types/project.ts
export interface Project {
  id: string;
  name: string;
  description: string | null;
  ownerId: string;
  status: "active" | "archived";
  createdAt: Date;
  archivedAt: Date | null;
}

export interface ProjectMember {
  userId: string;
  role: "owner" | "editor" | "viewer";
  name: string;
  avatarUrl: string | null;
  email: string;
}

export interface ProjectWithMembers extends Project {
  members: ProjectMember[];
}
```

```typescript
// ✅ lib/repositories/project-repository.ts
import type { Project, ProjectMember, ProjectWithMembers } from "@/lib/domain/types/project";
import { createClient } from "@/lib/supabase/server";

export class ProjectRepository {
  // ✅ Typed method with a clear contract — callers never see Supabase types
  async findById(projectId: string): Promise<Project | null> {
    const supabase = await createClient();
    const { data, error } = await supabase
      .from("projects")
      .select("id, name, description, owner_id, status, created_at, archived_at")
      .eq("id", projectId)
      .single();

    if (error || !data) return null;
    return this.toProject(data);
  }

  // ✅ Join logic encapsulated — services don't know about join tables
  async findWithMembers(projectId: string): Promise<ProjectWithMembers | null> {
    const supabase = await createClient();

    const { data: project, error } = await supabase
      .from("projects")
      .select("id, name, description, owner_id, status, created_at, archived_at")
      .eq("id", projectId)
      .single();

    if (error || !project) return null;

    const { data: memberRows } = await supabase
      .from("project_members")
      .select(`
        user_id,
        role,
        users (id, full_name, avatar_url, email)
      `)
      .eq("project_id", projectId);

    return {
      ...this.toProject(project),
      members: (memberRows ?? []).map((m) => this.toMember(m)),
    };
  }

  // ✅ Membership check is a repository concern — simple, fast query
  async isMember(projectId: string, userId: string): Promise<boolean> {
    const supabase = await createClient();
    const { data } = await supabase
      .from("project_members")
      .select("user_id")
      .eq("project_id", projectId)
      .eq("user_id", userId)
      .single();

    return data !== null;
  }

  // ✅ Write operations also go through the repository
  async archive(projectId: string): Promise<void> {
    const supabase = await createClient();
    const { error } = await supabase
      .from("projects")
      .update({ archived_at: new Date().toISOString(), status: "archived" })
      .eq("id", projectId);

    if (error) {
      throw new Error(`Failed to archive project: ${error.message}`);
    }
  }

  // ✅ Mapping is centralized — column renames only change this file
  private toProject(row: Record<string, unknown>): Project {
    return {
      id: row.id as string,
      name: row.name as string,
      description: (row.description as string) ?? null,
      ownerId: row.owner_id as string,
      status: row.status as Project["status"],
      createdAt: new Date(row.created_at as string),
      archivedAt: row.archived_at ? new Date(row.archived_at as string) : null,
    };
  }

  private toMember(row: Record<string, unknown>): ProjectMember {
    const user = row.users as Record<string, unknown>;
    return {
      userId: row.user_id as string,
      role: row.role as ProjectMember["role"],
      name: user.full_name as string,
      avatarUrl: (user.avatar_url as string) ?? null,
      email: user.email as string,
    };
  }
}
```

```typescript
// ✅ lib/services/project-service.ts — clean, testable, no data access
import type { ProjectWithMembers } from "@/lib/domain/types/project";
import type { ProjectRepository } from "@/lib/repositories/project-repository";

type ServiceResult<T> =
  | { success: true; data: T }
  | { success: false; error: string; code?: string };

export class ProjectService {
  constructor(private readonly projectRepo: ProjectRepository) {}

  async getProjectWithMembers(
    projectId: string,
    userId: string
  ): Promise<ServiceResult<ProjectWithMembers>> {
    // ✅ Service calls repository methods — no idea how data is fetched
    const isMember = await this.projectRepo.isMember(projectId, userId);
    if (!isMember) {
      return { success: false, error: "Not a project member", code: "FORBIDDEN" };
    }

    const project = await this.projectRepo.findWithMembers(projectId);
    if (!project) {
      return { success: false, error: "Project not found", code: "NOT_FOUND" };
    }

    return { success: true, data: project };
  }

  async archiveProject(
    projectId: string,
    userId: string
  ): Promise<ServiceResult<void>> {
    const project = await this.projectRepo.findById(projectId);
    if (!project) {
      return { success: false, error: "Project not found", code: "NOT_FOUND" };
    }

    if (project.ownerId !== userId) {
      return { success: false, error: "Only the owner can archive a project", code: "FORBIDDEN" };
    }

    if (project.status === "archived") {
      return { success: false, error: "Project is already archived", code: "CONFLICT" };
    }

    await this.projectRepo.archive(projectId);
    return { success: true, data: undefined };
  }
}
```

Reference: [Patterns of Enterprise Application Architecture - Repository](https://martinfowler.com/eaaCatalog/repository.html)
