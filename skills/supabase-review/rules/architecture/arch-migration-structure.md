---
title: Follow Canonical Migration File Structure
description: "Migration files without proper structure (table, indexes, RLS, policies, comments) are harder to review and prone to missing critical steps like RLS."
impact: MEDIUM
impact_description: ensures complete and reviewable migration files
tags: [architecture, supabase, migrations, postgresql, database, structure]
detection_grep: "CREATE TABLE"
---

## Follow Canonical Migration File Structure

**Impact: MEDIUM (ensures complete and reviewable migration files)**

Migration files are the source of truth for your database schema. Unstructured migrations — where tables, indexes, policies, and grants are scattered randomly — are difficult to review, easy to leave incomplete (missing RLS is the most common gap), and hard to debug when something goes wrong.

Following a consistent structure ensures every migration includes all necessary components and makes code review straightforward.

**Incorrect (unstructured migration — easy to miss things):**

```sql
-- ❌ No structure, missing sections, hard to review
-- supabase/migrations/20260303120000_create_stuff.sql

CREATE TABLE public.projects (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL,
  user_id uuid REFERENCES auth.users(id),
  team_id uuid REFERENCES public.teams(id),
  settings jsonb DEFAULT '{}',
  created_at timestamptz DEFAULT now()
);

-- Reviewer has to check: Did they add RLS? Indexes? Policies?
-- Answer: No RLS, no indexes on foreign keys, no policies
-- This is the #1 source of security bugs in Supabase apps
```

**Correct (canonical migration structure):**

```sql
-- supabase/migrations/20260303120000_create_projects.sql
-- Description: Create projects table with team-based access control
-- Related: Depends on teams table (migration 20260301...)

-- ============================================================================
-- 1. TABLE DEFINITION
-- ============================================================================
CREATE TABLE public.projects (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid REFERENCES auth.users(id) NOT NULL,
  team_id uuid REFERENCES public.teams(id) NOT NULL,
  name text NOT NULL,
  description text,
  status text NOT NULL DEFAULT 'active'
    CHECK (status IN ('active', 'archived', 'deleted')),
  settings jsonb DEFAULT '{}',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- ============================================================================
-- 2. INDEXES
-- ============================================================================
-- Foreign key indexes (required for JOINs and RLS performance)
CREATE INDEX idx_projects_user_id ON public.projects(user_id);
CREATE INDEX idx_projects_team_id ON public.projects(team_id);

-- Query-pattern indexes
CREATE INDEX idx_projects_team_status ON public.projects(team_id, status)
  WHERE status != 'deleted';

-- ============================================================================
-- 3. ROW LEVEL SECURITY
-- ============================================================================
ALTER TABLE public.projects ENABLE ROW LEVEL SECURITY;

-- ============================================================================
-- 4. POLICIES
-- ============================================================================
-- SELECT: Team members can view team projects
CREATE POLICY "Team members can view projects"
  ON public.projects FOR SELECT
  USING (
    team_id IN (
      SELECT team_id FROM public.team_members
      WHERE user_id = auth.uid()
    )
  );

-- INSERT: Team members can create projects in their teams
CREATE POLICY "Team members can create projects"
  ON public.projects FOR INSERT
  WITH CHECK (
    team_id IN (
      SELECT team_id FROM public.team_members
      WHERE user_id = auth.uid()
    )
    AND user_id = auth.uid()  -- creator must be the authenticated user
  );

-- UPDATE: Only project owner or team admin can update
CREATE POLICY "Project owner or team admin can update"
  ON public.projects FOR UPDATE
  USING (
    user_id = auth.uid()
    OR team_id IN (
      SELECT team_id FROM public.team_members
      WHERE user_id = auth.uid() AND role = 'admin'
    )
  )
  WITH CHECK (
    user_id = auth.uid()
    OR team_id IN (
      SELECT team_id FROM public.team_members
      WHERE user_id = auth.uid() AND role = 'admin'
    )
  );

-- DELETE: Only team admin can delete
CREATE POLICY "Team admin can delete projects"
  ON public.projects FOR DELETE
  USING (
    team_id IN (
      SELECT team_id FROM public.team_members
      WHERE user_id = auth.uid() AND role = 'admin'
    )
  );

-- ============================================================================
-- 5. TRIGGERS
-- ============================================================================
-- Auto-update updated_at timestamp
CREATE OR REPLACE FUNCTION public.set_updated_at()
RETURNS trigger AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER set_projects_updated_at
  BEFORE UPDATE ON public.projects
  FOR EACH ROW
  EXECUTE FUNCTION public.set_updated_at();

-- ============================================================================
-- 6. COMMENTS
-- ============================================================================
COMMENT ON TABLE public.projects IS 'Team projects with ownership and status tracking';
COMMENT ON COLUMN public.projects.settings IS 'JSON config: { notifications: bool, visibility: "public"|"private" }';
COMMENT ON COLUMN public.projects.status IS 'One of: active, archived, deleted';
```

**Migration checklist (copy into PR template):**

```markdown
## Migration Checklist
- [ ] Table has `NOT NULL` on required columns
- [ ] Foreign keys reference correct parent tables
- [ ] CHECK constraints on enum-like text columns
- [ ] Indexes on all foreign key columns
- [ ] Indexes on columns used in WHERE/ORDER BY
- [ ] `ALTER TABLE ... ENABLE ROW LEVEL SECURITY`
- [ ] SELECT policy
- [ ] INSERT policy with `WITH CHECK`
- [ ] UPDATE policy with both `USING` and `WITH CHECK`
- [ ] DELETE policy
- [ ] `updated_at` trigger if table has that column
- [ ] COMMENT ON TABLE and non-obvious columns
- [ ] Types regenerated: `npm run db:types`
```

**Detection hints:**

```bash
# Find migrations missing RLS
grep -rn "CREATE TABLE" supabase/migrations/ --include="*.sql" -l
grep -rn "ENABLE ROW LEVEL SECURITY" supabase/migrations/ --include="*.sql" -l
# Compare the two lists — any CREATE TABLE file missing from the RLS list is a gap
```

Reference: [Supabase Migrations](https://supabase.com/docs/guides/cli/managing-environments) · [PostgreSQL CREATE TABLE](https://www.postgresql.org/docs/current/sql-createtable.html)
