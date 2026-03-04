---
title: Use Migration Files Instead of MCP or Dashboard SQL
description: "Schema changes via Supabase MCP, SQL editor, or dashboard don't create migration files. This causes schema drift between environments."
impact: HIGH
impact_description: prevents schema drift between local, staging, and production
tags: [security, supabase, migrations, schema, database, devops]
detection_grep: "CREATE TABLE"
---

## Use Migration Files Instead of MCP or Dashboard SQL

**Impact: HIGH (prevents schema drift between local, staging, and production)**

Supabase provides multiple ways to modify your database schema: the Dashboard SQL editor, the MCP tool, and the Supabase CLI with migration files. Only migration files create a versioned, reproducible record of schema changes. Using the Dashboard or MCP to create tables, alter columns, or add policies leaves no trace in your repository — leading to schema drift where production has tables that don't exist in your migration history.

This becomes critical when onboarding new developers, spinning up staging environments, or recovering from a disaster. If the schema isn't in migrations, it doesn't exist in your deployment pipeline.

**Incorrect (creating tables via Supabase MCP or Dashboard):**

```sql
-- ❌ Running this in the Supabase Dashboard SQL Editor or via MCP
-- No migration file is created — this change exists only in this environment
CREATE TABLE public.notifications (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid REFERENCES auth.users(id),
  message text NOT NULL,
  read boolean DEFAULT false,
  created_at timestamptz DEFAULT now()
);

ALTER TABLE public.notifications ENABLE ROW LEVEL SECURITY;

-- Problems:
-- 1. Not tracked in version control
-- 2. Other developers don't get this table when running `supabase db reset`
-- 3. CI/CD pipeline doesn't know about it
-- 4. Staging environment is missing it
-- 5. If production DB is recreated, this table is lost
```

**Incorrect (using the AI/MCP tool to modify schema):**

```typescript
// ❌ Using Supabase MCP tool to create tables
// This modifies the remote database directly with no migration trail
// supabase.mcp.createTable('notifications', { ... })
// The schema change is invisible to git, CI, and other environments
```

**Correct (CLI migration workflow):**

```bash
# Step 1: Create a new migration file
supabase migration new create_notifications_table

# This creates: supabase/migrations/20260303120000_create_notifications_table.sql
```

```sql
-- Step 2: Write the SQL in the migration file
-- supabase/migrations/20260303120000_create_notifications_table.sql

CREATE TABLE public.notifications (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid REFERENCES auth.users(id) NOT NULL,
  message text NOT NULL,
  read boolean DEFAULT false,
  created_at timestamptz DEFAULT now()
);

-- Index for foreign key (used in RLS policies and JOINs)
CREATE INDEX idx_notifications_user_id ON public.notifications(user_id);

-- Enable RLS
ALTER TABLE public.notifications ENABLE ROW LEVEL SECURITY;

-- Policies
CREATE POLICY "Users can view own notifications"
  ON public.notifications FOR SELECT
  USING (auth.uid() = user_id);

CREATE POLICY "Users can update own notifications"
  ON public.notifications FOR UPDATE
  USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);

-- Add a comment for documentation
COMMENT ON TABLE public.notifications IS 'User notification inbox';
```

```bash
# Step 3: Apply the migration locally
supabase db push

# Step 4: Regenerate types
supabase gen types typescript --local > src/types/database.ts

# Step 5: Commit migration + types together
git add supabase/migrations/ src/types/database.ts
git commit -m "feat: add notifications table with RLS"
```

**If you already made changes via Dashboard, capture them:**

```bash
# Pull remote schema changes into a migration file
supabase db diff --use-migra -f capture_dashboard_changes

# Review the generated migration, then commit it
# This retroactively tracks the change, but prevent this workflow going forward
```

**Detection hints:**

```bash
# Check if migrations directory has recent changes matching the schema
ls -la supabase/migrations/
# Compare local schema with remote
supabase db diff --use-migra
```

Reference: [Supabase CLI Migrations](https://supabase.com/docs/guides/cli/managing-environments) · [Supabase Local Development](https://supabase.com/docs/guides/local-development)
