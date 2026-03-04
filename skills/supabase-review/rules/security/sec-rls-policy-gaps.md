---
title: Close RLS Policy Gaps for All Operations
description: "Tables with RLS enabled but missing policies for certain operations silently deny access. Ensure every table has policies for SELECT, INSERT, UPDATE, and DELETE."
impact: HIGH
impact_description: prevents silent data access failures and hidden authorization gaps
tags: [security, supabase, rls, row-level-security, policies, authorization]
cwe: ["CWE-862"]
owasp: ["A01:2021"]
detection_grep: "ENABLE ROW LEVEL SECURITY"
---

## Close RLS Policy Gaps for All Operations

**Impact: HIGH (prevents silent data access failures and hidden authorization gaps)**

When RLS is enabled on a table but policies are missing for certain operations, those operations are **silently denied**. This is a common source of bugs where inserts, updates, or deletes fail without any error message. Worse, it can mask authorization gaps — a table might have a SELECT policy but no INSERT policy, leading developers to think the table is "read-only" when it should allow writes.

Every table with RLS must have explicit policies for all operations the application needs, or a `FOR ALL` policy if the same rule applies to every operation.

**Incorrect (RLS enabled with only SELECT policy):**

```sql
ALTER TABLE public.todos ENABLE ROW LEVEL SECURITY;

-- Only a SELECT policy — inserts, updates, and deletes silently fail
CREATE POLICY "Users can view own todos"
  ON public.todos FOR SELECT
  USING (auth.uid() = user_id);

-- ❌ This insert will silently return null with no error:
-- const { data, error } = await supabase.from('todos').insert({ title: 'Test', user_id: userId })
-- data = null, error = null — no indication of failure
```

**Incorrect (UPDATE policy missing WITH CHECK):**

```sql
-- ❌ UPDATE with only USING — user can see rows but the update may fail
-- if the updated values would change user_id
CREATE POLICY "Users can update own todos"
  ON public.todos FOR UPDATE
  USING (auth.uid() = user_id);
  -- Missing: WITH CHECK (auth.uid() = user_id)
  -- An attacker could potentially change user_id to another user's ID
```

**Correct (complete policies for all four operations):**

```sql
ALTER TABLE public.todos ENABLE ROW LEVEL SECURITY;

-- SELECT: Users can read their own todos
CREATE POLICY "Users can view own todos"
  ON public.todos FOR SELECT
  USING (auth.uid() = user_id);

-- INSERT: Users can create todos assigned to themselves
CREATE POLICY "Users can create own todos"
  ON public.todos FOR INSERT
  WITH CHECK (auth.uid() = user_id);

-- UPDATE: Users can update their own todos, cannot reassign ownership
CREATE POLICY "Users can update own todos"
  ON public.todos FOR UPDATE
  USING (auth.uid() = user_id)       -- can only see own rows
  WITH CHECK (auth.uid() = user_id); -- cannot change user_id to someone else

-- DELETE: Users can delete their own todos
CREATE POLICY "Users can delete own todos"
  ON public.todos FOR DELETE
  USING (auth.uid() = user_id);
```

**Using FOR ALL when the same rule applies everywhere:**

```sql
-- ✅ Shorthand when the ownership check is identical for all operations
CREATE POLICY "Users can manage own todos"
  ON public.todos FOR ALL
  USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);
```

**Relational RLS (access through parent table):**

```sql
-- Child table: comments belong to documents
-- Access rule: you can manage comments on documents you own

CREATE POLICY "Users can view comments on own documents"
  ON public.comments FOR SELECT
  USING (
    EXISTS (
      SELECT 1 FROM public.documents
      WHERE documents.id = comments.document_id
      AND documents.user_id = auth.uid()
    )
  );

CREATE POLICY "Users can add comments on own documents"
  ON public.comments FOR INSERT
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM public.documents
      WHERE documents.id = comments.document_id
      AND documents.user_id = auth.uid()
    )
  );

-- Repeat for UPDATE and DELETE with the same EXISTS check
```

**Team/organization access pattern:**

```sql
-- Users can access data for any team they belong to
CREATE POLICY "Team members can view team documents"
  ON public.documents FOR SELECT
  USING (
    team_id IN (
      SELECT team_id FROM public.team_members
      WHERE user_id = auth.uid()
    )
  );
```

**Detection hints:**

```bash
# Find tables with RLS enabled, then check which operations have policies
grep -rn "ENABLE ROW LEVEL SECURITY" supabase/migrations/ --include="*.sql"
# Check for INSERT/UPDATE/DELETE policies for each table
grep -rn "CREATE POLICY" supabase/migrations/ --include="*.sql"
```

Reference: [Supabase RLS Guide](https://supabase.com/docs/guides/database/postgres/row-level-security) · [PostgreSQL RLS Policies](https://www.postgresql.org/docs/current/ddl-rowsecurity.html)
