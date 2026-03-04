---
title: Enable RLS on Every Table with Complete Policies
description: "Every table must have Row Level Security enabled with at least one policy per operation. Tables without RLS are accessible to any authenticated user."
impact: CRITICAL
impact_description: prevents unauthorized data access across tenants
tags: [security, supabase, rls, row-level-security, postgresql, authorization]
cwe: ["CWE-862"]
owasp: ["A01:2021"]
detection_grep: "CREATE TABLE"
---

## Enable RLS on Every Table with Complete Policies

**Impact: CRITICAL (prevents unauthorized data access across tenants)**

Every table in a Supabase project **must** have Row Level Security (RLS) enabled. Without RLS, any authenticated user (or anyone with the `anon` key) can read, insert, update, and delete **all** rows in the table. This is the most dangerous security misconfiguration in Supabase applications — it turns every table into a public API.

Even with RLS enabled, you need at least one policy per operation type (SELECT, INSERT, UPDATE, DELETE) or access is silently denied for that operation.

**Incorrect (table without RLS — fully exposed):**

```sql
-- ❌ No RLS — any authenticated user can read/write ALL rows
CREATE TABLE public.documents (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid REFERENCES auth.users(id) NOT NULL,
  title text NOT NULL,
  content text,
  created_at timestamptz DEFAULT now()
);

-- Forgot ALTER TABLE ... ENABLE ROW LEVEL SECURITY
-- Forgot to create any policies
-- Result: SELECT * FROM documents returns ALL documents for ALL users
```

**Correct (RLS enabled with policies for all operations):**

```sql
-- ✅ Table with RLS enabled and complete policies
CREATE TABLE public.documents (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid REFERENCES auth.users(id) NOT NULL,
  title text NOT NULL,
  content text,
  created_at timestamptz DEFAULT now()
);

-- Step 1: Enable RLS
ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;

-- Step 2: SELECT — users can only read their own documents
CREATE POLICY "Users can view own documents"
  ON public.documents FOR SELECT
  USING (auth.uid() = user_id);

-- Step 3: INSERT — users can only insert with their own user_id
CREATE POLICY "Users can create own documents"
  ON public.documents FOR INSERT
  WITH CHECK (auth.uid() = user_id);

-- Step 4: UPDATE — users can only update their own documents
CREATE POLICY "Users can update own documents"
  ON public.documents FOR UPDATE
  USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);

-- Step 5: DELETE — users can only delete their own documents
CREATE POLICY "Users can delete own documents"
  ON public.documents FOR DELETE
  USING (auth.uid() = user_id);
```

**RLS checklist for every migration:**

```
[ ] ALTER TABLE ... ENABLE ROW LEVEL SECURITY
[ ] SELECT policy with USING clause
[ ] INSERT policy with WITH CHECK clause
[ ] UPDATE policy with both USING and WITH CHECK clauses
[ ] DELETE policy with USING clause
[ ] Index on the column used in policies (e.g., user_id)
[ ] Test: can user A read user B's rows? (should fail)
[ ] Test: can anon key read any rows? (should fail unless intended)
```

**Relational RLS (access through parent table):**

```sql
-- For child tables, reference the parent's ownership
CREATE POLICY "Users can view own document comments"
  ON public.comments FOR SELECT
  USING (
    EXISTS (
      SELECT 1 FROM public.documents
      WHERE documents.id = comments.document_id
      AND documents.user_id = auth.uid()
    )
  );
```

**Detection hints:**

```bash
# Find CREATE TABLE statements without corresponding RLS
grep -rn "CREATE TABLE" supabase/migrations/ --include="*.sql"
# Check if ENABLE ROW LEVEL SECURITY follows each CREATE TABLE
grep -rn "ENABLE ROW LEVEL SECURITY" supabase/migrations/ --include="*.sql"
```

Reference: [Supabase RLS Guide](https://supabase.com/docs/guides/database/postgres/row-level-security) · [CWE-862: Missing Authorization](https://cwe.mitre.org/data/definitions/862.html)
