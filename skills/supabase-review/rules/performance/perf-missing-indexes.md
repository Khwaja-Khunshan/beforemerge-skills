---
title: Add Indexes for Filtered and Ordered Columns
description: "Filtering or ordering on unindexed columns causes full table scans. RLS policy columns like user_id and org_id especially need indexes."
impact: HIGH
impact_description: prevents full table scans, 10-1000x query speedup on large tables
tags: [performance, supabase, postgresql, indexes, queries]
cwe: ["CWE-405"]
detection_grep: ".eq('"
---

## Add Indexes for Filtered and Ordered Columns

**Impact: HIGH (prevents full table scans, 10-1000x query speedup on large tables)**

Every `.eq()`, `.in()`, `.order()`, `.gt()`, `.lt()`, and `.neq()` filter in your Supabase queries translates to a `WHERE` or `ORDER BY` clause in PostgreSQL. Without an index on those columns, PostgreSQL performs a sequential scan — reading every row in the table to find matches. On a table with 100K+ rows, this turns sub-millisecond queries into multi-second operations.

This is especially critical for columns used in RLS policies. Every query on an RLS-enabled table evaluates the policy's `USING` clause, meaning `auth.uid() = user_id` effectively adds a `WHERE user_id = ?` to every query. Without an index on `user_id`, **every single query** on that table triggers a full table scan — even if the application query itself uses an indexed column.

**Incorrect (unindexed columns used in filters and RLS):**

```sql
-- ❌ Table with no indexes on commonly filtered columns
CREATE TABLE public.documents (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid REFERENCES auth.users(id) NOT NULL,
  org_id uuid REFERENCES public.organizations(id) NOT NULL,
  title text NOT NULL,
  status text NOT NULL DEFAULT 'draft',
  category text,
  content text,
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now()
);

ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;

-- ❌ RLS policy on user_id — but user_id has no index
CREATE POLICY "Users can view own documents"
  ON public.documents FOR SELECT
  USING (auth.uid() = user_id);

-- No indexes besides the primary key
-- Every query now does a full table scan
```

```typescript
// ❌ All these queries trigger sequential scans on large tables
const { data: drafts } = await supabase
  .from('documents')
  .select('id, title, updated_at')
  .eq('status', 'draft')           // No index on status
  .eq('org_id', orgId)             // No index on org_id
  .order('updated_at', { ascending: false })  // No index on updated_at

const { data: recent } = await supabase
  .from('documents')
  .select('id, title, category')
  .eq('user_id', userId)           // No index on user_id (also used by RLS)
  .gt('created_at', thirtyDaysAgo) // No index on created_at
  .order('created_at', { ascending: false })
```

**Correct (indexes on filtered, ordered, and RLS-referenced columns):**

```sql
-- ✅ Table with proper indexes for all query and RLS patterns
CREATE TABLE public.documents (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid REFERENCES auth.users(id) NOT NULL,
  org_id uuid REFERENCES public.organizations(id) NOT NULL,
  title text NOT NULL,
  status text NOT NULL DEFAULT 'draft',
  category text,
  content text,
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now()
);

ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;

-- ✅ Index for RLS policy — this is the most critical index
CREATE INDEX idx_documents_user_id ON public.documents (user_id);

-- ✅ Index for org-scoped queries (multi-tenant)
CREATE INDEX idx_documents_org_id ON public.documents (org_id);

-- ✅ Composite index for common query pattern: filter by org + status, order by updated_at
CREATE INDEX idx_documents_org_status_updated
  ON public.documents (org_id, status, updated_at DESC);

-- ✅ Index for date-range queries
CREATE INDEX idx_documents_user_created
  ON public.documents (user_id, created_at DESC);

-- ✅ RLS policy on indexed column
CREATE POLICY "Users can view own documents"
  ON public.documents FOR SELECT
  USING (auth.uid() = user_id);

-- ✅ Org-based RLS policy with indexed column
CREATE POLICY "Org members can view org documents"
  ON public.documents FOR SELECT
  USING (
    org_id IN (
      SELECT org_id FROM public.org_members
      WHERE user_id = auth.uid()
    )
  );
```

```typescript
// ✅ These queries now use indexes — sub-millisecond on millions of rows
const { data: drafts } = await supabase
  .from('documents')
  .select('id, title, updated_at')
  .eq('org_id', orgId)
  .eq('status', 'draft')
  .order('updated_at', { ascending: false })
  .limit(20)
// Uses idx_documents_org_status_updated — index scan, not seq scan

const { data: recent } = await supabase
  .from('documents')
  .select('id, title, category')
  .eq('user_id', userId)
  .gt('created_at', thirtyDaysAgo)
  .order('created_at', { ascending: false })
  .limit(50)
// Uses idx_documents_user_created — index scan with range filter
```

**How to verify with EXPLAIN ANALYZE:**

```sql
-- Run in Supabase SQL Editor to see if your query uses indexes
EXPLAIN ANALYZE
SELECT id, title, updated_at
FROM public.documents
WHERE org_id = 'some-uuid'
  AND status = 'draft'
ORDER BY updated_at DESC
LIMIT 20;

-- Look for these in the output:
-- ✅ "Index Scan using idx_documents_org_status_updated"
-- ✅ "Index Only Scan" (even better — doesn't touch the table)
-- ❌ "Seq Scan on documents" — means no index is being used
-- ❌ "Sort" — means ORDER BY isn't covered by an index
```

**Index checklist for every migration:**

```
[ ] Every column in an RLS USING clause has an index
[ ] Every column passed to .eq(), .in(), .neq() has an index
[ ] Every column passed to .order() is the last column in a composite index
[ ] Columns in subqueries within RLS policies are indexed (e.g., org_members.user_id)
[ ] Composite indexes match query patterns (filter columns first, sort column last)
[ ] Run EXPLAIN ANALYZE on the 5 most common queries
```

**Detection hints:**

```bash
# Find .eq() calls to identify columns that need indexes
grep -rn ".eq('" src/ --include="*.ts" --include="*.tsx"
# Find .order() calls — ORDER BY without index is expensive
grep -rn ".order('" src/ --include="*.ts" --include="*.tsx"
# Find CREATE TABLE without corresponding CREATE INDEX in migrations
grep -rn "CREATE TABLE" supabase/migrations/ --include="*.sql"
grep -rn "CREATE INDEX" supabase/migrations/ --include="*.sql"
```

Reference: [Supabase Index Advisor](https://supabase.com/docs/guides/database/extensions/index_advisor) · [PostgreSQL EXPLAIN](https://www.postgresql.org/docs/current/using-explain.html) · [Supabase Performance Optimization](https://supabase.com/docs/guides/platform/performance)
