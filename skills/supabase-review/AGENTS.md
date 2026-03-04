# BeforeMerge: supabase-review

Code review rules for Supabase applications. Covers RLS security, auth patterns, query performance, migration workflows, and type safety. Each rule includes incorrect/correct examples, CWE/OWASP mappings, and detection hints.

## Table of Contents

### 1. Security Anti-Patterns (CRITICAL)
- 1. Never Expose Service Role Key in Client-Side Code — CRITICAL [CWE-798]
- 2. Use getUser() Instead of getSession() for Auth Checks — CRITICAL [CWE-287]
- 3. Use Migration Files Instead of MCP or Dashboard SQL — HIGH
- 4. Enable RLS on Every Table with Complete Policies — CRITICAL [CWE-862]
- 5. Close RLS Policy Gaps for All Operations — HIGH [CWE-862]
- 6. Never Log Sensitive Data — HIGH [CWE-532]
- 7. Never Use Service Role Client in Auth-Context Routes — CRITICAL [CWE-269]
- 8. Prevent SQL Injection in Custom RPC Functions — CRITICAL [CWE-89]
### 2. Performance Patterns (HIGH)
- 9. Use Batch Operations Instead of Single-Row Loops — HIGH
- 10. Use Connection Pooling (Supavisor) for Serverless Deployments — HIGH
- 11. Use Cursor-Based Pagination Instead of Offset Pagination — HIGH
- 12. Add Indexes for Filtered and Ordered Columns — HIGH [CWE-405]
- 13. Avoid N+1 Queries with Supabase Relational Selects — HIGH [CWE-400]
- 14. Avoid select('*') — Request Only the Columns You Need — HIGH
### 3. Architecture Patterns (MEDIUM)
- 15. Use the Correct Supabase Client for Each Context — HIGH
- 16. Follow Canonical Migration File Structure — MEDIUM
- 17. Generate Database Types from Schema — MEDIUM
### 4. Code Quality (LOW-MEDIUM)
- 18. Distinguish Not-Found from Other Supabase Errors — MEDIUM
- 19. Always Check Error Before Using Data from Supabase Queries — HIGH [CWE-252]
- 20. Validate Input at Runtime with Zod Instead of Type Assertions — HIGH [CWE-20]

---

## Rules

## Never Expose Service Role Key in Client-Side Code

**Impact: CRITICAL (prevents complete RLS bypass via leaked service role key)**

Next.js embeds any environment variable prefixed with `NEXT_PUBLIC_` into the client-side JavaScript bundle at build time. If `SUPABASE_SERVICE_ROLE_KEY` or `DATABASE_URL` is given a `NEXT_PUBLIC_` prefix, the secret is shipped to every browser that loads the app. Anyone can extract it from the bundle and use it to bypass all Row Level Security policies, gaining full read/write access to every table.

This also applies to `.env` files: variables without the `NEXT_PUBLIC_` prefix are only available server-side, which is the correct behavior for secrets.

**Incorrect (service role key exposed to client):**

```env
# .env.local
# ❌ NEXT_PUBLIC_ prefix ships this to the browser bundle
NEXT_PUBLIC_SUPABASE_URL=https://abc.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJ...anon...
NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=eyJ...service_role...
NEXT_PUBLIC_DATABASE_URL=postgresql://postgres:password@db.abc.supabase.co:5432/postgres
```

```typescript
// lib/supabase/client.ts
// ❌ Service role key accessible in browser — attacker can read it from JS bundle
import { createClient } from '@supabase/supabase-js'

export const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY!  // ❌ Full DB access in browser
)
```

**Correct (server-only env vars for secrets):**

```env
# .env.local
# ✅ Public vars (safe for browser — anon key is designed to be public)
NEXT_PUBLIC_SUPABASE_URL=https://abc.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJ...anon...

# ✅ Server-only vars (no NEXT_PUBLIC_ prefix — never reaches the browser)
SUPABASE_SERVICE_ROLE_KEY=eyJ...service_role...
DATABASE_URL=postgresql://postgres:password@db.abc.supabase.co:5432/postgres
```

```typescript
// lib/supabase/browser.ts
// ✅ Browser client uses only the anon key (public, RLS-enforced)
import { createBrowserClient } from '@supabase/ssr'

export function createClient() {
  return createBrowserClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!
  )
}
```

```typescript
// lib/supabase/service-role.ts
// ✅ Service role client is server-only — import guard prevents client usage
import 'server-only'  // Throws build error if imported from client component

import { createClient } from '@supabase/supabase-js'

export function createServiceRoleClient() {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY  // No NEXT_PUBLIC_ prefix

  if (!url || !key) {
    throw new Error('Missing Supabase service role environment variables')
  }

  return createClient(url, key, {
    auth: {
      autoRefreshToken: false,
      persistSession: false,
    },
  })
}
```

**Validating env vars at startup:**

```typescript
// lib/env.ts
import { z } from 'zod'

// ✅ Validate all env vars at startup — fail fast if misconfigured
const envSchema = z.object({
  NEXT_PUBLIC_SUPABASE_URL: z.string().url(),
  NEXT_PUBLIC_SUPABASE_ANON_KEY: z.string().min(1),
  SUPABASE_SERVICE_ROLE_KEY: z.string().min(1),
  DATABASE_URL: z.string().startsWith('postgresql://'),
})

// This runs at import time — app won't start with missing vars
export const env = envSchema.parse(process.env)
```

**Detection hints:**

```bash
# Find any NEXT_PUBLIC_ vars that look like secrets
grep -rn "NEXT_PUBLIC_.*SERVICE\|NEXT_PUBLIC_.*SECRET\|NEXT_PUBLIC_.*PASSWORD\|NEXT_PUBLIC_.*DATABASE" . --include="*.env*" --include="*.ts"
# Check if service role key is used in any client-side files
grep -rn "SUPABASE_SERVICE_ROLE_KEY" src/components/ src/app/**/page.tsx --include="*.tsx"
# Verify 'server-only' import on service role client
grep -rn "server-only" src/lib/supabase/ --include="*.ts"
```

Reference: [Next.js Environment Variables](https://nextjs.org/docs/app/building-your-application/configuring/environment-variables) · [Supabase API Keys](https://supabase.com/docs/guides/api/api-keys) · [CWE-798: Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

---

## Use getUser() Instead of getSession() for Auth Checks

**Impact: CRITICAL (prevents authentication bypass via cookie tampering)**

`supabase.auth.getSession()` reads the session from cookies/local storage **without** verifying the JWT with the Supabase Auth server. An attacker can forge or tamper with the session cookie to impersonate any user. `supabase.auth.getUser()` sends the access token to Supabase Auth for server-side verification, making it the only safe method for authentication checks.

The Supabase docs explicitly warn: "Never trust `getSession()` inside server-side code such as middleware, server components, or route handlers. It isn't guaranteed to revalidate the auth token."

**Incorrect (getSession can be spoofed from cookies):**

```typescript
// app/api/profile/route.ts
import { createClient } from '@/lib/supabase/server'

export async function GET() {
  const supabase = await createClient()

  // ❌ getSession() reads from cookies — attacker can forge this
  const { data: { session } } = await supabase.auth.getSession()

  if (!session) {
    return Response.json({ error: 'Unauthorized' }, { status: 401 })
  }

  // ❌ session.user.id could be any user ID the attacker chose
  const { data: profile } = await supabase
    .from('profiles')
    .select('*')
    .eq('id', session.user.id)
    .single()

  return Response.json(profile)
}
```

**Correct (getUser verifies with Supabase Auth server):**

```typescript
// app/api/profile/route.ts
import { createClient } from '@/lib/supabase/server'

export async function GET() {
  const supabase = await createClient()

  // ✅ getUser() sends the token to Supabase Auth for verification
  const { data: { user }, error } = await supabase.auth.getUser()

  if (error || !user) {
    return Response.json({ error: 'Unauthorized' }, { status: 401 })
  }

  // ✅ user.id is verified by the auth server — cannot be spoofed
  const { data: profile } = await supabase
    .from('profiles')
    .select('id, display_name, avatar_url')
    .eq('id', user.id)
    .single()

  return Response.json(profile)
}
```

**When getSession() is acceptable:**

`getSession()` is safe for **non-security** purposes only — such as reading the session to display UI elements (showing a username in a nav bar) or checking if a user is logged in for client-side routing. Never use it for:
- Authorization decisions (can this user do X?)
- Data access control (fetching data scoped to a user)
- Server-side auth checks (middleware, route handlers, server actions)

**Detection hints:**

```bash
# Find all getSession() calls — each one needs review
grep -rn "getSession" src/ --include="*.ts" --include="*.tsx"
# Find server-side files using getSession (high-priority)
grep -rn "getSession" src/app/api/ src/app/actions/ src/middleware.ts --include="*.ts"
```

Reference: [Supabase Auth — getUser()](https://supabase.com/docs/reference/javascript/auth-getuser) · [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)

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

---

## Never Log Sensitive Data

**Impact: HIGH (prevents credential leaks through log aggregation services)**

Logging sensitive data — OAuth tokens, refresh tokens, API keys, passwords, session IDs, or Personally Identifiable Information (PII) — exposes secrets to anyone with access to your log aggregation service (Datadog, Vercel Logs, CloudWatch, etc.). Supabase applications frequently handle auth tokens, and it is common during debugging to log entire session objects or error payloads that contain secrets.

Logs are often retained for weeks or months, indexed for search, and accessible to broader teams than the database itself. A single `console.log(session)` can expose every user's refresh token.

**Incorrect (logging auth tokens and session data):**

```typescript
// ❌ Logging the entire session object — contains access_token and refresh_token
const { data: { session }, error } = await supabase.auth.getSession()
console.log('Session:', session)
// Output includes: { access_token: "eyJ...", refresh_token: "abc123...", user: { email: "..." } }

// ❌ Logging OAuth callback data
export async function GET(request: Request) {
  const { searchParams } = new URL(request.url)
  const code = searchParams.get('code')
  console.log('OAuth code:', code) // ❌ Authorization codes are sensitive

  const { data, error } = await supabase.auth.exchangeCodeForSession(code!)
  console.log('Exchange result:', data) // ❌ Contains tokens
  console.log('Auth error:', error) // ❌ May contain token fragments in error message
}
```

```typescript
// ❌ Logging user PII
const { data: user } = await supabase.auth.getUser()
console.log('User logged in:', user)
// Logs email, phone, full name, metadata — all PII

// ❌ Logging API keys in error context
try {
  const response = await fetch(url, {
    headers: { Authorization: `Bearer ${process.env.SUPABASE_SERVICE_ROLE_KEY}` },
  })
} catch (err) {
  console.error('Request failed:', { url, headers: { Authorization: `Bearer ${process.env.SUPABASE_SERVICE_ROLE_KEY}` } })
  // ❌ Service role key is now in your logs
}
```

**Correct (scoped logging with sanitization):**

```typescript
// ✅ Log only non-sensitive identifiers
const { data: { user }, error } = await supabase.auth.getUser()

if (error) {
  console.error('Auth failed:', { code: error.status, message: error.message })
} else {
  console.log('User authenticated:', { userId: user.id })
  // Only log the user ID — not email, name, or tokens
}
```

```typescript
// ✅ Create a sanitized logger utility
const SENSITIVE_KEYS = new Set([
  'access_token', 'refresh_token', 'token', 'password',
  'secret', 'authorization', 'cookie', 'session_id',
  'email', 'phone', 'ssn', 'api_key', 'service_role',
])

function sanitize(obj: Record<string, unknown>): Record<string, unknown> {
  const sanitized: Record<string, unknown> = {}
  for (const [key, value] of Object.entries(obj)) {
    if (SENSITIVE_KEYS.has(key.toLowerCase())) {
      sanitized[key] = '[REDACTED]'
    } else if (typeof value === 'object' && value !== null) {
      sanitized[key] = sanitize(value as Record<string, unknown>)
    } else {
      sanitized[key] = value
    }
  }
  return sanitized
}

// Usage
console.log('Auth result:', sanitize(data as Record<string, unknown>))
```

```typescript
// ✅ Use error IDs for grouping instead of logging details
import { randomUUID } from 'crypto'

export async function handleAuthCallback(code: string) {
  const errorId = randomUUID()

  const { data, error } = await supabase.auth.exchangeCodeForSession(code)

  if (error) {
    // Log the error ID and category — not the token or code
    console.error('Auth callback failed:', {
      errorId,
      errorCode: error.status,
      errorName: error.name,
      // NOT: code, token, refresh_token, user email
    })

    // Return errorId to the client for support correlation
    return { error: 'Authentication failed', errorId }
  }

  console.log('Auth callback succeeded:', { userId: data.user.id, errorId })
  return { success: true }
}
```

**Detection hints:**

```bash
# Find console.log/error calls that might contain sensitive data
grep -rn "console\.\(log\|error\|warn\)" src/ --include="*.ts" --include="*.tsx"
# Look for logging of session, token, or key variables
grep -rn "console.*\(session\|token\|key\|password\|secret\)" src/ --include="*.ts"
```

Reference: [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) · [CWE-532: Information Exposure Through Log Files](https://cwe.mitre.org/data/definitions/532.html)

---

## Never Use Service Role Client in Auth-Context Routes

**Impact: CRITICAL (prevents complete RLS bypass in user-facing endpoints)**

The Supabase service role client (`createServiceRoleClient()`) uses the `service_role` key which **bypasses all Row Level Security policies**. It has full read/write access to every table, every row, with no restrictions. Using it in API routes, server actions, or any endpoint that handles user requests means an attacker only needs to call that endpoint to access all data.

The service role client should **only** be used in trusted server-side contexts like cron jobs, webhooks from trusted services, or admin operations that have already verified admin privileges through a separate mechanism.

**Incorrect (service role in an API route — bypasses all RLS):**

```typescript
// app/api/documents/route.ts
import { createServiceRoleClient } from '@/lib/supabase/service-role'

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url)
  const userId = searchParams.get('userId')

  // ❌ Service role bypasses RLS — this returns ALL documents
  // regardless of who the authenticated user is
  const supabase = createServiceRoleClient()

  const { data } = await supabase
    .from('documents')
    .select('*')
    .eq('user_id', userId)

  // An attacker can change userId param to any user's ID
  return Response.json(data)
}
```

**Incorrect (service role in a server action):**

```typescript
'use server'

import { createServiceRoleClient } from '@/lib/supabase/service-role'

export async function updateProfile(formData: FormData) {
  // ❌ Service role in a server action — any user can update any profile
  const supabase = createServiceRoleClient()

  await supabase
    .from('profiles')
    .update({ display_name: formData.get('name') as string })
    .eq('id', formData.get('userId') as string)
}
```

**Correct (server client that respects RLS):**

```typescript
// app/api/documents/route.ts
import { createClient } from '@/lib/supabase/server'

export async function GET() {
  // ✅ Server client respects RLS — only returns current user's documents
  const supabase = await createClient()

  const { data: { user }, error: authError } = await supabase.auth.getUser()
  if (authError || !user) {
    return Response.json({ error: 'Unauthorized' }, { status: 401 })
  }

  const { data } = await supabase
    .from('documents')
    .select('id, title, created_at')

  // RLS ensures only the authenticated user's documents are returned
  return Response.json(data)
}
```

**Correct (service role ONLY for admin operations with explicit check):**

```typescript
// app/api/admin/users/route.ts
import { createClient } from '@/lib/supabase/server'
import { createServiceRoleClient } from '@/lib/supabase/service-role'

export async function DELETE(request: Request) {
  // Step 1: Authenticate with the regular client
  const supabase = await createClient()
  const { data: { user } } = await supabase.auth.getUser()

  if (!user) {
    return Response.json({ error: 'Unauthorized' }, { status: 401 })
  }

  // Step 2: Verify admin role through RLS-protected query
  const { data: profile } = await supabase
    .from('profiles')
    .select('role')
    .eq('id', user.id)
    .single()

  if (profile?.role !== 'admin') {
    return Response.json({ error: 'Forbidden' }, { status: 403 })
  }

  // Step 3: Only NOW use service role for admin-only operation
  const adminClient = createServiceRoleClient()
  const { userId } = await request.json()

  await adminClient.auth.admin.deleteUser(userId)

  return Response.json({ success: true })
}
```

**Correct (service role for cron jobs / background tasks):**

```typescript
// app/api/cron/cleanup/route.ts
import { createServiceRoleClient } from '@/lib/supabase/service-role'

export async function POST(request: Request) {
  // Verify this is from your cron service (e.g., Vercel Cron)
  const authHeader = request.headers.get('Authorization')
  if (authHeader !== `Bearer ${process.env.CRON_SECRET}`) {
    return Response.json({ error: 'Unauthorized' }, { status: 401 })
  }

  // ✅ Service role is appropriate here — no user context, trusted caller
  const supabase = createServiceRoleClient()

  await supabase
    .from('temp_files')
    .delete()
    .lt('created_at', new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString())

  return Response.json({ success: true })
}
```

**Detection hints:**

```bash
# Find all service role client usage — each needs justification
grep -rn "createServiceRoleClient\|serviceRole\|service_role" src/ --include="*.ts"
# Check if service role is used in API routes or server actions
grep -rn "createServiceRoleClient" src/app/ --include="*.ts" --include="*.tsx"
```

Reference: [Supabase API Keys](https://supabase.com/docs/guides/api/api-keys) · [CWE-269: Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html)

---

## Prevent SQL Injection in Custom RPC Functions

**Impact: CRITICAL (prevents arbitrary SQL execution via user-controlled input)**

Supabase's PostgREST layer handles parameterization for standard CRUD queries (`.from().select()`, `.insert()`, etc.), making them safe from SQL injection. However, custom RPC functions called via `.rpc()` that build SQL with string concatenation or interpolation inside `EXECUTE` statements are fully vulnerable to SQL injection.

This is especially dangerous because RPC functions run with the caller's permissions (or the function owner's, if `SECURITY DEFINER`), and a successful injection can read, modify, or delete any data the function has access to.

**Incorrect (string concatenation in EXECUTE):**

```sql
-- ❌ SQL injection via string concatenation in PostgreSQL function
CREATE OR REPLACE FUNCTION search_rules(search_term text)
RETURNS SETOF rule AS $$
BEGIN
  -- Attacker can inject: ' OR 1=1 --
  -- Or worse: '; DROP TABLE rule; --
  RETURN QUERY EXECUTE
    'SELECT * FROM rule WHERE title LIKE ''%' || search_term || '%''';
END;
$$ LANGUAGE plpgsql;
```

```typescript
// app/api/rules/search/route.ts
export async function GET(request: Request) {
  const { searchParams } = new URL(request.url)
  const query = searchParams.get('q') ?? ''

  // ❌ User input goes directly into the vulnerable function
  const { data } = await supabase.rpc('search_rules', {
    search_term: query  // attacker sends: "' OR 1=1 --"
  })

  return Response.json(data)
}
```

**Correct (parameterized query with EXECUTE ... USING):**

```sql
-- ✅ Parameterized query prevents injection
CREATE OR REPLACE FUNCTION search_rules(search_term text)
RETURNS SETOF rule AS $$
BEGIN
  RETURN QUERY EXECUTE
    'SELECT * FROM rule WHERE title ILIKE $1'
    USING '%' || search_term || '%';
END;
$$ LANGUAGE plpgsql;
```

**Correct (avoid EXECUTE entirely when possible):**

```sql
-- ✅ Static SQL with parameters — no EXECUTE needed
CREATE OR REPLACE FUNCTION search_rules(search_term text)
RETURNS SETOF rule AS $$
  SELECT * FROM rule
  WHERE title ILIKE '%' || search_term || '%'
  ORDER BY created_at DESC
  LIMIT 50;
$$ LANGUAGE sql STABLE;
```

**Dynamic column names (allowlist pattern):**

```sql
-- ✅ Dynamic ORDER BY with format('%I') for identifier escaping
CREATE OR REPLACE FUNCTION list_rules(
  sort_column text DEFAULT 'created_at',
  sort_dir text DEFAULT 'desc'
)
RETURNS SETOF rule AS $$
BEGIN
  -- Validate sort_column against allowlist
  IF sort_column NOT IN ('created_at', 'title', 'impact', 'updated_at') THEN
    RAISE EXCEPTION 'Invalid sort column: %', sort_column;
  END IF;

  IF sort_dir NOT IN ('asc', 'desc') THEN
    RAISE EXCEPTION 'Invalid sort direction: %', sort_dir;
  END IF;

  -- %I safely quotes identifiers (prevents injection)
  RETURN QUERY EXECUTE
    format('SELECT * FROM rule ORDER BY %I %s LIMIT 100', sort_column, sort_dir);
END;
$$ LANGUAGE plpgsql STABLE;
```

**Detection hints:**

```bash
# Find all RPC calls that might pass user input
grep -rn ".rpc(" src/ --include="*.ts" --include="*.tsx"
# Find EXECUTE statements in migrations (check for parameterization)
grep -rn "EXECUTE" supabase/migrations/ --include="*.sql"
# Find string concatenation in SQL functions
grep -rn "||" supabase/migrations/ --include="*.sql"
```

Reference: [PostgreSQL EXECUTE](https://www.postgresql.org/docs/current/plpgsql-statements.html#PLPGSQL-STATEMENTS-EXECUTING-DYN) · [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html) · [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)

---

## Use Batch Operations Instead of Single-Row Loops

**Impact: HIGH (N HTTP requests reduced to 1, prevents timeouts and connection exhaustion)**

Every Supabase `.insert()`, `.update()`, or `.upsert()` call is an HTTP request to the PostgREST API. When you perform these operations inside a loop — inserting rows one by one, or updating records individually — you create N HTTP round trips where a single batch call would suffice. This wastes network bandwidth, adds cumulative latency (each round trip adds 50-200ms), and can trigger rate limits or timeouts on serverless platforms with 10-second execution limits.

Supabase's `.insert()` and `.upsert()` natively accept arrays of objects, batching the entire operation into a single HTTP request and a single SQL transaction.

**Incorrect (inserting rows one at a time in a loop):**

```typescript
// ❌ One HTTP request per row — O(n) network round trips
export async function importProducts(
  supabase: SupabaseClient,
  csvRows: ProductRow[]
) {
  const results: ImportResult[] = []

  for (const row of csvRows) {
    // ❌ Each iteration fires a separate HTTP request
    const { data, error } = await supabase
      .from('products')
      .insert({
        name: row.name,
        sku: row.sku,
        price: parseFloat(row.price),
        category_id: row.category_id,
        description: row.description,
        stock_quantity: parseInt(row.stock),
      })
      .select('id')
      .single()

    results.push({
      sku: row.sku,
      success: !error,
      id: data?.id,
      error: error?.message,
    })
  }

  return results
}
// 500 products = 500 HTTP requests = ~50 seconds at 100ms per request
// Serverless timeout hit at ~100 rows
```

**Incorrect (updating records one at a time):**

```typescript
// ❌ Updating order statuses one by one
export async function markOrdersAsShipped(
  supabase: SupabaseClient,
  orderIds: string[],
  trackingNumbers: Map<string, string>
) {
  for (const orderId of orderIds) {
    // ❌ Each update is a separate HTTP request
    await supabase
      .from('orders')
      .update({
        status: 'shipped',
        shipped_at: new Date().toISOString(),
        tracking_number: trackingNumbers.get(orderId),
      })
      .eq('id', orderId)
  }
}
// 200 orders = 200 HTTP requests
```

**Incorrect (Promise.all doesn't fix the underlying problem):**

```typescript
// ❌ Promise.all reduces wall time but still creates N connections
export async function createNotifications(
  supabase: SupabaseClient,
  userIds: string[],
  message: string
) {
  // ❌ Still N HTTP requests — just concurrent instead of sequential
  await Promise.all(
    userIds.map((userId) =>
      supabase.from('notifications').insert({
        user_id: userId,
        message,
        read: false,
        created_at: new Date().toISOString(),
      })
    )
  )
}
// 1000 users = 1000 concurrent HTTP requests = potential rate limiting
```

**Correct (batch insert with array):**

```typescript
// ✅ Single HTTP request for all rows
export async function importProducts(
  supabase: SupabaseClient,
  csvRows: ProductRow[]
) {
  // ✅ Transform all rows first, then insert in one batch
  const products = csvRows.map((row) => ({
    name: row.name,
    sku: row.sku,
    price: parseFloat(row.price),
    category_id: row.category_id,
    description: row.description,
    stock_quantity: parseInt(row.stock),
  }))

  const { data, error } = await supabase
    .from('products')
    .insert(products)  // ✅ Array of objects — single HTTP request
    .select('id, sku')

  if (error) throw error
  return data
}
// 500 products = 1 HTTP request = ~200ms total
```

**Correct (batch upsert with conflict handling):**

```typescript
// ✅ Upsert batch — insert or update based on unique constraint
export async function syncInventoryFromWarehouse(
  supabase: SupabaseClient,
  inventoryUpdates: InventoryUpdate[]
) {
  const records = inventoryUpdates.map((update) => ({
    sku: update.sku,
    stock_quantity: update.quantity,
    warehouse_id: update.warehouseId,
    last_synced_at: new Date().toISOString(),
  }))

  // ✅ Single request — inserts new SKUs, updates existing ones
  const { data, error } = await supabase
    .from('inventory')
    .upsert(records, {
      onConflict: 'sku,warehouse_id',     // ✅ Unique constraint columns
      ignoreDuplicates: false,              // ✅ Update existing rows
    })
    .select('sku, stock_quantity')

  if (error) throw error
  return data
}
// 1000 inventory updates = 1 HTTP request + 1 SQL transaction
```

**Correct (chunked batching for very large datasets):**

```typescript
// ✅ For very large datasets, chunk into batches of ~1000 rows
export async function bulkCreateNotifications(
  supabase: SupabaseClient,
  userIds: string[],
  notification: { title: string; message: string; type: string }
) {
  const BATCH_SIZE = 1000 // ✅ PostgREST handles up to ~1000 rows per request efficiently
  const records = userIds.map((userId) => ({
    user_id: userId,
    title: notification.title,
    message: notification.message,
    type: notification.type,
    read: false,
    created_at: new Date().toISOString(),
  }))

  const results: { inserted: number; errors: string[] } = {
    inserted: 0,
    errors: [],
  }

  // ✅ Process in chunks — N/1000 requests instead of N requests
  for (let i = 0; i < records.length; i += BATCH_SIZE) {
    const chunk = records.slice(i, i + BATCH_SIZE)
    const { data, error } = await supabase
      .from('notifications')
      .insert(chunk)
      .select('id')

    if (error) {
      results.errors.push(
        `Batch ${Math.floor(i / BATCH_SIZE) + 1}: ${error.message}`
      )
    } else {
      results.inserted += data.length
    }
  }

  return results
}
// 10,000 users = 10 HTTP requests (not 10,000)
```

**Correct (batch update using upsert for multiple different values):**

```typescript
// ✅ When each row needs a different update value, use upsert
export async function markOrdersAsShipped(
  supabase: SupabaseClient,
  shipments: { orderId: string; trackingNumber: string }[]
) {
  const now = new Date().toISOString()

  // ✅ Build array of full row updates
  const updates = shipments.map((s) => ({
    id: s.orderId,
    status: 'shipped' as const,
    shipped_at: now,
    tracking_number: s.trackingNumber,
  }))

  // ✅ Single request — upsert matches on primary key (id)
  const { data, error } = await supabase
    .from('orders')
    .upsert(updates, { onConflict: 'id' })
    .select('id, status, tracking_number')

  if (error) throw error
  return data
}
// 200 orders = 1 HTTP request (not 200)
```

**Detection hints:**

```bash
# Find insert/upsert calls inside for loops
grep -rn "for.*insert(" src/ --include="*.ts" --include="*.tsx"
grep -rn "for.*upsert(" src/ --include="*.ts" --include="*.tsx"
# Find insert/update inside .map() or .forEach() callbacks
grep -rn "\.map(.*\.insert\|\.forEach(.*\.insert" src/ --include="*.ts" --include="*.tsx"
# Find Promise.all wrapping individual inserts
grep -rn "Promise.all" src/ --include="*.ts" -A 5 | grep "\.insert\|\.upsert\|\.update"
```

Reference: [Supabase Insert](https://supabase.com/docs/reference/javascript/insert) · [Supabase Upsert](https://supabase.com/docs/reference/javascript/upsert) · [PostgREST Bulk Insert](https://docs.postgrest.org/en/stable/references/api/tables_views.html#bulk-insert)

---

## Use Connection Pooling (Supavisor) for Serverless Deployments

**Impact: HIGH (prevents connection exhaustion and database downtime under load)**

PostgreSQL has a hard limit on the number of simultaneous connections (default ~60 on Supabase's Micro plan, ~200 on Pro). In serverless environments — Next.js Edge Runtime, Vercel Serverless Functions, Supabase Edge Functions, AWS Lambda — every invocation can create a new connection. A traffic spike of 100 concurrent requests means 100 simultaneous PostgreSQL connections, which can instantly exhaust the pool and crash your database with `FATAL: too many connections for role` errors.

Supabase provides Supavisor, a connection pooler that sits between your application and PostgreSQL. Instead of each function opening a direct connection, they all share a pool of connections through Supavisor. This is the difference between your app handling 60 concurrent users and 10,000+.

For the Supabase JS client (`@supabase/supabase-js`), connection pooling is handled automatically through the REST API (PostgREST). The pooling concern primarily applies when using direct database connections via `postgres`, `pg`, Prisma, or Drizzle ORMs.

**Incorrect (direct database connection in serverless function):**

```typescript
// ❌ Direct connection string in a Vercel Serverless Function
// lib/db.ts
import { Pool } from 'pg'

// ❌ Direct connection — each invocation opens a new connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  // postgresql://postgres.[ref]:[password]@aws-0-us-east-1.pooler.supabase.com:5432/postgres
  // Port 5432 = direct connection — no pooling
})

export async function getActiveUsers() {
  const client = await pool.connect()
  try {
    const result = await client.query(
      'SELECT id, email, last_seen FROM profiles WHERE last_seen > NOW() - INTERVAL \'5 minutes\''
    )
    return result.rows
  } finally {
    client.release()
  }
}
// 100 concurrent requests = 100 PostgreSQL connections
// Supabase Micro plan has ~60 connections → instant failure
```

**Incorrect (Prisma without connection pooling in serverless):**

```typescript
// ❌ Prisma with direct connection in Next.js API route
// lib/prisma.ts
import { PrismaClient } from '@prisma/client'

// ❌ Direct connection — no pooler, and globalThis trick doesn't help in serverless
const prisma = new PrismaClient({
  datasources: {
    db: {
      url: process.env.DATABASE_URL,
      // ❌ postgresql://postgres.[ref]:[password]@aws-0-us-east-1.pooler.supabase.com:5432/postgres
    },
  },
})

export default prisma
```

```typescript
// ❌ Edge Function with direct Postgres connection
// supabase/functions/process-webhook/index.ts
import { Pool } from 'https://deno.land/x/postgres/mod.ts'

// ❌ Each edge function invocation creates a new connection
const pool = new Pool(Deno.env.get('DATABASE_URL'), 1)

Deno.serve(async (req) => {
  const connection = await pool.connect()
  try {
    const result = await connection.queryObject(
      'INSERT INTO webhook_events (payload) VALUES ($1) RETURNING id',
      [await req.json()]
    )
    return new Response(JSON.stringify(result.rows[0]))
  } finally {
    connection.release()
  }
})
```

**Correct (Supavisor pooler URL for serverless):**

```typescript
// ✅ Use Supavisor pooler URL (port 6543) for serverless
// lib/db.ts
import { Pool } from 'pg'

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  // ✅ Supavisor pooler URL — port 6543 for transaction mode
  // postgresql://postgres.[ref]:[password]@aws-0-us-east-1.pooler.supabase.com:6543/postgres?pgbouncer=true
  max: 1, // ✅ Serverless: only 1 connection per invocation
})

export async function getActiveUsers() {
  const client = await pool.connect()
  try {
    const result = await client.query(
      'SELECT id, email, last_seen FROM profiles WHERE last_seen > NOW() - INTERVAL \'5 minutes\''
    )
    return result.rows
  } finally {
    client.release()
  }
}
// 100 concurrent requests share a pool of ~15 actual database connections
```

**Correct (Prisma with pooler and direct URLs):**

```typescript
// ✅ Prisma configuration with Supavisor pooler
// lib/prisma.ts
import { PrismaClient } from '@prisma/client'

const globalForPrisma = globalThis as unknown as { prisma: PrismaClient }

const prisma =
  globalForPrisma.prisma ||
  new PrismaClient({
    datasources: {
      db: {
        // ✅ Pooler URL for queries (port 6543, transaction mode)
        url: process.env.DATABASE_URL,
      },
    },
  })

if (process.env.NODE_ENV !== 'production') globalForPrisma.prisma = prisma

export default prisma
```

```
# ✅ .env — separate URLs for pooled queries vs. migrations
# Pooled connection for application queries (port 6543)
DATABASE_URL="postgresql://postgres.[ref]:[password]@aws-0-us-east-1.pooler.supabase.com:6543/postgres?pgbouncer=true"

# Direct connection for migrations only (port 5432)
DIRECT_URL="postgresql://postgres.[ref]:[password]@aws-0-us-east-1.pooler.supabase.com:5432/postgres"
```

```prisma
// ✅ schema.prisma — use directUrl for migrations
datasource db {
  provider  = "postgresql"
  url       = env("DATABASE_URL")       // Pooled — for runtime queries
  directUrl = env("DIRECT_URL")         // Direct — for prisma migrate only
}
```

**Correct (Supabase JS client — already pooled via REST API):**

```typescript
// ✅ Supabase JS client uses PostgREST (HTTP), not direct connections
// This is already connection-pooling-safe — no changes needed
import { createClient } from '@supabase/supabase-js'

export const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,     // REST API endpoint
  process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY! // Public anon key
)
// PostgREST handles its own connection pool to PostgreSQL
// Safe for serverless — no connection exhaustion risk
```

**Connection strategy by environment:**

```
| Environment               | Use Supabase JS? | Use ORM/pg?                      |
|---------------------------|-------------------|----------------------------------|
| Next.js Serverless Route  | ✅ PostgREST      | ✅ Pooler URL (port 6543)        |
| Next.js Edge Runtime      | ✅ PostgREST      | ✅ Pooler URL (port 6543)        |
| Supabase Edge Function    | ✅ PostgREST      | ✅ Pooler URL (port 6543)        |
| Long-running server       | ✅ PostgREST      | ✅ Direct URL (port 5432) is OK  |
| Migrations/seeding        | N/A               | ✅ Direct URL (port 5432)        |
```

**Detection hints:**

```bash
# Find environment variable references that may use direct connections
grep -rn "NEXT_PUBLIC_SUPABASE_URL" src/ --include="*.ts" --include="*.tsx"
grep -rn "DATABASE_URL" src/ --include="*.ts" --include="*.tsx"
# Find direct connection port in env files
grep -rn ":5432" . --include="*.env*"
# Find pg Pool or Client instantiation
grep -rn "new Pool\|new Client" src/ --include="*.ts"
```

Reference: [Supabase Connection Pooling](https://supabase.com/docs/guides/database/connecting-to-postgres#connection-pooler) · [Supavisor Documentation](https://supabase.com/docs/guides/platform/custom-postgres-config) · [Prisma with Supabase](https://supabase.com/partners/integrations/prisma)

---

## Use Cursor-Based Pagination Instead of Offset Pagination

**Impact: HIGH (constant-time pagination vs. linear degradation on large datasets)**

Supabase's `.range(from, to)` method translates to PostgreSQL's `OFFSET ... LIMIT ...`. While simple to implement, offset pagination has a critical performance flaw: PostgreSQL must scan and discard all rows before the offset. Page 1 scans 20 rows. Page 100 scans 2,000 rows and discards 1,980. Page 10,000 scans 200,000 rows. Query time grows linearly with page depth.

Cursor-based pagination uses a `WHERE` clause to start reading from a known position (the last item on the previous page). PostgreSQL jumps directly to that position using an index, making page 10,000 just as fast as page 1.

**Incorrect (offset pagination with .range()):**

```typescript
// ❌ Offset pagination — performance degrades on deep pages
import { createClient } from '@/lib/supabase/server'

export async function GET(request: Request) {
  const supabase = await createClient()
  const { searchParams } = new URL(request.url)
  const page = parseInt(searchParams.get('page') ?? '1')
  const pageSize = 20
  const from = (page - 1) * pageSize
  const to = from + pageSize - 1

  // ❌ .range() uses OFFSET — scans all skipped rows
  const { data: posts, error, count } = await supabase
    .from('posts')
    .select('id, title, excerpt, published_at, author:profiles(full_name)', { count: 'exact' })
    .eq('published', true)
    .order('published_at', { ascending: false })
    .range(from, to)

  if (error) throw error

  return Response.json({
    posts,
    page,
    totalPages: Math.ceil((count ?? 0) / pageSize),
  })
}
// Page 1:    OFFSET 0    → scans 20 rows   → ~2ms
// Page 500:  OFFSET 9980 → scans 10,000 rows → ~150ms
// Page 5000: OFFSET 99980 → scans 100,000 rows → ~1,500ms
```

**Incorrect (offset pagination in infinite scroll):**

```typescript
// ❌ Client-side infinite scroll using offset — gets slower as user scrolls
'use client'

import { useState, useEffect } from 'react'
import { createClient } from '@/lib/supabase/client'

export function InfinitePostList() {
  const [posts, setPosts] = useState<Post[]>([])
  const [page, setPage] = useState(0)
  const supabase = createClient()

  async function loadMore() {
    const pageSize = 20
    // ❌ Deep offsets cause increasingly slow queries
    const from = page * pageSize
    const to = from + pageSize - 1

    const { data } = await supabase
      .from('posts')
      .select('id, title, excerpt, published_at')
      .eq('published', true)
      .order('published_at', { ascending: false })
      .range(from, to)

    setPosts((prev) => [...prev, ...(data ?? [])])
    setPage((prev) => prev + 1)
  }

  // After loading 100 pages (2000 posts), each "load more" takes 1+ seconds
}
```

**Correct (cursor-based pagination with .gt()/.lt()):**

```typescript
// ✅ Cursor-based pagination — constant time regardless of page depth
import { createClient } from '@/lib/supabase/server'

export async function GET(request: Request) {
  const supabase = await createClient()
  const { searchParams } = new URL(request.url)
  const cursor = searchParams.get('cursor') // ISO timestamp of last item
  const pageSize = 20

  let query = supabase
    .from('posts')
    .select('id, title, excerpt, published_at, author:profiles(full_name)')
    .eq('published', true)
    .order('published_at', { ascending: false })
    .limit(pageSize + 1) // ✅ Fetch one extra to detect if there's a next page

  // ✅ If cursor is provided, start after the last seen item
  if (cursor) {
    query = query.lt('published_at', cursor)
  }

  const { data: posts, error } = await query

  if (error) throw error

  const hasNextPage = (posts?.length ?? 0) > pageSize
  const results = hasNextPage ? posts!.slice(0, pageSize) : (posts ?? [])
  const nextCursor = hasNextPage
    ? results[results.length - 1].published_at
    : null

  return Response.json({
    posts: results,
    nextCursor, // Client passes this back as ?cursor= for the next page
    hasNextPage,
  })
}
// Page 1:    WHERE published_at < NOW()       → index scan → ~2ms
// Page 5000: WHERE published_at < '2023-...'  → index scan → ~2ms (same speed!)
```

**Correct (cursor-based infinite scroll on the client):**

```typescript
// ✅ Client-side infinite scroll with cursor — stays fast at any depth
'use client'

import { useState, useCallback } from 'react'
import { createClient } from '@/lib/supabase/client'

export function InfinitePostList() {
  const [posts, setPosts] = useState<Post[]>([])
  const [nextCursor, setNextCursor] = useState<string | null>(null)
  const [hasMore, setHasMore] = useState(true)
  const [isLoading, setIsLoading] = useState(false)
  const supabase = createClient()

  const loadMore = useCallback(async () => {
    if (isLoading || !hasMore) return
    setIsLoading(true)

    const pageSize = 20
    let query = supabase
      .from('posts')
      .select('id, title, excerpt, published_at')
      .eq('published', true)
      .order('published_at', { ascending: false })
      .limit(pageSize + 1)

    // ✅ Use cursor to fetch next page — no offset
    if (nextCursor) {
      query = query.lt('published_at', nextCursor)
    }

    const { data, error } = await query
    if (error) {
      console.error('Failed to load posts:', error)
      setIsLoading(false)
      return
    }

    const hasNextPage = (data?.length ?? 0) > pageSize
    const newPosts = hasNextPage ? data!.slice(0, pageSize) : (data ?? [])

    setPosts((prev) => [...prev, ...newPosts])
    setNextCursor(
      hasNextPage ? newPosts[newPosts.length - 1].published_at : null
    )
    setHasMore(hasNextPage)
    setIsLoading(false)
  }, [nextCursor, hasMore, isLoading, supabase])

  // Even after scrolling through 10,000 posts, loadMore stays <5ms
}
```

**Correct (compound cursor for non-unique sort columns):**

```typescript
// ✅ When the sort column isn't unique, use a compound cursor (column + id)
export async function GET(request: Request) {
  const supabase = await createClient()
  const { searchParams } = new URL(request.url)
  const cursorDate = searchParams.get('cursor_date')
  const cursorId = searchParams.get('cursor_id')
  const pageSize = 20

  let query = supabase
    .from('posts')
    .select('id, title, published_at')
    .eq('published', true)
    .order('published_at', { ascending: false })
    .order('id', { ascending: false }) // ✅ Tiebreaker on unique column
    .limit(pageSize + 1)

  if (cursorDate && cursorId) {
    // ✅ Compound cursor: skip past items with same timestamp using id
    query = query.or(
      `published_at.lt.${cursorDate},and(published_at.eq.${cursorDate},id.lt.${cursorId})`
    )
  }

  const { data: posts, error } = await query
  if (error) throw error

  const hasNextPage = (posts?.length ?? 0) > pageSize
  const results = hasNextPage ? posts!.slice(0, pageSize) : (posts ?? [])
  const lastItem = results[results.length - 1]

  return Response.json({
    posts: results,
    nextCursor: hasNextPage
      ? { date: lastItem.published_at, id: lastItem.id }
      : null,
    hasNextPage,
  })
}
```

**When offset pagination is acceptable:**

- Small datasets (< 1,000 rows) where performance difference is negligible
- Admin/backoffice pages where users need to jump to specific page numbers
- When total count and page number display are hard requirements

**Detection hints:**

```bash
# Find .range() calls — likely offset pagination
grep -rn ".range(" src/ --include="*.ts" --include="*.tsx"
# Find page number patterns that suggest offset pagination
grep -rn "page.*pageSize\|offset.*limit" src/ --include="*.ts" --include="*.tsx"
```

Reference: [Supabase Pagination](https://supabase.com/docs/guides/database/pagination) · [Use the Index, Luke — Pagination](https://use-the-index-luke.com/no-offset)

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

---

## Avoid N+1 Queries with Supabase Relational Selects

**Impact: HIGH (10-100x query reduction, eliminates serial HTTP round trips)**

N+1 queries are the most common performance killer in Supabase applications. The pattern occurs when you fetch a list of parent records (1 query), then iterate over each parent to fetch its children individually (N queries). Because every Supabase `.from().select()` call is a full HTTP request to the PostgREST API, this creates N+1 network round trips — not just N+1 database queries. With 200 parent records, you send 201 HTTP requests when a single request would suffice.

Supabase supports PostgREST's resource embedding, allowing you to fetch nested relations through foreign keys in one `.select()` call.

**Incorrect (N+1 — forEach loop firing individual queries):**

```typescript
// ❌ API route that creates N+1 HTTP requests to Supabase
import { createClient } from '@/lib/supabase/server'

export async function GET(request: Request) {
  const supabase = await createClient()
  const { searchParams } = new URL(request.url)
  const orgId = searchParams.get('org_id')

  // 1 query: fetch all teams in the org
  const { data: teams } = await supabase
    .from('teams')
    .select('id, name, slug')
    .eq('org_id', orgId!)

  const teamsWithMembers: TeamWithMembers[] = []

  // ❌ N queries: forEach fires one request per team
  teams?.forEach(async (team) => {
    const { data: members } = await supabase
      .from('team_members')
      .select('id, role, user:profiles(id, full_name, avatar_url)')
      .eq('team_id', team.id)

    teamsWithMembers.push({ ...team, members: members ?? [] })
  })

  // Bug: forEach with async doesn't await — response may be empty
  return Response.json(teamsWithMembers)
}
// 30 teams = 31 HTTP requests, plus a race condition bug
```

**Incorrect (hidden N+1 in React Server Components):**

```typescript
// ❌ Parent component fetches list, child component fetches per-item
async function OrderHistory({ userId }: { userId: string }) {
  const supabase = await createClient()
  const { data: orders } = await supabase
    .from('orders')
    .select('id, status, total, created_at')
    .eq('user_id', userId)
    .order('created_at', { ascending: false })

  return (
    <div>
      {orders?.map((order) => (
        // Each OrderRow independently queries for its line items
        <OrderRow key={order.id} orderId={order.id} />
      ))}
    </div>
  )
}

async function OrderRow({ orderId }: { orderId: string }) {
  const supabase = await createClient()
  // ❌ Fires once per order — N additional queries
  const { data: items } = await supabase
    .from('order_items')
    .select('id, quantity, product:products(name, price, image_url)')
    .eq('order_id', orderId)

  return <div>{items?.length} items</div>
}
```

**Correct (single query with Supabase nested select):**

```typescript
// ✅ One HTTP request fetches teams + members + profile data
import { createClient } from '@/lib/supabase/server'

export async function GET(request: Request) {
  const supabase = await createClient()
  const { searchParams } = new URL(request.url)
  const orgId = searchParams.get('org_id')

  // ✅ Nested select resolves all relations in a single PostgREST call
  const { data: teams, error } = await supabase
    .from('teams')
    .select(`
      id,
      name,
      slug,
      team_members (
        id,
        role,
        joined_at,
        user:profiles (
          id,
          full_name,
          avatar_url
        )
      )
    `)
    .eq('org_id', orgId!)
    .order('name')

  if (error) {
    return Response.json({ error: error.message }, { status: 500 })
  }

  return Response.json(teams)
}
// 30 teams = 1 HTTP request with all members and profiles embedded
```

**Correct (fix the server component N+1):**

```typescript
// ✅ Fetch all data at the parent level, pass down as props
async function OrderHistory({ userId }: { userId: string }) {
  const supabase = await createClient()

  const { data: orders, error } = await supabase
    .from('orders')
    .select(`
      id,
      status,
      total,
      created_at,
      order_items (
        id,
        quantity,
        product:products (
          name,
          price,
          image_url
        )
      )
    `)
    .eq('user_id', userId)
    .order('created_at', { ascending: false })

  if (error) throw error

  return (
    <div>
      {orders?.map((order) => (
        // ✅ No Supabase call in child — data already resolved
        <OrderRow key={order.id} order={order} />
      ))}
    </div>
  )
}

function OrderRow({ order }: { order: OrderWithItems }) {
  return <div>{order.order_items.length} items</div>
}
```

**Correct (batch with .in() when no foreign key relation exists):**

```typescript
// ✅ Two queries instead of N+1 when tables aren't directly related
async function getProductsWithReviewCounts(categoryId: string) {
  const supabase = await createClient()

  const { data: products } = await supabase
    .from('products')
    .select('id, name, price')
    .eq('category_id', categoryId)

  const productIds = products?.map((p) => p.id) ?? []

  // ✅ Single query for all review counts
  const { data: reviewCounts } = await supabase
    .rpc('get_review_counts', { product_ids: productIds })

  const countsMap = new Map(reviewCounts?.map((r) => [r.product_id, r.count]))

  return products?.map((product) => ({
    ...product,
    reviewCount: countsMap.get(product.id) ?? 0,
  }))
}
// 100 products = 2 HTTP requests (not 101)
```

**Detection hints:**

```bash
# Find queries inside forEach — classic N+1 pattern
grep -rn "forEach.*from(" src/ --include="*.ts" --include="*.tsx"
# Find async map callbacks that call Supabase
grep -rn "\.map(async" src/ --include="*.ts" --include="*.tsx" -A 5 | grep "\.from("
# Find Supabase calls inside child server components
grep -rn "await.*supabase" src/ --include="*.tsx" -B 3 | grep "function.*{.*:.*string"
```

Reference: [PostgREST Resource Embedding](https://docs.postgrest.org/en/stable/references/api/resource_embedding.html) · [Supabase Querying Joins](https://supabase.com/docs/guides/database/joins-and-nesting)

---

## Avoid select('*') — Request Only the Columns You Need

**Impact: HIGH (reduces payload size 2-10x, enables index-only scans, prevents data leakage)**

Using `.select('*')` in Supabase queries fetches every column from the table, including large `text`, `jsonb`, and `bytea` fields that your UI may never render. This creates three problems:

1. **Wasted bandwidth** — large columns (markdown content, JSON metadata, file data) inflate every response. A table with a `content` column averaging 5KB per row turns a 100-row list query from ~20KB to ~500KB.
2. **No index-only scans** — PostgreSQL can satisfy queries entirely from an index if you only request indexed columns. `SELECT *` forces a heap fetch for every row, which is significantly slower on large tables.
3. **Data leakage** — even with RLS, `select('*')` exposes the full table schema and may return sensitive columns (internal notes, soft-delete flags, audit fields) that the frontend should never see.

**Incorrect (select all columns for a list view):**

```typescript
// ❌ Fetches all columns including large 'content' and 'metadata' fields
export async function getArticles(supabase: SupabaseClient) {
  const { data, error } = await supabase
    .from('articles')
    .select('*')
    .eq('published', true)
    .order('published_at', { ascending: false })
    .limit(20)

  if (error) throw error
  return data
}
// Each article has a 'content' column (avg 8KB of markdown)
// and a 'metadata' column (avg 2KB of JSON)
// List view only shows title, excerpt, and date
// Payload: ~200KB instead of ~15KB
```

**Incorrect (select all in server component data fetching):**

```typescript
// ❌ Fetches full user profile including fields never displayed
async function MemberList({ teamId }: { teamId: string }) {
  const supabase = await createClient()
  const { data: members } = await supabase
    .from('profiles')
    .select('*')  // ❌ Returns: id, full_name, email, avatar_url, bio,
                   //           settings (jsonb), onboarding_state (jsonb),
                   //           stripe_customer_id, internal_notes, ...
    .in('id', teamMemberIds)

  return (
    <ul>
      {members?.map((m) => (
        <li key={m.id}>
          <Avatar url={m.avatar_url} />
          <span>{m.full_name}</span>
        </li>
      ))}
    </ul>
  )
}
// Only uses 3 columns, fetches 15+
```

**Correct (select only the columns needed):**

```typescript
// ✅ Request only columns the list view actually renders
export async function getArticles(supabase: SupabaseClient) {
  const { data, error } = await supabase
    .from('articles')
    .select('id, title, excerpt, slug, published_at, author:profiles(full_name, avatar_url)')
    .eq('published', true)
    .order('published_at', { ascending: false })
    .limit(20)

  if (error) throw error
  return data
}
// Payload: ~15KB — only the fields rendered in the card grid
// PostgreSQL can use an index-only scan on (published, published_at) covering (id, title, excerpt, slug)
```

**Correct (targeted select for member list):**

```typescript
// ✅ Only the 3 columns actually used in the UI
async function MemberList({ teamId }: { teamId: string }) {
  const supabase = await createClient()
  const { data: members, error } = await supabase
    .from('team_members')
    .select(`
      role,
      user:profiles (
        id,
        full_name,
        avatar_url
      )
    `)
    .eq('team_id', teamId)
    .order('role')

  if (error) throw error

  return (
    <ul>
      {members?.map((m) => (
        <li key={m.user.id}>
          <Avatar url={m.user.avatar_url} />
          <span>{m.user.full_name}</span>
          <Badge>{m.role}</Badge>
        </li>
      ))}
    </ul>
  )
}
// No sensitive fields ever leave the database
```

**Correct (full detail view — select('*') is acceptable here):**

```typescript
// ✅ Fetching all columns is fine for a single-record detail view
export async function getArticleBySlug(supabase: SupabaseClient, slug: string) {
  const { data, error } = await supabase
    .from('articles')
    .select(`
      id,
      title,
      content,
      excerpt,
      slug,
      published_at,
      metadata,
      author:profiles (
        id,
        full_name,
        avatar_url,
        bio
      )
    `)
    .eq('slug', slug)
    .single()

  if (error) throw error
  return data
}
// Single record — even with large content column, this is fine
// Still explicitly name columns to avoid leaking internal fields
```

**Detection hints:**

```bash
# Find all select('*') calls
grep -rn "select('*')" src/ --include="*.ts" --include="*.tsx"
# Find select("*") with double quotes
grep -rn 'select("*")' src/ --include="*.ts" --include="*.tsx"
# Find .select() with no arguments (defaults to *)
grep -rn "\.select()" src/ --include="*.ts" --include="*.tsx"
```

Reference: [Supabase Select Query](https://supabase.com/docs/reference/javascript/select) · [PostgreSQL Index-Only Scans](https://www.postgresql.org/docs/current/indexes-index-only-scans.html)

---

## Use the Correct Supabase Client for Each Context

**Impact: HIGH (prevents RLS bypass, auth leaks, and hydration mismatches)**

Supabase with Next.js requires different client configurations for different rendering contexts. Using the wrong client causes subtle but serious bugs: server clients in client components cause hydration errors, client-side clients in server components miss the auth cookie (bypassing RLS), and missing middleware clients break auth refresh.

Each context has a specific client factory function that handles cookies, auth tokens, and SSR compatibility correctly.

**Client selection table:**

| Context | Client Import | Async? | Cookie Access | RLS |
|---------|--------------|--------|---------------|-----|
| Server Component | `createClient` from `@/lib/supabase/server` | `await` | Read-only (headers) | Yes |
| Client Component | `createClient` from `@/lib/supabase/client` | No | Read/write (browser) | Yes |
| Server Action | `createClient` from `@/lib/supabase/server` | `await` | Read/write (headers) | Yes |
| Route Handler | `createClient` from `@/lib/supabase/server` | `await` | Read/write (headers) | Yes |
| Middleware | `createClient` from `@/lib/supabase/middleware` | `await` | Request/Response | Yes |
| Cron/Admin | `createServiceRoleClient` from `@/lib/supabase/service-role` | No | None | **Bypassed** |

**Incorrect (using browser client in server component):**

```typescript
// ❌ Browser client in a Server Component — no auth cookies available
// app/dashboard/page.tsx (Server Component)
import { createClient } from '@/lib/supabase/client' // Wrong import!

export default async function DashboardPage() {
  const supabase = createClient()

  // This query runs without auth context — RLS treats it as anonymous
  const { data: projects } = await supabase
    .from('projects')
    .select('*')

  // Returns empty array or error — RLS blocks because no user context
  return <ProjectList projects={projects ?? []} />
}
```

**Incorrect (server client in client component):**

```typescript
// ❌ Server client in a Client Component — causes errors
'use client'
import { createClient } from '@/lib/supabase/server' // Wrong import!

export function ProjectForm() {
  const handleSubmit = async (formData: FormData) => {
    // ❌ createClient from server.ts uses cookies() from next/headers
    // which is not available in Client Components
    const supabase = await createClient()
    // Error: cookies() can only be called in Server Components
  }

  return <form action={handleSubmit}>...</form>
}
```

**Correct (server client in Server Component):**

```typescript
// app/dashboard/page.tsx (Server Component)
import { createClient } from '@/lib/supabase/server'

export default async function DashboardPage() {
  // ✅ Server client reads auth cookies from the request
  const supabase = await createClient()

  const { data: { user } } = await supabase.auth.getUser()
  if (!user) redirect('/login')

  // ✅ RLS works correctly — query scoped to authenticated user
  const { data: projects } = await supabase
    .from('projects')
    .select('id, name, status, created_at')

  return <ProjectList projects={projects ?? []} />
}
```

**Correct (browser client in Client Component):**

```typescript
'use client'
import { createClient } from '@/lib/supabase/client'

export function ProjectForm() {
  // ✅ Browser client uses browser cookies for auth
  const supabase = createClient() // No await — synchronous

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    const formData = new FormData(e.currentTarget)

    const { error } = await supabase
      .from('projects')
      .insert({ name: formData.get('name') as string })

    if (error) console.error(error)
  }

  return <form onSubmit={handleSubmit}>...</form>
}
```

**Correct (server client in Server Action):**

```typescript
// app/actions/projects.ts
'use server'

import { createClient } from '@/lib/supabase/server'

export async function createProject(formData: FormData) {
  // ✅ Server client in Server Action — has access to request cookies
  const supabase = await createClient()

  const { data: { user }, error: authError } = await supabase.auth.getUser()
  if (authError || !user) throw new Error('Unauthorized')

  const { error } = await supabase
    .from('projects')
    .insert({ name: formData.get('name') as string })

  if (error) throw error
  revalidatePath('/dashboard')
}
```

**Correct (middleware client for auth refresh):**

```typescript
// middleware.ts
import { createClient } from '@/lib/supabase/middleware'
import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'

export async function middleware(request: NextRequest) {
  // ✅ Middleware client handles token refresh on every request
  const { supabase, response } = await createClient(request)

  // This refreshes the auth token if expired
  const { data: { user } } = await supabase.auth.getUser()

  if (!user && request.nextUrl.pathname.startsWith('/dashboard')) {
    return NextResponse.redirect(new URL('/login', request.url))
  }

  return response
}
```

**Detection hints:**

```bash
# Find client imports to verify they match the file context
grep -rn "from.*supabase/server\|from.*supabase/client\|from.*supabase/middleware" src/ --include="*.ts" --include="*.tsx"
# Find 'use client' files that import server client
grep -rn "use client" src/ --include="*.tsx" -l | xargs grep "supabase/server"
```

Reference: [Supabase SSR Guide](https://supabase.com/docs/guides/auth/server-side/nextjs) · [Supabase Auth Helpers](https://supabase.com/docs/guides/auth/server-side)

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

---

## Generate Database Types from Schema

**Impact: MEDIUM (prevents type drift between application code and database schema)**

Hand-writing TypeScript interfaces for your database tables is a maintenance burden that inevitably drifts from the actual schema. When a migration adds a column, changes a type, or makes a field nullable, the hand-written interface stays stale — leading to runtime errors that TypeScript was supposed to prevent.

Supabase CLI generates types directly from your database schema, ensuring your TypeScript types always match reality. These generated types also provide autocomplete for `.from()` table names, `.select()` column names, and `.eq()` filter values.

**Incorrect (hand-written types that drift from schema):**

```typescript
// ❌ Manually defined — will drift from actual schema
interface User {
  id: string
  email: string
  name: string       // Column was renamed to display_name in migration 042
  avatar: string     // Column is actually avatar_url and nullable
  created_at: string // Column is timestamptz, not string
}

interface Document {
  id: string
  userId: string     // Column is actually user_id (snake_case in PostgreSQL)
  title: string
  content: string    // Column was changed to nullable in migration 038
  tags: string[]     // Column is actually jsonb, not string[]
}

// ❌ No type safety on queries
const { data } = await supabase
  .from('documents')   // No autocomplete for table names
  .select('*')         // No type checking on returned shape
  .eq('userId', id)    // Runtime error — column is user_id, not userId
```

**Correct (generate types from schema):**

```bash
# Step 1: Generate types from local database
supabase gen types typescript --local > src/types/database.ts

# Or from remote (if not using local development)
supabase gen types typescript --project-id your-project-ref > src/types/database.ts
```

```typescript
// src/types/database.ts (auto-generated — do not edit manually)
export type Json = string | number | boolean | null | { [key: string]: Json | undefined } | Json[]

export interface Database {
  public: {
    Tables: {
      documents: {
        Row: {
          id: string
          user_id: string
          title: string
          content: string | null
          tags: Json
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          user_id: string
          title: string
          content?: string | null
          tags?: Json
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          user_id?: string
          title?: string
          content?: string | null
          tags?: Json
          updated_at?: string
        }
      }
      // ... other tables
    }
  }
}
```

```typescript
// ✅ Type-safe Supabase client
import { createClient } from '@supabase/supabase-js'
import type { Database } from '@/types/database'

export const supabase = createClient<Database>(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!
)

// Now all queries are type-safe:
const { data } = await supabase
  .from('documents')                    // ✅ Autocomplete for table names
  .select('id, title, created_at')      // ✅ Autocomplete for column names
  .eq('user_id', userId)                // ✅ Type error if column doesn't exist

// data is typed as: { id: string; title: string; created_at: string }[] | null
```

**Derive application types from generated types:**

```typescript
// ✅ Derive types from the generated Database type — never hand-write
type Document = Database['public']['Tables']['documents']['Row']
type DocumentInsert = Database['public']['Tables']['documents']['Insert']
type DocumentUpdate = Database['public']['Tables']['documents']['Update']

// ✅ Create application-specific types as intersections
type DocumentWithAuthor = Document & {
  author: Database['public']['Tables']['profiles']['Row']
}

// ✅ Use Pick for view-specific subsets
type DocumentListItem = Pick<Document, 'id' | 'title' | 'created_at'>
```

**Add type generation to your workflow:**

```json
// package.json
{
  "scripts": {
    "db:types": "supabase gen types typescript --local > src/types/database.ts",
    "db:migrate": "supabase db push && npm run db:types",
    "db:reset": "supabase db reset && npm run db:types"
  }
}
```

```bash
# After every migration, regenerate types:
supabase migration new add_status_to_documents
# ... write migration SQL ...
supabase db push
npm run db:types
git add supabase/migrations/ src/types/database.ts
git commit -m "feat: add status column to documents"
```

**Detection hints:**

```bash
# Find hand-written interfaces that might represent database tables
grep -rn "interface.*{" src/types/ --include="*.ts" | grep -v "database.ts"
# Check if database.ts exists and is recent
ls -la src/types/database.ts
# Find any type definitions that might shadow generated types
grep -rn "type.*Row\|interface.*Table" src/ --include="*.ts" | grep -v "database.ts\|node_modules"
```

Reference: [Supabase Type Generation](https://supabase.com/docs/guides/api/rest/generating-types) · [Supabase CLI Reference](https://supabase.com/docs/reference/cli/supabase-gen-types)

---

## Distinguish Not-Found from Other Supabase Errors

**Impact: MEDIUM (prevents masking 404s as 500s and enables proper error recovery)**

Supabase queries can fail for many reasons: network errors, RLS violations, invalid column names, constraint violations, or simply "no rows found." Treating all errors identically with `if (error) throw error` masks the difference between a missing record (expected, recoverable) and a query failure (unexpected, needs investigation).

PostgREST uses specific error codes that you can check to distinguish these cases. The most important is `PGRST116` — "no rows returned" when using `.single()` or `.maybeSingle()`.

**Incorrect (treating all errors the same):**

```typescript
// ❌ Treats "not found" the same as "database down"
async function getProject(projectId: string) {
  const supabase = await createClient()

  const { data, error } = await supabase
    .from('projects')
    .select('id, name, status')
    .eq('id', projectId)
    .single()

  if (error) {
    // ❌ This could be:
    // - PGRST116: No rows found (project doesn't exist) → should return 404
    // - 42501: RLS violation (user can't access) → should return 403
    // - 42P01: Table doesn't exist (bug) → should return 500
    // - Network error → should retry or return 503
    throw error // All become the same generic error
  }

  return data
}
```

```typescript
// ❌ Catching errors with a generic message
export async function GET(
  request: Request,
  { params }: { params: { id: string } }
) {
  const supabase = await createClient()

  const { data, error } = await supabase
    .from('projects')
    .select('*')
    .eq('id', params.id)
    .single()

  if (error) {
    // ❌ Returns 500 even when the project simply doesn't exist
    return Response.json({ error: 'Something went wrong' }, { status: 500 })
  }

  return Response.json(data)
}
```

**Correct (check error codes for proper handling):**

```typescript
// ✅ Handle different error types appropriately
async function getProject(projectId: string) {
  const supabase = await createClient()

  const { data, error } = await supabase
    .from('projects')
    .select('id, name, status, created_at')
    .eq('id', projectId)
    .single()

  if (error) {
    // Not found — record doesn't exist or RLS hides it
    if (error.code === 'PGRST116') {
      return null // Caller can handle missing project
    }

    // All other errors are unexpected — log and throw
    console.error('Failed to fetch project:', {
      code: error.code,
      message: error.message,
      projectId,
    })
    throw new Error('Failed to load project')
  }

  return data
}
```

**Correct (ServiceResult pattern for typed error handling):**

```typescript
// ✅ Define a typed result type for service functions
type ServiceResult<T> =
  | { data: T; error: null }
  | { data: null; error: { code: 'NOT_FOUND' | 'FORBIDDEN' | 'INTERNAL'; message: string } }

async function getProject(projectId: string): Promise<ServiceResult<Project>> {
  const supabase = await createClient()

  const { data, error } = await supabase
    .from('projects')
    .select('id, name, status, created_at')
    .eq('id', projectId)
    .single()

  if (error) {
    if (error.code === 'PGRST116') {
      return { data: null, error: { code: 'NOT_FOUND', message: 'Project not found' } }
    }

    if (error.code === '42501' || error.code === 'PGRST301') {
      return { data: null, error: { code: 'FORBIDDEN', message: 'Access denied' } }
    }

    console.error('Unexpected project query error:', error)
    return { data: null, error: { code: 'INTERNAL', message: 'Failed to load project' } }
  }

  return { data, error: null }
}

// Usage in a Route Handler:
export async function GET(
  request: Request,
  { params }: { params: { id: string } }
) {
  const result = await getProject(params.id)

  if (result.error) {
    const statusMap = { NOT_FOUND: 404, FORBIDDEN: 403, INTERNAL: 500 } as const
    return Response.json(
      { error: result.error.message },
      { status: statusMap[result.error.code] }
    )
  }

  return Response.json(result.data)
}
```

**Common PostgREST error codes:**

| Code | Meaning | Typical HTTP Status |
|------|---------|-------------------|
| `PGRST116` | No rows returned (`.single()`) | 404 |
| `PGRST301` | JWT expired or invalid | 401 |
| `23505` | Unique constraint violation | 409 |
| `23503` | Foreign key violation | 400 |
| `23502` | Not-null violation | 400 |
| `42501` | Insufficient privilege (RLS) | 403 |
| `42P01` | Undefined table | 500 |

**Detection hints:**

```bash
# Find generic error handling patterns
grep -rn "if (error) throw error\|if (error) throw new Error" src/ --include="*.ts" --include="*.tsx"
# Find .single() calls without PGRST116 handling
grep -rn "\.single()" src/ --include="*.ts" --include="*.tsx"
```

Reference: [PostgREST Error Handling](https://docs.postgrest.org/en/stable/references/errors.html) · [PostgreSQL Error Codes](https://www.postgresql.org/docs/current/errcodes-appendix.html)

---

## Always Check Error Before Using Data from Supabase Queries

**Impact: HIGH (prevents silent failures and null reference crashes in production)**

Every Supabase query returns `{ data, error }`. When `error` is non-null, `data` is **always** `null`. Destructuring only `{ data }` and using it without checking `error` leads to `TypeError: Cannot read properties of null` at runtime. These crashes are especially hard to diagnose because the actual cause (RLS violation, network timeout, invalid column) is silently discarded.

This is the Supabase equivalent of unchecked return values — the query failed, but your code proceeds as if it succeeded.

**Incorrect (ignoring error entirely):**

```typescript
// ❌ Destructures data without checking error
export default async function DashboardPage() {
  const supabase = await createClient()

  const { data: projects } = await supabase
    .from('projects')
    .select('id, name, created_at')
    .order('created_at', { ascending: false })

  // ❌ If query fails (RLS, network, typo in table name), projects is null
  // This crashes with: TypeError: Cannot read properties of null (reading 'map')
  return (
    <ul>
      {projects.map((project) => (
        <li key={project.id}>{project.name}</li>
      ))}
    </ul>
  )
}
```

**Incorrect (checking error but continuing to use data):**

```typescript
// ❌ Logs error but still uses data (which is null)
export async function GET() {
  const supabase = await createClient()

  const { data, error } = await supabase
    .from('projects')
    .select('*')

  if (error) {
    console.warn('Query had an error:', error.message)
    // ❌ Falls through — data is null below
  }

  // ❌ data is null when error is non-null
  return Response.json({ projects: data }) // Returns { projects: null }
}
```

**Incorrect (optional chaining hides the real problem):**

```typescript
// ❌ Optional chaining silences the error but shows blank UI
const { data: profile } = await supabase
  .from('profiles')
  .select('display_name, avatar_url')
  .eq('id', userId)
  .single()

// User sees "Unknown" with default avatar — no indication of failure
return (
  <div>
    <h1>{profile?.display_name ?? 'Unknown'}</h1>
    <img src={profile?.avatar_url ?? '/default.png'} />
  </div>
)
```

**Correct (check error and return early in Server Components):**

```typescript
// ✅ Check error before using data
export default async function DashboardPage() {
  const supabase = await createClient()

  const { data: projects, error } = await supabase
    .from('projects')
    .select('id, name, created_at')
    .order('created_at', { ascending: false })

  if (error) {
    // ✅ Log for debugging, throw for error boundary
    console.error('Projects query failed:', { code: error.code, message: error.message })
    throw new Error('Failed to load projects')
  }

  // ✅ TypeScript narrows: projects is non-null here
  return (
    <ul>
      {projects.map((project) => (
        <li key={project.id}>{project.name}</li>
      ))}
    </ul>
  )
}
```

**Correct (check error in Route Handlers):**

```typescript
// ✅ Return appropriate HTTP status on error
export async function GET() {
  const supabase = await createClient()

  const { data: projects, error } = await supabase
    .from('projects')
    .select('id, name, created_at')

  if (error) {
    console.error('Projects query failed:', { code: error.code, message: error.message })
    return Response.json(
      { error: 'Failed to load projects' },
      { status: 500 }
    )
  }

  return Response.json({ projects })
}
```

**Correct (check error in Client Components):**

```typescript
'use client'

export function ProjectList() {
  const [projects, setProjects] = useState<Project[]>([])
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    async function load() {
      const supabase = createClient()

      const { data, error } = await supabase
        .from('projects')
        .select('id, name, created_at')

      if (error) {
        console.error('Projects query failed:', error.message)
        setError('Could not load projects. Please try again.')
        return // ✅ Early return — don't touch data
      }

      setProjects(data) // ✅ Safe — data is non-null
    }

    load()
  }, [])

  if (error) return <div role="alert">{error}</div>

  return (
    <ul>
      {projects.map((project) => (
        <li key={project.id}>{project.name}</li>
      ))}
    </ul>
  )
}
```

**Helper to enforce error checking:**

```typescript
// ✅ Utility that throws on error, returning only data
async function queryOrThrow<T>(
  query: PromiseLike<{ data: T | null; error: { message: string; code: string } | null }>
): Promise<T> {
  const { data, error } = await query

  if (error) {
    console.error('Supabase query failed:', { code: error.code, message: error.message })
    throw new Error(`Query failed: ${error.code}`)
  }

  return data as T
}

// Usage — cannot forget to check error
const projects = await queryOrThrow(
  supabase.from('projects').select('id, name').order('created_at', { ascending: false })
)
```

**Detection hints:**

```bash
# Find destructured data without error check
grep -rn "const { data }" src/ --include="*.ts" --include="*.tsx"
grep -rn "const { data:" src/ --include="*.ts" --include="*.tsx"
# Find .from() calls to audit error handling
grep -rn "\.from(" src/ --include="*.ts" --include="*.tsx"
```

Reference: [Supabase Fetch Data](https://supabase.com/docs/reference/javascript/select) · [CWE-252: Unchecked Return Value](https://cwe.mitre.org/data/definitions/252.html)

---

## Validate Input at Runtime with Zod Instead of Type Assertions

**Impact: HIGH (prevents invalid data from reaching the database and causing constraint errors)**

TypeScript's `as` keyword is a compile-time assertion that provides **zero runtime validation**. When you write `params.id as string`, TypeScript trusts you — but at runtime, `params.id` could be `undefined`, an array, a number, or a malicious string. This unvalidated input then flows into your Supabase queries, causing cryptic database errors, constraint violations, or worse — data corruption.

Zod provides runtime schema validation that catches invalid input **before** it reaches your database, with descriptive error messages that help both developers and users understand what went wrong.

**Incorrect (type assertions on route parameters):**

```typescript
// ❌ 'as string' provides zero runtime safety
export async function GET(
  request: Request,
  { params }: { params: { id: string } }
) {
  const supabase = await createClient()

  // ❌ params.id could be undefined, empty string, or not a valid UUID
  const projectId = params.id as string

  const { data, error } = await supabase
    .from('projects')
    .select('*')
    .eq('id', projectId) // If projectId is not a UUID, this returns empty or errors
    .single()

  return Response.json(data)
}
```

**Incorrect (type assertions on form data):**

```typescript
'use server'

export async function updateProfile(formData: FormData) {
  const supabase = await createClient()

  // ❌ All of these could be null, empty, or unexpected types
  const displayName = formData.get('displayName') as string
  const bio = formData.get('bio') as string
  const age = formData.get('age') as string

  const { error } = await supabase
    .from('profiles')
    .update({
      display_name: displayName,  // Could be null or empty
      bio: bio,                    // Could exceed column length
      age: parseInt(age),          // parseInt(null) = NaN → database error
    })
    .eq('id', userId)
}
```

**Incorrect (type assertions on request body):**

```typescript
// ❌ Trusting request body shape
export async function POST(request: Request) {
  const body = await request.json() as { name: string; teamId: string }
  // body could be anything: null, array, missing fields, extra fields

  const { error } = await supabase
    .from('projects')
    .insert({
      name: body.name,     // Could be undefined → NOT NULL violation
      team_id: body.teamId // Could be "not-a-uuid" → FK violation
    })
}
```

**Correct (Zod validation on route parameters):**

```typescript
import { z } from 'zod'

const ParamsSchema = z.object({
  id: z.string().uuid('Invalid project ID format'),
})

export async function GET(
  request: Request,
  { params }: { params: { id: string } }
) {
  // ✅ Validates that id exists and is a valid UUID
  const result = ParamsSchema.safeParse(params)

  if (!result.success) {
    return Response.json(
      { error: 'Invalid project ID', details: result.error.flatten() },
      { status: 400 }
    )
  }

  const supabase = await createClient()

  const { data, error } = await supabase
    .from('projects')
    .select('id, name, status, created_at')
    .eq('id', result.data.id) // ✅ Guaranteed valid UUID
    .single()

  if (error) {
    if (error.code === 'PGRST116') {
      return Response.json({ error: 'Project not found' }, { status: 404 })
    }
    return Response.json({ error: 'Internal error' }, { status: 500 })
  }

  return Response.json(data)
}
```

**Correct (Zod validation on form data in Server Actions):**

```typescript
'use server'

import { z } from 'zod'

const UpdateProfileSchema = z.object({
  displayName: z.string().min(1, 'Name is required').max(100, 'Name too long'),
  bio: z.string().max(500, 'Bio must be under 500 characters').optional(),
  age: z.coerce.number().int().min(13).max(150).optional(),
})

export async function updateProfile(formData: FormData) {
  // ✅ Validate and coerce all inputs
  const result = UpdateProfileSchema.safeParse({
    displayName: formData.get('displayName'),
    bio: formData.get('bio'),
    age: formData.get('age'),
  })

  if (!result.success) {
    return { error: result.error.flatten().fieldErrors }
  }

  const supabase = await createClient()
  const { data: { user } } = await supabase.auth.getUser()
  if (!user) throw new Error('Unauthorized')

  const { error } = await supabase
    .from('profiles')
    .update({
      display_name: result.data.displayName,
      bio: result.data.bio,
      age: result.data.age,
    })
    .eq('id', user.id)

  if (error) throw new Error('Failed to update profile')

  revalidatePath('/profile')
  return { success: true }
}
```

**Correct (Zod validation on request body):**

```typescript
import { z } from 'zod'

const CreateProjectSchema = z.object({
  name: z.string().min(1).max(200),
  teamId: z.string().uuid(),
  description: z.string().max(2000).optional(),
})

export async function POST(request: Request) {
  const body = await request.json()

  // ✅ Full runtime validation with descriptive errors
  const result = CreateProjectSchema.safeParse(body)

  if (!result.success) {
    return Response.json(
      { error: 'Validation failed', details: result.error.flatten() },
      { status: 400 }
    )
  }

  const supabase = await createClient()

  const { data, error } = await supabase
    .from('projects')
    .insert({
      name: result.data.name,         // ✅ Guaranteed string, 1-200 chars
      team_id: result.data.teamId,    // ✅ Guaranteed valid UUID
      description: result.data.description,
    })
    .select('id, name')
    .single()

  if (error) {
    return Response.json({ error: 'Failed to create project' }, { status: 500 })
  }

  return Response.json(data, { status: 201 })
}
```

**Detection hints:**

```bash
# Find 'as string' assertions on external input
grep -rn "as string\|as number" src/ --include="*.ts" --include="*.tsx"
# Find formData.get() without Zod validation
grep -rn "formData.get(" src/ --include="*.ts" --include="*.tsx"
# Find request.json() without schema validation
grep -rn "request.json()" src/ --include="*.ts" --include="*.tsx"
```

Reference: [Zod Documentation](https://zod.dev/) · [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)

---

*Generated by BeforeMerge build script on 2026-03-04.*
*Version: 0.1.0 | Rules: 20*