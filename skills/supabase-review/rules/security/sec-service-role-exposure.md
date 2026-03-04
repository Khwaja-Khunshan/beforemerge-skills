---
title: Never Use Service Role Client in Auth-Context Routes
description: "createServiceRoleClient() bypasses ALL RLS policies. Using it in request handlers lets any authenticated user access or modify all data."
impact: CRITICAL
impact_description: prevents complete RLS bypass in user-facing endpoints
tags: [security, supabase, service-role, rls, privilege-escalation]
cwe: ["CWE-269"]
owasp: ["A04:2021"]
detection_grep: "createServiceRoleClient"
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
