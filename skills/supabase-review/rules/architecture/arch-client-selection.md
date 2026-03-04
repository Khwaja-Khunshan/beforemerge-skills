---
title: Use the Correct Supabase Client for Each Context
description: "Using the wrong Supabase client for the context breaks RLS, leaks auth state, or causes hydration errors. Match client type to Next.js rendering context."
impact: HIGH
impact_description: prevents RLS bypass, auth leaks, and hydration mismatches
tags: [architecture, supabase, client, server, middleware, nextjs, ssr]
detection_grep: "createClient"
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
