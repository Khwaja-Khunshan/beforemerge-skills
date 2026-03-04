---
title: Authenticate Route Handlers Like Server Actions
description: "App Router route handlers (GET, POST, PUT, DELETE) are public HTTP endpoints. Every exported function must independently verify auth — middleware alone is insufficient."
impact: CRITICAL
impact_description: prevents unauthorized access to API endpoints that bypass middleware
tags: [security, route-handlers, authentication, authorization, api, nextjs]
cwe: ["CWE-862"]
owasp: ["A01:2021"]
detection_grep: "export async function GET|export async function POST|export async function PUT|export async function DELETE"
---

## Authenticate Route Handlers Like Server Actions

**Impact: CRITICAL (prevents unauthorized access to API endpoints that bypass middleware)**

App Router route handlers (`app/api/.../route.ts`) are publicly accessible HTTP endpoints. Each exported function — `GET`, `POST`, `PUT`, `DELETE` — resolves independently and must verify authentication and authorization on its own. Middleware and layout-level auth checks do not protect route handlers because:

1. Route handlers are resolved independently from the page component tree
2. Middleware can be bypassed (see CVE-2025-29927)
3. Direct HTTP requests skip the UI entirely — there is no layout wrapping an API call

This is the route handler equivalent of `sec-server-action-auth`. The same principle applies: treat every route handler as a public-facing API endpoint.

**Incorrect (no auth — anyone can call this):**

```typescript
// app/api/users/[id]/route.ts
// ❌ Assumes middleware already checked auth
export async function GET(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  const user = await db.user.findUnique({ where: { id: params.id } })
  return NextResponse.json(user) // Leaks any user's data
}

export async function DELETE(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  await db.user.delete({ where: { id: params.id } }) // Anyone can delete any user
  return NextResponse.json({ success: true })
}
```

**Correct (auth in every handler):**

```typescript
// app/api/users/[id]/route.ts
import { auth } from '@/lib/auth'

export async function GET(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  const session = await auth()
  if (!session?.user) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }

  // Authorization: users can only read their own data (or admins can read any)
  if (session.user.id !== params.id && session.user.role !== 'admin') {
    return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
  }

  const user = await db.user.findUnique({ where: { id: params.id } })
  if (!user) {
    return NextResponse.json({ error: 'Not found' }, { status: 404 })
  }

  return NextResponse.json(user)
}

export async function DELETE(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  const session = await auth()
  if (!session?.user) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }
  if (session.user.role !== 'admin') {
    return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
  }

  await db.user.delete({ where: { id: params.id } })
  return NextResponse.json({ success: true })
}
```

**Extract a reusable auth guard to reduce boilerplate:**

```typescript
// lib/api-auth.ts
import { auth } from '@/lib/auth'
import { NextResponse } from 'next/server'

export async function requireAuth(roles?: string[]) {
  const session = await auth()
  if (!session?.user) {
    return { error: NextResponse.json({ error: 'Unauthorized' }, { status: 401 }) }
  }
  if (roles && !roles.includes(session.user.role)) {
    return { error: NextResponse.json({ error: 'Forbidden' }, { status: 403 }) }
  }
  return { session }
}

// Usage in route handler:
export async function DELETE(request: NextRequest, { params }) {
  const { session, error } = await requireAuth(['admin'])
  if (error) return error
  // ... safe to proceed
}
```

**Detection hints:**

```bash
# Find route handlers missing auth checks
grep -rn "export async function GET\|export async function POST\|export async function PUT\|export async function DELETE" src/ --include="*.ts" -l | \
  xargs grep -L "auth\|session\|getServerSession\|requireAuth"
```

Reference: [Next.js Route Handlers](https://nextjs.org/docs/app/building-your-application/routing/route-handlers) · [CWE-862: Missing Authorization](https://cwe.mitre.org/data/definitions/862.html)
