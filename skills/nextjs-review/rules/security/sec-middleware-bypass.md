---
title: Never Rely Solely on Middleware for Authorization
description: "Next.js middleware can be bypassed (CVE-2025-29927). Always enforce auth checks inside route handlers and Server Actions as defense-in-depth."
impact: CRITICAL
impact_description: complete authentication bypass allowing unauthorized access to all protected routes
tags: [security, middleware, authentication, authorization, nextjs, cve]
cwe: ["CWE-287"]
owasp: ["A01:2021"]
detection_grep: "middleware.ts"
---

## Never Rely Solely on Middleware for Authorization

**Impact: CRITICAL (complete authentication bypass allowing unauthorized access to all protected routes)**

CVE-2025-29927 (CVSS 9.1) proved that Next.js middleware can be bypassed entirely with a single HTTP header. An internal `x-middleware-subrequest` header — designed to prevent infinite recursion — was trusted from external clients. Any attacker who set this header skipped all middleware logic, including auth checks, redirects, and access control. This affected Next.js 11.1.4 through 15.2.2.

Even on patched versions, middleware is a **convenience layer**, not a security boundary. The defense-in-depth rule: **every route handler and Server Action must independently verify authentication and authorization.**

**Incorrect (relying solely on middleware for auth):**

```typescript
// middleware.ts — the ONLY place auth is checked
import { NextResponse } from 'next/server'
import { verifyToken } from '@/lib/auth'

export function middleware(request: NextRequest) {
  const token = request.cookies.get('session')?.value
  if (!token || !verifyToken(token)) {
    return NextResponse.redirect(new URL('/login', request.url))
  }
  return NextResponse.next()
}

export const config = {
  matcher: ['/dashboard/:path*', '/api/admin/:path*'],
}

// ❌ Route handler assumes middleware already checked auth
// app/api/admin/users/route.ts
export async function DELETE(request: NextRequest) {
  const { userId } = await request.json()
  await db.user.delete({ where: { id: userId } }) // No auth check!
  return NextResponse.json({ success: true })
}
```

**Correct (auth in middleware AND in each handler):**

```typescript
// middleware.ts — first layer (convenience: redirects, early rejection)
export function middleware(request: NextRequest) {
  const token = request.cookies.get('session')?.value
  if (!token) {
    return NextResponse.redirect(new URL('/login', request.url))
  }
  return NextResponse.next()
}

// app/api/admin/users/route.ts — second layer (authoritative)
import { auth } from '@/lib/auth'

export async function DELETE(request: NextRequest) {
  const session = await auth() // Always re-verify
  if (!session?.user) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }
  if (session.user.role !== 'admin') {
    return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
  }

  const { userId } = await request.json()
  await db.user.delete({ where: { id: userId } })
  return NextResponse.json({ success: true })
}
```

**If self-hosting, strip the header at the reverse proxy:**

```nginx
# nginx — block the internal header from external clients
proxy_set_header x-middleware-subrequest "";
```

**Detection hints:**

```bash
# Find route handlers that don't contain auth checks
grep -rn "export async function GET\|export async function POST\|export async function PUT\|export async function DELETE" src/ --include="*.ts" --include="*.tsx" -l | \
  xargs grep -L "auth\|session\|getServerSession"
# Check if middleware is the only auth layer
grep -rn "matcher.*dashboard\|matcher.*admin\|matcher.*api" middleware.ts
```

Reference: [CVE-2025-29927](https://nvd.nist.gov/vuln/detail/CVE-2025-29927) · [Vercel Postmortem](https://vercel.com/blog/postmortem-on-next-js-middleware-bypass) · [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
