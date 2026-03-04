---
title: Validate CSRF Tokens on All State-Changing Requests
description: "State-changing API routes without CSRF validation allow cross-site request forgery. Validate tokens on POST/PUT/PATCH/DELETE with known exemptions."
impact: HIGH
impact_description: prevents cross-site request forgery on mutation endpoints
tags: [security, csrf, mutations, middleware, api, nextjs]
cwe: ["CWE-352"]
owasp: ["A01:2021"]
detection_grep: "export async function POST"
---

## Validate CSRF Tokens on All State-Changing Requests

**Impact: HIGH (prevents cross-site request forgery on mutation endpoints)**

Cross-Site Request Forgery (CSRF) tricks authenticated users into making unintended state-changing requests. If a user is logged into your app and visits a malicious page, that page can submit forms or fire fetch requests to your API endpoints using the user's cookies. Without CSRF validation, every POST, PUT, PATCH, and DELETE endpoint is vulnerable.

CSRF protection should be applied as middleware in the compose chain, with explicit exemptions only for endpoints that handle their own authentication (webhooks, OAuth callbacks, cron jobs).

**Incorrect (no CSRF validation on mutation endpoints):**

```typescript
// app/api/rules/route.ts
// ❌ No CSRF check — a malicious page can create rules on behalf of logged-in users
export async function POST(request: NextRequest) {
  const session = await getSession()
  if (!session) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }

  const body = await request.json()
  const rule = await db.rules.create({
    user_id: session.user.id,
    ...body,
  })

  return NextResponse.json(rule, { status: 201 })
}
```

```typescript
// app/api/account/delete/route.ts
// ❌ Account deletion with zero CSRF protection
export async function DELETE(request: NextRequest) {
  const session = await getSession()
  if (!session) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }

  await db.users.delete({ where: { id: session.user.id } })
  return NextResponse.json({ success: true })
}
```

**Correct (CSRF validation as compose middleware):**

```typescript
// lib/middleware/withCsrf.ts
const CSRF_HEADER = 'x-csrf-token'
const CSRF_COOKIE = '__csrf'

// Paths exempt from CSRF — they authenticate via other mechanisms
const EXEMPT_PATHS = [
  '/api/webhooks/',       // Authenticated via signature verification
  '/api/cron/',           // Authenticated via CRON_SECRET header
  '/api/auth/callback/',  // OAuth callbacks use state parameter
]

export function withCsrf() {
  return (handler: RouteHandler): RouteHandler => {
    return async (request: NextRequest, context) => {
      // Only check mutations
      if (['GET', 'HEAD', 'OPTIONS'].includes(request.method)) {
        return handler(request, context)
      }

      // Skip exempt paths
      const pathname = new URL(request.url).pathname
      if (EXEMPT_PATHS.some((path) => pathname.startsWith(path))) {
        return handler(request, context)
      }

      const headerToken = request.headers.get(CSRF_HEADER)
      const cookieToken = request.cookies.get(CSRF_COOKIE)?.value

      if (!headerToken || !cookieToken || headerToken !== cookieToken) {
        return NextResponse.json(
          { error: 'Invalid CSRF token' },
          { status: 403 }
        )
      }

      return handler(request, context)
    }
  }
}
```

```typescript
// app/api/rules/route.ts
// ✅ CSRF validation applied via compose — runs before business logic
import { compose } from '@/lib/middleware/compose'
import { withRateLimit } from '@/lib/middleware/withRateLimit'
import { withCsrf } from '@/lib/middleware/withCsrf'
import { withAuth } from '@/lib/middleware/withAuth'

export const POST = compose(
  withRateLimit('default'),
  withCsrf(),
  withAuth(),
)(async (request: NextRequest, context: AuthenticatedContext) => {
  const input = CreateRuleSchema.parse(await request.json())
  const result = await ruleService.createRule(context.user.id, input)
  return NextResponse.json(result.data, { status: 201 })
})
```

```typescript
// lib/csrf.ts — Client-side token management
// ✅ Generate and attach CSRF token to all mutation requests
export function getCsrfToken(): string {
  const cookies = document.cookie.split(';')
  const csrf = cookies.find((c) => c.trim().startsWith('__csrf='))
  return csrf?.split('=')[1] ?? ''
}

// ✅ Use in fetch wrapper
export async function apiFetch(url: string, options: RequestInit = {}) {
  const method = options.method?.toUpperCase() ?? 'GET'
  const headers = new Headers(options.headers)

  if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
    headers.set('x-csrf-token', getCsrfToken())
  }

  return fetch(url, { ...options, headers })
}
```

**Exempt path reference:**

| Path Pattern | Reason | Alternative Auth |
|-------------|--------|-----------------|
| `/api/webhooks/*` | External service callbacks | Signature verification |
| `/api/cron/*` | Scheduled job triggers | `CRON_SECRET` header |
| `/api/auth/callback/*` | OAuth provider callbacks | OAuth state parameter |

**Detection hints:**

```bash
# Find POST/PUT/PATCH/DELETE handlers without CSRF
grep -rn "export async function POST\|export async function PUT\|export async function DELETE" src/app/api --include="*.ts" -l
# Check which routes use CSRF middleware
grep -rn "withCsrf\|validateCSRF\|csrf" src/app/api --include="*.ts" -l
```

Reference: [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html) · [CWE-352: Cross-Site Request Forgery](https://cwe.mitre.org/data/definitions/352.html)
