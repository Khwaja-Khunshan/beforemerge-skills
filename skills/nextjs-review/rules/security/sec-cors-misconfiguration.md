---
title: Restrict CORS to Specific Allowed Origins
description: "Setting Access-Control-Allow-Origin to wildcard or reflecting the request Origin lets any website make authenticated requests to your API."
impact: HIGH
impact_description: allows unauthorized cross-origin access to API endpoints and user data
tags: [security, cors, api, route-handlers, nextjs]
cwe: ["CWE-942"]
owasp: ["A05:2021"]
detection_grep: "Access-Control-Allow-Origin|cors|CORS"
---

## Restrict CORS to Specific Allowed Origins

**Impact: HIGH (allows unauthorized cross-origin access to API endpoints and user data)**

Next.js route handlers have no CORS headers by default — which is secure. Problems start when developers add permissive CORS to "fix" cross-origin errors during development and ship it to production. The two most dangerous patterns:

1. **`Access-Control-Allow-Origin: *`** — any website can read your API responses
2. **Reflecting the request `Origin` header** — any website can make credentialed requests

**Incorrect (permissive CORS):**

```typescript
// app/api/user/route.ts
// ❌ Wildcard allows ANY website to read user data
export async function GET(request: NextRequest) {
  const user = await getCurrentUser(request)
  return NextResponse.json(user, {
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE',
      'Access-Control-Allow-Headers': '*',
    },
  })
}
```

```typescript
// ❌ Reflecting Origin without validation — even worse with credentials
export async function GET(request: NextRequest) {
  const origin = request.headers.get('origin')
  return NextResponse.json(data, {
    headers: {
      'Access-Control-Allow-Origin': origin ?? '*', // Reflects anything!
      'Access-Control-Allow-Credentials': 'true',   // With cookies!
    },
  })
}
```

```typescript
// ❌ middleware.ts blanket CORS for all API routes
export function middleware(request: NextRequest) {
  const response = NextResponse.next()
  response.headers.set('Access-Control-Allow-Origin', '*')
  return response
}
```

**Correct (strict CORS with origin allowlist):**

```typescript
// lib/cors.ts
const ALLOWED_ORIGINS = new Set([
  'https://app.example.com',
  'https://admin.example.com',
  ...(process.env.NODE_ENV === 'development' ? ['http://localhost:3000'] : []),
])

export function getCorsHeaders(request: NextRequest) {
  const origin = request.headers.get('origin')

  // Only allow listed origins
  if (!origin || !ALLOWED_ORIGINS.has(origin)) {
    return {} // No CORS headers = browser blocks the request
  }

  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Max-Age': '86400', // Cache preflight for 24 hours
  }
}
```

```typescript
// app/api/user/route.ts
import { getCorsHeaders } from '@/lib/cors'

// ✅ Handle preflight
export async function OPTIONS(request: NextRequest) {
  return new NextResponse(null, {
    status: 204,
    headers: getCorsHeaders(request),
  })
}

export async function GET(request: NextRequest) {
  const session = await auth()
  if (!session?.user) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }

  const user = await getUser(session.user.id)
  return NextResponse.json(user, {
    headers: getCorsHeaders(request),
  })
}
```

**Key CORS rules:**

1. **Never use `*` with `Access-Control-Allow-Credentials: true`** — browsers block this, but developers often work around it with Origin reflection, which is worse
2. **Validate the Origin against an allowlist** — do not reflect it blindly
3. **Keep the allowlist in server-side config** — not in client code or env vars prefixed with `NEXT_PUBLIC_`
4. **If your API is only consumed by your own frontend** — you may not need CORS at all (same-origin requests don't need it)

**Detection hints:**

```bash
# Find permissive CORS headers
grep -rn "Access-Control-Allow-Origin.*\*" src/ --include="*.ts" --include="*.tsx"
# Find Origin reflection
grep -rn "Access-Control-Allow-Origin.*origin\|Allow-Origin.*request.headers" src/ --include="*.ts"
```

Reference: [MDN CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS) · [CWE-942: Permissive Cross-domain Policy](https://cwe.mitre.org/data/definitions/942.html)
