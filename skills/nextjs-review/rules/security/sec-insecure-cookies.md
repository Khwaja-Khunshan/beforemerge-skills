---
title: Set Secure Cookie Attributes (HttpOnly, Secure, SameSite)
description: "Session cookies without HttpOnly, Secure, and SameSite are vulnerable to XSS theft and CSRF. The Next.js cookies() API does not enforce secure defaults."
impact: HIGH
impact_description: prevents session hijacking via XSS and cross-site request forgery
tags: [security, cookies, session, authentication, xss, csrf, nextjs]
cwe: ["CWE-614", "CWE-1004"]
owasp: ["A05:2021"]
detection_grep: "cookies().set|setCookie|Set-Cookie"
---

## Set Secure Cookie Attributes (HttpOnly, Secure, SameSite)

**Impact: HIGH (prevents session hijacking via XSS and cross-site request forgery)**

The Next.js `cookies()` API makes it easy to set cookies but does **not** enforce secure defaults. A session cookie missing `HttpOnly` can be stolen by XSS (`document.cookie`). A cookie missing `Secure` can be intercepted over HTTP. A cookie missing `SameSite` defaults to `Lax` in modern browsers, but explicit is better than implicit for security-critical cookies.

**Incorrect (missing security attributes):**

```typescript
// ❌ No HttpOnly — any XSS can steal this cookie
import { cookies } from 'next/headers'

export async function login(credentials: unknown) {
  const session = await createSession(credentials)
  cookies().set('session-token', session.token)
  // Default: no HttpOnly, no Secure, SameSite=Lax (browser default)
}
```

```typescript
// ❌ Explicitly insecure
cookies().set('session-token', token, {
  httpOnly: false,  // Accessible via document.cookie — XSS can steal it
  secure: false,    // Sent over HTTP — vulnerable to MITM
  sameSite: 'none', // Sent on ALL cross-site requests — CSRF risk
})
```

```typescript
// ❌ Setting cookies via headers without attributes
return new NextResponse(null, {
  headers: {
    'Set-Cookie': `token=${value}`, // No attributes at all!
  },
})
```

**Correct (secure cookie configuration):**

```typescript
import { cookies } from 'next/headers'

// ✅ Always set all three security attributes on session cookies
export async function login(credentials: unknown) {
  const session = await createSession(credentials)

  cookies().set('session-token', session.token, {
    httpOnly: true,                                    // Not accessible via JS
    secure: process.env.NODE_ENV === 'production',     // HTTPS only in prod
    sameSite: 'lax',                                   // Prevents most CSRF
    path: '/',                                         // Available site-wide
    maxAge: 60 * 60 * 24 * 7,                          // 7 days
  })
}
```

```typescript
// ✅ For auth tokens that never need client-side access
cookies().set('auth-token', token, {
  httpOnly: true,
  secure: true,
  sameSite: 'strict',  // Strictest: never sent cross-site
  path: '/',
  maxAge: 60 * 60 * 24, // 24 hours
})

// ✅ For CSRF tokens that DO need client-side access
cookies().set('csrf-token', csrfToken, {
  httpOnly: false,     // Client JS needs to read this to send in headers
  secure: true,
  sameSite: 'strict',
  path: '/',
})
```

**Create a helper to enforce defaults:**

```typescript
// lib/cookies.ts
import { cookies } from 'next/headers'

const SECURE_DEFAULTS: Partial<ResponseCookie> = {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'lax' as const,
  path: '/',
}

export function setSecureCookie(
  name: string,
  value: string,
  options?: Partial<ResponseCookie>
) {
  cookies().set(name, value, { ...SECURE_DEFAULTS, ...options })
}

// Usage:
setSecureCookie('session-token', token, { maxAge: 60 * 60 * 24 * 7 })
```

**Cookie attribute reference:**

| Attribute | Purpose | Value for session cookies |
|-----------|---------|--------------------------|
| `httpOnly` | Blocks `document.cookie` access | `true` (always) |
| `secure` | HTTPS only | `true` in production |
| `sameSite` | Controls cross-site sending | `lax` or `strict` |
| `path` | URL scope | `/` (or narrowest needed) |
| `maxAge` | Expiry in seconds | Match your session lifetime |

**Detection hints:**

```bash
# Find cookie sets without security attributes
grep -rn "cookies().set\|\.set(" src/ --include="*.ts" --include="*.tsx" | grep -v "httpOnly\|HttpOnly"
# Find raw Set-Cookie headers
grep -rn "Set-Cookie" src/ --include="*.ts" --include="*.tsx"
```

Reference: [Next.js cookies() API](https://nextjs.org/docs/app/api-reference/functions/cookies) · [CWE-614: Sensitive Cookie Without 'Secure'](https://cwe.mitre.org/data/definitions/614.html) · [CWE-1004: Sensitive Cookie Without 'HttpOnly'](https://cwe.mitre.org/data/definitions/1004.html)
