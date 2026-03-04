---
title: Understand CSRF Limitations in Server Actions
description: "Next.js Server Actions rely on Origin header checks, not CSRF tokens. Reverse proxies and misconfigured allowedOrigins can bypass this protection."
impact: HIGH
impact_description: cross-site request forgery enabling unauthorized state changes on behalf of authenticated users
tags: [security, csrf, server-actions, authentication, nextjs]
cwe: ["CWE-352"]
owasp: ["A01:2021"]
detection_grep: "allowedOrigins|serverActions"
---

## Understand CSRF Limitations in Server Actions

**Impact: HIGH (cross-site request forgery enabling unauthorized state changes on behalf of authenticated users)**

Next.js Server Actions have built-in CSRF mitigation: they only accept POST requests and compare the `Origin` header against the host. However, this is **not** a CSRF token — it has known limitations:

1. **Reverse proxies that strip the `Origin` header** — some proxies, load balancers, or WAFs remove or rewrite the `Origin` header, disabling the check entirely
2. **Misconfigured `serverActions.allowedOrigins`** — adding domains to the allowlist expands who can invoke your actions cross-origin
3. **Same-site subdomains** — if an attacker controls `evil.example.com` and your app is on `app.example.com`, same-origin policies may not protect you

**Incorrect (assuming Server Actions are CSRF-proof):**

```typescript
// next.config.js
// ❌ Overly permissive allowedOrigins
module.exports = {
  experimental: {
    serverActions: {
      allowedOrigins: ['*'], // Disables CSRF protection entirely!
    },
  },
}
```

```typescript
// next.config.js
// ❌ Allowing untrusted origins
module.exports = {
  experimental: {
    serverActions: {
      allowedOrigins: [
        'app.example.com',
        'staging.example.com',
        'partner-site.com', // Do you trust this domain's security?
      ],
    },
  },
}
```

**Correct (tighten CSRF protection):**

```typescript
// next.config.js
// ✅ Only allow your own domains
module.exports = {
  experimental: {
    serverActions: {
      allowedOrigins: ['app.example.com'], // Strict — only your production domain
    },
  },
}
```

```typescript
// ✅ For sensitive mutations, add a CSRF token as defense-in-depth
// lib/csrf.ts
import { cookies } from 'next/headers'
import { randomBytes } from 'crypto'

export function generateCsrfToken() {
  const token = randomBytes(32).toString('hex')
  cookies().set('csrf-token', token, {
    httpOnly: true,
    sameSite: 'strict',
    secure: process.env.NODE_ENV === 'production',
  })
  return token
}

export function validateCsrfToken(token: string) {
  const stored = cookies().get('csrf-token')?.value
  if (!stored || stored !== token) {
    throw new Error('Invalid CSRF token')
  }
}
```

```typescript
// ✅ Use the token in high-value Server Actions
'use server'

import { validateCsrfToken } from '@/lib/csrf'
import { z } from 'zod'

const TransferSchema = z.object({
  csrfToken: z.string(),
  toAccount: z.string(),
  amount: z.number().positive(),
})

export async function transferFunds(rawInput: unknown) {
  const { csrfToken, toAccount, amount } = TransferSchema.parse(rawInput)
  validateCsrfToken(csrfToken) // Extra layer for high-value actions
  // ... proceed with transfer
}
```

**If behind a reverse proxy, ensure Origin is forwarded:**

```nginx
# nginx — pass the Origin header through
proxy_set_header Origin $http_origin;
proxy_set_header Host $host;
```

**Detection hints:**

```bash
# Check if allowedOrigins is configured (and what it allows)
grep -rn "allowedOrigins" next.config.* --include="*.js" --include="*.ts" --include="*.mjs"
# Check if proxies might strip Origin
grep -rn "proxy_set_header\|ProxyPass\|X-Forwarded" nginx.conf apache.conf
```

Reference: [Next.js Server Actions Security](https://nextjs.org/blog/security-nextjs-server-components-actions) · [CWE-352: Cross-Site Request Forgery](https://cwe.mitre.org/data/definitions/352.html)
