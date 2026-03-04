---
title: Implement Rate Limiting on Sensitive Endpoints
description: "Next.js has no built-in rate limiting. Without it, login, signup, password reset, and Server Actions are vulnerable to brute force and credential stuffing."
impact: HIGH
impact_description: prevents brute force attacks, credential stuffing, and resource exhaustion
tags: [security, rate-limiting, brute-force, authentication, api, nextjs]
cwe: ["CWE-799", "CWE-307"]
owasp: ["A04:2021"]
detection_grep: "rateLimit|rateLimiter|limiter"
---

## Implement Rate Limiting on Sensitive Endpoints

**Impact: HIGH (prevents brute force attacks, credential stuffing, and resource exhaustion)**

Next.js provides zero built-in rate limiting. Every login endpoint, password reset, signup form, OTP verification, and sensitive Server Action is vulnerable to brute force attacks by default. Credential stuffing is the #1 attack vector against authentication systems.

Without rate limiting, an attacker can:
- Try thousands of password combinations per minute
- Enumerate valid usernames via timing differences
- Exhaust AI/API credits by spamming expensive endpoints
- DoS your app by flooding Server Actions

**Incorrect (no rate limiting):**

```typescript
// app/api/auth/login/route.ts
// ❌ No rate limiting — attacker can try millions of passwords
export async function POST(request: NextRequest) {
  const { email, password } = await request.json()
  const user = await db.user.findUnique({ where: { email } })
  if (!user || !await verifyPassword(password, user.passwordHash)) {
    return NextResponse.json({ error: 'Invalid credentials' }, { status: 401 })
  }
  // ... create session
}
```

```typescript
// ❌ Server Action with no rate limiting on expensive operation
'use server'
export async function analyzeCode(code: string) {
  const result = await callAI(code) // Costs money per call!
  return result
}
```

**Correct (rate limiting with Upstash Redis):**

```typescript
// lib/rate-limit.ts
import { Ratelimit } from '@upstash/ratelimit'
import { Redis } from '@upstash/redis'

const redis = Redis.fromEnv()

// Different limiters for different sensitivity levels
export const authLimiter = new Ratelimit({
  redis,
  limiter: Ratelimit.slidingWindow(5, '15 m'), // 5 attempts per 15 minutes
  prefix: 'rl:auth',
})

export const apiLimiter = new Ratelimit({
  redis,
  limiter: Ratelimit.slidingWindow(60, '1 m'), // 60 requests per minute
  prefix: 'rl:api',
})

export const expensiveLimiter = new Ratelimit({
  redis,
  limiter: Ratelimit.slidingWindow(10, '1 h'), // 10 per hour
  prefix: 'rl:expensive',
})
```

```typescript
// app/api/auth/login/route.ts
import { authLimiter } from '@/lib/rate-limit'

export async function POST(request: NextRequest) {
  // Rate limit by IP (or email for account-level limiting)
  const ip = request.headers.get('x-forwarded-for') ?? 'unknown'
  const { success, remaining, reset } = await authLimiter.limit(ip)

  if (!success) {
    return NextResponse.json(
      { error: 'Too many attempts. Try again later.' },
      {
        status: 429,
        headers: {
          'Retry-After': String(Math.ceil((reset - Date.now()) / 1000)),
          'X-RateLimit-Remaining': String(remaining),
        },
      }
    )
  }

  const { email, password } = await request.json()
  // ... validate credentials
}
```

```typescript
// ✅ Rate limiting in Server Actions
'use server'

import { expensiveLimiter } from '@/lib/rate-limit'
import { auth } from '@/lib/auth'
import { headers } from 'next/headers'

export async function analyzeCode(rawInput: unknown) {
  const session = await auth()
  if (!session?.user) throw new Error('Unauthorized')

  // Rate limit by user ID for authenticated actions
  const { success } = await expensiveLimiter.limit(session.user.id)
  if (!success) {
    return { error: 'Rate limit exceeded. Please wait before trying again.' }
  }

  // ... proceed with expensive operation
}
```

**Lightweight alternative (in-memory, for single-instance deployments):**

```typescript
// lib/rate-limit-memory.ts — no external dependencies
const attempts = new Map<string, { count: number; resetAt: number }>()

export function checkRateLimit(key: string, maxAttempts: number, windowMs: number) {
  const now = Date.now()
  const entry = attempts.get(key)

  if (!entry || now > entry.resetAt) {
    attempts.set(key, { count: 1, resetAt: now + windowMs })
    return { success: true, remaining: maxAttempts - 1 }
  }

  if (entry.count >= maxAttempts) {
    return { success: false, remaining: 0, resetAt: entry.resetAt }
  }

  entry.count++
  return { success: true, remaining: maxAttempts - entry.count }
}
```

**Detection hints:**

```bash
# Find auth endpoints without rate limiting
grep -rn "login\|signin\|signup\|reset-password\|verify-otp" src/app/api --include="*.ts" -l | \
  xargs grep -L "rateLimit\|limiter\|Ratelimit\|rateLimiter"
# Find server actions doing expensive operations without limits
grep -rn "callAI\|openai\|anthropic\|stripe" src/ --include="*.ts" --include="*.tsx" -l | \
  xargs grep -L "rateLimit\|limiter"
```

Reference: [Upstash Rate Limiting](https://upstash.com/docs/oss/sdks/ts/ratelimit/overview) · [CWE-307: Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html)
