---
title: Rate Limit Every API Route with Appropriate Buckets
description: "API routes without rate limiting enable brute force, DDoS, and credit exhaustion attacks. Apply tiered rate limits as the first middleware."
impact: HIGH
impact_description: prevents brute force attacks, resource exhaustion, and API abuse
tags: [security, rate-limiting, brute-force, middleware, api, nextjs]
cwe: ["CWE-770"]
owasp: ["A04:2021"]
detection_grep: "export async function POST"
---

## Rate Limit Every API Route with Appropriate Buckets

**Impact: HIGH (prevents brute force attacks, resource exhaustion, and API abuse)**

Every API route is a public endpoint. Without rate limiting, attackers can brute force authentication, exhaust AI/API credits, enumerate data, or DDoS your application. Rate limiting should be the first middleware in the compose chain, applied before authentication or any business logic runs.

Different endpoints need different limits. A general CRUD endpoint can tolerate 60 requests per minute, but an AI-powered endpoint should be limited to 10, and authentication endpoints to 5.

**Incorrect (no rate limiting on any routes):**

```typescript
// app/api/ai/analyze/route.ts
// ❌ No rate limiting — attacker can burn through your entire OpenAI budget
export async function POST(request: NextRequest) {
  const session = await getSession()
  if (!session) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }

  const { code } = await request.json()
  const result = await openai.chat.completions.create({
    model: 'gpt-4',
    messages: [{ role: 'user', content: `Analyze: ${code}` }],
  })

  return NextResponse.json({ analysis: result.choices[0].message.content })
}
```

```typescript
// app/api/auth/login/route.ts
// ❌ No rate limiting — attacker can try millions of passwords
export async function POST(request: NextRequest) {
  const { email, password } = await request.json()
  const user = await verifyCredentials(email, password)
  if (!user) {
    return NextResponse.json({ error: 'Invalid credentials' }, { status: 401 })
  }
  return NextResponse.json({ token: createToken(user) })
}
```

**Correct (tiered rate limiting as first middleware):**

```typescript
// lib/middleware/withRateLimit.ts
import { Ratelimit } from '@upstash/ratelimit'
import { Redis } from '@upstash/redis'

const redis = Redis.fromEnv()

// ✅ Rate limit bucket table — different limits for different sensitivity levels
const buckets = {
  default: new Ratelimit({
    redis,
    limiter: Ratelimit.slidingWindow(60, '1 m'),  // 60 req/min
    prefix: 'rl:default',
  }),
  ai: new Ratelimit({
    redis,
    limiter: Ratelimit.slidingWindow(10, '1 m'),  // 10 req/min
    prefix: 'rl:ai',
  }),
  auth: new Ratelimit({
    redis,
    limiter: Ratelimit.slidingWindow(5, '15 m'),  // 5 req/15 min
    prefix: 'rl:auth',
  }),
  webhook: new Ratelimit({
    redis,
    limiter: Ratelimit.slidingWindow(100, '1 m'), // 100 req/min
    prefix: 'rl:webhook',
  }),
} as const

type BucketName = keyof typeof buckets

export function withRateLimit(bucket: BucketName = 'default') {
  return (handler: RouteHandler): RouteHandler => {
    return async (request: NextRequest, context) => {
      const ip = request.headers.get('x-forwarded-for') ?? 'unknown'
      const limiter = buckets[bucket]
      const { success, remaining, reset } = await limiter.limit(ip)

      if (!success) {
        return NextResponse.json(
          { error: 'Too many requests. Please try again later.' },
          {
            status: 429,
            headers: {
              'Retry-After': String(Math.ceil((reset - Date.now()) / 1000)),
              'X-RateLimit-Remaining': String(remaining),
            },
          }
        )
      }

      return handler(request, context)
    }
  }
}
```

```typescript
// app/api/ai/analyze/route.ts
// ✅ Rate limiting is the first middleware — runs before auth or business logic
import { compose } from '@/lib/middleware/compose'
import { withRateLimit } from '@/lib/middleware/withRateLimit'
import { withAuth } from '@/lib/middleware/withAuth'

export const POST = compose(
  withRateLimit('ai'),     // 10 req/min — expensive operation
  withAuth(),
)(async (request: NextRequest, context: AuthenticatedContext) => {
  const { code } = await request.json()
  const result = await analyzeService.analyze(context.user.id, code)
  return NextResponse.json(result)
})
```

```typescript
// app/api/auth/login/route.ts
// ✅ Auth endpoints get the strictest limits
export const POST = compose(
  withRateLimit('auth'),   // 5 req/15 min — prevent brute force
)(async (request: NextRequest) => {
  const input = LoginSchema.parse(await request.json())
  const result = await authService.login(input)
  // ...
})
```

**Rate limit bucket reference:**

| Bucket | Limit | Use For |
|--------|-------|---------|
| `default` | 60/min | Standard CRUD endpoints |
| `ai` | 10/min | AI-powered endpoints, expensive computations |
| `auth` | 5/15 min | Login, signup, password reset, OTP |
| `webhook` | 100/min | Incoming webhooks from trusted services |

**Detection hints:**

```bash
# Find route handlers without rate limiting
grep -rn "export async function POST\|export async function GET" src/app/api --include="*.ts" -l
# Check which routes use rate limiting
grep -rn "withRateLimit\|rateLimit" src/app/api --include="*.ts" -l
```

Reference: [Upstash Rate Limiting](https://upstash.com/docs/oss/sdks/ts/ratelimit/overview) · [CWE-770: Allocation of Resources Without Limits](https://cwe.mitre.org/data/definitions/770.html) · [OWASP A04:2021](https://owasp.org/Top10/A04_2021-Insecure_Design/)
