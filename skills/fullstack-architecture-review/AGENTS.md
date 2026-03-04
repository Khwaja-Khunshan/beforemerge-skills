# BeforeMerge: fullstack-architecture-review

Code review rules for DRY/SOLID layered architecture in fullstack TypeScript applications. Covers dependency direction, service/repository patterns, factory injection, domain entities, and code quality patterns. Framework-agnostic principles with Next.js+Supabase examples.

## Table of Contents

### 1. Security Anti-Patterns (CRITICAL)
- 1. Validate CSRF Tokens on All State-Changing Requests — HIGH [CWE-352]
- 2. Never Expose Raw Errors or Stack Traces to Clients — MEDIUM [CWE-209]
- 3. Rate Limit Every API Route with Appropriate Buckets — HIGH [CWE-770]
- 4. Keep API Route Handlers Thin — Delegate to Services — CRITICAL [CWE-1064]
### 2. Performance Patterns (HIGH)
- 5. Keep 'use client' on the Smallest Possible Leaf Components — HIGH
- 6. Use Promise.all for Independent Data Fetches — HIGH
- 7. Stream Slow Content with Suspense Boundaries — MEDIUM
- 8. Prefer Server Components Over useEffect + Fetch for Data Loading — HIGH
### 3. Architecture Patterns (MEDIUM)
- 9. Build Features Bottom-Up from Domain to Presentation — MEDIUM
- 10. Dependency Direction Violation — CRITICAL [CWE-1047]
- 11. Domain Entities Must Be Framework-Independent — MEDIUM
- 12. Missing Factory for Dependency Injection — MEDIUM
- 13. Segregate Repository Interfaces by Consumer Need — MEDIUM
- 14. Missing Repository Abstraction — HIGH [CWE-1057]
- 15. Missing Service Layer — HIGH [CWE-1086]
### 4. Code Quality (LOW-MEDIUM)
- 16. Extract Duplicated Logic After the Third Occurrence — HIGH
- 17. Use Scoped Loggers with Structured Context — MEDIUM
- 18. Search Existing Code Before Creating New Utilities — MEDIUM
- 19. Use Consistent ServiceResult Type for All Service Returns — MEDIUM

---

## Rules

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

---

## Never Expose Raw Errors or Stack Traces to Clients

**Impact: MEDIUM (prevents leaking database schemas, file paths, and internal implementation details)**

Returning raw error messages or stack traces to API consumers exposes internal implementation details that attackers use for reconnaissance. A database error might reveal table names and column types. A file system error might reveal your deployment path. A validation library error might reveal your schema structure. Always return generic error messages for 5xx errors and include a `requestId` so developers can correlate client errors with server logs.

The key distinction is between operational errors (expected failures like "user not found" or "invalid input") and programmer errors (unexpected failures like null pointer exceptions or database connection failures). Operational errors can have descriptive messages. Programmer errors must always be generic.

**Incorrect (leaking raw errors to clients):**

```typescript
// app/api/rules/[id]/route.ts
// ❌ Raw error message and stack trace sent to client
export async function GET(request: NextRequest, { params }: { params: { id: string } }) {
  try {
    const supabase = await createServerSupabaseClient()
    const { data, error } = await supabase
      .from('rules')
      .select('*, conditions(*)')
      .eq('id', params.id)
      .single()

    if (error) {
      // ❌ Leaks table names, column names, and Supabase internals
      return NextResponse.json({ error: error.message }, { status: 500 })
    }

    return NextResponse.json(data)
  } catch (error) {
    // ❌ Stack trace reveals file paths, dependency versions, and code structure
    return NextResponse.json(
      {
        error: (error as Error).message,
        stack: (error as Error).stack,
      },
      { status: 500 }
    )
  }
}
```

```typescript
// ❌ Leaking validation details from third-party libraries
export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const rule = SomeInternalSchema.parse(body)
    // ...
  } catch (error) {
    // ❌ ZodError reveals entire schema structure to attackers
    return NextResponse.json({ error: error }, { status: 400 })
  }
}
```

**Correct (generic messages with requestId for debugging):**

```typescript
// lib/errors.ts
import { randomUUID } from 'crypto'

// ✅ Operational errors — expected failures with safe messages
export class AppError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly statusCode: number = 400
  ) {
    super(message)
    this.name = 'AppError'
  }
}

// ✅ Standard error response — never leaks internals
export function errorResponse(
  error: unknown,
  log: ScopedLogger
): NextResponse {
  const requestId = randomUUID()

  // Operational error — safe to show message to client
  if (error instanceof AppError) {
    log.warn('Operational error', {
      requestId,
      code: error.code,
      message: error.message,
    })
    return NextResponse.json(
      { error: error.message, code: error.code, requestId },
      { status: error.statusCode }
    )
  }

  // Zod validation error — safe to show field-level issues
  if (error instanceof ZodError) {
    log.warn('Validation error', {
      requestId,
      issues: error.issues,
    })
    return NextResponse.json(
      {
        error: 'Validation failed',
        details: error.issues.map((i) => ({
          field: i.path.join('.'),
          message: i.message,
        })),
        requestId,
      },
      { status: 400 }
    )
  }

  // Programmer error — NEVER expose details to client
  log.error('Unexpected error', {
    requestId,
    error: error instanceof Error ? error.message : String(error),
    stack: error instanceof Error ? error.stack : undefined,
  })

  return NextResponse.json(
    {
      error: 'An unexpected error occurred. Please try again.',
      requestId,
    },
    { status: 500 }
  )
}
```

```typescript
// app/api/rules/[id]/route.ts
// ✅ Clean error handling — all details stay server-side
import { errorResponse } from '@/lib/errors'
import { createScopedLogger } from '@/lib/logger'

const log = createScopedLogger('RulesAPI')

export const GET = compose(
  withRateLimit('default'),
  withAuth(),
)(async (request: NextRequest, context: AuthenticatedContext) => {
  try {
    const result = await ruleService.findById(context.params.id, context.user.id)

    if (!result.success) {
      return NextResponse.json(
        { error: result.error, code: result.code },
        { status: 404 }
      )
    }

    return NextResponse.json(result.data)
  } catch (error) {
    return errorResponse(error, log)
  }
})
```

**Error type reference:**

| Error Type | Client Message | Status | Log Level |
|-----------|---------------|--------|-----------|
| Operational (AppError) | Descriptive message | 4xx | `warn` |
| Validation (ZodError) | Field-level issues | 400 | `warn` |
| Programmer (unexpected) | Generic + requestId | 500 | `error` |

**Detection hints:**

```bash
# Find raw error messages being returned to clients
grep -rn "error\.message\|error\.stack" src/app/api --include="*.ts"
# Find catch blocks returning the raw error
grep -rn "catch.*error.*NextResponse\.json.*error" src/app/api --include="*.ts"
```

Reference: [OWASP Error Handling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html) · [CWE-209: Generation of Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/209.html)

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

---

## Keep API Route Handlers Thin — Delegate to Services

**Impact: CRITICAL (prevents untestable, unauditable business logic in the API layer)**

API route handlers that contain business logic, database queries, validation, and response formatting in one function are nearly impossible to unit test, difficult to audit for security, and guaranteed to accumulate technical debt. A "fat controller" is a code smell that violates the Single Responsibility Principle and makes it trivial to introduce security bugs — because the reviewer has to mentally parse 200+ lines to verify correctness.

Route handlers should do exactly three things: validate input, call a service, and return a response.

**Incorrect (fat controller with everything in the route handler):**

```typescript
// app/api/rules/route.ts
// ❌ 200+ line route handler doing validation, auth, DB queries, business logic, response formatting
export async function POST(request: NextRequest) {
  try {
    const session = await getSession()
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }

    const body = await request.json()

    // Validation mixed into the route
    if (!body.name || body.name.length > 100) {
      return NextResponse.json({ error: 'Invalid name' }, { status: 400 })
    }
    if (!body.conditions || !Array.isArray(body.conditions)) {
      return NextResponse.json({ error: 'Invalid conditions' }, { status: 400 })
    }

    // Direct database access in the route
    const supabase = await createServerSupabaseClient()
    const existing = await supabase
      .from('rules')
      .select('id')
      .eq('user_id', session.user.id)
      .eq('name', body.name)
      .single()

    if (existing.data) {
      return NextResponse.json({ error: 'Rule already exists' }, { status: 409 })
    }

    // Business logic embedded in route
    const priority = body.conditions.length > 5 ? 'high' : 'normal'
    const slug = body.name.toLowerCase().replace(/\s+/g, '-')
    const evaluationOrder = await supabase
      .from('rules')
      .select('evaluation_order')
      .eq('user_id', session.user.id)
      .order('evaluation_order', { ascending: false })
      .limit(1)
      .single()

    const nextOrder = (evaluationOrder.data?.evaluation_order ?? 0) + 1

    // More DB operations
    const { data: rule, error } = await supabase
      .from('rules')
      .insert({
        user_id: session.user.id,
        name: body.name,
        slug,
        priority,
        evaluation_order: nextOrder,
        conditions: body.conditions,
      })
      .select()
      .single()

    if (error) {
      console.log('Error creating rule:', error)
      return NextResponse.json({ error: error.message }, { status: 500 })
    }

    return NextResponse.json(rule, { status: 201 })
  } catch (error) {
    console.log('Error:', error)
    return NextResponse.json({ error: (error as Error).message }, { status: 500 })
  }
}
```

**Correct (thin route handler with compose middleware and service delegation):**

```typescript
// app/api/rules/route.ts
// ✅ Route handler is ~20 lines — validates input, calls service, returns response
import { compose } from '@/lib/middleware/compose'
import { withAuth } from '@/lib/middleware/withAuth'
import { withRateLimit } from '@/lib/middleware/withRateLimit'
import { withCsrf } from '@/lib/middleware/withCsrf'
import { ServiceFactory } from '@/lib/factories/ServiceFactory'
import { CreateRuleSchema } from '@/lib/validation/rule-schemas'

export const POST = compose(
  withRateLimit('default'),
  withCsrf(),
  withAuth(),
)(async (request: NextRequest, context: AuthenticatedContext) => {
  const body = await request.json()
  const input = CreateRuleSchema.parse(body)

  const ruleService = ServiceFactory.createRuleService()
  const result = await ruleService.createRule(context.user.id, input)

  if (!result.success) {
    const status = result.code === 'DUPLICATE' ? 409 : 400
    return NextResponse.json({ error: result.error }, { status })
  }

  return NextResponse.json(result.data, { status: 201 })
})
```

```typescript
// lib/middleware/compose.ts
// ✅ Compose pattern chains middleware cleanly
type Middleware = (
  handler: RouteHandler
) => RouteHandler

export function compose(...middlewares: Middleware[]) {
  return (handler: RouteHandler): RouteHandler => {
    return middlewares.reduceRight(
      (next, middleware) => middleware(next),
      handler
    )
  }
}
```

**Rule of thumb:** If your route handler exceeds 30 lines of actual logic (excluding imports and types), it is doing too much. Extract business logic to a service, validation to schemas, and cross-cutting concerns to middleware.

**Detection hints:**

```bash
# Find fat route handlers (files with POST/GET/PUT/DELETE exports over 50 lines)
grep -rn "export async function POST\|export async function GET" src/app/api --include="*.ts" -l
# Find direct database access in route handlers
grep -rn "createServerSupabaseClient\|supabase.*from.*select" src/app/api --include="*.ts" -l
```

Reference: [Clean Architecture — Robert C. Martin](https://blog.cleancoder.com/uncle-bob/2012/08/13/the-clean-architecture.html) · [CWE-1064: Invokable Control Element with Excessive File or Data Access](https://cwe.mitre.org/data/definitions/1064.html)

---

## Keep 'use client' on the Smallest Possible Leaf Components

**Impact: HIGH (reduces client-side JavaScript bundle size and improves initial page load)**

Every component marked with `'use client'` -- and its entire import tree -- ships JavaScript to the browser. Placing `'use client'` on a page component, layout, or large wrapper forces the entire subtree to be client-rendered, eliminating the benefits of Server Components (zero JS, direct data access, streaming). Push `'use client'` down to the smallest interactive leaf component.

The composition pattern lets you keep most of your component tree server-rendered while wrapping small interactive parts in client components.

**Incorrect ('use client' on large components that mostly render static content):**

```tsx
// app/rules/page.tsx
// ❌ Entire page is a client component — ships everything to the browser
'use client'

import { useState, useEffect } from 'react'
import { RulesList } from '@/components/RulesList'
import { RulesFilter } from '@/components/RulesFilter'
import { RulesStats } from '@/components/RulesStats'

export default function RulesPage() {
  const [rules, setRules] = useState([])
  const [filter, setFilter] = useState('all')

  useEffect(() => {
    fetch('/api/rules').then(r => r.json()).then(setRules)
  }, [])

  // ❌ RulesList and RulesStats are pure display but forced client-side
  // because the parent is 'use client'
  return (
    <div>
      <h1>Rules</h1>
      <RulesStats rules={rules} />
      <RulesFilter value={filter} onChange={setFilter} />
      <RulesList rules={rules} filter={filter} />
    </div>
  )
}
```

```tsx
// components/RulesStats.tsx
// ❌ This is pure display — doesn't need 'use client' but is forced into
// the client bundle because it's imported by a client component
'use client'

export function RulesStats({ rules }: { rules: Rule[] }) {
  return (
    <div>
      <span>Total: {rules.length}</span>
      <span>Active: {rules.filter(r => r.active).length}</span>
    </div>
  )
}
```

**Correct (server page with interactive leaves):**

```tsx
// app/rules/page.tsx
// ✅ Server Component — no JS shipped, direct data access
import { Suspense } from 'react'
import { ruleService } from '@/lib/services'
import { RulesStats } from '@/components/RulesStats'
import { RulesListWithFilter } from '@/components/RulesListWithFilter'

export default async function RulesPage() {
  const result = await ruleService.getRulesForCurrentUser()
  const rules = result.success ? result.data : []

  return (
    <div>
      <h1>Rules</h1>
      {/* ✅ Pure display — stays server-rendered, zero JS */}
      <RulesStats rules={rules} />
      {/* ✅ Only the interactive filter is a client component */}
      <RulesListWithFilter initialRules={rules} />
    </div>
  )
}
```

```tsx
// components/RulesStats.tsx
// ✅ No 'use client' — pure Server Component, ships zero JavaScript
export function RulesStats({ rules }: { rules: Rule[] }) {
  return (
    <div>
      <span>Total: {rules.length}</span>
      <span>Active: {rules.filter(r => r.active).length}</span>
    </div>
  )
}
```

```tsx
// components/RulesListWithFilter.tsx
// ✅ 'use client' only on the interactive wrapper — keeps interactivity minimal
'use client'

import { useState } from 'react'

export function RulesListWithFilter({ initialRules }: { initialRules: Rule[] }) {
  const [filter, setFilter] = useState('all')
  const filtered = filter === 'all'
    ? initialRules
    : initialRules.filter(r => r.status === filter)

  return (
    <>
      <select value={filter} onChange={e => setFilter(e.target.value)}>
        <option value="all">All</option>
        <option value="active">Active</option>
        <option value="draft">Draft</option>
      </select>
      <ul>
        {filtered.map(rule => (
          <li key={rule.id}>{rule.name}</li>
        ))}
      </ul>
    </>
  )
}
```

**The composition pattern (server parent passes children to client wrapper):**

```tsx
// components/CollapsibleSection.tsx
// ✅ Client component provides interactivity — children stay server-rendered
'use client'

import { useState, type ReactNode } from 'react'

export function CollapsibleSection({
  title,
  children,
}: {
  title: string
  children: ReactNode
}) {
  const [open, setOpen] = useState(true)
  return (
    <section>
      <button onClick={() => setOpen(!open)}>{title}</button>
      {open && children}
    </section>
  )
}

// app/rules/page.tsx — Server Component uses client wrapper
// ✅ HeavyContent stays server-rendered even though CollapsibleSection is client
export default async function RulesPage() {
  const data = await fetchHeavyData()
  return (
    <CollapsibleSection title="Details">
      <HeavyContent data={data} /> {/* Server Component — zero JS */}
    </CollapsibleSection>
  )
}
```

**Rule of thumb:** If a component does not use `useState`, `useEffect`, `useRef`, event handlers, or browser APIs, it should not have `'use client'`.

**Detection hints:**

```bash
# Find 'use client' in page files (likely too high in the tree)
grep -rn "use client" src/app --include="*.tsx" -l
# Find large client components
grep -rn "use client" src/components --include="*.tsx" -l
```

Reference: [Next.js Server and Client Components](https://nextjs.org/docs/app/building-your-application/rendering/composition-patterns) · [React Server Components](https://react.dev/reference/rsc/server-components)

---

## Use Promise.all for Independent Data Fetches

**Impact: HIGH (2-5x faster page loads by eliminating sequential data fetch waterfalls)**

Sequential `await` calls on independent operations add unnecessary latency. If `fetchUser()` takes 200ms, `fetchRules()` takes 300ms, and `fetchAnalytics()` takes 150ms, sequential execution takes 650ms while `Promise.all` takes 300ms — the time of the slowest call. This applies to Server Components, API route handlers, and service methods alike.

The pattern is especially damaging in service methods where multiple repository calls are independent.

**Incorrect (sequential awaits for independent operations):**

```typescript
// lib/services/DashboardService.ts
// ❌ Three independent fetches executed sequentially — total: sum of all three
async getDashboardData(userId: string): Promise<ServiceResult<DashboardData>> {
  const user = await this.userRepo.findById(userId)          // 200ms
  const rules = await this.ruleRepo.findByUserId(userId)     // 300ms
  const analytics = await this.analyticsRepo.getSummary(userId) // 150ms
  // Total: 650ms

  return success({
    user,
    rules,
    analytics,
  })
}
```

```typescript
// app/dashboard/page.tsx
// ❌ Sequential Server Component fetches
export default async function DashboardPage() {
  const user = await fetchUser()           // 200ms
  const posts = await fetchPosts()         // 300ms
  const notifications = await fetchNotifs() // 100ms
  // Total: 600ms — user stares at blank screen

  return <Dashboard user={user} posts={posts} notifications={notifications} />
}
```

**Correct (parallel execution with Promise.all):**

```typescript
// lib/services/DashboardService.ts
// ✅ All three fire simultaneously — total: max of all three
async getDashboardData(userId: string): Promise<ServiceResult<DashboardData>> {
  const [user, rules, analytics] = await Promise.all([
    this.userRepo.findById(userId),           // 200ms ─┐
    this.ruleRepo.findByUserId(userId),       // 300ms ─┤ All concurrent
    this.analyticsRepo.getSummary(userId),    // 150ms ─┘
  ])
  // Total: 300ms (max of the three)

  if (!user) {
    return failure('User not found', 'USER_NOT_FOUND')
  }

  return success({ user, rules, analytics })
}
```

**Correct (Suspense-based progressive rendering for Server Components):**

```tsx
// app/dashboard/page.tsx
// ✅ Even better: stream content as each piece resolves independently
import { Suspense } from 'react'

export default function DashboardPage() {
  return (
    <div className="grid grid-cols-2 gap-4">
      <Suspense fallback={<UserCardSkeleton />}>
        <UserSection />
      </Suspense>
      <Suspense fallback={<RulesListSkeleton />}>
        <RulesSection />
      </Suspense>
      <Suspense fallback={<AnalyticsSkeleton />}>
        <AnalyticsSection />
      </Suspense>
    </div>
  )
}

// Each component fetches its own data — React streams them as they resolve
async function UserSection() {
  const user = await userService.getCurrentUser()
  return <UserCard user={user} />
}

async function RulesSection() {
  const rules = await ruleService.getActiveRules()
  return <RulesList rules={rules} />
}
```

**Partial dependencies (when some calls depend on others):**

```typescript
// ✅ Fetch user first (needed for dependent calls), then parallelize the rest
async getProfileData(userId: string): Promise<ServiceResult<ProfileData>> {
  const user = await this.userRepo.findById(userId)
  if (!user) {
    return failure('User not found', 'USER_NOT_FOUND')
  }

  // These depend on user.teamId but not on each other
  const [teamMembers, teamRules, teamAnalytics] = await Promise.all([
    this.teamRepo.getMembers(user.teamId),
    this.ruleRepo.findByTeamId(user.teamId),
    this.analyticsRepo.getTeamSummary(user.teamId),
  ])

  return success({ user, teamMembers, teamRules, teamAnalytics })
}
```

**Detection hints:**

```bash
# Find consecutive awaits that might be parallelizable
grep -rn "const.*= await" src/lib/services --include="*.ts"
grep -rn "const.*= await" src/app --include="*.tsx"
```

Reference: [MDN Promise.all](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise/all) · [Next.js Parallel Data Fetching](https://nextjs.org/docs/app/building-your-application/data-fetching/fetching#parallel-data-fetching)

---

## Stream Slow Content with Suspense Boundaries

**Impact: MEDIUM (improves perceived load time by showing content as it becomes available)**

A page that awaits all data before rendering shows a blank screen (or a full-page spinner) until the slowest query completes. If your page fetches user data (50ms), rules (200ms), and analytics from a third-party API (2 seconds), the entire page is blocked for 2 seconds — even though most content was ready in 200ms.

Suspense boundaries let React stream content to the client as each section resolves. Fast sections appear immediately while slow sections show skeleton placeholders, then pop in when ready. This dramatically improves perceived performance without changing your data fetching logic.

**Incorrect (all-or-nothing page rendering):**

```tsx
// app/dashboard/page.tsx
// ❌ Entire page blocked until slowest fetch completes
export default async function DashboardPage() {
  const user = await fetchUser()                    // 50ms
  const rules = await ruleService.getActiveRules()  // 200ms
  const analytics = await analyticsApi.getSummary()  // 2000ms ← blocks everything

  // User sees nothing for 2+ seconds
  return (
    <div>
      <UserHeader user={user} />
      <RulesSummary rules={rules} />
      <AnalyticsDashboard analytics={analytics} />
    </div>
  )
}
```

```tsx
// ❌ Even with Promise.all, page still blocks until slowest resolves
export default async function DashboardPage() {
  const [user, rules, analytics] = await Promise.all([
    fetchUser(),                   // 50ms  ─┐
    ruleService.getActiveRules(),  // 200ms ─┤ Concurrent but page
    analyticsApi.getSummary(),     // 2000ms ┘ still waits for all three
  ])

  return (
    <div>
      <UserHeader user={user} />
      <RulesSummary rules={rules} />
      <AnalyticsDashboard analytics={analytics} />
    </div>
  )
}
```

**Correct (Suspense boundaries for progressive streaming):**

```tsx
// app/dashboard/page.tsx
// ✅ Fast sections render immediately, slow sections stream in
import { Suspense } from 'react'

export default async function DashboardPage() {
  // Fast data fetched at page level — available immediately
  const user = await fetchUser() // 50ms

  return (
    <div>
      {/* ✅ Renders instantly — data already loaded */}
      <UserHeader user={user} />

      {/* ✅ Renders in ~200ms with its own loading state */}
      <Suspense fallback={<RulesSummarySkeleton />}>
        <RulesSummarySection userId={user.id} />
      </Suspense>

      {/* ✅ Renders in ~2s — doesn't block anything above */}
      <Suspense fallback={<AnalyticsSkeleton />}>
        <AnalyticsSection userId={user.id} />
      </Suspense>
    </div>
  )
}
```

```tsx
// components/RulesSummarySection.tsx
// ✅ Async Server Component — fetches its own data independently
async function RulesSummarySection({ userId }: { userId: string }) {
  const rules = await ruleService.getActiveRules(userId) // 200ms
  return <RulesSummary rules={rules} />
}

// components/AnalyticsSection.tsx
// ✅ Slow third-party call doesn't block the rest of the page
async function AnalyticsSection({ userId }: { userId: string }) {
  const analytics = await analyticsApi.getSummary(userId) // 2000ms
  return <AnalyticsDashboard analytics={analytics} />
}
```

```tsx
// components/skeletons/AnalyticsSkeleton.tsx
// ✅ Meaningful skeleton — matches the shape of the real content
export function AnalyticsSkeleton() {
  return (
    <div className="animate-pulse space-y-4">
      <div className="h-8 w-48 bg-gray-200 rounded" />
      <div className="grid grid-cols-3 gap-4">
        {[1, 2, 3].map((i) => (
          <div key={i} className="h-32 bg-gray-200 rounded" />
        ))}
      </div>
      <div className="h-64 bg-gray-200 rounded" />
    </div>
  )
}
```

**When to use Suspense vs Promise.all:**

| Scenario | Use | Reason |
|----------|-----|--------|
| All data needed before render | `Promise.all` | Can't show partial UI |
| Sections can render independently | `Suspense` | Stream content progressively |
| Mix of fast and slow fetches | `Suspense` | Show fast content immediately |
| Data dependencies between sections | `Promise.all` first, then `Suspense` | Resolve dependencies, stream the rest |

**Detection hints:**

```bash
# Find page components with multiple sequential awaits (candidates for Suspense)
grep -rn "await.*Service\|await.*fetch\|await.*api" src/app --include="page.tsx"
# Find pages without any Suspense boundaries
grep -rL "Suspense" src/app --include="page.tsx"
```

Reference: [React Suspense](https://react.dev/reference/react/Suspense) · [Next.js Streaming](https://nextjs.org/docs/app/building-your-application/routing/loading-ui-and-streaming)

---

## Prefer Server Components Over useEffect + Fetch for Data Loading

**Impact: HIGH (eliminates client-side waterfalls, loading spinners, and unnecessary API roundtrips)**

The `useEffect` + `useState` data fetching pattern is a legacy from the Client Component era. It creates a waterfall: the page loads, JavaScript executes, the component renders, useEffect fires, a network request goes to your API route, the API route queries the database, the response travels back, then the component re-renders with data. Server Components eliminate this entire chain by fetching data directly on the server during rendering.

The critical rule: **never create an API route just to fetch data for your own pages.** If the only consumer of an API route is your own frontend, the data should be fetched in a Server Component or server action instead.

**Incorrect (useEffect + fetch pattern):**

```tsx
// components/RulesList.tsx
// ❌ Client-side data fetching — creates waterfall and unnecessary API route
'use client'

import { useState, useEffect } from 'react'

export function RulesList({ userId }: { userId: string }) {
  const [rules, setRules] = useState<Rule[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    fetch(`/api/rules?userId=${userId}`)
      .then(r => {
        if (!r.ok) throw new Error('Failed to fetch')
        return r.json()
      })
      .then(data => setRules(data))
      .catch(err => setError(err.message))
      .finally(() => setLoading(false))
  }, [userId])

  if (loading) return <Spinner /> // ❌ Loading spinner flashes on every navigation
  if (error) return <ErrorMessage message={error} />

  return (
    <ul>
      {rules.map(rule => (
        <li key={rule.id}>{rule.name}</li>
      ))}
    </ul>
  )
}
```

```typescript
// app/api/rules/route.ts
// ❌ API route exists ONLY to serve the client component above
export async function GET(request: NextRequest) {
  const userId = request.nextUrl.searchParams.get('userId')
  const supabase = await createServerSupabaseClient()
  const { data } = await supabase
    .from('rules')
    .select('*')
    .eq('user_id', userId)
  return NextResponse.json(data)
}
```

**Correct (async Server Component with direct data access):**

```tsx
// components/RulesList.tsx
// ✅ Server Component — fetches data directly, no loading state needed
import { ruleService } from '@/lib/services'

export async function RulesList({ userId }: { userId: string }) {
  const result = await ruleService.getRulesByUserId(userId)

  if (!result.success) {
    return <ErrorMessage message="Failed to load rules" />
  }

  return (
    <ul>
      {result.data.map(rule => (
        <li key={rule.id}>{rule.name}</li>
      ))}
    </ul>
  )
}

// No API route needed! The service fetches data directly on the server.
// The API route from the incorrect example can be deleted entirely.
```

```tsx
// app/rules/page.tsx
// ✅ Page is a Server Component — no useEffect, no loading spinner
import { Suspense } from 'react'
import { RulesList } from '@/components/RulesList'
import { getCurrentUser } from '@/lib/auth'

export default async function RulesPage() {
  const user = await getCurrentUser()

  return (
    <div>
      <h1>Your Rules</h1>
      <Suspense fallback={<RulesListSkeleton />}>
        <RulesList userId={user.id} />
      </Suspense>
    </div>
  )
}
```

**When you DO need an API route:**

```typescript
// ✅ API routes are for external consumers, webhooks, and client-side mutations
// These are valid API routes:

// External API consumed by mobile app or third parties
// app/api/v1/rules/route.ts
export async function GET(request: NextRequest) { /* ... */ }

// Webhook endpoint for external service
// app/api/webhooks/stripe/route.ts
export async function POST(request: NextRequest) { /* ... */ }

// Mutation triggered by client interaction (form submit, button click)
// app/api/rules/route.ts
export async function POST(request: NextRequest) { /* ... */ }
```

**Decision flowchart:**

| Question | Answer | Action |
|----------|--------|--------|
| Is data needed for initial page render? | Yes | Server Component |
| Is the only consumer your own frontend? | Yes | Server Component (delete the API route) |
| Is data needed after user interaction? | Yes | Server Action or API route |
| Do external clients need this data? | Yes | API route |
| Does data need real-time updates? | Yes | Client Component with subscription |

**Detection hints:**

```bash
# Find useEffect data fetching patterns
grep -rn "useEffect.*fetch\|useEffect.*axios\|useEffect.*api" src/ --include="*.tsx"
# Find API routes that only serve GET requests (candidates for elimination)
grep -rn "export async function GET" src/app/api --include="*.ts" -l
```

Reference: [Next.js Data Fetching](https://nextjs.org/docs/app/building-your-application/data-fetching) · [React Server Components](https://react.dev/reference/rsc/server-components)

---

## Build Features Bottom-Up from Domain to Presentation

**Impact: MEDIUM (Top-down development lets UI concerns leak into data models, creating tightly coupled systems)**

When building a new feature, the order in which you create the layers matters. Building top-down -- starting with the UI and working backward to the database -- causes the page layout to dictate the shape of your data model. Fields get added to entities because a form needs them. API routes return whatever the component expects. The result is a system where changing the UI requires changing the database schema and vice versa.

Build bottom-up instead: **Domain -> Interface -> Repository -> Service -> Controller/Route -> Presentation**. Define the business entity first, then the contract for accessing it, then the implementation, and finally the UI that consumes it. Each layer depends only on the layer below it, and no layer dictates the shape of another.

**Incorrect (top-down: page component drives everything, directly queries the database):**

```typescript
// src/app/scans/page.tsx

// ❌ Building top-down: the page component IS the feature
// UI concerns, data fetching, business logic, and presentation all in one file
import { createServerClient } from '@supabase/ssr';
import { cookies } from 'next/headers';

export default async function ScansPage() {
  const cookieStore = await cookies();
  const supabase = createServerClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
    { cookies: { getAll: () => cookieStore.getAll() } }
  );

  // ❌ Raw database query inside a React component
  const { data: scans, error } = await supabase
    .from('scans')
    .select(`
      id,
      repo_url,
      status,
      created_at,
      scan_results (
        id,
        rule_id,
        severity,
        line_number,
        file_path,
        message
      )
    `)
    .eq('user_id', (await supabase.auth.getUser()).data.user?.id)
    .order('created_at', { ascending: false });

  if (error) {
    return <div>Error loading scans</div>; // ❌ No proper error boundary
  }

  // ❌ Business logic computed inline in the component
  const scansWithStats = scans?.map((scan) => ({
    ...scan,
    criticalCount: scan.scan_results.filter((r) => r.severity === 'critical').length,
    highCount: scan.scan_results.filter((r) => r.severity === 'high').length,
    totalFindings: scan.scan_results.length,
    // ❌ UI display concern mixed with data transformation
    statusLabel: scan.status === 'in_progress' ? 'Running...' : scan.status,
    statusColor: scan.status === 'completed' ? 'green' : scan.status === 'failed' ? 'red' : 'yellow',
  }));

  return (
    <div className="space-y-4">
      <h1>Your Scans</h1>
      {scansWithStats?.map((scan) => (
        <div key={scan.id} className="border p-4 rounded">
          <p>{scan.repo_url}</p>
          <span style={{ color: scan.statusColor }}>{scan.statusLabel}</span>
          <p>{scan.criticalCount} critical, {scan.highCount} high, {scan.totalFindings} total</p>
        </div>
      ))}
    </div>
  );
}
```

**Correct (bottom-up: domain first, then repository, service, and finally the page):**

```typescript
// Step 1: Domain Entity -- define the business concept first
// src/domain/entities/scan.ts

// ✅ Pure TypeScript, no framework imports
export interface ScanEntity {
  id: string;
  repositoryUrl: string;
  status: ScanStatus;
  createdAt: Date;
  findings: ScanFinding[];
}

export type ScanStatus = 'pending' | 'in_progress' | 'completed' | 'failed';

export interface ScanFinding {
  id: string;
  ruleId: string;
  severity: FindingSeverity;
  lineNumber: number;
  filePath: string;
  message: string;
}

export type FindingSeverity = 'critical' | 'high' | 'medium' | 'low';

// ✅ Domain logic lives with the entity
export function computeScanStats(scan: ScanEntity): ScanStats {
  return {
    criticalCount: scan.findings.filter((f) => f.severity === 'critical').length,
    highCount: scan.findings.filter((f) => f.severity === 'high').length,
    totalFindings: scan.findings.length,
  };
}

export interface ScanStats {
  criticalCount: number;
  highCount: number;
  totalFindings: number;
}
```

```typescript
// Step 2: Repository Interface -- define the contract
// src/domain/repositories/scan-repository.ts

import type { ScanEntity } from '@/domain/entities/scan';

// ✅ Interface depends only on domain types
export interface ScanRepository {
  findByUserId(userId: string): Promise<ScanEntity[]>;
  findById(id: string): Promise<ScanEntity | null>;
}
```

```typescript
// Step 3: Repository Implementation -- infrastructure details
// src/infrastructure/repositories/supabase-scan-repository.ts

import type { SupabaseClient } from '@supabase/supabase-js';
import type { ScanRepository } from '@/domain/repositories/scan-repository';
import type { ScanEntity } from '@/domain/entities/scan';

// ✅ Framework imports stay in the infrastructure layer
export class SupabaseScanRepository implements ScanRepository {
  constructor(private readonly supabase: SupabaseClient) {}

  async findByUserId(userId: string): Promise<ScanEntity[]> {
    const { data, error } = await this.supabase
      .from('scans')
      .select('id, repo_url, status, created_at, scan_results (id, rule_id, severity, line_number, file_path, message)')
      .eq('user_id', userId)
      .order('created_at', { ascending: false });

    if (error) throw new Error(`Failed to fetch scans: ${error.message}`);

    // ✅ Map from database shape to domain shape
    return (data ?? []).map((row) => ({
      id: row.id,
      repositoryUrl: row.repo_url,
      status: row.status,
      createdAt: new Date(row.created_at),
      findings: row.scan_results.map((r) => ({
        id: r.id,
        ruleId: r.rule_id,
        severity: r.severity,
        lineNumber: r.line_number,
        filePath: r.file_path,
        message: r.message,
      })),
    }));
  }

  async findById(id: string): Promise<ScanEntity | null> {
    // ... similar mapping logic
    return null;
  }
}
```

```typescript
// Step 4: Service -- orchestrates business logic
// src/services/scan-list-service.ts

import type { ScanRepository } from '@/domain/repositories/scan-repository';
import { computeScanStats, type ScanEntity, type ScanStats } from '@/domain/entities/scan';

export interface ScanListItem {
  scan: ScanEntity;
  stats: ScanStats;
}

// ✅ Service depends on repository interface, not implementation
export class ScanListService {
  constructor(private readonly scanRepo: ScanRepository) {}

  async getUserScans(userId: string): Promise<ScanListItem[]> {
    const scans = await this.scanRepo.findByUserId(userId);

    return scans.map((scan) => ({
      scan,
      stats: computeScanStats(scan), // ✅ Uses domain logic from the entity module
    }));
  }
}
```

```typescript
// Step 5: Presentation -- consumes the service, handles only display concerns
// src/app/scans/page.tsx

import { ScanListService } from '@/services/scan-list-service';
import { createScanRepository } from '@/infrastructure/factories/scan-repository-factory';
import { getAuthenticatedUser } from '@/lib/auth';
import { ScanCard } from '@/components/scans/scan-card';

// ✅ Page component is thin -- it wires dependencies and renders
export default async function ScansPage() {
  const user = await getAuthenticatedUser();
  const scanRepo = createScanRepository();
  const service = new ScanListService(scanRepo);
  const items = await service.getUserScans(user.id);

  return (
    <div className="space-y-4">
      <h1>Your Scans</h1>
      {items.map(({ scan, stats }) => (
        <ScanCard key={scan.id} scan={scan} stats={stats} />
      ))}
    </div>
  );
}
```

Reference: [The Clean Architecture -- Robert C. Martin](https://blog.cleancoder.com/uncle-bob/2012/08/13/the-clean-architecture.html)

---

## Dependency Direction Violation

**Impact: CRITICAL (Inverted dependencies create circular coupling, break testability, and make refactoring cascade across the entire codebase)**

Clean Architecture enforces a strict dependency rule: source code dependencies must point inward. Each layer may only import from the layer directly below it or from shared domain types. The dependency hierarchy is:

```
Presentation (Components, Pages)
  -> Controllers (Route Handlers, Server Actions)
    -> Services (Business Logic)
      -> Repositories (Data Access)
        -> Domain (Types, Entities, Value Objects)
```

When a service imports from a route handler, or a repository imports from a service, the dependency arrow points outward. This creates tight coupling between layers that should be independent, makes unit testing impossible without spinning up HTTP infrastructure, and means changes in the outer layer break inner layers that should be stable.

**Incorrect (service imports from a route handler and accesses request-level concerns):**

```typescript
// ❌ lib/services/billing-service.ts
// VIOLATION: Service layer imports from the API route (controller) layer
import { validateApiKey } from "@/app/api/billing/route";
// VIOLATION: Service layer depends on Next.js request infrastructure
import { headers } from "next/headers";

export class BillingService {
  async createInvoice(customerId: string, amount: number) {
    // ❌ Service reaches into the HTTP layer to get auth context
    const headersList = await headers();
    const apiKey = headersList.get("x-api-key");

    // ❌ Service calls a function defined in a route handler file
    const isValid = await validateApiKey(apiKey);
    if (!isValid) {
      throw new Error("Unauthorized");
    }

    // ❌ Service is now untestable without mocking Next.js headers()
    const invoice = await this.generateInvoice(customerId, amount);
    return invoice;
  }
}
```

```typescript
// ❌ lib/repositories/user-repository.ts
// VIOLATION: Repository imports from the service layer
import { UserService } from "@/lib/services/user-service";
import { supabase } from "@/lib/supabase/client";

export class UserRepository {
  // ❌ Repository depends on a service to compute derived data
  async findActiveUsers() {
    const userService = new UserService();
    const users = await supabase.from("users").select("*");

    // ❌ Repository delegates business logic to a service it shouldn't know about
    return users.data?.filter((u) => userService.isUserActive(u));
  }
}
```

**Correct (each layer only imports from layers below it):**

```typescript
// ✅ Domain layer — no dependencies on any other layer
// lib/domain/types/billing.ts
export interface Invoice {
  id: string;
  customerId: string;
  amount: number;
  status: "draft" | "sent" | "paid";
  createdAt: Date;
}

export interface CreateInvoiceInput {
  customerId: string;
  amount: number;
}
```

```typescript
// ✅ Repository layer — depends only on Domain types
// lib/repositories/invoice-repository.ts
import type { Invoice, CreateInvoiceInput } from "@/lib/domain/types/billing";
import { createClient } from "@/lib/supabase/server";

export class InvoiceRepository {
  async create(input: CreateInvoiceInput): Promise<Invoice> {
    const supabase = await createClient();
    const { data, error } = await supabase
      .from("invoices")
      .insert({
        customer_id: input.customerId,
        amount: input.amount,
        status: "draft",
      })
      .select()
      .single();

    if (error) throw new Error(`Failed to create invoice: ${error.message}`);
    return this.toDomain(data);
  }

  private toDomain(row: Record<string, unknown>): Invoice {
    return {
      id: row.id as string,
      customerId: row.customer_id as string,
      amount: row.amount as number,
      status: row.status as Invoice["status"],
      createdAt: new Date(row.created_at as string),
    };
  }
}
```

```typescript
// ✅ Service layer — depends on Repository and Domain, never on Controllers
// lib/services/billing-service.ts
import type { Invoice, CreateInvoiceInput } from "@/lib/domain/types/billing";
import type { InvoiceRepository } from "@/lib/repositories/invoice-repository";

export interface ServiceResult<T> {
  success: boolean;
  data?: T;
  error?: string;
}

export class BillingService {
  constructor(private readonly invoiceRepo: InvoiceRepository) {}

  // ✅ Service receives already-authenticated context, no HTTP concerns
  async createInvoice(input: CreateInvoiceInput): Promise<ServiceResult<Invoice>> {
    if (input.amount <= 0) {
      return { success: false, error: "Invoice amount must be positive" };
    }

    const invoice = await this.invoiceRepo.create(input);
    return { success: true, data: invoice };
  }
}
```

```typescript
// ✅ Controller layer — depends on Service and Domain, handles HTTP concerns
// app/api/billing/invoices/route.ts
import { NextRequest, NextResponse } from "next/server";
import { ServiceFactory } from "@/lib/factories/service-factory";
import { authenticate } from "@/lib/middleware/auth";

export async function POST(request: NextRequest) {
  // ✅ Authentication lives in the controller/middleware layer
  const auth = await authenticate(request);
  if (!auth.success) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const body = await request.json();

  // ✅ Controller delegates to the service layer
  const billingService = ServiceFactory.createBillingService();
  const result = await billingService.createInvoice({
    customerId: body.customerId,
    amount: body.amount,
  });

  if (!result.success) {
    return NextResponse.json({ error: result.error }, { status: 400 });
  }

  return NextResponse.json(result.data, { status: 201 });
}
```

Reference: [Clean Architecture by Robert C. Martin](https://blog.cleancoder.com/uncle-bob/2012/08/13/the-clean-architecture.html)

---

## Domain Entities Must Be Framework-Independent

**Impact: MEDIUM (Framework-coupled entities break portability, testability, and violate clean architecture boundaries)**

Domain entities represent core business concepts -- User, Rule, Scan, Organization -- and encapsulate domain validation logic. They sit at the center of your architecture and should have zero knowledge of infrastructure concerns like databases, ORMs, UI frameworks, or HTTP. When domain entities import from `@supabase/supabase-js`, `react`, or `next`, every layer that depends on them inherits those framework dependencies, making the codebase rigid and difficult to test or migrate.

**Incorrect (domain entity coupled to Supabase types and database schema):**

```typescript
// src/domain/entities/user.ts
import { Database } from '@supabase/supabase-js'; // ❌ Framework dependency in domain layer

// ❌ Entity shape is dictated by the database schema, not business requirements
type UserRow = Database['public']['Tables']['users']['Row'];

export interface UserEntity extends UserRow { // ❌ Domain entity extends infrastructure type
  // Business logic is mixed with database concerns
  full_name: string; // ❌ Using snake_case from DB column names
  created_at: string; // ❌ String type because that's what Supabase returns
  subscription_tier: 'free' | 'pro' | 'enterprise';
}

// ❌ Validation logic depends on Supabase types
export function validateUser(user: UserRow): boolean {
  return user.full_name.length > 0 && user.email.includes('@');
}
```

**Correct (pure TypeScript domain entity with a separate mapping layer):**

```typescript
// src/domain/entities/user.ts
// ✅ Zero imports -- pure TypeScript, no framework dependencies

export interface UserEntity {
  id: string;
  fullName: string; // ✅ Domain uses camelCase, not DB column names
  email: string;
  subscriptionTier: SubscriptionTier;
  createdAt: Date; // ✅ Proper Date type, not a string
}

export type SubscriptionTier = 'free' | 'pro' | 'enterprise';

// ✅ Domain validation logic lives with the entity, uses no external types
export function validateUser(user: UserEntity): ValidationResult {
  const errors: string[] = [];

  if (!user.fullName || user.fullName.trim().length === 0) {
    errors.push('Full name is required');
  }

  if (!user.email || !user.email.includes('@')) {
    errors.push('A valid email address is required');
  }

  return { valid: errors.length === 0, errors };
}

export interface ValidationResult {
  valid: boolean;
  errors: string[];
}
```

```typescript
// src/infrastructure/mappers/user-mapper.ts
import type { Database } from '@/lib/supabase/types'; // ✅ Infrastructure import stays in infrastructure
import type { UserEntity } from '@/domain/entities/user';

type UserRow = Database['public']['Tables']['users']['Row'];

// ✅ Mapping layer translates between infrastructure and domain
export function toUserEntity(row: UserRow): UserEntity {
  return {
    id: row.id,
    fullName: row.full_name,
    email: row.email,
    subscriptionTier: row.subscription_tier,
    createdAt: new Date(row.created_at),
  };
}

export function toUserRow(entity: UserEntity): Omit<UserRow, 'id' | 'created_at'> {
  return {
    full_name: entity.fullName,
    email: entity.email,
    subscription_tier: entity.subscriptionTier,
  };
}
```

Reference: [Clean Architecture by Robert C. Martin](https://blog.cleancoder.com/uncle-bob/2012/08/13/the-clean-architecture.html)

---

## Missing Factory for Dependency Injection

**Impact: MEDIUM (Direct instantiation couples callers to concrete implementations, making it impossible to swap dependencies for testing or configuration)**

When a route handler or server action calls `new UserService(new UserRepository())` inline, three problems emerge: (1) every call site must know the full dependency graph of the service it creates, (2) swapping a real repository for a mock requires changing production code or complex module-level mocking, and (3) if `UserService` gains a new dependency, every call site must be updated.

Factory classes centralize dependency wiring. A `RepositoryFactory` creates repositories, and a `ServiceFactory` creates services by pulling their repository dependencies from the `RepositoryFactory`. Route handlers and server actions call `ServiceFactory.createUserService()` and receive a fully wired instance. In tests, you can create the service with mock repositories directly -- the factory is only the default wiring, not a required path.

**Incorrect (direct instantiation scattered across route handlers and server actions):**

```typescript
// ❌ app/api/users/[id]/route.ts
import { NextRequest, NextResponse } from "next/server";
import { UserService } from "@/lib/services/user-service";
import { UserRepository } from "@/lib/repositories/user-repository";
import { AuditLogRepository } from "@/lib/repositories/audit-log-repository";
import { EmailService } from "@/lib/services/email-service";
import { NotificationRepository } from "@/lib/repositories/notification-repository";

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  // ❌ Route handler knows the entire dependency graph
  const userRepo = new UserRepository();
  const auditRepo = new AuditLogRepository();
  const notificationRepo = new NotificationRepository();
  const emailService = new EmailService();
  const userService = new UserService(userRepo, auditRepo, notificationRepo, emailService);

  const { id } = await params;
  const result = await userService.getUser(id);
  return NextResponse.json(result);
}
```

```typescript
// ❌ app/actions/user.ts
"use server";

import { UserService } from "@/lib/services/user-service";
import { UserRepository } from "@/lib/repositories/user-repository";
import { AuditLogRepository } from "@/lib/repositories/audit-log-repository";
import { EmailService } from "@/lib/services/email-service";
import { NotificationRepository } from "@/lib/repositories/notification-repository";

export async function updateUserProfile(formData: FormData) {
  // ❌ Exact same wiring duplicated in a second file
  const userRepo = new UserRepository();
  const auditRepo = new AuditLogRepository();
  const notificationRepo = new NotificationRepository();
  const emailService = new EmailService();
  const userService = new UserService(userRepo, auditRepo, notificationRepo, emailService);

  // If UserService adds a new dependency, BOTH files break
  return userService.updateProfile(/* ... */);
}
```

```typescript
// ❌ lib/services/__tests__/user-service.test.ts
import { UserService } from "../user-service";

// ❌ Must use jest.mock to intercept module imports — brittle and opaque
jest.mock("@/lib/repositories/user-repository");
jest.mock("@/lib/repositories/audit-log-repository");
jest.mock("@/lib/repositories/notification-repository");
jest.mock("@/lib/services/email-service");

// Tests become tightly coupled to file paths and module structure
```

**Correct (factory classes centralize wiring; tests inject mocks directly through constructors):**

```typescript
// ✅ lib/factories/repository-factory.ts
import { UserRepository } from "@/lib/repositories/user-repository";
import { AuditLogRepository } from "@/lib/repositories/audit-log-repository";
import { NotificationRepository } from "@/lib/repositories/notification-repository";

export class RepositoryFactory {
  static createUserRepository(): UserRepository {
    return new UserRepository();
  }

  static createAuditLogRepository(): AuditLogRepository {
    return new AuditLogRepository();
  }

  static createNotificationRepository(): NotificationRepository {
    return new NotificationRepository();
  }
}
```

```typescript
// ✅ lib/factories/service-factory.ts
import { UserService } from "@/lib/services/user-service";
import { EmailService } from "@/lib/services/email-service";
import { TeamService } from "@/lib/services/team-service";
import { RepositoryFactory } from "./repository-factory";

export class ServiceFactory {
  // ✅ Single place that knows how to wire UserService
  static createUserService(): UserService {
    return new UserService(
      RepositoryFactory.createUserRepository(),
      RepositoryFactory.createAuditLogRepository(),
      RepositoryFactory.createNotificationRepository(),
      new EmailService()
    );
  }

  // ✅ Adding a new dependency to UserService only changes this file
  static createTeamService(): TeamService {
    return new TeamService(
      RepositoryFactory.createUserRepository(),
      new EmailService()
    );
  }
}
```

```typescript
// ✅ app/api/users/[id]/route.ts — clean, no wiring knowledge
import { NextRequest, NextResponse } from "next/server";
import { ServiceFactory } from "@/lib/factories/service-factory";

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  // ✅ One line — route handler does not know about repositories
  const userService = ServiceFactory.createUserService();

  const { id } = await params;
  const result = await userService.getUser(id);

  if (!result.success) {
    return NextResponse.json({ error: result.error }, { status: 404 });
  }

  return NextResponse.json(result.data);
}
```

```typescript
// ✅ app/actions/user.ts — same one-liner, zero duplication
"use server";

import { ServiceFactory } from "@/lib/factories/service-factory";

export async function updateUserProfile(formData: FormData) {
  const userService = ServiceFactory.createUserService();
  return userService.updateProfile(/* ... */);
}
```

```typescript
// ✅ lib/services/__tests__/user-service.test.ts — no jest.mock needed
import { UserService } from "../user-service";
import type { UserRepository } from "@/lib/repositories/user-repository";
import type { AuditLogRepository } from "@/lib/repositories/audit-log-repository";
import type { NotificationRepository } from "@/lib/repositories/notification-repository";
import type { EmailService } from "@/lib/services/email-service";

describe("UserService", () => {
  // ✅ Create lightweight mocks that satisfy the interface
  const mockUserRepo: jest.Mocked<Pick<UserRepository, "findById" | "update">> = {
    findById: jest.fn(),
    update: jest.fn(),
  };

  const mockAuditRepo: jest.Mocked<Pick<AuditLogRepository, "log">> = {
    log: jest.fn(),
  };

  const mockNotificationRepo: jest.Mocked<Pick<NotificationRepository, "create">> = {
    create: jest.fn(),
  };

  const mockEmailService: jest.Mocked<Pick<EmailService, "sendEmail">> = {
    sendEmail: jest.fn(),
  };

  // ✅ Inject mocks via constructor — no module-level patching
  const userService = new UserService(
    mockUserRepo as unknown as UserRepository,
    mockAuditRepo as unknown as AuditLogRepository,
    mockNotificationRepo as unknown as NotificationRepository,
    mockEmailService as unknown as EmailService
  );

  it("returns NOT_FOUND when user does not exist", async () => {
    mockUserRepo.findById.mockResolvedValue(null);

    const result = await userService.getUser("nonexistent-id");

    expect(result).toEqual({
      success: false,
      error: "User not found",
      code: "NOT_FOUND",
    });
    // ✅ Easy to assert exact calls without framework magic
    expect(mockUserRepo.findById).toHaveBeenCalledWith("nonexistent-id");
  });
});
```

Reference: [Dependency Injection Principles, Practices, and Patterns (Manning)](https://www.manning.com/books/dependency-injection-principles-practices-patterns)

---

## Segregate Repository Interfaces by Consumer Need

**Impact: MEDIUM (Monolithic interfaces increase coupling, bloat test mocks, and make refactoring risky)**

The Interface Segregation Principle (ISP) states that no client should be forced to depend on methods it does not use. When a single repository interface defines every possible operation -- read, write, search, aggregate, archive -- every consumer and every test mock must account for that entire surface area. A service that only reads data still depends on an interface that includes `delete` and `bulkUpdate`. Splitting interfaces into focused contracts (ReadRepository, WriteRepository, SearchRepository) reduces coupling, simplifies testing, and makes it obvious what capabilities each consumer actually requires.

**Incorrect (monolithic repository interface that forces all consumers to depend on everything):**

```typescript
// src/domain/repositories/scan-repository.ts

// ❌ One massive interface with 15+ methods
export interface ScanRepository {
  findById(id: string): Promise<Scan | null>;
  findByUserId(userId: string): Promise<Scan[]>;
  findByOrganization(orgId: string): Promise<Scan[]>;
  search(query: string, filters: ScanFilters): Promise<PaginatedResult<Scan>>;
  getAggregateStats(orgId: string): Promise<ScanStats>;
  create(scan: CreateScanInput): Promise<Scan>;
  update(id: string, data: Partial<Scan>): Promise<Scan>;
  bulkUpdate(ids: string[], data: Partial<Scan>): Promise<Scan[]>;
  delete(id: string): Promise<void>;
  bulkDelete(ids: string[]): Promise<void>;
  archive(id: string): Promise<void>;
  restore(id: string): Promise<void>;
  getHistory(id: string): Promise<ScanHistoryEntry[]>;
  export(orgId: string, format: ExportFormat): Promise<Buffer>;
  getRunningScans(): Promise<Scan[]>;
}
```

```typescript
// src/services/scan-summary-service.ts
import type { ScanRepository } from '@/domain/repositories/scan-repository';

export class ScanSummaryService {
  // ❌ This service only calls findById and getAggregateStats,
  //    but depends on the full 15-method interface
  constructor(private readonly scanRepo: ScanRepository) {}

  async getSummary(orgId: string): Promise<OrgScanSummary> {
    const stats = await this.scanRepo.getAggregateStats(orgId);
    return { organizationId: orgId, ...stats };
  }
}
```

```typescript
// src/__tests__/scan-summary-service.test.ts

// ❌ Test mock must implement all 15 methods even though the service uses 1
const mockRepo: ScanRepository = {
  findById: jest.fn(),
  findByUserId: jest.fn(),
  findByOrganization: jest.fn(),
  search: jest.fn(),
  getAggregateStats: jest.fn().mockResolvedValue(mockStats),
  create: jest.fn(),
  update: jest.fn(),
  bulkUpdate: jest.fn(),
  delete: jest.fn(),
  bulkDelete: jest.fn(),
  archive: jest.fn(),
  restore: jest.fn(),
  getHistory: jest.fn(),
  export: jest.fn(),
  getRunningScans: jest.fn(),
};
```

**Correct (segregated interfaces composed where needed):**

```typescript
// src/domain/repositories/scan-read-repository.ts

// ✅ Focused interface for read-only access
export interface ScanReadRepository {
  findById(id: string): Promise<Scan | null>;
  findByUserId(userId: string): Promise<Scan[]>;
  findByOrganization(orgId: string): Promise<Scan[]>;
}
```

```typescript
// src/domain/repositories/scan-write-repository.ts

// ✅ Focused interface for write operations
export interface ScanWriteRepository {
  create(scan: CreateScanInput): Promise<Scan>;
  update(id: string, data: Partial<Scan>): Promise<Scan>;
  delete(id: string): Promise<void>;
}
```

```typescript
// src/domain/repositories/scan-search-repository.ts

// ✅ Focused interface for search and aggregation
export interface ScanSearchRepository {
  search(query: string, filters: ScanFilters): Promise<PaginatedResult<Scan>>;
  getAggregateStats(orgId: string): Promise<ScanStats>;
}
```

```typescript
// src/domain/repositories/scan-lifecycle-repository.ts

// ✅ Focused interface for lifecycle management
export interface ScanLifecycleRepository {
  archive(id: string): Promise<void>;
  restore(id: string): Promise<void>;
  getHistory(id: string): Promise<ScanHistoryEntry[]>;
}
```

```typescript
// src/services/scan-summary-service.ts
import type { ScanSearchRepository } from '@/domain/repositories/scan-search-repository';

export class ScanSummaryService {
  // ✅ Depends only on the interface it actually uses
  constructor(private readonly scanSearch: ScanSearchRepository) {}

  async getSummary(orgId: string): Promise<OrgScanSummary> {
    const stats = await this.scanSearch.getAggregateStats(orgId);
    return { organizationId: orgId, ...stats };
  }
}
```

```typescript
// src/__tests__/scan-summary-service.test.ts

// ✅ Test mock only implements the 2 methods in ScanSearchRepository
const mockSearchRepo: ScanSearchRepository = {
  search: jest.fn(),
  getAggregateStats: jest.fn().mockResolvedValue(mockStats),
};

const service = new ScanSummaryService(mockSearchRepo);
```

```typescript
// src/infrastructure/repositories/supabase-scan-repository.ts

// ✅ The concrete implementation can still satisfy multiple interfaces
export class SupabaseScanRepository
  implements ScanReadRepository, ScanWriteRepository, ScanSearchRepository, ScanLifecycleRepository
{
  constructor(private readonly supabase: SupabaseClient) {}

  async findById(id: string): Promise<Scan | null> { /* ... */ }
  async findByUserId(userId: string): Promise<Scan[]> { /* ... */ }
  async findByOrganization(orgId: string): Promise<Scan[]> { /* ... */ }
  async search(query: string, filters: ScanFilters): Promise<PaginatedResult<Scan>> { /* ... */ }
  async getAggregateStats(orgId: string): Promise<ScanStats> { /* ... */ }
  async create(scan: CreateScanInput): Promise<Scan> { /* ... */ }
  async update(id: string, data: Partial<Scan>): Promise<Scan> { /* ... */ }
  async delete(id: string): Promise<void> { /* ... */ }
  async archive(id: string): Promise<void> { /* ... */ }
  async restore(id: string): Promise<void> { /* ... */ }
  async getHistory(id: string): Promise<ScanHistoryEntry[]> { /* ... */ }
}
```

Reference: [Interface Segregation Principle -- Robert C. Martin](https://web.archive.org/web/20150905081110/http://www.objectmentor.com/resources/articles/isp.pdf)

---

## Missing Repository Abstraction

**Impact: HIGH (Direct database calls in services tightly couple business logic to the data layer, preventing testing and making data source migrations costly)**

The Repository pattern places a typed abstraction between business logic and data persistence. When a service calls `supabase.from("users").select("*")` directly, that service is coupled to Supabase's query API, its column naming conventions, and its error structure. You cannot unit test the service without a live database or an elaborate mock of the Supabase client. If you later need to read users from a cache, a different database, or an external API, every service that touches that table must change.

Repositories own the mapping between database rows and domain types, handle query construction and error translation, and expose a small surface area of typed methods (`findById`, `create`, `update`) that services consume.

**Incorrect (Supabase queries scattered directly in the service layer):**

```typescript
// ❌ lib/services/project-service.ts
import { createClient } from "@/lib/supabase/server";

export class ProjectService {
  async getProjectWithMembers(projectId: string, userId: string) {
    const supabase = await createClient();

    // ❌ Raw Supabase query in the service — coupled to table schema
    const { data: project, error: projectError } = await supabase
      .from("projects")
      .select("id, name, description, created_at, owner_id")
      .eq("id", projectId)
      .single();

    if (projectError) {
      throw new Error("Project not found");
    }

    // ❌ Second query in the service — service knows about join tables
    const { data: members } = await supabase
      .from("project_members")
      .select(`
        user_id,
        role,
        users (id, full_name, avatar_url, email)
      `)
      .eq("project_id", projectId);

    // ❌ Authorization check uses raw query — logic is untestable
    const isMember = members?.some((m) => m.user_id === userId);
    if (!isMember) {
      throw new Error("Not a project member");
    }

    // ❌ Manual mapping from snake_case DB columns — duplicated everywhere
    return {
      id: project.id,
      name: project.name,
      description: project.description,
      createdAt: project.created_at,
      ownerId: project.owner_id,
      members: members?.map((m) => ({
        userId: m.user_id,
        role: m.role,
        name: (m.users as any).full_name,
        avatarUrl: (m.users as any).avatar_url,
        email: (m.users as any).email,
      })),
    };
  }

  async archiveProject(projectId: string) {
    const supabase = await createClient();

    // ❌ Another raw query — if the column name changes, every service breaks
    const { error } = await supabase
      .from("projects")
      .update({ archived_at: new Date().toISOString(), status: "archived" })
      .eq("id", projectId);

    if (error) {
      throw new Error("Failed to archive project");
    }
  }
}
```

**Correct (repository abstracts all data access behind typed methods):**

```typescript
// ✅ lib/domain/types/project.ts
export interface Project {
  id: string;
  name: string;
  description: string | null;
  ownerId: string;
  status: "active" | "archived";
  createdAt: Date;
  archivedAt: Date | null;
}

export interface ProjectMember {
  userId: string;
  role: "owner" | "editor" | "viewer";
  name: string;
  avatarUrl: string | null;
  email: string;
}

export interface ProjectWithMembers extends Project {
  members: ProjectMember[];
}
```

```typescript
// ✅ lib/repositories/project-repository.ts
import type { Project, ProjectMember, ProjectWithMembers } from "@/lib/domain/types/project";
import { createClient } from "@/lib/supabase/server";

export class ProjectRepository {
  // ✅ Typed method with a clear contract — callers never see Supabase types
  async findById(projectId: string): Promise<Project | null> {
    const supabase = await createClient();
    const { data, error } = await supabase
      .from("projects")
      .select("id, name, description, owner_id, status, created_at, archived_at")
      .eq("id", projectId)
      .single();

    if (error || !data) return null;
    return this.toProject(data);
  }

  // ✅ Join logic encapsulated — services don't know about join tables
  async findWithMembers(projectId: string): Promise<ProjectWithMembers | null> {
    const supabase = await createClient();

    const { data: project, error } = await supabase
      .from("projects")
      .select("id, name, description, owner_id, status, created_at, archived_at")
      .eq("id", projectId)
      .single();

    if (error || !project) return null;

    const { data: memberRows } = await supabase
      .from("project_members")
      .select(`
        user_id,
        role,
        users (id, full_name, avatar_url, email)
      `)
      .eq("project_id", projectId);

    return {
      ...this.toProject(project),
      members: (memberRows ?? []).map((m) => this.toMember(m)),
    };
  }

  // ✅ Membership check is a repository concern — simple, fast query
  async isMember(projectId: string, userId: string): Promise<boolean> {
    const supabase = await createClient();
    const { data } = await supabase
      .from("project_members")
      .select("user_id")
      .eq("project_id", projectId)
      .eq("user_id", userId)
      .single();

    return data !== null;
  }

  // ✅ Write operations also go through the repository
  async archive(projectId: string): Promise<void> {
    const supabase = await createClient();
    const { error } = await supabase
      .from("projects")
      .update({ archived_at: new Date().toISOString(), status: "archived" })
      .eq("id", projectId);

    if (error) {
      throw new Error(`Failed to archive project: ${error.message}`);
    }
  }

  // ✅ Mapping is centralized — column renames only change this file
  private toProject(row: Record<string, unknown>): Project {
    return {
      id: row.id as string,
      name: row.name as string,
      description: (row.description as string) ?? null,
      ownerId: row.owner_id as string,
      status: row.status as Project["status"],
      createdAt: new Date(row.created_at as string),
      archivedAt: row.archived_at ? new Date(row.archived_at as string) : null,
    };
  }

  private toMember(row: Record<string, unknown>): ProjectMember {
    const user = row.users as Record<string, unknown>;
    return {
      userId: row.user_id as string,
      role: row.role as ProjectMember["role"],
      name: user.full_name as string,
      avatarUrl: (user.avatar_url as string) ?? null,
      email: user.email as string,
    };
  }
}
```

```typescript
// ✅ lib/services/project-service.ts — clean, testable, no data access
import type { ProjectWithMembers } from "@/lib/domain/types/project";
import type { ProjectRepository } from "@/lib/repositories/project-repository";

type ServiceResult<T> =
  | { success: true; data: T }
  | { success: false; error: string; code?: string };

export class ProjectService {
  constructor(private readonly projectRepo: ProjectRepository) {}

  async getProjectWithMembers(
    projectId: string,
    userId: string
  ): Promise<ServiceResult<ProjectWithMembers>> {
    // ✅ Service calls repository methods — no idea how data is fetched
    const isMember = await this.projectRepo.isMember(projectId, userId);
    if (!isMember) {
      return { success: false, error: "Not a project member", code: "FORBIDDEN" };
    }

    const project = await this.projectRepo.findWithMembers(projectId);
    if (!project) {
      return { success: false, error: "Project not found", code: "NOT_FOUND" };
    }

    return { success: true, data: project };
  }

  async archiveProject(
    projectId: string,
    userId: string
  ): Promise<ServiceResult<void>> {
    const project = await this.projectRepo.findById(projectId);
    if (!project) {
      return { success: false, error: "Project not found", code: "NOT_FOUND" };
    }

    if (project.ownerId !== userId) {
      return { success: false, error: "Only the owner can archive a project", code: "FORBIDDEN" };
    }

    if (project.status === "archived") {
      return { success: false, error: "Project is already archived", code: "CONFLICT" };
    }

    await this.projectRepo.archive(projectId);
    return { success: true, data: undefined };
  }
}
```

Reference: [Patterns of Enterprise Application Architecture - Repository](https://martinfowler.com/eaaCatalog/repository.html)

---

## Missing Service Layer

**Impact: HIGH (Business logic scattered across handlers and actions is untestable, duplicated, and impossible to reuse across entry points)**

Route handlers and server actions are entry points, not business logic containers. When validation rules, authorization checks, data transformations, or orchestration logic lives inside a `POST` handler or `"use server"` function, that logic cannot be unit tested without simulating HTTP requests, cannot be reused when a second entry point (webhook, cron job, CLI) needs the same behavior, and becomes invisible to developers who assume thin controllers.

Services should return a discriminated union `ServiceResult<T>` rather than throwing exceptions or returning raw data. This forces callers to handle both success and failure paths explicitly and keeps HTTP status code decisions in the controller where they belong.

```typescript
// The ServiceResult pattern — define once, use everywhere
type ServiceResult<T> =
  | { success: true; data: T }
  | { success: false; error: string; code?: string };
```

**Incorrect (fat server action with business logic, validation, and data access mixed together):**

```typescript
// ❌ app/actions/team.ts
"use server";

import { createClient } from "@/lib/supabase/server";
import { revalidatePath } from "next/cache";

export async function inviteTeamMember(formData: FormData) {
  const supabase = await createClient();

  const email = formData.get("email") as string;
  const teamId = formData.get("teamId") as string;
  const role = formData.get("role") as string;

  // ❌ Validation logic embedded in the server action
  if (!email || !email.includes("@")) {
    return { error: "Valid email is required" };
  }
  if (!["admin", "member", "viewer"].includes(role)) {
    return { error: "Invalid role" };
  }

  // ❌ Authorization logic in the server action
  const { data: currentUser } = await supabase.auth.getUser();
  const { data: membership } = await supabase
    .from("team_members")
    .select("role")
    .eq("team_id", teamId)
    .eq("user_id", currentUser.user?.id)
    .single();

  if (membership?.role !== "admin") {
    return { error: "Only admins can invite members" };
  }

  // ❌ Business rule (duplicate check) in the server action
  const { data: existing } = await supabase
    .from("team_invitations")
    .select("id")
    .eq("team_id", teamId)
    .eq("email", email)
    .eq("status", "pending")
    .single();

  if (existing) {
    return { error: "Invitation already pending for this email" };
  }

  // ❌ Data mutation directly in the server action
  const { error } = await supabase.from("team_invitations").insert({
    team_id: teamId,
    email,
    role,
    invited_by: currentUser.user?.id,
    expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
  });

  if (error) {
    return { error: "Failed to send invitation" };
  }

  // ❌ Side effects (email sending) mixed in with everything else
  await fetch(`${process.env.NEXT_PUBLIC_APP_URL}/api/email/send`, {
    method: "POST",
    body: JSON.stringify({
      to: email,
      template: "team-invite",
      data: { teamId, role },
    }),
  });

  revalidatePath(`/dashboard/teams/${teamId}`);
  return { success: true };
}
```

**Correct (thin server action delegating to a service that returns ServiceResult):**

```typescript
// ✅ lib/domain/types/team.ts
export interface TeamInvitation {
  id: string;
  teamId: string;
  email: string;
  role: "admin" | "member" | "viewer";
  invitedBy: string;
  status: "pending" | "accepted" | "expired";
  expiresAt: Date;
}

export interface InviteMemberInput {
  teamId: string;
  email: string;
  role: "admin" | "member" | "viewer";
  invitedByUserId: string;
}
```

```typescript
// ✅ lib/services/team-service.ts
import type { TeamInvitation, InviteMemberInput } from "@/lib/domain/types/team";
import type { TeamRepository } from "@/lib/repositories/team-repository";
import type { EmailService } from "@/lib/services/email-service";

export type ServiceResult<T> =
  | { success: true; data: T }
  | { success: false; error: string; code?: string };

const VALID_ROLES = ["admin", "member", "viewer"] as const;
const INVITATION_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

export class TeamService {
  constructor(
    private readonly teamRepo: TeamRepository,
    private readonly emailService: EmailService
  ) {}

  // ✅ All business logic in one testable method
  async inviteMember(input: InviteMemberInput): Promise<ServiceResult<TeamInvitation>> {
    // ✅ Validation
    if (!input.email || !input.email.includes("@")) {
      return { success: false, error: "Valid email is required", code: "INVALID_EMAIL" };
    }
    if (!VALID_ROLES.includes(input.role as (typeof VALID_ROLES)[number])) {
      return { success: false, error: "Invalid role", code: "INVALID_ROLE" };
    }

    // ✅ Authorization check via repository
    const membership = await this.teamRepo.getMembership(input.teamId, input.invitedByUserId);
    if (membership?.role !== "admin") {
      return { success: false, error: "Only admins can invite members", code: "FORBIDDEN" };
    }

    // ✅ Business rule: prevent duplicate invitations
    const existingInvite = await this.teamRepo.findPendingInvitation(input.teamId, input.email);
    if (existingInvite) {
      return { success: false, error: "Invitation already pending for this email", code: "DUPLICATE" };
    }

    // ✅ Create invitation through repository
    const invitation = await this.teamRepo.createInvitation({
      teamId: input.teamId,
      email: input.email,
      role: input.role,
      invitedBy: input.invitedByUserId,
      expiresAt: new Date(Date.now() + INVITATION_TTL_MS),
    });

    // ✅ Side effect handled by a dedicated service
    await this.emailService.sendTeamInvitation(input.email, {
      teamId: input.teamId,
      role: input.role,
      invitationId: invitation.id,
    });

    return { success: true, data: invitation };
  }
}
```

```typescript
// ✅ app/actions/team.ts — thin server action, only wiring and response mapping
"use server";

import { createClient } from "@/lib/supabase/server";
import { ServiceFactory } from "@/lib/factories/service-factory";
import { revalidatePath } from "next/cache";

export async function inviteTeamMember(formData: FormData) {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();

  if (!user) {
    return { error: "Not authenticated" };
  }

  const teamService = ServiceFactory.createTeamService();

  // ✅ Server action only extracts input and delegates
  const result = await teamService.inviteMember({
    teamId: formData.get("teamId") as string,
    email: formData.get("email") as string,
    role: formData.get("role") as "admin" | "member" | "viewer",
    invitedByUserId: user.id,
  });

  if (!result.success) {
    return { error: result.error };
  }

  revalidatePath(`/dashboard/teams/${result.data.teamId}`);
  return { success: true, data: { id: result.data.id } };
}
```

Reference: [Patterns of Enterprise Application Architecture - Service Layer](https://martinfowler.com/eaaCatalog/serviceLayer.html)

---

## Extract Duplicated Logic After the Third Occurrence

**Impact: HIGH (prevents logic drift, reduces maintenance burden, and enforces consistency)**

The "Three Strikes" rule balances pragmatism with DRY: duplicate once (strike one), tolerate it (strike two), but the moment you write the same logic a third time (strike three), extract it to a shared location. Premature abstraction is harmful, but letting the same Supabase query, validation rule, type definition, or business calculation exist in three places guarantees that they will diverge over time, creating subtle bugs that are nearly impossible to track down.

The key is knowing *where* to extract. Different kinds of duplication belong in different layers.

**Incorrect (same logic duplicated across 3+ locations):**

```typescript
// app/api/rules/route.ts
// ❌ Strike 1: Supabase query for active rules
export async function GET(request: NextRequest) {
  const supabase = await createServerSupabaseClient()
  const { data } = await supabase
    .from('rules')
    .select('*, rule_conditions(*)')
    .eq('user_id', userId)
    .eq('is_active', true)
    .order('evaluation_order', { ascending: true })
  // ...
}
```

```typescript
// app/api/evaluation/route.ts
// ❌ Strike 2: Same query, slightly different
export async function POST(request: NextRequest) {
  const supabase = await createServerSupabaseClient()
  const { data: rules } = await supabase
    .from('rules')
    .select('*, rule_conditions(*)')
    .eq('user_id', userId)
    .eq('is_active', true)
    .order('evaluation_order', { ascending: true })
  // ...
}
```

```typescript
// lib/services/WebhookService.ts
// ❌ Strike 3: Same query AGAIN — now in a third location
async processWebhook(userId: string) {
  const supabase = await createServerSupabaseClient()
  const { data: rules } = await supabase
    .from('rules')
    .select('*, rule_conditions(*)')
    .eq('user_id', userId)
    .eq('is_active', true)
    .order('evaluation_order', { ascending: true })
  // ...
}
```

```typescript
// ❌ Same validation schema defined in 2 forms and 1 API route
// components/CreateRuleForm.tsx
const ruleSchema = z.object({
  name: z.string().min(1).max(100),
  conditions: z.array(conditionSchema).min(1).max(20),
})

// components/EditRuleForm.tsx
const ruleSchema = z.object({
  name: z.string().min(1).max(100),
  conditions: z.array(conditionSchema).min(1).max(20),
})

// app/api/rules/route.ts
const createRuleSchema = z.object({
  name: z.string().min(1).max(100),
  conditions: z.array(conditionSchema).min(1).max(20),
})
```

**Correct (extracted to the appropriate layer):**

```typescript
// lib/repositories/RuleRepository.ts
// ✅ Database query extracted to repository — single source of truth
export class SupabaseRuleRepository implements IRuleRepository {
  async findActiveByUserId(userId: string): Promise<Rule[]> {
    const { data, error } = await this.supabase
      .from('rules')
      .select('*, rule_conditions(*)')
      .eq('user_id', userId)
      .eq('is_active', true)
      .order('evaluation_order', { ascending: true })

    if (error || !data) return []
    return data.map(row => this.toDomain(row))
  }
}
```

```typescript
// lib/validation/rule-schemas.ts
// ✅ Validation schema extracted to shared location — used by forms AND API
import { z } from 'zod'

export const RuleConditionSchema = z.object({
  field: z.string().min(1),
  operator: z.enum(['equals', 'contains', 'matches', 'greater_than', 'less_than']),
  value: z.string(),
})

export const CreateRuleSchema = z.object({
  name: z.string().min(1).max(100),
  conditions: z.array(RuleConditionSchema).min(1).max(20),
})

export const UpdateRuleSchema = CreateRuleSchema.partial()

export type CreateRuleInput = z.infer<typeof CreateRuleSchema>
export type UpdateRuleInput = z.infer<typeof UpdateRuleSchema>
```

**Where to extract (layer mapping table):**

| Duplicated Logic | Extract To | Location |
|-----------------|-----------|----------|
| Database queries | Repository method | `lib/repositories/` |
| Business rules/calculations | Service method | `lib/services/` |
| Validation schemas | Shared schema | `lib/validation/` |
| Type definitions | Shared types | `lib/domain/types/` or `lib/types/` |
| UI patterns/components | Shared component | `components/` |
| Utility functions | Utility module | `lib/utils/` |
| API request helpers | API client | `lib/api/` |
| Constants/config | Config module | `lib/config/` |

**How to spot duplication:**

Before writing new code, search these directories for existing implementations:

1. `lib/services/` -- business logic
2. `lib/repositories/` -- data access patterns
3. `lib/validation/` -- Zod schemas
4. `lib/utils/` -- utility functions
5. `lib/types/` or `lib/domain/types/` -- type definitions
6. `components/` -- UI patterns
7. `lib/hooks/` -- React hooks

**Detection hints:**

```bash
# Find duplicate Supabase queries
grep -rn "from.*select" src/ --include="*.ts" --include="*.tsx"
# Find duplicate Zod schemas
grep -rn "z\.object" src/ --include="*.ts" --include="*.tsx" -l
# Find duplicate type definitions
grep -rn "interface.*Rule " src/ --include="*.ts" --include="*.tsx"
```

Reference: [Don't Repeat Yourself (DRY)](https://en.wikipedia.org/wiki/Don%27t_repeat_yourself) · [Rule of Three](https://en.wikipedia.org/wiki/Rule_of_three_(computer_programming))

---

## Use Scoped Loggers with Structured Context

**Impact: MEDIUM (enables production debugging with structured, searchable, context-rich log entries)**

Bare `console.log("Error:", error)` in production gives you a message with no context: no service name, no user ID, no request ID, no error code. When your service handles 10,000 requests per minute and something fails, you need to filter logs by service, correlate errors with specific users, and search by error ID to find the root cause. Scoped loggers attach this context automatically.

Every service and middleware should create a scoped logger with its name, and every log entry should include an `errorId` following the convention `COMPONENT_OPERATION_RESULT`.

**Incorrect (bare console.log with no context):**

```typescript
// lib/services/RuleService.ts
// ❌ No context, no structure, impossible to filter in production

export class RuleService {
  async createRule(userId: string, input: CreateRuleInput) {
    console.log('Creating rule') // ❌ Which service? Which user? Which rule?

    try {
      const rule = await this.repo.create(input)
      console.log('Rule created:', rule.id) // ❌ No userId for correlation
      return rule
    } catch (error) {
      console.log('Error creating rule:', error) // ❌ No errorId, no structured data
      throw error
    }
  }

  async deleteRule(userId: string, ruleId: string) {
    console.log('Deleting rule', ruleId) // ❌ Same generic format everywhere

    const rule = await this.repo.findById(ruleId)
    if (rule?.userId !== userId) {
      console.log('Unauthorized delete attempt') // ❌ No userId — who tried?
      return null
    }

    await this.repo.delete(ruleId)
    console.log('Rule deleted') // ❌ No correlation data
  }
}
```

**Correct (scoped logger with structured context):**

```typescript
// lib/logger.ts
// ✅ Scoped logger factory — every service gets its own context

export interface ScopedLogger {
  info(message: string, context?: Record<string, unknown>): void
  warn(message: string, context?: Record<string, unknown>): void
  error(message: string, context?: Record<string, unknown>): void
  debug(message: string, context?: Record<string, unknown>): void
}

export function createScopedLogger(service: string): ScopedLogger {
  const log = (
    level: 'info' | 'warn' | 'error' | 'debug',
    message: string,
    context?: Record<string, unknown>
  ) => {
    const entry = {
      timestamp: new Date().toISOString(),
      level,
      service,
      message,
      ...context,
    }

    // Structured JSON in production, readable in development
    if (process.env.NODE_ENV === 'production') {
      console[level](JSON.stringify(entry))
    } else {
      console[level](`[${service}] ${message}`, context ?? '')
    }
  }

  return {
    info: (message, context) => log('info', message, context),
    warn: (message, context) => log('warn', message, context),
    error: (message, context) => log('error', message, context),
    debug: (message, context) => log('debug', message, context),
  }
}
```

```typescript
// lib/services/RuleService.ts
// ✅ Scoped logger with structured context on every operation

import { createScopedLogger } from '@/lib/logger'
import { success, failure, type ServiceResult } from '@/lib/types/ServiceResult'

export class RuleService {
  constructor(
    private ruleRepo: IRuleRepository,
    private log: ScopedLogger,  // ✅ Injected via constructor
  ) {}

  async createRule(
    userId: string,
    input: CreateRuleInput
  ): Promise<ServiceResult<Rule>> {
    this.log.info('Creating rule', {
      errorId: 'RULE_CREATE_STARTED',  // ✅ Searchable error ID
      userId,
      ruleName: input.name,
      conditionCount: input.conditions.length,
    })

    try {
      const existingRules = await this.ruleRepo.findByUserId(userId)
      if (existingRules.length >= 50) {
        this.log.warn('Rule limit reached', {
          errorId: 'RULE_CREATE_LIMIT_REACHED',
          userId,
          currentCount: existingRules.length,
        })
        return failure('Rule limit reached', 'RULE_LIMIT')
      }

      const rule = await this.ruleRepo.create({
        userId,
        name: input.name,
        conditions: input.conditions,
      })

      this.log.info('Rule created successfully', {
        errorId: 'RULE_CREATE_SUCCESS',
        userId,
        ruleId: rule.id,
      })

      return success(rule)
    } catch (error) {
      this.log.error('Failed to create rule', {
        errorId: 'RULE_CREATE_FAILED',  // ✅ Unique, searchable error ID
        userId,
        ruleName: input.name,
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined,
      })
      throw error
    }
  }

  async deleteRule(
    userId: string,
    ruleId: string
  ): Promise<ServiceResult<void>> {
    const rule = await this.ruleRepo.findById(ruleId)

    if (!rule || rule.userId !== userId) {
      this.log.warn('Unauthorized delete attempt', {
        errorId: 'RULE_DELETE_UNAUTHORIZED',  // ✅ Security-relevant log
        userId,
        ruleId,
        ruleExists: !!rule,
      })
      return failure('Rule not found', 'NOT_FOUND')
    }

    await this.ruleRepo.delete(ruleId)
    this.log.info('Rule deleted', {
      errorId: 'RULE_DELETE_SUCCESS',
      userId,
      ruleId,
    })

    return success(undefined)
  }
}
```

```typescript
// lib/factories/ServiceFactory.ts
// ✅ Logger created with service name at factory level
export class ServiceFactory {
  static async createRuleService(): Promise<RuleService> {
    const supabase = await createServerSupabaseClient()
    const repos = new RepositoryFactory(supabase)
    return new RuleService(
      repos.createRuleRepository(),
      createScopedLogger('RuleService'),  // ✅ Scoped to service name
    )
  }
}
```

**ErrorId naming convention:**

```
COMPONENT_OPERATION_RESULT

Examples:
  RULE_CREATE_STARTED     — operation began
  RULE_CREATE_SUCCESS     — operation completed
  RULE_CREATE_FAILED      — operation threw an error
  RULE_CREATE_LIMIT_REACHED — business rule prevented operation
  RULE_DELETE_UNAUTHORIZED — security-relevant rejection
  AUTH_LOGIN_FAILED        — authentication failure
  WEBHOOK_PROCESS_TIMEOUT  — external integration timeout
```

**Production log output (JSON, searchable):**

```json
{"timestamp":"2026-03-03T14:22:01.123Z","level":"error","service":"RuleService","message":"Failed to create rule","errorId":"RULE_CREATE_FAILED","userId":"usr_abc123","ruleName":"My Rule","error":"unique constraint violation"}
```

**Detection hints:**

```bash
# Find bare console.log in services (should use scoped logger)
grep -rn "console\.log\|console\.error\|console\.warn" src/lib/services --include="*.ts"
# Find console.log in API routes (should use scoped logger)
grep -rn "console\.log" src/app/api --include="*.ts"
# Verify scoped loggers are being used
grep -rn "createScopedLogger" src/lib --include="*.ts"
```

Reference: [Structured Logging](https://www.thoughtworks.com/en-us/radar/techniques/structured-logging) · [12 Factor App — Logs](https://12factor.net/logs)

---

## Search Existing Code Before Creating New Utilities

**Impact: MEDIUM (prevents duplicate utilities, reduces bundle size, and maintains consistency)**

As a codebase grows, it becomes increasingly common for developers to create new utilities, hooks, components, or validation schemas without realizing an equivalent already exists. This leads to multiple date formatters that handle edge cases differently, three separate loading spinners with inconsistent styles, two Zod schemas for the same entity with different constraints, and utility functions that do the same thing under different names.

Before creating anything new, search the existing codebase systematically. This is especially important for AI agents generating code -- always search first.

**Incorrect (creating without searching):**

```typescript
// components/rules/RuleCard.tsx
// ❌ Created a new date formatter without checking lib/utils/
function formatDate(date: string): string {
  const d = new Date(date)
  return `${d.getMonth() + 1}/${d.getDate()}/${d.getFullYear()}`
}

export function RuleCard({ rule }: { rule: Rule }) {
  return (
    <div>
      <h3>{rule.name}</h3>
      <span>Created: {formatDate(rule.createdAt)}</span>
    </div>
  )
}
```

```typescript
// lib/utils/formatDate.ts (ALREADY EXISTS but was never found)
// This handles timezones, locales, and relative dates
export function formatDate(date: Date | string, options?: FormatOptions): string {
  const d = typeof date === 'string' ? new Date(date) : date
  return new Intl.DateTimeFormat('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    ...options,
  }).format(d)
}

export function formatRelativeDate(date: Date | string): string {
  // Handles "2 hours ago", "yesterday", etc.
}
```

```typescript
// lib/hooks/useDebounce.ts (file 1 — created by developer A)
export function useDebounce<T>(value: T, delay: number): T {
  const [debouncedValue, setDebouncedValue] = useState(value)
  useEffect(() => {
    const timer = setTimeout(() => setDebouncedValue(value), delay)
    return () => clearTimeout(timer)
  }, [value, delay])
  return debouncedValue
}

// lib/hooks/useDebouncedValue.ts (file 2 — created by developer B, same logic)
export function useDebouncedValue<T>(val: T, ms: number): T {
  // ❌ Identical implementation with different parameter names
}
```

**Correct (search first, then create only if nothing exists):**

```typescript
// ✅ Before creating a new utility, run through this checklist:

// 1. Search lib/utils/ for existing utility functions
//    grep -rn "formatDate\|dateFormat\|format.*date" lib/utils/

// 2. Search lib/services/ for existing business logic
//    grep -rn "calculatePriority\|priority" lib/services/

// 3. Search components/ for existing UI patterns
//    grep -rn "Spinner\|Loading\|Skeleton" components/

// 4. Search lib/hooks/ for existing React hooks
//    grep -rn "useDebounce\|useDebouncedValue" lib/hooks/

// 5. Search lib/validation/ for existing Zod schemas
//    grep -rn "RuleSchema\|ruleSchema" lib/validation/

// 6. Search lib/types/ for existing type definitions
//    grep -rn "interface Rule " lib/types/ lib/domain/
```

```typescript
// components/rules/RuleCard.tsx
// ✅ Found existing utility and used it
import { formatDate } from '@/lib/utils/formatDate'

export function RuleCard({ rule }: { rule: Rule }) {
  return (
    <div>
      <h3>{rule.name}</h3>
      <span>Created: {formatDate(rule.createdAt)}</span>
    </div>
  )
}
```

**Mandatory search checklist (run before creating):**

| Creating... | Search In | Search For |
|------------|-----------|------------|
| Utility function | `lib/utils/` | Function name, similar purpose |
| React hook | `lib/hooks/` | Hook name, similar behavior |
| Zod schema | `lib/validation/` | Entity name + "Schema" |
| Type/Interface | `lib/types/`, `lib/domain/` | Entity name |
| UI component | `components/` | Component purpose (e.g., "Spinner", "Modal") |
| Service method | `lib/services/` | Operation name, entity name |
| Repository method | `lib/repositories/` | Query pattern, entity name |
| API helper | `lib/api/` | Endpoint name, HTTP method |
| Constant | `lib/config/`, `lib/constants/` | Constant name, value |

**When you find a near-match:**

1. **Exact match:** Use it directly, do not create a new one
2. **Close match (80%+ overlap):** Extend the existing one with optional parameters
3. **Partial match (50% overlap):** Consider extracting shared logic to a helper, then both use it
4. **No match:** Create the new utility, placing it in the correct directory

**Detection hints:**

```bash
# Find potential duplicate utilities
grep -rn "export function format" src/lib --include="*.ts" -l
# Find duplicate hooks
grep -rn "export function use" src/lib/hooks --include="*.ts" -l
# Find duplicate type definitions for the same concept
grep -rn "interface.*Rule[^s]" src/ --include="*.ts"
```

Reference: [Don't Repeat Yourself (DRY)](https://en.wikipedia.org/wiki/Don%27t_repeat_yourself)

---

## Use Consistent ServiceResult Type for All Service Returns

**Impact: MEDIUM (ensures consistent, type-safe error handling across all service boundaries)**

When some service methods throw exceptions, others return `null`, and others return `{ error: string }`, every caller must guess what kind of error handling to use. Thrown exceptions crash the process if uncaught. Returned nulls give no indication of why something failed. Ad-hoc error objects have inconsistent shapes across services. A discriminated union `ServiceResult<T>` forces every service method to explicitly communicate success or failure with a consistent shape, and TypeScript's type narrowing ensures callers handle both cases.

**Incorrect (inconsistent error handling across services):**

```typescript
// lib/services/RuleService.ts
// ❌ Three different error patterns in the same service

export class RuleService {
  // ❌ Pattern 1: Throws exceptions
  async createRule(input: CreateRuleInput): Promise<Rule> {
    if (input.conditions.length > 20) {
      throw new Error('Too many conditions')
    }
    // ...
    return rule
  }

  // ❌ Pattern 2: Returns null on failure
  async findById(id: string): Promise<Rule | null> {
    const rule = await this.repo.findById(id)
    return rule // Caller has no idea WHY it's null
  }

  // ❌ Pattern 3: Returns ad-hoc error object
  async deleteRule(id: string): Promise<{ success: boolean; error?: string }> {
    const rule = await this.repo.findById(id)
    if (!rule) {
      return { success: false, error: 'Not found' }
    }
    await this.repo.delete(id)
    return { success: true }
  }
}
```

```typescript
// app/api/rules/route.ts
// ❌ Caller must handle three different patterns
export async function POST(request: NextRequest) {
  try {
    const rule = await ruleService.createRule(input) // Might throw
    return NextResponse.json(rule, { status: 201 })
  } catch (error) {
    // What status code? 400? 500? We don't know.
    return NextResponse.json({ error: (error as Error).message }, { status: 500 })
  }
}

export async function GET(request: NextRequest) {
  const rule = await ruleService.findById(id) // Might be null
  if (!rule) {
    // Was it not found? Permission denied? Database error? No idea.
    return NextResponse.json({ error: 'Not found' }, { status: 404 })
  }
  return NextResponse.json(rule)
}
```

**Correct (consistent ServiceResult type everywhere):**

```typescript
// lib/types/ServiceResult.ts
// ✅ Discriminated union — TypeScript enforces exhaustive handling

export type ServiceResult<T> =
  | { success: true; data: T }
  | { success: false; error: string; code?: string }

// ✅ Helper functions for clean construction
export function success<T>(data: T): ServiceResult<T> {
  return { success: true, data }
}

export function failure(error: string, code?: string): ServiceResult<never> {
  return { success: false, error, code }
}
```

```typescript
// lib/services/RuleService.ts
// ✅ Every method returns ServiceResult<T> — no exceptions, no nulls, no guessing
import { success, failure, type ServiceResult } from '@/lib/types/ServiceResult'

export class RuleService {
  constructor(
    private ruleRepo: IRuleRepository,
    private log: ScopedLogger,
  ) {}

  async createRule(
    userId: string,
    input: CreateRuleInput
  ): Promise<ServiceResult<Rule>> {
    if (input.conditions.length > 20) {
      return failure('Rules can have at most 20 conditions', 'MAX_CONDITIONS')
    }

    const existingRules = await this.ruleRepo.findByUserId(userId)
    if (existingRules.length >= 50) {
      return failure('Rule limit reached', 'RULE_LIMIT')
    }

    const rule = await this.ruleRepo.create({
      userId,
      name: input.name,
      conditions: input.conditions,
    })

    this.log.info('Rule created', { userId, ruleId: rule.id })
    return success(rule)
  }

  async findById(
    id: string,
    userId: string
  ): Promise<ServiceResult<Rule>> {
    const rule = await this.ruleRepo.findById(id)

    if (!rule) {
      return failure('Rule not found', 'NOT_FOUND')
    }

    if (rule.userId !== userId) {
      return failure('Rule not found', 'NOT_FOUND') // Don't reveal existence
    }

    return success(rule)
  }

  async deleteRule(
    id: string,
    userId: string
  ): Promise<ServiceResult<void>> {
    const rule = await this.ruleRepo.findById(id)

    if (!rule || rule.userId !== userId) {
      return failure('Rule not found', 'NOT_FOUND')
    }

    await this.ruleRepo.delete(id)
    this.log.info('Rule deleted', { userId, ruleId: id })
    return success(undefined)
  }
}
```

```typescript
// app/api/rules/route.ts
// ✅ Caller uses consistent pattern — TypeScript narrows the type
export const POST = compose(
  withRateLimit('default'),
  withAuth(),
)(async (request: NextRequest, context: AuthenticatedContext) => {
  const input = CreateRuleSchema.parse(await request.json())
  const ruleService = await ServiceFactory.createRuleService()
  const result = await ruleService.createRule(context.user.id, input)

  if (!result.success) {
    // ✅ Map service error codes to HTTP status codes at the API boundary
    const statusMap: Record<string, number> = {
      MAX_CONDITIONS: 400,
      RULE_LIMIT: 403,
      DUPLICATE: 409,
    }
    const status = statusMap[result.code ?? ''] ?? 400
    return NextResponse.json({ error: result.error, code: result.code }, { status })
  }

  // ✅ TypeScript knows result.data is Rule here (type narrowing)
  return NextResponse.json(result.data, { status: 201 })
})
```

**ServiceResult status code mapping table:**

| Service Code | HTTP Status | Meaning |
|-------------|-------------|---------|
| `NOT_FOUND` | 404 | Resource does not exist or user lacks access |
| `FORBIDDEN` | 403 | User is authenticated but not authorized |
| `DUPLICATE` | 409 | Resource already exists |
| `INVALID_INPUT` | 400 | Validation or business rule failure |
| `RULE_LIMIT` | 403 | Quota or limit exceeded |
| (no code) | 400 | Generic business logic failure |

**Detection hints:**

```bash
# Find services that throw instead of returning ServiceResult
grep -rn "throw new Error" src/lib/services --include="*.ts"
# Find inconsistent return patterns
grep -rn "return null" src/lib/services --include="*.ts"
# Find services already using ServiceResult
grep -rn "ServiceResult" src/lib/services --include="*.ts"
```

Reference: [TypeScript Discriminated Unions](https://www.typescriptlang.org/docs/handbook/2/narrowing.html#discriminated-unions) · [Railway-Oriented Programming](https://fsharpforfunandprofit.com/rop/)

---

*Generated by BeforeMerge build script on 2026-03-04.*
*Version: 0.1.0 | Rules: 19*