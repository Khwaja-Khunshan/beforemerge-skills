---
title: Keep API Route Handlers Thin — Delegate to Services
description: "API routes with business logic are hard to test, audit, and secure. Keep route handlers under 100 lines by delegating to service classes."
impact: CRITICAL
impact_description: prevents untestable, unauditable business logic in the API layer
tags: [security, architecture, thin-controllers, single-responsibility, nextjs, api]
cwe: ["CWE-1064"]
detection_grep: "export async function POST"
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
