---
title: Never Expose Raw Errors or Stack Traces to Clients
description: "Returning raw error messages or stack traces leaks implementation details. Return generic messages with a requestId for server-side debugging."
impact: MEDIUM
impact_description: prevents leaking database schemas, file paths, and internal implementation details
tags: [security, error-handling, information-disclosure, api, nextjs]
cwe: ["CWE-209"]
detection_grep: "error.message"
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
