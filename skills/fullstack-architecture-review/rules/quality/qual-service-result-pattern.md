---
title: Use Consistent ServiceResult Type for All Service Returns
description: "Inconsistent error handling with thrown exceptions, returned nulls, and ad-hoc error objects makes callers fragile. Use a discriminated union ServiceResult type."
impact: MEDIUM
impact_description: ensures consistent, type-safe error handling across all service boundaries
tags: [quality, error-handling, service-result, discriminated-union, typescript]
detection_grep: "ServiceResult"
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
