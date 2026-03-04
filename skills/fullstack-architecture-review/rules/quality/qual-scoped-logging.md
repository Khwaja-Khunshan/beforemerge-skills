---
title: Use Scoped Loggers with Structured Context
description: "Bare console.log statements with no context make production debugging impossible. Use scoped loggers with errorId, userId, and structured metadata."
impact: MEDIUM
impact_description: enables production debugging with structured, searchable, context-rich log entries
tags: [quality, logging, debugging, observability, production]
detection_grep: "console.log"
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
