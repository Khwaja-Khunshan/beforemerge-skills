---
title: Extract Duplicated Logic After the Third Occurrence
description: "Same logic duplicated in 3+ places creates consistency bugs and maintenance burden. Extract to the appropriate layer after the third occurrence."
impact: HIGH
impact_description: prevents logic drift, reduces maintenance burden, and enforces consistency
tags: [quality, dry, duplication, refactoring, maintainability]
detection_grep: "supabase.*from.*select"
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
