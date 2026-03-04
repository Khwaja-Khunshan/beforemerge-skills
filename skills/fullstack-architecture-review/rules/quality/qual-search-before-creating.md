---
title: Search Existing Code Before Creating New Utilities
description: "Creating new components or utilities without checking if one already exists leads to duplicated logic and inconsistency. Search existing code first."
impact: MEDIUM
impact_description: prevents duplicate utilities, reduces bundle size, and maintains consistency
tags: [quality, dry, discoverability, code-reuse, maintainability]
detection_grep: "export function"
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
