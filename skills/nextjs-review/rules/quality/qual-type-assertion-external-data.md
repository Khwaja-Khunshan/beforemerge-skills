---
title: Never Use Type Assertions on External Data — Validate Instead
description: "Casting API responses, form data, or URL params with 'as Type' bypasses TypeScript guarantees. When the shape doesn't match, crashes happen far from the boundary."
impact: MEDIUM
impact_description: prevents delayed runtime crashes from data that silently bypasses type safety
tags: [quality, typescript, type-assertions, validation, type-safety, nextjs]
cwe: ["CWE-20"]
detection_grep: "as \\w+|await.*json().*as|formData.*as"
---

## Never Use Type Assertions on External Data — Validate Instead

**Impact: MEDIUM (prevents delayed runtime crashes from data that silently bypasses type safety)**

`as SomeType` is a type assertion — it tells TypeScript "trust me, I know what this is." It performs zero runtime checking. When you assert the type of an API response, form data, URL parameter, or any external data, TypeScript shows no errors at compile time. But if the actual data doesn't match, the crash happens deep in your application — far from the boundary where you could have caught it — making debugging extremely difficult.

This is distinct from `qual-typescript-any-boundary` (which covers `any`). Type assertions are more insidious because the code looks fully typed.

**Incorrect (type assertions on external data):**

```typescript
// ❌ Looks safe — TypeScript shows no errors — but is a lie
interface User {
  id: string
  name: string
  email: string
  role: 'admin' | 'user'
}

export async function GET() {
  const res = await fetch('https://api.example.com/user/1')
  const user = await res.json() as User // TypeScript trusts you completely

  // If API returns { id: 1, fullName: "..." } instead:
  // user.name → undefined (no crash here, silent corruption)
  // user.name.toUpperCase() → "Cannot read properties of undefined" (crashes later)
  // user.role === 'admin' → false (security bug: can't distinguish missing from 'user')
  return NextResponse.json({ greeting: `Hello ${user.name}` }) // "Hello undefined"
}
```

```typescript
// ❌ Type assertion on search params
export default function Page({ searchParams }: { searchParams: Record<string, string> }) {
  const filters = searchParams as { category: string; sort: 'asc' | 'desc'; page: string }
  // If ?sort=invalid → filters.sort is "invalid" but TypeScript says it's 'asc' | 'desc'
  const items = await getItems({ sort: filters.sort }) // Passes invalid value to query
}
```

```typescript
// ❌ Double assertion to force incompatible types
const config = JSON.parse(rawConfig) as unknown as AppConfig
// If rawConfig is malformed, config silently has wrong shape
```

**Correct (runtime validation, type inference):**

```typescript
// ✅ Parse + infer — type comes from the schema, not an assertion
import { z } from 'zod'

const UserSchema = z.object({
  id: z.string(),
  name: z.string(),
  email: z.string().email(),
  role: z.enum(['admin', 'user']),
})

type User = z.infer<typeof UserSchema> // Derived from schema, always in sync

export async function GET() {
  const res = await fetch('https://api.example.com/user/1')
  const json = await res.json()
  const user = UserSchema.parse(json) // Throws with clear error if shape is wrong

  // TypeScript knows the exact shape — because it was validated
  return NextResponse.json({ greeting: `Hello ${user.name}` })
}
```

```typescript
// ✅ Search params with safe parsing and defaults
const FiltersSchema = z.object({
  category: z.string().optional(),
  sort: z.enum(['asc', 'desc']).default('asc'),
  page: z.coerce.number().int().min(1).default(1),
})

export default async function Page({
  searchParams,
}: {
  searchParams: Record<string, string | string[] | undefined>
}) {
  const filters = FiltersSchema.parse(searchParams) // Validated + defaulted
  const items = await getItems(filters) // All values are guaranteed valid
}
```

```typescript
// ✅ Use safeParse when you want to handle errors gracefully
const result = UserSchema.safeParse(json)
if (!result.success) {
  console.error('API returned unexpected shape:', result.error.flatten())
  return NextResponse.json({ error: 'Upstream API error' }, { status: 502 })
}
const user = result.data // Fully typed
```

**The pattern to replace:**

| Before (unsafe) | After (safe) |
|-----------------|-------------|
| `await res.json() as User` | `UserSchema.parse(await res.json())` |
| `formData as FormValues` | `FormSchema.parse(Object.fromEntries(formData))` |
| `searchParams as Filters` | `FiltersSchema.parse(searchParams)` |
| `JSON.parse(str) as Config` | `ConfigSchema.parse(JSON.parse(str))` |
| `body as WebhookPayload` | `WebhookSchema.parse(body)` |

**Detection hints:**

```bash
# Find type assertions on external data
grep -rn "as \w\+\b" src/ --include="*.ts" --include="*.tsx" | grep -E "json\(\)|formData|searchParams|params|\.body|JSON\.parse"
# Find double assertions (almost always wrong)
grep -rn "as unknown as" src/ --include="*.ts" --include="*.tsx"
```

Reference: [TypeScript Type Assertions](https://www.typescriptlang.org/docs/handbook/2/everyday-types.html#type-assertions) · [Zod Documentation](https://zod.dev/) · [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
