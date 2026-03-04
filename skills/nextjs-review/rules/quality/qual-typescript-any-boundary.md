---
title: Ban any at Trust Boundaries — Use unknown with Validation
description: "Using 'any' or 'as any' at API boundaries, form handlers, and external data silently disables TypeScript safety, causing runtime crashes from unexpected data."
impact: HIGH
impact_description: prevents runtime crashes from untyped external data that bypasses compile-time checks
tags: [quality, typescript, type-safety, any, unknown, validation, nextjs]
cwe: ["CWE-20"]
detection_grep: "as any|: any|<any>"
---

## Ban `any` at Trust Boundaries — Use `unknown` with Validation

**Impact: HIGH (prevents runtime crashes from untyped external data that bypasses compile-time checks)**

`any` silently turns off TypeScript at exactly the places where type safety matters most — system boundaries where external data enters your application. When you cast API responses, form data, URL params, or webhook payloads as `any`, TypeScript stops checking the entire downstream call chain. The app compiles cleanly but crashes at runtime when the actual data doesn't match your assumptions.

This complements `qual-validate-boundaries`: even if you validate, casting to `any` anywhere in the chain nullifies the validation.

**Incorrect (any at boundaries):**

```typescript
// ❌ any spreads like a virus — disables type checking for everything it touches
export async function GET() {
  const res = await fetch('https://api.example.com/users')
  const data: any = await res.json() // TypeScript gives up here

  // No errors shown, but all of these could crash at runtime:
  const name = data.users[0].profile.displayName // Cannot read property of undefined
  const email = data.users[0].email.toLowerCase() // .toLowerCase of undefined
  return NextResponse.json({ name, email })
}
```

```typescript
// ❌ 'as any' to suppress TypeScript errors — hides real bugs
export async function POST(request: NextRequest) {
  const body = await request.json()
  const user = body as any
  await db.user.create({ data: user }) // Passes ANYTHING to the database
}
```

```typescript
// ❌ any in Server Actions — parameters come from untrusted network requests
'use server'
export async function updateSettings(settings: any) {
  await db.settings.update({ data: settings }) // Prototype pollution risk
}
```

```typescript
// ❌ Catch-all any in utility functions at boundaries
function processWebhook(payload: any) {
  // Every downstream function now accepts any shape
  updateOrder(payload.order)
  notifyUser(payload.user)
  updateInventory(payload.items)
}
```

**Correct (unknown + validation):**

```typescript
// ✅ unknown forces you to validate before use
import { z } from 'zod'

const UsersResponseSchema = z.object({
  users: z.array(z.object({
    profile: z.object({ displayName: z.string() }),
    email: z.string().email(),
  })),
})

export async function GET() {
  const res = await fetch('https://api.example.com/users')
  const json: unknown = await res.json()
  const data = UsersResponseSchema.parse(json) // Throws descriptive error if wrong

  const { displayName } = data.users[0].profile // TypeScript knows the shape
  const { email } = data.users[0] // Autocomplete works correctly
  return NextResponse.json({ name: displayName, email })
}
```

```typescript
// ✅ Server Actions: unknown parameter + schema validation
'use server'
import { z } from 'zod'

const SettingsSchema = z.object({
  theme: z.enum(['light', 'dark']),
  language: z.string().min(2).max(5),
  notifications: z.boolean(),
})

export async function updateSettings(rawInput: unknown) {
  const settings = SettingsSchema.parse(rawInput)
  await db.settings.update({ data: settings }) // Only validated fields reach DB
}
```

```typescript
// ✅ Webhook handler with proper typing
const WebhookPayloadSchema = z.discriminatedUnion('event', [
  z.object({
    event: z.literal('order.completed'),
    order: z.object({ id: z.string(), total: z.number() }),
  }),
  z.object({
    event: z.literal('user.created'),
    user: z.object({ id: z.string(), email: z.string() }),
  }),
])

export async function POST(request: NextRequest) {
  const json: unknown = await request.json()
  const payload = WebhookPayloadSchema.parse(json)

  // TypeScript narrows the type based on the event discriminator
  if (payload.event === 'order.completed') {
    await updateOrder(payload.order) // TypeScript knows .order exists
  }
}
```

**The `any` → `unknown` migration path:**

1. Change the type from `any` to `unknown`
2. TypeScript will show errors everywhere the value is used without narrowing
3. Add a Zod schema and `.parse()` at the boundary
4. All downstream code now has proper types

**ESLint enforcement:**

```json
{
  "rules": {
    "@typescript-eslint/no-explicit-any": "error",
    "@typescript-eslint/no-unsafe-assignment": "error",
    "@typescript-eslint/no-unsafe-member-access": "error"
  }
}
```

**Detection hints:**

```bash
# Find 'any' at system boundaries
grep -rn ": any\|as any\|<any>" src/ --include="*.ts" --include="*.tsx" | grep -i "request\|response\|fetch\|json\|param\|form\|webhook\|payload"
# Count total 'any' usage
grep -rn ": any\b" src/ --include="*.ts" --include="*.tsx" -c
```

Reference: [TypeScript unknown vs any](https://www.typescriptlang.org/docs/handbook/2/functions.html#unknown) · [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
