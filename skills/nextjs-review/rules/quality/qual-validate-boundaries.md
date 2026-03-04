---
title: Validate External Data at System Boundaries
description: "TypeScript types vanish at runtime. Validate external data at system boundaries with Zod to prevent crashes from unexpected shapes."
impact: MEDIUM
impact_description: prevents runtime crashes from unexpected API responses or user input
tags: [quality, validation, type-safety, zod, typescript, nextjs]
cwe: ["CWE-20"]
detection_grep: "await.*\\.json()"
---

## Validate External Data at System Boundaries

**Impact: MEDIUM (prevents runtime crashes from unexpected API responses or user input)**

TypeScript types disappear at runtime. When data crosses a system boundary — API responses, form submissions, URL parameters, webhook payloads, third-party SDK responses — the shape is not guaranteed. Runtime validation with a library like Zod catches malformed data before it causes cryptic errors deep in your application.

**Incorrect (trusting external data with only TypeScript):**

```typescript
// ❌ TypeScript doesn't protect you at runtime
interface User {
  id: string
  name: string
  email: string
}

export async function GET() {
  const res = await fetch('https://api.example.com/users/1')
  const user: User = await res.json() // ← This is a lie. It could be anything.
  return Response.json({ greeting: `Hello ${user.name}` })
  // If API returns { id: 1, fullName: "..." } → user.name is undefined → "Hello undefined"
}
```

```typescript
// ❌ Trusting URL params
export default function Page({ searchParams }: { searchParams: { page: string } }) {
  const page = parseInt(searchParams.page) // Could be NaN, negative, or 999999
  const data = await fetchItems({ skip: page * 20 })
}
```

**Correct (validate at the boundary):**

```typescript
// ✅ Validate API responses
import { z } from 'zod'

const UserSchema = z.object({
  id: z.string(),
  name: z.string(),
  email: z.string().email(),
})

type User = z.infer<typeof UserSchema> // Derive the type from the schema

export async function GET() {
  const res = await fetch('https://api.example.com/users/1')
  const json = await res.json()
  const user = UserSchema.parse(json) // Throws descriptive error if shape is wrong
  return Response.json({ greeting: `Hello ${user.name}` })
}
```

```typescript
// ✅ Validate URL search params
const SearchParamsSchema = z.object({
  page: z.coerce.number().int().min(1).max(100).default(1),
  sort: z.enum(['newest', 'oldest', 'popular']).default('newest'),
})

export default async function Page({
  searchParams,
}: {
  searchParams: Record<string, string | string[] | undefined>
}) {
  const { page, sort } = SearchParamsSchema.parse(searchParams)
  const data = await fetchItems({ skip: (page - 1) * 20, sort })
}
```

```typescript
// ✅ Validate Server Action input
'use server'

const ContactFormSchema = z.object({
  name: z.string().min(1).max(100),
  email: z.string().email(),
  message: z.string().min(10).max(5000),
})

export async function submitContact(formData: FormData) {
  const input = ContactFormSchema.parse({
    name: formData.get('name'),
    email: formData.get('email'),
    message: formData.get('message'),
  })

  await sendEmail(input)
  return { success: true }
}
```

**Detection hints:**

```bash
# Find fetch calls without validation
grep -rn "await.*\.json()" src/ --include="*.ts" --include="*.tsx" | grep -v "parse\|schema\|validate\|zod"
# Find type assertions on external data
grep -rn "as \w\+\b" src/ --include="*.ts" --include="*.tsx" | grep -E "json\(\)|formData|searchParams|params"
```

Reference: [Zod Documentation](https://zod.dev/) · [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
