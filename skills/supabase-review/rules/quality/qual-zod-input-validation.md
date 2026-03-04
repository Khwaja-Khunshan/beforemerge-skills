---
title: Validate Input at Runtime with Zod Instead of Type Assertions
description: "Using 'as' type assertions on external input (params, form data, request bodies) provides zero runtime safety. Use Zod for runtime validation."
impact: HIGH
impact_description: prevents invalid data from reaching the database and causing constraint errors
tags: [quality, supabase, validation, zod, typescript, input, type-safety]
cwe: ["CWE-20"]
owasp: ["A03:2021"]
detection_grep: "as string"
---

## Validate Input at Runtime with Zod Instead of Type Assertions

**Impact: HIGH (prevents invalid data from reaching the database and causing constraint errors)**

TypeScript's `as` keyword is a compile-time assertion that provides **zero runtime validation**. When you write `params.id as string`, TypeScript trusts you — but at runtime, `params.id` could be `undefined`, an array, a number, or a malicious string. This unvalidated input then flows into your Supabase queries, causing cryptic database errors, constraint violations, or worse — data corruption.

Zod provides runtime schema validation that catches invalid input **before** it reaches your database, with descriptive error messages that help both developers and users understand what went wrong.

**Incorrect (type assertions on route parameters):**

```typescript
// ❌ 'as string' provides zero runtime safety
export async function GET(
  request: Request,
  { params }: { params: { id: string } }
) {
  const supabase = await createClient()

  // ❌ params.id could be undefined, empty string, or not a valid UUID
  const projectId = params.id as string

  const { data, error } = await supabase
    .from('projects')
    .select('*')
    .eq('id', projectId) // If projectId is not a UUID, this returns empty or errors
    .single()

  return Response.json(data)
}
```

**Incorrect (type assertions on form data):**

```typescript
'use server'

export async function updateProfile(formData: FormData) {
  const supabase = await createClient()

  // ❌ All of these could be null, empty, or unexpected types
  const displayName = formData.get('displayName') as string
  const bio = formData.get('bio') as string
  const age = formData.get('age') as string

  const { error } = await supabase
    .from('profiles')
    .update({
      display_name: displayName,  // Could be null or empty
      bio: bio,                    // Could exceed column length
      age: parseInt(age),          // parseInt(null) = NaN → database error
    })
    .eq('id', userId)
}
```

**Incorrect (type assertions on request body):**

```typescript
// ❌ Trusting request body shape
export async function POST(request: Request) {
  const body = await request.json() as { name: string; teamId: string }
  // body could be anything: null, array, missing fields, extra fields

  const { error } = await supabase
    .from('projects')
    .insert({
      name: body.name,     // Could be undefined → NOT NULL violation
      team_id: body.teamId // Could be "not-a-uuid" → FK violation
    })
}
```

**Correct (Zod validation on route parameters):**

```typescript
import { z } from 'zod'

const ParamsSchema = z.object({
  id: z.string().uuid('Invalid project ID format'),
})

export async function GET(
  request: Request,
  { params }: { params: { id: string } }
) {
  // ✅ Validates that id exists and is a valid UUID
  const result = ParamsSchema.safeParse(params)

  if (!result.success) {
    return Response.json(
      { error: 'Invalid project ID', details: result.error.flatten() },
      { status: 400 }
    )
  }

  const supabase = await createClient()

  const { data, error } = await supabase
    .from('projects')
    .select('id, name, status, created_at')
    .eq('id', result.data.id) // ✅ Guaranteed valid UUID
    .single()

  if (error) {
    if (error.code === 'PGRST116') {
      return Response.json({ error: 'Project not found' }, { status: 404 })
    }
    return Response.json({ error: 'Internal error' }, { status: 500 })
  }

  return Response.json(data)
}
```

**Correct (Zod validation on form data in Server Actions):**

```typescript
'use server'

import { z } from 'zod'

const UpdateProfileSchema = z.object({
  displayName: z.string().min(1, 'Name is required').max(100, 'Name too long'),
  bio: z.string().max(500, 'Bio must be under 500 characters').optional(),
  age: z.coerce.number().int().min(13).max(150).optional(),
})

export async function updateProfile(formData: FormData) {
  // ✅ Validate and coerce all inputs
  const result = UpdateProfileSchema.safeParse({
    displayName: formData.get('displayName'),
    bio: formData.get('bio'),
    age: formData.get('age'),
  })

  if (!result.success) {
    return { error: result.error.flatten().fieldErrors }
  }

  const supabase = await createClient()
  const { data: { user } } = await supabase.auth.getUser()
  if (!user) throw new Error('Unauthorized')

  const { error } = await supabase
    .from('profiles')
    .update({
      display_name: result.data.displayName,
      bio: result.data.bio,
      age: result.data.age,
    })
    .eq('id', user.id)

  if (error) throw new Error('Failed to update profile')

  revalidatePath('/profile')
  return { success: true }
}
```

**Correct (Zod validation on request body):**

```typescript
import { z } from 'zod'

const CreateProjectSchema = z.object({
  name: z.string().min(1).max(200),
  teamId: z.string().uuid(),
  description: z.string().max(2000).optional(),
})

export async function POST(request: Request) {
  const body = await request.json()

  // ✅ Full runtime validation with descriptive errors
  const result = CreateProjectSchema.safeParse(body)

  if (!result.success) {
    return Response.json(
      { error: 'Validation failed', details: result.error.flatten() },
      { status: 400 }
    )
  }

  const supabase = await createClient()

  const { data, error } = await supabase
    .from('projects')
    .insert({
      name: result.data.name,         // ✅ Guaranteed string, 1-200 chars
      team_id: result.data.teamId,    // ✅ Guaranteed valid UUID
      description: result.data.description,
    })
    .select('id, name')
    .single()

  if (error) {
    return Response.json({ error: 'Failed to create project' }, { status: 500 })
  }

  return Response.json(data, { status: 201 })
}
```

**Detection hints:**

```bash
# Find 'as string' assertions on external input
grep -rn "as string\|as number" src/ --include="*.ts" --include="*.tsx"
# Find formData.get() without Zod validation
grep -rn "formData.get(" src/ --include="*.ts" --include="*.tsx"
# Find request.json() without schema validation
grep -rn "request.json()" src/ --include="*.ts" --include="*.tsx"
```

Reference: [Zod Documentation](https://zod.dev/) · [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
