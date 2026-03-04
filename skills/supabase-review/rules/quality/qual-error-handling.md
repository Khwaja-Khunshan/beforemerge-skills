---
title: Distinguish Not-Found from Other Supabase Errors
description: "Treating all Supabase errors the same (if error, throw) hides whether a record is missing or the query itself failed. Check error codes for proper handling."
impact: MEDIUM
impact_description: prevents masking 404s as 500s and enables proper error recovery
tags: [quality, supabase, error-handling, postgrest, error-codes]
detection_grep: "if (error)"
---

## Distinguish Not-Found from Other Supabase Errors

**Impact: MEDIUM (prevents masking 404s as 500s and enables proper error recovery)**

Supabase queries can fail for many reasons: network errors, RLS violations, invalid column names, constraint violations, or simply "no rows found." Treating all errors identically with `if (error) throw error` masks the difference between a missing record (expected, recoverable) and a query failure (unexpected, needs investigation).

PostgREST uses specific error codes that you can check to distinguish these cases. The most important is `PGRST116` — "no rows returned" when using `.single()` or `.maybeSingle()`.

**Incorrect (treating all errors the same):**

```typescript
// ❌ Treats "not found" the same as "database down"
async function getProject(projectId: string) {
  const supabase = await createClient()

  const { data, error } = await supabase
    .from('projects')
    .select('id, name, status')
    .eq('id', projectId)
    .single()

  if (error) {
    // ❌ This could be:
    // - PGRST116: No rows found (project doesn't exist) → should return 404
    // - 42501: RLS violation (user can't access) → should return 403
    // - 42P01: Table doesn't exist (bug) → should return 500
    // - Network error → should retry or return 503
    throw error // All become the same generic error
  }

  return data
}
```

```typescript
// ❌ Catching errors with a generic message
export async function GET(
  request: Request,
  { params }: { params: { id: string } }
) {
  const supabase = await createClient()

  const { data, error } = await supabase
    .from('projects')
    .select('*')
    .eq('id', params.id)
    .single()

  if (error) {
    // ❌ Returns 500 even when the project simply doesn't exist
    return Response.json({ error: 'Something went wrong' }, { status: 500 })
  }

  return Response.json(data)
}
```

**Correct (check error codes for proper handling):**

```typescript
// ✅ Handle different error types appropriately
async function getProject(projectId: string) {
  const supabase = await createClient()

  const { data, error } = await supabase
    .from('projects')
    .select('id, name, status, created_at')
    .eq('id', projectId)
    .single()

  if (error) {
    // Not found — record doesn't exist or RLS hides it
    if (error.code === 'PGRST116') {
      return null // Caller can handle missing project
    }

    // All other errors are unexpected — log and throw
    console.error('Failed to fetch project:', {
      code: error.code,
      message: error.message,
      projectId,
    })
    throw new Error('Failed to load project')
  }

  return data
}
```

**Correct (ServiceResult pattern for typed error handling):**

```typescript
// ✅ Define a typed result type for service functions
type ServiceResult<T> =
  | { data: T; error: null }
  | { data: null; error: { code: 'NOT_FOUND' | 'FORBIDDEN' | 'INTERNAL'; message: string } }

async function getProject(projectId: string): Promise<ServiceResult<Project>> {
  const supabase = await createClient()

  const { data, error } = await supabase
    .from('projects')
    .select('id, name, status, created_at')
    .eq('id', projectId)
    .single()

  if (error) {
    if (error.code === 'PGRST116') {
      return { data: null, error: { code: 'NOT_FOUND', message: 'Project not found' } }
    }

    if (error.code === '42501' || error.code === 'PGRST301') {
      return { data: null, error: { code: 'FORBIDDEN', message: 'Access denied' } }
    }

    console.error('Unexpected project query error:', error)
    return { data: null, error: { code: 'INTERNAL', message: 'Failed to load project' } }
  }

  return { data, error: null }
}

// Usage in a Route Handler:
export async function GET(
  request: Request,
  { params }: { params: { id: string } }
) {
  const result = await getProject(params.id)

  if (result.error) {
    const statusMap = { NOT_FOUND: 404, FORBIDDEN: 403, INTERNAL: 500 } as const
    return Response.json(
      { error: result.error.message },
      { status: statusMap[result.error.code] }
    )
  }

  return Response.json(result.data)
}
```

**Common PostgREST error codes:**

| Code | Meaning | Typical HTTP Status |
|------|---------|-------------------|
| `PGRST116` | No rows returned (`.single()`) | 404 |
| `PGRST301` | JWT expired or invalid | 401 |
| `23505` | Unique constraint violation | 409 |
| `23503` | Foreign key violation | 400 |
| `23502` | Not-null violation | 400 |
| `42501` | Insufficient privilege (RLS) | 403 |
| `42P01` | Undefined table | 500 |

**Detection hints:**

```bash
# Find generic error handling patterns
grep -rn "if (error) throw error\|if (error) throw new Error" src/ --include="*.ts" --include="*.tsx"
# Find .single() calls without PGRST116 handling
grep -rn "\.single()" src/ --include="*.ts" --include="*.tsx"
```

Reference: [PostgREST Error Handling](https://docs.postgrest.org/en/stable/references/errors.html) · [PostgreSQL Error Codes](https://www.postgresql.org/docs/current/errcodes-appendix.html)
