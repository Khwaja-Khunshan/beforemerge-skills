---
title: Always Check Error Before Using Data from Supabase Queries
description: "Destructuring { data } without checking { error } from Supabase queries ignores failures silently. When error is non-null, data is always null."
impact: HIGH
impact_description: prevents silent failures and null reference crashes in production
tags: [quality, supabase, error-handling, typescript, null-safety]
cwe: ["CWE-252"]
detection_grep: "const { data }"
---

## Always Check Error Before Using Data from Supabase Queries

**Impact: HIGH (prevents silent failures and null reference crashes in production)**

Every Supabase query returns `{ data, error }`. When `error` is non-null, `data` is **always** `null`. Destructuring only `{ data }` and using it without checking `error` leads to `TypeError: Cannot read properties of null` at runtime. These crashes are especially hard to diagnose because the actual cause (RLS violation, network timeout, invalid column) is silently discarded.

This is the Supabase equivalent of unchecked return values — the query failed, but your code proceeds as if it succeeded.

**Incorrect (ignoring error entirely):**

```typescript
// ❌ Destructures data without checking error
export default async function DashboardPage() {
  const supabase = await createClient()

  const { data: projects } = await supabase
    .from('projects')
    .select('id, name, created_at')
    .order('created_at', { ascending: false })

  // ❌ If query fails (RLS, network, typo in table name), projects is null
  // This crashes with: TypeError: Cannot read properties of null (reading 'map')
  return (
    <ul>
      {projects.map((project) => (
        <li key={project.id}>{project.name}</li>
      ))}
    </ul>
  )
}
```

**Incorrect (checking error but continuing to use data):**

```typescript
// ❌ Logs error but still uses data (which is null)
export async function GET() {
  const supabase = await createClient()

  const { data, error } = await supabase
    .from('projects')
    .select('*')

  if (error) {
    console.warn('Query had an error:', error.message)
    // ❌ Falls through — data is null below
  }

  // ❌ data is null when error is non-null
  return Response.json({ projects: data }) // Returns { projects: null }
}
```

**Incorrect (optional chaining hides the real problem):**

```typescript
// ❌ Optional chaining silences the error but shows blank UI
const { data: profile } = await supabase
  .from('profiles')
  .select('display_name, avatar_url')
  .eq('id', userId)
  .single()

// User sees "Unknown" with default avatar — no indication of failure
return (
  <div>
    <h1>{profile?.display_name ?? 'Unknown'}</h1>
    <img src={profile?.avatar_url ?? '/default.png'} />
  </div>
)
```

**Correct (check error and return early in Server Components):**

```typescript
// ✅ Check error before using data
export default async function DashboardPage() {
  const supabase = await createClient()

  const { data: projects, error } = await supabase
    .from('projects')
    .select('id, name, created_at')
    .order('created_at', { ascending: false })

  if (error) {
    // ✅ Log for debugging, throw for error boundary
    console.error('Projects query failed:', { code: error.code, message: error.message })
    throw new Error('Failed to load projects')
  }

  // ✅ TypeScript narrows: projects is non-null here
  return (
    <ul>
      {projects.map((project) => (
        <li key={project.id}>{project.name}</li>
      ))}
    </ul>
  )
}
```

**Correct (check error in Route Handlers):**

```typescript
// ✅ Return appropriate HTTP status on error
export async function GET() {
  const supabase = await createClient()

  const { data: projects, error } = await supabase
    .from('projects')
    .select('id, name, created_at')

  if (error) {
    console.error('Projects query failed:', { code: error.code, message: error.message })
    return Response.json(
      { error: 'Failed to load projects' },
      { status: 500 }
    )
  }

  return Response.json({ projects })
}
```

**Correct (check error in Client Components):**

```typescript
'use client'

export function ProjectList() {
  const [projects, setProjects] = useState<Project[]>([])
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    async function load() {
      const supabase = createClient()

      const { data, error } = await supabase
        .from('projects')
        .select('id, name, created_at')

      if (error) {
        console.error('Projects query failed:', error.message)
        setError('Could not load projects. Please try again.')
        return // ✅ Early return — don't touch data
      }

      setProjects(data) // ✅ Safe — data is non-null
    }

    load()
  }, [])

  if (error) return <div role="alert">{error}</div>

  return (
    <ul>
      {projects.map((project) => (
        <li key={project.id}>{project.name}</li>
      ))}
    </ul>
  )
}
```

**Helper to enforce error checking:**

```typescript
// ✅ Utility that throws on error, returning only data
async function queryOrThrow<T>(
  query: PromiseLike<{ data: T | null; error: { message: string; code: string } | null }>
): Promise<T> {
  const { data, error } = await query

  if (error) {
    console.error('Supabase query failed:', { code: error.code, message: error.message })
    throw new Error(`Query failed: ${error.code}`)
  }

  return data as T
}

// Usage — cannot forget to check error
const projects = await queryOrThrow(
  supabase.from('projects').select('id, name').order('created_at', { ascending: false })
)
```

**Detection hints:**

```bash
# Find destructured data without error check
grep -rn "const { data }" src/ --include="*.ts" --include="*.tsx"
grep -rn "const { data:" src/ --include="*.ts" --include="*.tsx"
# Find .from() calls to audit error handling
grep -rn "\.from(" src/ --include="*.ts" --include="*.tsx"
```

Reference: [Supabase Fetch Data](https://supabase.com/docs/reference/javascript/select) · [CWE-252: Unchecked Return Value](https://cwe.mitre.org/data/definitions/252.html)
