---
title: Prefer Server Components Over useEffect + Fetch for Data Loading
description: "Using useEffect + useState for data fetching creates waterfalls, loading spinners, and unnecessary API routes. Use async Server Components instead."
impact: HIGH
impact_description: eliminates client-side waterfalls, loading spinners, and unnecessary API roundtrips
tags: [performance, useeffect, data-fetching, server-components, react, nextjs]
detection_grep: "useEffect"
---

## Prefer Server Components Over useEffect + Fetch for Data Loading

**Impact: HIGH (eliminates client-side waterfalls, loading spinners, and unnecessary API roundtrips)**

The `useEffect` + `useState` data fetching pattern is a legacy from the Client Component era. It creates a waterfall: the page loads, JavaScript executes, the component renders, useEffect fires, a network request goes to your API route, the API route queries the database, the response travels back, then the component re-renders with data. Server Components eliminate this entire chain by fetching data directly on the server during rendering.

The critical rule: **never create an API route just to fetch data for your own pages.** If the only consumer of an API route is your own frontend, the data should be fetched in a Server Component or server action instead.

**Incorrect (useEffect + fetch pattern):**

```tsx
// components/RulesList.tsx
// ❌ Client-side data fetching — creates waterfall and unnecessary API route
'use client'

import { useState, useEffect } from 'react'

export function RulesList({ userId }: { userId: string }) {
  const [rules, setRules] = useState<Rule[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    fetch(`/api/rules?userId=${userId}`)
      .then(r => {
        if (!r.ok) throw new Error('Failed to fetch')
        return r.json()
      })
      .then(data => setRules(data))
      .catch(err => setError(err.message))
      .finally(() => setLoading(false))
  }, [userId])

  if (loading) return <Spinner /> // ❌ Loading spinner flashes on every navigation
  if (error) return <ErrorMessage message={error} />

  return (
    <ul>
      {rules.map(rule => (
        <li key={rule.id}>{rule.name}</li>
      ))}
    </ul>
  )
}
```

```typescript
// app/api/rules/route.ts
// ❌ API route exists ONLY to serve the client component above
export async function GET(request: NextRequest) {
  const userId = request.nextUrl.searchParams.get('userId')
  const supabase = await createServerSupabaseClient()
  const { data } = await supabase
    .from('rules')
    .select('*')
    .eq('user_id', userId)
  return NextResponse.json(data)
}
```

**Correct (async Server Component with direct data access):**

```tsx
// components/RulesList.tsx
// ✅ Server Component — fetches data directly, no loading state needed
import { ruleService } from '@/lib/services'

export async function RulesList({ userId }: { userId: string }) {
  const result = await ruleService.getRulesByUserId(userId)

  if (!result.success) {
    return <ErrorMessage message="Failed to load rules" />
  }

  return (
    <ul>
      {result.data.map(rule => (
        <li key={rule.id}>{rule.name}</li>
      ))}
    </ul>
  )
}

// No API route needed! The service fetches data directly on the server.
// The API route from the incorrect example can be deleted entirely.
```

```tsx
// app/rules/page.tsx
// ✅ Page is a Server Component — no useEffect, no loading spinner
import { Suspense } from 'react'
import { RulesList } from '@/components/RulesList'
import { getCurrentUser } from '@/lib/auth'

export default async function RulesPage() {
  const user = await getCurrentUser()

  return (
    <div>
      <h1>Your Rules</h1>
      <Suspense fallback={<RulesListSkeleton />}>
        <RulesList userId={user.id} />
      </Suspense>
    </div>
  )
}
```

**When you DO need an API route:**

```typescript
// ✅ API routes are for external consumers, webhooks, and client-side mutations
// These are valid API routes:

// External API consumed by mobile app or third parties
// app/api/v1/rules/route.ts
export async function GET(request: NextRequest) { /* ... */ }

// Webhook endpoint for external service
// app/api/webhooks/stripe/route.ts
export async function POST(request: NextRequest) { /* ... */ }

// Mutation triggered by client interaction (form submit, button click)
// app/api/rules/route.ts
export async function POST(request: NextRequest) { /* ... */ }
```

**Decision flowchart:**

| Question | Answer | Action |
|----------|--------|--------|
| Is data needed for initial page render? | Yes | Server Component |
| Is the only consumer your own frontend? | Yes | Server Component (delete the API route) |
| Is data needed after user interaction? | Yes | Server Action or API route |
| Do external clients need this data? | Yes | API route |
| Does data need real-time updates? | Yes | Client Component with subscription |

**Detection hints:**

```bash
# Find useEffect data fetching patterns
grep -rn "useEffect.*fetch\|useEffect.*axios\|useEffect.*api" src/ --include="*.tsx"
# Find API routes that only serve GET requests (candidates for elimination)
grep -rn "export async function GET" src/app/api --include="*.ts" -l
```

Reference: [Next.js Data Fetching](https://nextjs.org/docs/app/building-your-application/data-fetching) · [React Server Components](https://react.dev/reference/rsc/server-components)
