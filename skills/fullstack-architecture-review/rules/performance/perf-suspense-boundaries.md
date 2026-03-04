---
title: Stream Slow Content with Suspense Boundaries
description: "Pages that block until all data loads show nothing until everything is ready. Wrap slow components in Suspense to stream content progressively."
impact: MEDIUM
impact_description: improves perceived load time by showing content as it becomes available
tags: [performance, suspense, streaming, server-components, loading-states, nextjs]
detection_grep: "async function.*Page"
---

## Stream Slow Content with Suspense Boundaries

**Impact: MEDIUM (improves perceived load time by showing content as it becomes available)**

A page that awaits all data before rendering shows a blank screen (or a full-page spinner) until the slowest query completes. If your page fetches user data (50ms), rules (200ms), and analytics from a third-party API (2 seconds), the entire page is blocked for 2 seconds — even though most content was ready in 200ms.

Suspense boundaries let React stream content to the client as each section resolves. Fast sections appear immediately while slow sections show skeleton placeholders, then pop in when ready. This dramatically improves perceived performance without changing your data fetching logic.

**Incorrect (all-or-nothing page rendering):**

```tsx
// app/dashboard/page.tsx
// ❌ Entire page blocked until slowest fetch completes
export default async function DashboardPage() {
  const user = await fetchUser()                    // 50ms
  const rules = await ruleService.getActiveRules()  // 200ms
  const analytics = await analyticsApi.getSummary()  // 2000ms ← blocks everything

  // User sees nothing for 2+ seconds
  return (
    <div>
      <UserHeader user={user} />
      <RulesSummary rules={rules} />
      <AnalyticsDashboard analytics={analytics} />
    </div>
  )
}
```

```tsx
// ❌ Even with Promise.all, page still blocks until slowest resolves
export default async function DashboardPage() {
  const [user, rules, analytics] = await Promise.all([
    fetchUser(),                   // 50ms  ─┐
    ruleService.getActiveRules(),  // 200ms ─┤ Concurrent but page
    analyticsApi.getSummary(),     // 2000ms ┘ still waits for all three
  ])

  return (
    <div>
      <UserHeader user={user} />
      <RulesSummary rules={rules} />
      <AnalyticsDashboard analytics={analytics} />
    </div>
  )
}
```

**Correct (Suspense boundaries for progressive streaming):**

```tsx
// app/dashboard/page.tsx
// ✅ Fast sections render immediately, slow sections stream in
import { Suspense } from 'react'

export default async function DashboardPage() {
  // Fast data fetched at page level — available immediately
  const user = await fetchUser() // 50ms

  return (
    <div>
      {/* ✅ Renders instantly — data already loaded */}
      <UserHeader user={user} />

      {/* ✅ Renders in ~200ms with its own loading state */}
      <Suspense fallback={<RulesSummarySkeleton />}>
        <RulesSummarySection userId={user.id} />
      </Suspense>

      {/* ✅ Renders in ~2s — doesn't block anything above */}
      <Suspense fallback={<AnalyticsSkeleton />}>
        <AnalyticsSection userId={user.id} />
      </Suspense>
    </div>
  )
}
```

```tsx
// components/RulesSummarySection.tsx
// ✅ Async Server Component — fetches its own data independently
async function RulesSummarySection({ userId }: { userId: string }) {
  const rules = await ruleService.getActiveRules(userId) // 200ms
  return <RulesSummary rules={rules} />
}

// components/AnalyticsSection.tsx
// ✅ Slow third-party call doesn't block the rest of the page
async function AnalyticsSection({ userId }: { userId: string }) {
  const analytics = await analyticsApi.getSummary(userId) // 2000ms
  return <AnalyticsDashboard analytics={analytics} />
}
```

```tsx
// components/skeletons/AnalyticsSkeleton.tsx
// ✅ Meaningful skeleton — matches the shape of the real content
export function AnalyticsSkeleton() {
  return (
    <div className="animate-pulse space-y-4">
      <div className="h-8 w-48 bg-gray-200 rounded" />
      <div className="grid grid-cols-3 gap-4">
        {[1, 2, 3].map((i) => (
          <div key={i} className="h-32 bg-gray-200 rounded" />
        ))}
      </div>
      <div className="h-64 bg-gray-200 rounded" />
    </div>
  )
}
```

**When to use Suspense vs Promise.all:**

| Scenario | Use | Reason |
|----------|-----|--------|
| All data needed before render | `Promise.all` | Can't show partial UI |
| Sections can render independently | `Suspense` | Stream content progressively |
| Mix of fast and slow fetches | `Suspense` | Show fast content immediately |
| Data dependencies between sections | `Promise.all` first, then `Suspense` | Resolve dependencies, stream the rest |

**Detection hints:**

```bash
# Find page components with multiple sequential awaits (candidates for Suspense)
grep -rn "await.*Service\|await.*fetch\|await.*api" src/app --include="page.tsx"
# Find pages without any Suspense boundaries
grep -rL "Suspense" src/app --include="page.tsx"
```

Reference: [React Suspense](https://react.dev/reference/react/Suspense) · [Next.js Streaming](https://nextjs.org/docs/app/building-your-application/routing/loading-ui-and-streaming)
