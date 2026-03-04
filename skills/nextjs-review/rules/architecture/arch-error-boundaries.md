---
title: Add Error Boundaries Around Unreliable Content
description: "Without error boundaries, a single component failure crashes the entire page. Use error.tsx and granular ErrorBoundary wrappers."
impact: MEDIUM
impact_description: prevents full-page crashes from isolated component failures
tags: [architecture, error-handling, resilience, error-boundary, nextjs]
---

## Add Error Boundaries Around Unreliable Content

**Impact: MEDIUM (prevents full-page crashes from isolated component failures)**

Without error boundaries, a single thrown error in any component crashes the entire page. In Next.js App Router, `error.tsx` files act as error boundaries at the route segment level. For more granular control, wrap unreliable sections (third-party widgets, user-generated content, data-dependent components) so failures are contained.

**Incorrect (no error boundaries — one failure kills the page):**

```tsx
// ❌ If AnalyticsChart throws, the entire dashboard crashes
export default async function DashboardPage() {
  const user = await fetchUser()
  const analytics = await fetchAnalytics()

  return (
    <div>
      <UserHeader user={user} />
      <AnalyticsChart data={analytics} />  {/* If this throws = blank page */}
      <RecentActivity />
    </div>
  )
}
```

**Correct (Next.js error.tsx at the route level):**

```tsx
// app/dashboard/error.tsx
'use client'

export default function DashboardError({
  error,
  reset,
}: {
  error: Error & { digest?: string }
  reset: () => void
}) {
  return (
    <div>
      <h2>Something went wrong loading the dashboard.</h2>
      <button onClick={() => reset()}>Try again</button>
    </div>
  )
}
```

**Correct (granular error boundaries for unreliable sections):**

```tsx
// ✅ Isolate failures so the rest of the page still works
import { ErrorBoundary } from 'react-error-boundary'

export default async function DashboardPage() {
  const user = await fetchUser()

  return (
    <div>
      <UserHeader user={user} />

      <ErrorBoundary fallback={<p>Charts temporarily unavailable.</p>}>
        <Suspense fallback={<ChartSkeleton />}>
          <AnalyticsChart userId={user.id} />
        </Suspense>
      </ErrorBoundary>

      <ErrorBoundary fallback={<p>Could not load activity feed.</p>}>
        <Suspense fallback={<ActivitySkeleton />}>
          <RecentActivity userId={user.id} />
        </Suspense>
      </ErrorBoundary>
    </div>
  )
}
```

**Also add not-found.tsx for missing data:**

```tsx
// app/dashboard/[id]/not-found.tsx
export default function NotFound() {
  return <p>This dashboard does not exist.</p>
}

// app/dashboard/[id]/page.tsx
import { notFound } from 'next/navigation'

export default async function DashboardPage({ params }: { params: { id: string } }) {
  const dashboard = await fetchDashboard(params.id)
  if (!dashboard) notFound()

  return <Dashboard data={dashboard} />
}
```

**Detection hints:**

```bash
# Find route segments missing error.tsx
find src/app -type d | while read dir; do
  if [ -f "$dir/page.tsx" ] && [ ! -f "$dir/error.tsx" ]; then
    echo "Missing error.tsx: $dir"
  fi
done
```

Reference: [Next.js Error Handling](https://nextjs.org/docs/app/building-your-application/routing/error-handling) · [react-error-boundary](https://github.com/bvaughn/react-error-boundary)
