---
title: Implement loading.tsx and error.tsx at Every Route Segment
description: "Missing loading.tsx causes full-page spinners instead of granular streaming. Missing error.tsx lets errors crash parent layouts instead of being contained."
impact: MEDIUM
impact_description: prevents full-page loading states and uncontained error propagation
tags: [architecture, loading, error-handling, suspense, streaming, nextjs]
detection_grep: "loading.tsx|error.tsx"
---

## Implement loading.tsx and error.tsx at Every Route Segment

**Impact: MEDIUM (prevents full-page loading states and uncontained error propagation)**

Next.js App Router uses `loading.tsx` and `error.tsx` as automatic Suspense and Error Boundaries. Without them:

- **Missing `loading.tsx`**: Suspense falls back to the nearest parent boundary — often the root layout — showing a full-page spinner instead of a granular skeleton for just the loading section
- **Missing `error.tsx`**: Errors propagate up the component tree and crash the nearest parent layout, potentially taking down the entire page or even the app shell

**Incorrect (missing boundary files):**

```
app/
├── layout.tsx          ← Only error/loading boundary for the entire app
├── page.tsx
├── dashboard/
│   ├── page.tsx        ← ❌ No loading.tsx — full page spinner when navigating here
│   ├── analytics/
│   │   └── page.tsx    ← ❌ No error.tsx — API failure crashes the entire dashboard
│   └── settings/
│       └── page.tsx
└── profile/
    └── page.tsx
```

```tsx
// ❌ No loading state — user sees nothing while data loads
// app/dashboard/page.tsx
export default async function Dashboard() {
  const data = await fetchDashboardData() // 2-3 second fetch, no visual feedback
  return <DashboardView data={data} />
}

// ❌ No error boundary — if fetchAnalytics throws, the dashboard layout crashes
// app/dashboard/analytics/page.tsx
export default async function Analytics() {
  const data = await fetchAnalytics() // Throws → entire dashboard is blank
  return <AnalyticsView data={data} />
}
```

**Correct (boundary files at each route segment):**

```
app/
├── layout.tsx
├── loading.tsx          ← Root loading state (for initial page load)
├── error.tsx            ← Root error boundary (last resort)
├── page.tsx
├── dashboard/
│   ├── layout.tsx
│   ├── loading.tsx      ← ✅ Dashboard-specific skeleton
│   ├── error.tsx        ← ✅ Dashboard-specific error UI
│   ├── page.tsx
│   ├── analytics/
│   │   ├── loading.tsx  ← ✅ Analytics skeleton while data loads
│   │   ├── error.tsx    ← ✅ Isolates analytics errors from dashboard
│   │   └── page.tsx
│   └── settings/
│       ├── loading.tsx
│       ├── error.tsx
│       └── page.tsx
└── profile/
    ├── loading.tsx
    ├── error.tsx
    └── page.tsx
```

```tsx
// app/dashboard/loading.tsx — shows while dashboard page data loads
export default function DashboardLoading() {
  return (
    <div className="animate-pulse space-y-4">
      <div className="h-8 bg-gray-200 rounded w-1/3" />
      <div className="grid grid-cols-3 gap-4">
        <div className="h-32 bg-gray-200 rounded" />
        <div className="h-32 bg-gray-200 rounded" />
        <div className="h-32 bg-gray-200 rounded" />
      </div>
    </div>
  )
}
```

```tsx
// app/dashboard/analytics/error.tsx — contains errors to this segment
'use client' // Error boundaries must be Client Components

export default function AnalyticsError({
  error,
  reset,
}: {
  error: Error & { digest?: string }
  reset: () => void
}) {
  return (
    <div className="p-4 border border-red-200 rounded bg-red-50">
      <h2 className="text-red-800 font-semibold">Analytics unavailable</h2>
      <p className="text-red-600 text-sm mt-1">
        {error.message || 'Failed to load analytics data.'}
      </p>
      <button
        onClick={reset}
        className="mt-3 px-4 py-2 bg-red-600 text-white rounded text-sm"
      >
        Try again
      </button>
    </div>
  )
}
```

**Key principles:**

1. **Every route segment with async data should have a `loading.tsx`** — enables streaming and progressive rendering
2. **Every route segment with external dependencies should have an `error.tsx`** — contains failures to that segment
3. **`error.tsx` must be a Client Component** (`'use client'`) — React Error Boundaries require it
4. **`error.tsx` cannot catch errors in the same segment's `layout.tsx`** — use a parent `error.tsx` for layout errors, or the special `global-error.tsx` at the root
5. **Don't use a single root loading/error** — that defeats granular streaming

**Detection hints:**

```bash
# Find route segments missing loading.tsx
ls -d src/app/**/page.tsx | while read f; do dir=$(dirname "$f"); [ ! -f "$dir/loading.tsx" ] && echo "Missing: $dir/loading.tsx"; done
# Find route segments missing error.tsx
ls -d src/app/**/page.tsx | while read f; do dir=$(dirname "$f"); [ ! -f "$dir/error.tsx" ] && echo "Missing: $dir/error.tsx"; done
```

Reference: [Next.js Loading UI](https://nextjs.org/docs/app/building-your-application/routing/loading-ui-and-streaming) · [Next.js Error Handling](https://nextjs.org/docs/app/building-your-application/routing/error-handling)
