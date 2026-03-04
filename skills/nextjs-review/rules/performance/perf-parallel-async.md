---
title: Parallelize Independent Async Operations
description: "Sequential await calls on independent operations create request waterfalls. Use Promise.all or Suspense boundaries to parallelize."
impact: CRITICAL
impact_description: 2-10x faster page loads by eliminating request waterfalls
tags: [performance, async, waterfalls, server-components, nextjs]
detection_grep: "await "
---

## Parallelize Independent Async Operations

**Impact: CRITICAL (2-10× faster page loads by eliminating request waterfalls)**

Sequential `await` calls that don't depend on each other add unnecessary latency. Each `await` blocks until it completes before the next one starts. If three independent calls each take 200ms, sequential execution takes 600ms while parallel takes 200ms.

This is especially impactful in Server Components where multiple data fetches are common.

**Incorrect (sequential — each await blocks the next):**

```typescript
// ❌ 3 sequential round trips in a Server Component
// Total time: fetchUser + fetchPosts + fetchAnalytics
export default async function DashboardPage() {
  const user = await fetchUser()
  const posts = await fetchPosts()
  const analytics = await fetchAnalytics()

  return <Dashboard user={user} posts={posts} analytics={analytics} />
}
```

```typescript
// ❌ Sequential in API routes too
export async function GET() {
  const products = await db.product.findMany()
  const categories = await db.category.findMany()
  const reviews = await db.review.findMany({ take: 10 })

  return Response.json({ products, categories, reviews })
}
```

**Correct (parallel — all fire at once):**

```typescript
// ✅ All three fetch simultaneously
// Total time: max(fetchUser, fetchPosts, fetchAnalytics)
export default async function DashboardPage() {
  const [user, posts, analytics] = await Promise.all([
    fetchUser(),
    fetchPosts(),
    fetchAnalytics(),
  ])

  return <Dashboard user={user} posts={posts} analytics={analytics} />
}
```

**Correct (Suspense boundaries for progressive loading):**

```tsx
// ✅ Even better: stream content as it resolves
import { Suspense } from 'react'

export default async function DashboardPage() {
  return (
    <>
      <Suspense fallback={<UserSkeleton />}>
        <UserSection />
      </Suspense>
      <Suspense fallback={<PostsSkeleton />}>
        <PostsSection />
      </Suspense>
      <Suspense fallback={<AnalyticsSkeleton />}>
        <AnalyticsSection />
      </Suspense>
    </>
  )
}

// Each component fetches its own data independently
async function UserSection() {
  const user = await fetchUser()
  return <UserCard user={user} />
}
```

**Partial dependencies (when some calls depend on others):**

```typescript
// ✅ Fetch user first, then parallelize the rest
export default async function DashboardPage() {
  const user = await fetchUser()

  // These depend on user.id but not on each other
  const [posts, settings, notifications] = await Promise.all([
    fetchPosts(user.id),
    fetchSettings(user.id),
    fetchNotifications(user.id),
  ])

  return <Dashboard user={user} posts={posts} settings={settings} />
}
```

**Detection hints:**

```bash
# Find consecutive awaits in the same function
grep -rn "await " src/ --include="*.ts" --include="*.tsx" -A 1 | grep -B 1 "await "
```

Reference: [Next.js Data Fetching Patterns](https://nextjs.org/docs/app/building-your-application/data-fetching/fetching#parallel-data-fetching)
