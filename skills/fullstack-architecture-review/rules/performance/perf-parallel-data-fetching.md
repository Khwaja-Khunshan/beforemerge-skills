---
title: Use Promise.all for Independent Data Fetches
description: "Serial await statements for independent data fetches create request waterfalls. Use Promise.all to parallelize and cut load times by 2-5x."
impact: HIGH
impact_description: 2-5x faster page loads by eliminating sequential data fetch waterfalls
tags: [performance, async, waterfalls, promise-all, server-components, nextjs]
detection_grep: "await "
---

## Use Promise.all for Independent Data Fetches

**Impact: HIGH (2-5x faster page loads by eliminating sequential data fetch waterfalls)**

Sequential `await` calls on independent operations add unnecessary latency. If `fetchUser()` takes 200ms, `fetchRules()` takes 300ms, and `fetchAnalytics()` takes 150ms, sequential execution takes 650ms while `Promise.all` takes 300ms — the time of the slowest call. This applies to Server Components, API route handlers, and service methods alike.

The pattern is especially damaging in service methods where multiple repository calls are independent.

**Incorrect (sequential awaits for independent operations):**

```typescript
// lib/services/DashboardService.ts
// ❌ Three independent fetches executed sequentially — total: sum of all three
async getDashboardData(userId: string): Promise<ServiceResult<DashboardData>> {
  const user = await this.userRepo.findById(userId)          // 200ms
  const rules = await this.ruleRepo.findByUserId(userId)     // 300ms
  const analytics = await this.analyticsRepo.getSummary(userId) // 150ms
  // Total: 650ms

  return success({
    user,
    rules,
    analytics,
  })
}
```

```typescript
// app/dashboard/page.tsx
// ❌ Sequential Server Component fetches
export default async function DashboardPage() {
  const user = await fetchUser()           // 200ms
  const posts = await fetchPosts()         // 300ms
  const notifications = await fetchNotifs() // 100ms
  // Total: 600ms — user stares at blank screen

  return <Dashboard user={user} posts={posts} notifications={notifications} />
}
```

**Correct (parallel execution with Promise.all):**

```typescript
// lib/services/DashboardService.ts
// ✅ All three fire simultaneously — total: max of all three
async getDashboardData(userId: string): Promise<ServiceResult<DashboardData>> {
  const [user, rules, analytics] = await Promise.all([
    this.userRepo.findById(userId),           // 200ms ─┐
    this.ruleRepo.findByUserId(userId),       // 300ms ─┤ All concurrent
    this.analyticsRepo.getSummary(userId),    // 150ms ─┘
  ])
  // Total: 300ms (max of the three)

  if (!user) {
    return failure('User not found', 'USER_NOT_FOUND')
  }

  return success({ user, rules, analytics })
}
```

**Correct (Suspense-based progressive rendering for Server Components):**

```tsx
// app/dashboard/page.tsx
// ✅ Even better: stream content as each piece resolves independently
import { Suspense } from 'react'

export default function DashboardPage() {
  return (
    <div className="grid grid-cols-2 gap-4">
      <Suspense fallback={<UserCardSkeleton />}>
        <UserSection />
      </Suspense>
      <Suspense fallback={<RulesListSkeleton />}>
        <RulesSection />
      </Suspense>
      <Suspense fallback={<AnalyticsSkeleton />}>
        <AnalyticsSection />
      </Suspense>
    </div>
  )
}

// Each component fetches its own data — React streams them as they resolve
async function UserSection() {
  const user = await userService.getCurrentUser()
  return <UserCard user={user} />
}

async function RulesSection() {
  const rules = await ruleService.getActiveRules()
  return <RulesList rules={rules} />
}
```

**Partial dependencies (when some calls depend on others):**

```typescript
// ✅ Fetch user first (needed for dependent calls), then parallelize the rest
async getProfileData(userId: string): Promise<ServiceResult<ProfileData>> {
  const user = await this.userRepo.findById(userId)
  if (!user) {
    return failure('User not found', 'USER_NOT_FOUND')
  }

  // These depend on user.teamId but not on each other
  const [teamMembers, teamRules, teamAnalytics] = await Promise.all([
    this.teamRepo.getMembers(user.teamId),
    this.ruleRepo.findByTeamId(user.teamId),
    this.analyticsRepo.getTeamSummary(user.teamId),
  ])

  return success({ user, teamMembers, teamRules, teamAnalytics })
}
```

**Detection hints:**

```bash
# Find consecutive awaits that might be parallelizable
grep -rn "const.*= await" src/lib/services --include="*.ts"
grep -rn "const.*= await" src/app --include="*.tsx"
```

Reference: [MDN Promise.all](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise/all) · [Next.js Parallel Data Fetching](https://nextjs.org/docs/app/building-your-application/data-fetching/fetching#parallel-data-fetching)
