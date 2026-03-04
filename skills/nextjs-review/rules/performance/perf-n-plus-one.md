---
title: Eliminate N+1 Database Queries
description: "Fetching related data inside loops creates N+1 queries that scale linearly with data size. Use eager loading or batch queries instead."
impact: CRITICAL
impact_description: 10-100x query reduction, prevents database overload
tags: [performance, database, n-plus-one, prisma, drizzle, nextjs]
cwe: ["CWE-400"]
detection_grep: "\\.map(async"
---

## Eliminate N+1 Database Queries

**Impact: CRITICAL (10-100× query reduction, prevents database overload)**

The N+1 query problem occurs when code fetches a list of items (1 query), then loops through each item to fetch related data (N queries). This is the most common performance killer in web applications and scales linearly with data size — 100 users = 101 queries.

**Incorrect (N+1 — one query per user in the loop):**

```typescript
// ❌ 1 query to get users + N queries to get posts
export async function getUsersWithPosts() {
  const users = await prisma.user.findMany()

  const usersWithPosts = await Promise.all(
    users.map(async (user) => {
      const posts = await prisma.post.findMany({
        where: { authorId: user.id },
      })
      return { ...user, posts }
    })
  )

  return usersWithPosts
}
// 100 users = 101 database queries 💀
```

**Correct (single query with include/join):**

```typescript
// ✅ Single query with eager loading
export async function getUsersWithPosts() {
  return prisma.user.findMany({
    include: {
      posts: true,
    },
  })
}
// 100 users = 1-2 database queries ✅
```

**Correct (batch query with IN clause):**

```typescript
// ✅ Two queries instead of N+1
export async function getUsersWithPosts() {
  const users = await prisma.user.findMany()
  const userIds = users.map((u) => u.id)

  const posts = await prisma.post.findMany({
    where: { authorId: { in: userIds } },
  })

  // Group posts by author in memory
  const postsByAuthor = new Map<string, Post[]>()
  for (const post of posts) {
    const existing = postsByAuthor.get(post.authorId) ?? []
    existing.push(post)
    postsByAuthor.set(post.authorId, existing)
  }

  return users.map((user) => ({
    ...user,
    posts: postsByAuthor.get(user.id) ?? [],
  }))
}
// 100 users = 2 database queries ✅
```

**In Server Components (hidden N+1):**

```typescript
// ❌ Each UserCard triggers its own query
async function UserList() {
  const users = await prisma.user.findMany()
  return users.map((user) => <UserCard key={user.id} userId={user.id} />)
}

async function UserCard({ userId }: { userId: string }) {
  // This runs once per card = N queries
  const profile = await prisma.profile.findUnique({
    where: { userId },
  })
  return <div>{profile?.bio}</div>
}

// ✅ Fix: fetch all data at the parent level
async function UserList() {
  const users = await prisma.user.findMany({
    include: { profile: true },
  })
  return users.map((user) => <UserCard key={user.id} user={user} />)
}
```

**Detection hints:**

```bash
# Find queries inside .map() or .forEach() — likely N+1
grep -rn "\.map(async" src/ --include="*.ts" --include="*.tsx" -A 3 | grep -E "prisma\.|supabase\.|db\."
# Find queries inside loop bodies
grep -rn "for.*of\|forEach" src/ --include="*.ts" --include="*.tsx" -A 5 | grep -E "await.*\.(find|get|fetch|query)"
```

Reference: [Prisma Relation Queries](https://www.prisma.io/docs/orm/prisma-client/queries/relation-queries)
