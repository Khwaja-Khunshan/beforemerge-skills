---
title: Break Up God Components Into Focused, Composable Units
description: "Components handling data fetching, business logic, state, and rendering are hard to test and maintain. Decompose by responsibility."
impact: MEDIUM
impact_description: improves maintainability, testability, and reuse across the codebase
tags: [architecture, components, composition, single-responsibility, react, nextjs]
detection_grep: "useState"
---

## Break Up God Components Into Focused, Composable Units

**Impact: MEDIUM (improves maintainability, testability, and reuse)**

"God components" are components that do too much — handling data fetching, business logic, state management, and rendering all in one file. They are hard to test, hard to reuse, and create merge conflicts when multiple developers work on the same feature. A component should have one clear job.

**Incorrect (single component doing everything):**

```tsx
// ❌ 300+ line component handling fetch, state, validation, and rendering
'use client'

export function UserDashboard({ userId }: { userId: string }) {
  const [user, setUser] = useState(null)
  const [posts, setPosts] = useState([])
  const [analytics, setAnalytics] = useState(null)
  const [editMode, setEditMode] = useState(false)
  const [formData, setFormData] = useState({})
  const [errors, setErrors] = useState({})
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetch(`/api/users/${userId}`).then(r => r.json()).then(setUser)
    fetch(`/api/users/${userId}/posts`).then(r => r.json()).then(setPosts)
    fetch(`/api/analytics/${userId}`).then(r => r.json()).then(setAnalytics)
    setLoading(false)
  }, [userId])

  function validateForm() { /* 40 lines of validation */ }
  function handleSubmit() { /* 30 lines of submission logic */ }
  function handleDelete(postId: string) { /* 20 lines */ }

  if (loading) return <Spinner />

  return (
    <div>
      {/* 200 lines of mixed rendering: profile header, edit form,
          posts list, analytics charts, action buttons... */}
    </div>
  )
}
```

**Correct (decomposed into focused components):**

```tsx
// ✅ Page-level Server Component handles data fetching
// app/dashboard/page.tsx
export default async function DashboardPage({ params }: { params: { userId: string } }) {
  const [user, posts, analytics] = await Promise.all([
    fetchUser(params.userId),
    fetchPosts(params.userId),
    fetchAnalytics(params.userId),
  ])

  return (
    <div>
      <UserHeader user={user} />
      <UserProfileEditor user={user} />
      <PostsList posts={posts} />
      <AnalyticsOverview analytics={analytics} />
    </div>
  )
}
```

```tsx
// ✅ Each component has one job
// components/UserHeader.tsx — pure display, no state needed
export function UserHeader({ user }: { user: User }) {
  return (
    <header>
      <img src={user.avatarUrl} alt={user.name} />
      <h1>{user.name}</h1>
      <p>{user.role}</p>
    </header>
  )
}

// components/UserProfileEditor.tsx — handles edit state only
'use client'
export function UserProfileEditor({ user }: { user: User }) {
  const [editMode, setEditMode] = useState(false)
  // Focused: only handles profile editing
}

// components/PostsList.tsx — handles post display + actions
export function PostsList({ posts }: { posts: Post[] }) {
  return posts.map((post) => <PostCard key={post.id} post={post} />)
}
```

**Rule of thumb:** If a component file exceeds ~150 lines or manages more than 3 pieces of state, it's a strong candidate for decomposition.

**Detection hints:**

```bash
# Find large component files (likely god components)
find src/ -name "*.tsx" -exec wc -l {} + | sort -rn | head -20
# Find components with many useState calls
grep -rn "useState" src/ --include="*.tsx" -c | sort -t: -k2 -rn | head -10
```

Reference: [React Composition Patterns](https://react.dev/learn/thinking-in-react)
