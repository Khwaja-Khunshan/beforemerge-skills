---
title: Extract Duplicated Stateful Logic into Custom Hooks
description: "Duplicating stateful logic (useState + useEffect patterns) across multiple components leads to inconsistency and maintenance burden. Extract into reusable custom hooks."
impact: MEDIUM
impact_description: reduces code duplication and ensures consistent behavior across components
tags: [architecture, react, custom-hooks, reusability, DRY]
detection_grep: "useEffect"
---

## Extract Duplicated Stateful Logic into Custom Hooks

**Impact: MEDIUM (reduces code duplication and ensures consistent behavior across components)**

When the same combination of `useState`, `useEffect`, `useRef`, or `useCallback` appears in multiple components — such as fetching data, managing form state, handling window resize, debouncing input, or tracking online status — each copy is an independent maintenance burden. Bug fixes must be applied in every location, and subtle inconsistencies creep in. Custom hooks encapsulate this logic once, making it testable in isolation and reusable everywhere.

**Incorrect (same fetch + loading + error pattern duplicated across components):**

```tsx
// ❌ Component A
function UserProfile({ userId }: { userId: string }) {
  const [user, setUser] = useState<User | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<Error | null>(null)

  useEffect(() => {
    setLoading(true)
    fetch(`/api/users/${userId}`)
      .then((r) => r.json())
      .then(setUser)
      .catch(setError)
      .finally(() => setLoading(false))
  }, [userId])

  if (loading) return <Spinner />
  if (error) return <ErrorMessage error={error} />
  return <div>{user?.name}</div>
}

// ❌ Component B — exact same pattern, copy-pasted
function TeamMembers({ teamId }: { teamId: string }) {
  const [members, setMembers] = useState<User[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<Error | null>(null)

  useEffect(() => {
    setLoading(true)
    fetch(`/api/teams/${teamId}/members`)
      .then((r) => r.json())
      .then(setMembers)
      .catch(setError)
      .finally(() => setLoading(false))
  }, [teamId])

  if (loading) return <Spinner />
  if (error) return <ErrorMessage error={error} />
  return <MemberList members={members} />
}
```

**Correct (extract shared logic into a custom hook):**

```tsx
// ✅ Custom hook encapsulates the pattern once
function useFetch<T>(url: string) {
  const [data, setData] = useState<T | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<Error | null>(null)

  useEffect(() => {
    const controller = new AbortController()
    setLoading(true)
    setError(null)

    fetch(url, { signal: controller.signal })
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`)
        return r.json()
      })
      .then(setData)
      .catch((err) => {
        if (err.name !== 'AbortError') setError(err)
      })
      .finally(() => setLoading(false))

    return () => controller.abort()  // ✅ proper cleanup
  }, [url])

  return { data, loading, error }
}

// ✅ Components become thin and focused
function UserProfile({ userId }: { userId: string }) {
  const { data: user, loading, error } = useFetch<User>(`/api/users/${userId}`)
  if (loading) return <Spinner />
  if (error) return <ErrorMessage error={error} />
  return <div>{user?.name}</div>
}

function TeamMembers({ teamId }: { teamId: string }) {
  const { data: members, loading, error } = useFetch<User[]>(`/api/teams/${teamId}/members`)
  if (loading) return <Spinner />
  if (error) return <ErrorMessage error={error} />
  return <MemberList members={members ?? []} />
}
```

**Additional context:**

- Common candidates for custom hooks: `useDebounce`, `useLocalStorage`, `useMediaQuery`, `useOnClickOutside`, `useIntersectionObserver`, `usePrevious`, `useWindowSize`.
- Custom hooks are testable in isolation using `renderHook` from `@testing-library/react`.
- If your custom hook becomes too complex (> 50 lines, multiple branching paths), it may need to be split further or replaced with a dedicated library (TanStack Query for data fetching, React Hook Form for forms).
- Naming convention: custom hooks must start with `use` to get lint rule enforcement from the Rules of Hooks.

**Detection hints:**

```bash
# Find duplicated useState + useEffect patterns across components
grep -rn "useState.*useEffect\|useEffect.*useState" src/ --include="*.tsx" --include="*.ts"
```

Reference: [React docs on reusing logic with custom hooks](https://react.dev/learn/reusing-logic-with-custom-hooks)
