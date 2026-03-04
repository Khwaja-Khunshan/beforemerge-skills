---
title: Prevent Unnecessary Re-renders from Unstable References
description: "Inline objects, arrays, and functions as props create new references every render, defeating React.memo and causing cascading re-renders across the tree."
impact: HIGH
impact_description: eliminates cascading re-renders that degrade Core Web Vitals and interaction responsiveness
tags: [performance, react, rerender, memo, usememo, usecallback, nextjs]
detection_grep: "style=\\{\\{|onClick=\\{\\(\\)|options=\\{\\[|context.*value=\\{\\{"
---

## Prevent Unnecessary Re-renders from Unstable References

**Impact: HIGH (eliminates cascading re-renders that degrade Core Web Vitals and interaction responsiveness)**

React re-renders a component whenever its parent re-renders or its props change. Props are compared by **reference**, not by value. This means inline objects (`style={{}}`), inline arrays (`items={[]}`), and inline functions (`onClick={() => {}}`) create new references every render — even if the values are identical — triggering re-renders in every child component.

This is the root cause of most "my React app is slow" complaints.

**Incorrect (new references every render):**

```tsx
'use client'

function Dashboard({ userId }: { userId: string }) {
  const [count, setCount] = useState(0)

  return (
    <div>
      <button onClick={() => setCount(c => c + 1)}>Click: {count}</button>

      {/* ❌ Every click re-renders ALL of these children */}
      <UserProfile
        style={{ padding: 16, margin: 8 }}      // New object every render
        options={['edit', 'delete', 'share']}     // New array every render
        onAction={(action) => handleAction(action)} // New function every render
      />
      <ActivityFeed filters={{ userId, limit: 20 }} />  // New object every render
      <Sidebar config={{ theme: 'dark', collapsed: false }} />
    </div>
  )
}
```

```tsx
// ❌ Context value creates a new object every render → all consumers re-render
function AppProvider({ children }) {
  const [user, setUser] = useState(null)
  const [theme, setTheme] = useState('light')

  return (
    <AppContext.Provider value={{ user, setUser, theme, setTheme }}>
      {children}
    </AppContext.Provider>
  )
}
```

**Correct (stable references):**

```tsx
'use client'

// ✅ Move static values outside the component
const profileStyle = { padding: 16, margin: 8 }
const profileOptions = ['edit', 'delete', 'share'] as const
const sidebarConfig = { theme: 'dark', collapsed: false }

function Dashboard({ userId }: { userId: string }) {
  const [count, setCount] = useState(0)

  // ✅ Memoize dynamic objects that depend on props/state
  const feedFilters = useMemo(() => ({ userId, limit: 20 }), [userId])

  // ✅ Stabilize callbacks
  const handleAction = useCallback((action: string) => {
    // ... handle action
  }, [])

  return (
    <div>
      <button onClick={() => setCount(c => c + 1)}>Click: {count}</button>
      <UserProfile
        style={profileStyle}
        options={profileOptions}
        onAction={handleAction}
      />
      <ActivityFeed filters={feedFilters} />
      <Sidebar config={sidebarConfig} />
    </div>
  )
}
```

```tsx
// ✅ Memoize context value to prevent unnecessary consumer re-renders
function AppProvider({ children }) {
  const [user, setUser] = useState(null)
  const [theme, setTheme] = useState('light')

  const value = useMemo(
    () => ({ user, setUser, theme, setTheme }),
    [user, theme]
  )

  return (
    <AppContext.Provider value={value}>
      {children}
    </AppContext.Provider>
  )
}
```

```tsx
// ✅ Split contexts by update frequency — state that changes together stays together
const UserContext = createContext<{ user: User | null; setUser: SetState }>()
const ThemeContext = createContext<{ theme: string; setTheme: SetState }>()

// Now changing theme doesn't re-render components that only use user
```

**Quick reference:**

| Pattern | Problem | Fix |
|---------|---------|-----|
| `style={{ ... }}` | New object every render | Const outside component |
| `options={[...]}` | New array every render | Const outside or `useMemo` |
| `onClick={() => fn()}` | New function every render | `useCallback` |
| `context value={{ a, b }}` | All consumers re-render | `useMemo` on value |
| Frequently-changing state in Context | Cascading re-renders | Split contexts |

**Detection hints:**

```bash
# Find inline objects/arrays as JSX props
grep -rn "style={{" src/ --include="*.tsx"
grep -rn "={\\[" src/ --include="*.tsx" | grep -v "import\|const\|let\|var"
# Find context providers with inline value objects
grep -rn "Provider value={{" src/ --include="*.tsx"
```

Reference: [React Docs: Optimizing Re-renders](https://react.dev/reference/react/memo) · [When to useMemo and useCallback](https://kentcdodds.com/blog/usememo-and-usecallback)
