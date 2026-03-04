---
title: Eliminate Prop Drilling Through 3+ Component Levels
description: "Passing props through 3+ levels of intermediate components that don't use them creates tight coupling and maintenance burden. Use context, composition, or state management."
impact: MEDIUM
impact_description: reduces coupling and maintenance burden from deeply threaded props
tags: [architecture, react, prop-drilling, context, composition]
detection_grep: "props."
---

## Eliminate Prop Drilling Through 3+ Component Levels

**Impact: MEDIUM (reduces coupling and maintenance burden from deeply threaded props)**

Prop drilling occurs when a prop is passed through multiple intermediate components that don't use it, only to reach a deeply nested component that does. This creates tight coupling between layers, makes refactoring painful (renaming or removing a prop requires touching every intermediate component), and obscures the actual data flow. When props pass through 3+ levels, it is a strong signal to restructure.

**Incorrect (prop drilled through 3 intermediate components):**

```tsx
// ❌ App > Layout > Sidebar > NavMenu > UserAvatar — user prop threaded through all layers
function App() {
  const user = useUser()
  return <Layout user={user} />
}

function Layout({ user }: { user: User }) {
  // Layout doesn't use `user` — just passes it down
  return (
    <div>
      <Sidebar user={user} />
      <MainContent />
    </div>
  )
}

function Sidebar({ user }: { user: User }) {
  // Sidebar doesn't use `user` either — just passes it down
  return (
    <nav>
      <NavMenu user={user} />
    </nav>
  )
}

function NavMenu({ user }: { user: User }) {
  return <UserAvatar name={user.name} avatarUrl={user.avatarUrl} />
}
```

**Correct (use composition or context to eliminate intermediaries):**

```tsx
// ✅ Option 1: Component composition — pass the rendered element, not the data
function App() {
  const user = useUser()
  return (
    <Layout
      sidebar={
        <Sidebar>
          <NavMenu>
            <UserAvatar name={user.name} avatarUrl={user.avatarUrl} />
          </NavMenu>
        </Sidebar>
      }
    />
  )
}

function Layout({ sidebar }: { sidebar: ReactNode }) {
  return (
    <div>
      {sidebar}
      <MainContent />
    </div>
  )
}

// ✅ Option 2: Context for widely-used data
const UserContext = createContext<User | null>(null)

function useCurrentUser() {
  const user = useContext(UserContext)
  if (!user) throw new Error('useCurrentUser must be inside UserProvider')
  return user
}

function App() {
  const user = useUser()
  return (
    <UserContext.Provider value={user}>
      <Layout />
    </UserContext.Provider>
  )
}

// NavMenu reads directly from context — no drilling
function NavMenu() {
  const user = useCurrentUser()
  return <UserAvatar name={user.name} avatarUrl={user.avatarUrl} />
}
```

**Additional context:**

- Composition (passing `children` or render slots) is often the simplest fix and avoids the indirection of context. Prefer it when the data consumer is a direct descendant in the JSX tree.
- Context is appropriate when many components at different depths need the same data (theme, auth, locale).
- For complex or frequently-changing shared state, a state management library (Zustand, Jotai, Redux Toolkit) provides selectors and avoids the re-render issues of context.
- One level of prop passing is normal and expected. The threshold for concern is typically 3+ levels of pure pass-through.

**Detection hints:**

```bash
# Look for props being destructured but only passed down to children
grep -rn "props\.\|{ .* }" src/ --include="*.tsx" --include="*.jsx"
```

Reference: [React docs on passing data deeply with context](https://react.dev/learn/passing-data-deeply-with-context)
