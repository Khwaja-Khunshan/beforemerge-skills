---
title: Avoid Inline Object/Array/Function Creation in JSX Props
description: "Creating new objects, arrays, or functions inline in JSX causes child components to re-render on every parent render due to referential inequality."
impact: HIGH
impact_description: prevents unnecessary re-renders that degrade UI responsiveness
tags: [performance, react, rerenders, memoization, useMemo, useCallback]
detection_grep: "style={{"
---

## Avoid Inline Object/Array/Function Creation in JSX Props

**Impact: HIGH (prevents unnecessary re-renders that degrade UI responsiveness)**

Every time a parent component renders, inline expressions like `style={{ margin: 8 }}`, `options={[1, 2, 3]}`, or `onClick={() => doThing(id)}` create brand-new object/array/function references. When these are passed as props to child components, React's shallow comparison sees them as changed — even when the values are identical — causing the child to re-render. This is especially costly when the child is a complex component, a memoized component (defeating `React.memo`), or appears in a list.

**Incorrect (inline creation forces re-renders on every parent render):**

```tsx
function UserList({ users }: { users: User[] }) {
  return (
    <div>
      {users.map((user) => (
        <UserCard
          key={user.id}
          user={user}
          // ❌ New object every render — defeats React.memo on UserCard
          style={{ padding: 16, borderRadius: 8 }}
          // ❌ New array every render
          roles={['viewer']}
          // ❌ New function every render
          onSelect={() => selectUser(user.id)}
        />
      ))}
    </div>
  )
}
```

**Correct (stable references via constants, useMemo, and useCallback):**

```tsx
// ✅ Extract static values outside the component
const cardStyle = { padding: 16, borderRadius: 8 }
const defaultRoles = ['viewer']

function UserList({ users }: { users: User[] }) {
  // ✅ useCallback for stable function reference
  const handleSelect = useCallback((userId: string) => {
    selectUser(userId)
  }, [])

  return (
    <div>
      {users.map((user) => (
        <UserCard
          key={user.id}
          user={user}
          style={cardStyle}
          roles={defaultRoles}
          onSelect={handleSelect}
        />
      ))}
    </div>
  )
}

// If the child component is expensive, wrap it with React.memo
const UserCard = React.memo(function UserCard({
  user,
  style,
  roles,
  onSelect,
}: UserCardProps) {
  return (
    <div style={style} onClick={() => onSelect(user.id)}>
      {user.name}
    </div>
  )
})
```

**Additional context:**

- This optimization matters most when: (1) the child component is wrapped in `React.memo`, (2) the list is large, or (3) the parent re-renders frequently (e.g., on every keystroke).
- For components that are not memoized and have trivial render logic, the overhead of inline creation is negligible. Do not prematurely optimize every prop.
- React Compiler (React 19+) can auto-memoize these patterns, but explicit stable references remain best practice until Compiler adoption is widespread.
- Use the React DevTools Profiler's "Why did this render?" feature to identify unnecessary re-renders caused by referential inequality.

**Detection hints:**

```bash
# Find inline style objects in JSX
grep -rn "style={{" src/ --include="*.tsx" --include="*.jsx"
# Find inline arrow functions in JSX props (common pattern)
grep -rn "={().*=>.*}" src/ --include="*.tsx" --include="*.jsx"
```

Reference: [React docs on useMemo](https://react.dev/reference/react/useMemo)
