---
title: Prefer Composition Over Monolithic Conditional Rendering
description: "Monolithic components with deeply nested ternaries and conditionals are hard to read, test, and extend. Use composition patterns (children, render props, compound components)."
impact: MEDIUM
impact_description: improves readability, testability, and extensibility of component APIs
tags: [architecture, react, composition, compound-components, render-props]
detection_grep: "? <"
---

## Prefer Composition Over Monolithic Conditional Rendering

**Impact: MEDIUM (improves readability, testability, and extensibility of component APIs)**

When a single component handles many variants through deeply nested ternaries, long chains of `if/else`, or numerous boolean props (`isLoading`, `isEmpty`, `isError`, `isCompact`, `isAdmin`), it becomes a "god component" that is difficult to understand, test, and extend. Each new variant adds more branching, increasing cyclomatic complexity. Composition patterns — `children`, render props, compound components — distribute responsibility across focused, testable units.

**Incorrect (monolithic conditional rendering):**

```tsx
// ❌ One component handling every state, variant, and layout
function DataDisplay({
  data,
  isLoading,
  error,
  isEmpty,
  isCompact,
  isAdmin,
  onRetry,
}: DataDisplayProps) {
  if (isLoading) {
    return isCompact ? <SmallSpinner /> : <FullPageLoader />
  }
  if (error) {
    return (
      <div>
        <p>{error.message}</p>
        {isAdmin ? <pre>{error.stack}</pre> : null}
        <button onClick={onRetry}>Retry</button>
      </div>
    )
  }
  if (isEmpty) {
    return isCompact ? <span>No data</span> : <EmptyState />
  }
  return isCompact ? (
    <CompactTable data={data} showAdminCols={isAdmin} />
  ) : (
    <FullTable data={data} showAdminCols={isAdmin} />
  )
}
```

**Correct (composition with focused components):**

```tsx
// ✅ Compound component pattern — each state is a focused component
function DataView({ children }: { children: ReactNode }) {
  return <div className="data-view">{children}</div>
}

DataView.Loading = function Loading({ children }: { children?: ReactNode }) {
  return children ?? <FullPageLoader />
}

DataView.Error = function Error({
  error,
  onRetry,
  children,
}: {
  error: Error
  onRetry: () => void
  children?: ReactNode
}) {
  return (
    <div role="alert">
      <p>{error.message}</p>
      {children}
      <button onClick={onRetry}>Retry</button>
    </div>
  )
}

DataView.Empty = function Empty({ children }: { children?: ReactNode }) {
  return children ?? <EmptyState />
}

// ✅ Usage — clear, flat, easy to follow
function UserDashboard() {
  const { data, isLoading, error, refetch } = useUsers()

  if (isLoading) return <DataView.Loading />
  if (error) return <DataView.Error error={error} onRetry={refetch} />
  if (!data?.length) return <DataView.Empty />

  return (
    <DataView>
      <UserTable data={data} />
    </DataView>
  )
}
```

**With render props for flexible injection:**

```tsx
// ✅ Render prop pattern for customizable list items
function List<T>({
  items,
  renderItem,
  keyExtractor,
}: {
  items: T[]
  renderItem: (item: T, index: number) => ReactNode
  keyExtractor: (item: T) => string
}) {
  return (
    <ul>
      {items.map((item, i) => (
        <li key={keyExtractor(item)}>{renderItem(item, i)}</li>
      ))}
    </ul>
  )
}
```

**Additional context:**

- Compound components (like `<Tabs>`, `<Tabs.Panel>`, `<Tabs.List>`) are the gold standard for complex UI components. They share state implicitly via context while exposing a flexible, composable API.
- The `children` prop is the simplest form of composition and should be the first approach considered.
- When a component has more than 3 boolean variant props, it is a strong signal to refactor into composed sub-components.

**Detection hints:**

```bash
# Find deeply nested ternaries in JSX
grep -rn "? <" src/ --include="*.tsx" --include="*.jsx"
# Find components with many boolean props
grep -rn "isLoading\|isEmpty\|isError\|isCompact\|isDisabled" src/ --include="*.tsx"
```

Reference: [React docs on composition vs inheritance](https://react.dev/learn/passing-props-to-a-component)
