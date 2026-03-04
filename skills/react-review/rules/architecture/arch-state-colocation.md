---
title: Colocate State with the Components That Use It
description: "Lifting state higher than necessary causes unnecessary re-renders in the parent and all siblings. Keep state as close as possible to where it is consumed."
impact: MEDIUM
impact_description: reduces unnecessary re-renders and simplifies component responsibilities
tags: [architecture, react, state-management, colocation, performance]
detection_grep: "useState"
---

## Colocate State with the Components That Use It

**Impact: MEDIUM (reduces unnecessary re-renders and simplifies component responsibilities)**

A common anti-pattern is lifting all state to the nearest common ancestor "just in case" or out of habit. When state lives higher in the tree than it needs to, every update to that state re-renders the parent and all of its children — even siblings that have nothing to do with that state. This also clutters the parent component with state management logic it shouldn't own. State should be colocated with the component (or subtree) that actually reads and writes it.

**Incorrect (state lifted too high — search input state in a page-level component):**

```tsx
// ❌ SearchPage owns the search query state, causing the entire page
// (header, sidebar, footer) to re-render on every keystroke
function SearchPage() {
  const [query, setQuery] = useState('')
  const [selectedCategory, setSelectedCategory] = useState('all')
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc')
  const results = useSearchResults(query, selectedCategory, sortOrder)

  return (
    <div>
      <Header />  {/* ❌ Re-renders on every keystroke */}
      <Sidebar />  {/* ❌ Re-renders on every keystroke */}
      <SearchBar value={query} onChange={setQuery} />
      <FilterBar
        category={selectedCategory}
        onCategoryChange={setSelectedCategory}
        sortOrder={sortOrder}
        onSortChange={setSortOrder}
      />
      <ResultsList results={results} />
      <Footer />  {/* ❌ Re-renders on every keystroke */}
    </div>
  )
}
```

**Correct (colocate state with the subtree that uses it):**

```tsx
// ✅ SearchPage is a thin layout shell — no unnecessary state
function SearchPage() {
  return (
    <div>
      <Header />
      <Sidebar />
      <SearchSection />  {/* All search state lives here */}
      <Footer />
    </div>
  )
}

// ✅ State is colocated — only this subtree re-renders on changes
function SearchSection() {
  const [query, setQuery] = useState('')
  const [selectedCategory, setSelectedCategory] = useState('all')
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc')
  const results = useSearchResults(query, selectedCategory, sortOrder)

  return (
    <section>
      <SearchBar value={query} onChange={setQuery} />
      <FilterBar
        category={selectedCategory}
        onCategoryChange={setSelectedCategory}
        sortOrder={sortOrder}
        onSortChange={setSortOrder}
      />
      <ResultsList results={results} />
    </section>
  )
}
```

**Additional context:**

- The principle: "push state down" as far as possible. Only lift state when two sibling components genuinely need to share it.
- This is the inverse of prop drilling. Prop drilling means state is too high; state colocation is the fix.
- Form input state (search bars, individual form fields) is the most common offender. Each input's state should live in or near that input component, not at the page level.
- If a parent truly needs to react to a child's state (e.g., to show a count of results in the header), consider lifting only that derived value or using a callback rather than the full state.
- React DevTools Profiler can highlight which components re-render. If siblings re-render on unrelated state changes, state is likely too high.

**Detection hints:**

```bash
# Find components with many useState calls — potential over-lifting
grep -rn "useState" src/ --include="*.tsx" --include="*.ts"
```

Reference: [React docs on choosing the state structure](https://react.dev/learn/choosing-the-state-structure)
