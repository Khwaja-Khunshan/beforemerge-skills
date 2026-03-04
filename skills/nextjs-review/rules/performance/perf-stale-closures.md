---
title: Avoid Stale Closure Bugs in Hooks and Callbacks
description: "Event handlers and effects that capture state in closures can reference outdated values, causing silent data corruption and missed updates."
impact: MEDIUM
impact_description: prevents silent data corruption from outdated state references in async operations
tags: [performance, react, closures, hooks, state, useeffect, nextjs]
detection_grep: "setInterval.*useState|setTimeout.*useState|addEventListener.*useState"
---

## Avoid Stale Closure Bugs in Hooks and Callbacks

**Impact: MEDIUM (prevents silent data corruption from outdated state references in async operations)**

JavaScript closures capture variables at creation time. When a callback inside `useEffect`, `setInterval`, `setTimeout`, or `addEventListener` references a state variable, it captures the value from that specific render — not the current value. This causes the callback to silently use outdated data.

Stale closures are the most frequently misdiagnosed React bug. They manifest as "my state isn't updating" or "my handler uses the old value."

**Incorrect (stale closure captures initial state):**

```tsx
'use client'

// ❌ count is always 0 inside the interval — captured from the first render
function Counter() {
  const [count, setCount] = useState(0)

  useEffect(() => {
    const id = setInterval(() => {
      console.log(count) // Always logs 0!
      setCount(count + 1) // Always sets to 1!
    }, 1000)
    return () => clearInterval(id)
  }, []) // Empty deps = closure captures initial count forever

  return <span>{count}</span>
}
```

```tsx
// ❌ Debounced handler uses stale search term
function SearchBar() {
  const [query, setQuery] = useState('')
  const [results, setResults] = useState([])

  const debouncedSearch = useMemo(
    () => debounce(async () => {
      const data = await fetch(`/api/search?q=${query}`) // query is stale!
      setResults(await data.json())
    }, 300),
    [] // query not in deps = always uses initial empty string
  )

  return <input onChange={e => { setQuery(e.target.value); debouncedSearch() }} />
}
```

```tsx
// ❌ Event listener references stale state
function ChatRoom({ roomId }) {
  const [messages, setMessages] = useState([])

  useEffect(() => {
    const ws = new WebSocket(`/ws/${roomId}`)
    ws.onmessage = (event) => {
      // messages is always [] here — captured from this render
      setMessages([...messages, JSON.parse(event.data)]) // Overwrites all messages!
    }
    return () => ws.close()
  }, [roomId])
}
```

**Correct (avoid stale closures):**

```tsx
'use client'

// ✅ Use functional updater — always gets the current state
function Counter() {
  const [count, setCount] = useState(0)

  useEffect(() => {
    const id = setInterval(() => {
      setCount(prev => prev + 1) // prev is always current
    }, 1000)
    return () => clearInterval(id)
  }, [])

  return <span>{count}</span>
}
```

```tsx
// ✅ Use a ref for values needed in long-lived callbacks
function SearchBar() {
  const [query, setQuery] = useState('')
  const queryRef = useRef(query)
  queryRef.current = query // Always up to date

  const debouncedSearch = useMemo(
    () => debounce(async () => {
      const data = await fetch(`/api/search?q=${queryRef.current}`) // Always fresh
      setResults(await data.json())
    }, 300),
    []
  )

  return <input onChange={e => { setQuery(e.target.value); debouncedSearch() }} />
}
```

```tsx
// ✅ Functional updater for arrays/objects in subscriptions
function ChatRoom({ roomId }) {
  const [messages, setMessages] = useState([])

  useEffect(() => {
    const ws = new WebSocket(`/ws/${roomId}`)
    ws.onmessage = (event) => {
      setMessages(prev => [...prev, JSON.parse(event.data)]) // prev is current
    }
    return () => ws.close()
  }, [roomId])
}
```

**Patterns and fixes:**

| Pattern | Fix |
|---------|-----|
| `setCount(count + 1)` in interval/timeout | `setCount(prev => prev + 1)` |
| `[...array, item]` in subscription | `setArray(prev => [...prev, item])` |
| Reading state in debounce/throttle | Use `useRef` to mirror the value |
| Comparing state in event listener | Pass value as dependency, or use ref |

**Detection hints:**

```bash
# Find setInterval/setTimeout using state variables directly
grep -rn "setInterval\|setTimeout" src/ --include="*.tsx" --include="*.ts" -A 3 | grep -v "prev =>\|prev)"
```

Reference: [React Docs: Removing Effect Dependencies](https://react.dev/learn/removing-effect-dependencies) · [A Complete Guide to useEffect](https://overreacted.io/a-complete-guide-to-useeffect/)
