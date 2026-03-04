---
title: Always Return Cleanup Functions from useEffect
description: "useEffect hooks that set up subscriptions, timers, or event listeners without cleanup cause memory leaks, stale state updates, and race conditions."
impact: HIGH
impact_description: prevents memory leaks, stale state updates on unmounted components, and race conditions
tags: [performance, react, useeffect, memory-leak, cleanup, nextjs]
detection_grep: "useEffect|addEventListener|setInterval|setTimeout|subscribe"
---

## Always Return Cleanup Functions from useEffect

**Impact: HIGH (prevents memory leaks, stale state updates on unmounted components, and race conditions)**

Every `useEffect` that creates a subscription, timer, event listener, or starts an async operation needs a cleanup function. Without cleanup:

- **Event listeners accumulate** — each re-render adds another listener
- **Timers keep firing** after the component unmounts, updating stale state
- **Fetch requests complete** after navigation, causing "state update on unmounted component" errors
- **WebSocket connections stay open**, leaking memory and server resources

This is the single most common React bug found in code reviews.

**Incorrect (missing cleanup):**

```tsx
'use client'

// ❌ Event listener added on every render, never removed
useEffect(() => {
  window.addEventListener('resize', handleResize)
}, [])

// ❌ Interval runs forever, even after unmount
useEffect(() => {
  setInterval(() => {
    setCount(c => c + 1)
  }, 1000)
}, [])

// ❌ Fetch race condition — if component re-renders, both requests resolve
useEffect(() => {
  fetch(`/api/user/${userId}`)
    .then(res => res.json())
    .then(data => setUser(data)) // May set state on unmounted component
}, [userId])

// ❌ WebSocket never closed
useEffect(() => {
  const ws = new WebSocket('wss://api.example.com/feed')
  ws.onmessage = (event) => setMessages(prev => [...prev, event.data])
}, [])
```

**Correct (cleanup functions that prevent leaks):**

```tsx
'use client'

// ✅ Event listener: add and remove
useEffect(() => {
  window.addEventListener('resize', handleResize)
  return () => window.removeEventListener('resize', handleResize)
}, [])

// ✅ Interval: clear on unmount
useEffect(() => {
  const id = setInterval(() => {
    setCount(c => c + 1)
  }, 1000)
  return () => clearInterval(id)
}, [])

// ✅ Fetch: abort on cleanup to prevent race conditions
useEffect(() => {
  const controller = new AbortController()

  fetch(`/api/user/${userId}`, { signal: controller.signal })
    .then(res => res.json())
    .then(data => setUser(data))
    .catch(err => {
      if (err.name !== 'AbortError') throw err // Ignore abort errors
    })

  return () => controller.abort()
}, [userId])

// ✅ WebSocket: close on unmount
useEffect(() => {
  const ws = new WebSocket('wss://api.example.com/feed')
  ws.onmessage = (event) => setMessages(prev => [...prev, event.data])

  return () => ws.close()
}, [])

// ✅ Third-party subscription: unsubscribe
useEffect(() => {
  const unsubscribe = store.subscribe((state) => {
    setLocalState(state)
  })
  return unsubscribe
}, [])
```

**Rule of thumb:** if you see `addEventListener`, `setInterval`, `setTimeout`, `subscribe`, `new WebSocket`, `new EventSource`, or `fetch` inside a `useEffect`, there must be a corresponding cleanup in the return function.

**Detection hints:**

```bash
# Find useEffects with subscriptions but no cleanup return
grep -rn "useEffect" src/ --include="*.tsx" --include="*.ts" -A 5 | grep -B 2 "addEventListener\|setInterval\|subscribe\|WebSocket"
```

Reference: [React useEffect Cleanup](https://react.dev/learn/synchronizing-with-effects#how-to-handle-the-effect-firing-twice-in-development) · [React Docs: You Might Not Need an Effect](https://react.dev/learn/you-might-not-need-an-effect)
