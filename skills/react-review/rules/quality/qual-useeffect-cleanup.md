---
title: Always Clean Up useEffect Side Effects
description: "Missing cleanup in useEffect for subscriptions, timers, event listeners, and AbortControllers causes memory leaks, stale callbacks, and state updates on unmounted components."
impact: MEDIUM
impact_description: prevents memory leaks and state-update-on-unmounted-component bugs
tags: [quality, react, useEffect, cleanup, memory-leak]
detection_grep: "useEffect"
---

## Always Clean Up useEffect Side Effects

**Impact: MEDIUM (prevents memory leaks and state-update-on-unmounted-component bugs)**

`useEffect` runs side effects after render. When those side effects create persistent resources — event listeners, `setInterval` timers, WebSocket connections, Intersection/Mutation/Resize observers, or in-flight fetch requests — they must be cleaned up when the component unmounts or the effect re-runs. Without cleanup, listeners accumulate (one per render), timers keep firing after navigation, and state updates target unmounted components.

**Incorrect (no cleanup — leaks on every re-render and unmount):**

```tsx
function LivePrice({ symbol }: { symbol: string }) {
  const [price, setPrice] = useState<number | null>(null)

  useEffect(() => {
    // ❌ WebSocket never closed — new connection on every symbol change
    const ws = new WebSocket(`wss://prices.example.com/${symbol}`)
    ws.onmessage = (event) => setPrice(JSON.parse(event.data).price)
  }, [symbol])

  useEffect(() => {
    // ❌ Listener never removed — accumulates on every render
    const handleResize = () => console.log(window.innerWidth)
    window.addEventListener('resize', handleResize)
  }, [])

  useEffect(() => {
    // ❌ Interval never cleared — keeps running after unmount
    const id = setInterval(() => {
      fetch(`/api/prices/${symbol}`).then(r => r.json()).then(d => setPrice(d.price))
    }, 5000)
  }, [symbol])

  return <div>{price}</div>
}
```

**Correct (cleanup function returned from every effect with resources):**

```tsx
function LivePrice({ symbol }: { symbol: string }) {
  const [price, setPrice] = useState<number | null>(null)

  useEffect(() => {
    const ws = new WebSocket(`wss://prices.example.com/${symbol}`)
    ws.onmessage = (event) => setPrice(JSON.parse(event.data).price)

    // ✅ Close WebSocket when symbol changes or component unmounts
    return () => ws.close()
  }, [symbol])

  useEffect(() => {
    const handleResize = () => console.log(window.innerWidth)
    window.addEventListener('resize', handleResize)

    // ✅ Remove listener on unmount
    return () => window.removeEventListener('resize', handleResize)
  }, [])

  useEffect(() => {
    const controller = new AbortController()
    const id = setInterval(() => {
      fetch(`/api/prices/${symbol}`, { signal: controller.signal })
        .then((r) => r.json())
        .then((d) => setPrice(d.price))
        .catch((err) => {
          if (err.name !== 'AbortError') console.error(err)
        })
    }, 5000)

    // ✅ Clear interval and abort in-flight request
    return () => {
      clearInterval(id)
      controller.abort()
    }
  }, [symbol])

  return <div>{price}</div>
}
```

**Additional context:**

- **Rule of thumb:** If your effect creates something (listener, timer, connection, observer), return a function that destroys it.
- Common cleanup targets: `removeEventListener`, `clearInterval`, `clearTimeout`, `AbortController.abort()`, `observer.disconnect()`, `subscription.unsubscribe()`, `WebSocket.close()`.
- In React Strict Mode (development), effects run twice to help surface missing cleanup. If you see "double subscription" issues in dev, it means cleanup is missing.
- For fetch requests, use `AbortController` to cancel in-flight requests when dependencies change. This prevents race conditions where a slow response from the old request overwrites a fast response from the new one.

**Detection hints:**

```bash
# Find useEffect without return statement (potential missing cleanup)
grep -rn "useEffect" src/ --include="*.tsx" --include="*.ts"
# Find addEventListener without corresponding removeEventListener
grep -rn "addEventListener" src/ --include="*.tsx" --include="*.ts"
# Find setInterval without clearInterval
grep -rn "setInterval" src/ --include="*.tsx" --include="*.ts"
```

Reference: [React docs on synchronizing with effects](https://react.dev/learn/synchronizing-with-effects#how-to-handle-the-effect-firing-twice-in-development)
