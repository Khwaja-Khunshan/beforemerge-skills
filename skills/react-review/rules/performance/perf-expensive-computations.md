---
title: Memoize Expensive Computations with useMemo
description: "Running expensive calculations (sorting, filtering, transforming large datasets) on every render wastes CPU cycles. Use useMemo to cache results."
impact: HIGH
impact_description: prevents jank and slow interactions caused by redundant heavy computation
tags: [performance, react, useMemo, computation, memoization]
detection_grep: "useMemo"
---

## Memoize Expensive Computations with useMemo

**Impact: HIGH (prevents jank and slow interactions caused by redundant heavy computation)**

React components re-render frequently — on state changes, context updates, and parent re-renders. If a component performs expensive work on every render (sorting thousands of items, parsing data, computing aggregates, building complex data structures), this blocks the main thread and makes the UI feel sluggish. `useMemo` caches the result and only recomputes when its dependencies change.

**Incorrect (expensive computation runs on every render):**

```tsx
function AnalyticsDashboard({ transactions }: { transactions: Transaction[] }) {
  // ❌ Sorts and aggregates 10,000+ transactions on every render
  // Even a keystroke in an unrelated input triggers this
  const sorted = [...transactions].sort((a, b) => b.amount - a.amount)
  const topMerchants = computeTopMerchants(transactions)
  const monthlyTotals = transactions.reduce((acc, t) => {
    const month = t.date.slice(0, 7)
    acc[month] = (acc[month] ?? 0) + t.amount
    return acc
  }, {} as Record<string, number>)

  return (
    <div>
      <MerchantChart data={topMerchants} />
      <MonthlyChart data={monthlyTotals} />
      <TransactionTable data={sorted} />
    </div>
  )
}
```

**Correct (memoize expensive work so it only recomputes when dependencies change):**

```tsx
function AnalyticsDashboard({ transactions }: { transactions: Transaction[] }) {
  // ✅ Only recomputes when `transactions` reference changes
  const sorted = useMemo(
    () => [...transactions].sort((a, b) => b.amount - a.amount),
    [transactions]
  )

  const topMerchants = useMemo(
    () => computeTopMerchants(transactions),
    [transactions]
  )

  const monthlyTotals = useMemo(
    () =>
      transactions.reduce((acc, t) => {
        const month = t.date.slice(0, 7)
        acc[month] = (acc[month] ?? 0) + t.amount
        return acc
      }, {} as Record<string, number>),
    [transactions]
  )

  return (
    <div>
      <MerchantChart data={topMerchants} />
      <MonthlyChart data={monthlyTotals} />
      <TransactionTable data={sorted} />
    </div>
  )
}
```

**Additional context:**

- `useMemo` is not free — it has a small overhead for tracking dependencies. Only use it when the computation is measurably expensive (typically > 1ms or involving 1,000+ items).
- For filtering and sorting based on user input (search, sort column), `useMemo` ensures the work only happens when the input or data changes, not on every keystroke of unrelated state.
- If the expensive computation is in a synchronous event handler (not during render), you do not need `useMemo`. Only render-path computations benefit from memoization.
- Profile first with React DevTools Profiler or `console.time()` before adding `useMemo`.

**Detection hints:**

```bash
# Find .sort(), .filter(), .reduce() on large datasets during render (without useMemo wrapping)
grep -rn "\.sort(\|\.filter(\|\.reduce(" src/ --include="*.tsx" --include="*.jsx"
```

Reference: [React docs on useMemo](https://react.dev/reference/react/useMemo)
