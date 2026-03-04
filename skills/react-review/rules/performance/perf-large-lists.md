---
title: Virtualize Large Lists Instead of Rendering All Items
description: "Rendering thousands of DOM nodes for long lists causes slow initial render, high memory usage, and scroll jank. Use virtualization (react-window, TanStack Virtual)."
impact: HIGH
impact_description: prevents UI freezes and excessive memory consumption from large lists
tags: [performance, react, virtualization, lists, react-window, tanstack-virtual]
detection_grep: ".map("
---

## Virtualize Large Lists Instead of Rendering All Items

**Impact: HIGH (prevents UI freezes and excessive memory consumption from large lists)**

Rendering a `.map()` over thousands of items creates thousands of DOM nodes, all of which the browser must lay out, paint, and keep in memory. This causes multi-second initial render times, high memory usage, and scroll jank as the browser struggles to manage thousands of elements. Virtualization renders only the items currently visible in the viewport (plus a small overscan buffer), typically reducing the DOM node count from thousands to 20-50.

**Incorrect (rendering all items in the DOM):**

```tsx
function TransactionList({ transactions }: { transactions: Transaction[] }) {
  // ❌ If transactions has 10,000 items, this creates 10,000 DOM nodes
  return (
    <div className="transaction-list">
      {transactions.map((tx) => (
        <TransactionRow key={tx.id} transaction={tx} />
      ))}
    </div>
  )
}
```

**Correct (virtualize with react-window or TanStack Virtual):**

```tsx
import { useVirtualizer } from '@tanstack/react-virtual'
import { useRef } from 'react'

function TransactionList({ transactions }: { transactions: Transaction[] }) {
  const parentRef = useRef<HTMLDivElement>(null)

  // ✅ Only renders visible items + small overscan buffer
  const virtualizer = useVirtualizer({
    count: transactions.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 48, // estimated row height in px
    overscan: 10,
  })

  return (
    <div ref={parentRef} style={{ height: 600, overflow: 'auto' }}>
      <div style={{ height: virtualizer.getTotalSize(), position: 'relative' }}>
        {virtualizer.getVirtualItems().map((virtualItem) => {
          const tx = transactions[virtualItem.index]
          return (
            <div
              key={tx.id}
              style={{
                position: 'absolute',
                top: virtualItem.start,
                height: virtualItem.size,
                width: '100%',
              }}
            >
              <TransactionRow transaction={tx} />
            </div>
          )
        })}
      </div>
    </div>
  )
}
```

**With react-window (simpler API):**

```tsx
import { FixedSizeList as List } from 'react-window'

function TransactionList({ transactions }: { transactions: Transaction[] }) {
  // ✅ Only visible rows are rendered
  return (
    <List height={600} itemCount={transactions.length} itemSize={48} width="100%">
      {({ index, style }) => (
        <div style={style}>
          <TransactionRow transaction={transactions[index]} />
        </div>
      )}
    </List>
  )
}
```

**Additional context:**

- As a rule of thumb, virtualize when rendering more than ~100-200 items. Below that threshold, the overhead of virtualization may not be worth it.
- For variable-height rows, use `VariableSizeList` (react-window) or set `estimateSize` dynamically with `measureElement` (TanStack Virtual).
- Virtualization also benefits tables (TanStack Virtual has table examples), grids, and tree views.
- Combine virtualization with `React.memo` on row components for best results.

**Detection hints:**

```bash
# Find .map() calls that might render large lists
grep -rn "\.map(" src/ --include="*.tsx" --include="*.jsx"
# Check if virtualization libraries are installed
grep -rn "react-window\|react-virtualized\|@tanstack/react-virtual" package.json
```

Reference: [TanStack Virtual documentation](https://tanstack.com/virtual/latest)
