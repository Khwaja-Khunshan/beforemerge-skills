---
title: Keep 'use client' on the Smallest Possible Leaf Components
description: "Adding 'use client' to large components or pages ships unnecessary JavaScript to the browser. Push interactivity to the smallest leaf components."
impact: HIGH
impact_description: reduces client-side JavaScript bundle size and improves initial page load
tags: [performance, client-components, server-components, bundle-size, react, nextjs]
detection_grep: "use client"
---

## Keep 'use client' on the Smallest Possible Leaf Components

**Impact: HIGH (reduces client-side JavaScript bundle size and improves initial page load)**

Every component marked with `'use client'` -- and its entire import tree -- ships JavaScript to the browser. Placing `'use client'` on a page component, layout, or large wrapper forces the entire subtree to be client-rendered, eliminating the benefits of Server Components (zero JS, direct data access, streaming). Push `'use client'` down to the smallest interactive leaf component.

The composition pattern lets you keep most of your component tree server-rendered while wrapping small interactive parts in client components.

**Incorrect ('use client' on large components that mostly render static content):**

```tsx
// app/rules/page.tsx
// ❌ Entire page is a client component — ships everything to the browser
'use client'

import { useState, useEffect } from 'react'
import { RulesList } from '@/components/RulesList'
import { RulesFilter } from '@/components/RulesFilter'
import { RulesStats } from '@/components/RulesStats'

export default function RulesPage() {
  const [rules, setRules] = useState([])
  const [filter, setFilter] = useState('all')

  useEffect(() => {
    fetch('/api/rules').then(r => r.json()).then(setRules)
  }, [])

  // ❌ RulesList and RulesStats are pure display but forced client-side
  // because the parent is 'use client'
  return (
    <div>
      <h1>Rules</h1>
      <RulesStats rules={rules} />
      <RulesFilter value={filter} onChange={setFilter} />
      <RulesList rules={rules} filter={filter} />
    </div>
  )
}
```

```tsx
// components/RulesStats.tsx
// ❌ This is pure display — doesn't need 'use client' but is forced into
// the client bundle because it's imported by a client component
'use client'

export function RulesStats({ rules }: { rules: Rule[] }) {
  return (
    <div>
      <span>Total: {rules.length}</span>
      <span>Active: {rules.filter(r => r.active).length}</span>
    </div>
  )
}
```

**Correct (server page with interactive leaves):**

```tsx
// app/rules/page.tsx
// ✅ Server Component — no JS shipped, direct data access
import { Suspense } from 'react'
import { ruleService } from '@/lib/services'
import { RulesStats } from '@/components/RulesStats'
import { RulesListWithFilter } from '@/components/RulesListWithFilter'

export default async function RulesPage() {
  const result = await ruleService.getRulesForCurrentUser()
  const rules = result.success ? result.data : []

  return (
    <div>
      <h1>Rules</h1>
      {/* ✅ Pure display — stays server-rendered, zero JS */}
      <RulesStats rules={rules} />
      {/* ✅ Only the interactive filter is a client component */}
      <RulesListWithFilter initialRules={rules} />
    </div>
  )
}
```

```tsx
// components/RulesStats.tsx
// ✅ No 'use client' — pure Server Component, ships zero JavaScript
export function RulesStats({ rules }: { rules: Rule[] }) {
  return (
    <div>
      <span>Total: {rules.length}</span>
      <span>Active: {rules.filter(r => r.active).length}</span>
    </div>
  )
}
```

```tsx
// components/RulesListWithFilter.tsx
// ✅ 'use client' only on the interactive wrapper — keeps interactivity minimal
'use client'

import { useState } from 'react'

export function RulesListWithFilter({ initialRules }: { initialRules: Rule[] }) {
  const [filter, setFilter] = useState('all')
  const filtered = filter === 'all'
    ? initialRules
    : initialRules.filter(r => r.status === filter)

  return (
    <>
      <select value={filter} onChange={e => setFilter(e.target.value)}>
        <option value="all">All</option>
        <option value="active">Active</option>
        <option value="draft">Draft</option>
      </select>
      <ul>
        {filtered.map(rule => (
          <li key={rule.id}>{rule.name}</li>
        ))}
      </ul>
    </>
  )
}
```

**The composition pattern (server parent passes children to client wrapper):**

```tsx
// components/CollapsibleSection.tsx
// ✅ Client component provides interactivity — children stay server-rendered
'use client'

import { useState, type ReactNode } from 'react'

export function CollapsibleSection({
  title,
  children,
}: {
  title: string
  children: ReactNode
}) {
  const [open, setOpen] = useState(true)
  return (
    <section>
      <button onClick={() => setOpen(!open)}>{title}</button>
      {open && children}
    </section>
  )
}

// app/rules/page.tsx — Server Component uses client wrapper
// ✅ HeavyContent stays server-rendered even though CollapsibleSection is client
export default async function RulesPage() {
  const data = await fetchHeavyData()
  return (
    <CollapsibleSection title="Details">
      <HeavyContent data={data} /> {/* Server Component — zero JS */}
    </CollapsibleSection>
  )
}
```

**Rule of thumb:** If a component does not use `useState`, `useEffect`, `useRef`, event handlers, or browser APIs, it should not have `'use client'`.

**Detection hints:**

```bash
# Find 'use client' in page files (likely too high in the tree)
grep -rn "use client" src/app --include="*.tsx" -l
# Find large client components
grep -rn "use client" src/components --include="*.tsx" -l
```

Reference: [Next.js Server and Client Components](https://nextjs.org/docs/app/building-your-application/rendering/composition-patterns) · [React Server Components](https://react.dev/reference/rsc/server-components)
