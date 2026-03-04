---
title: Prefer Server Components — Only Add 'use client' When Necessary
description: "Adding 'use client' unnecessarily ships component JS to the browser. Only use it when you need hooks, event handlers, or browser APIs."
impact: HIGH
impact_description: reduces JavaScript bundle sent to browser, improves load times
tags: [performance, server-components, client-components, bundle-size, nextjs]
detection_grep: "'use client'"
---

## Prefer Server Components — Only Add 'use client' When Necessary

**Impact: HIGH (reduces JavaScript bundle sent to browser, improves load times)**

In the Next.js App Router, components are Server Components by default. Adding `'use client'` sends the component's JavaScript to the browser, increasing bundle size and Time to Interactive. Only add the client directive when you actually need browser APIs, event handlers, or React hooks that require client-side execution.

**Incorrect (unnecessary 'use client'):**

```tsx
// ❌ This component has no interactivity — why is it a client component?
'use client'

export function UserProfile({ user }: { user: User }) {
  return (
    <div>
      <h1>{user.name}</h1>
      <p>{user.bio}</p>
      <img src={user.avatarUrl} alt={user.name} />
    </div>
  )
}
```

```tsx
// ❌ Marking the entire page as client just because one small part needs interactivity
'use client'

import { useState } from 'react'

export default function ProductPage({ product }: { product: Product }) {
  const [showDetails, setShowDetails] = useState(false)

  return (
    <div>
      <h1>{product.name}</h1>
      <p>{product.description}</p>           {/* Static */}
      <ProductSpecs specs={product.specs} />  {/* Static */}
      <ReviewsList reviews={product.reviews} /> {/* Static */}
      <button onClick={() => setShowDetails(!showDetails)}>
        {showDetails ? 'Hide' : 'Show'} Details
      </button>
      {showDetails && <Details product={product} />}
    </div>
  )
}
```

**Correct (push 'use client' to the leaf):**

```tsx
// ✅ Page stays as Server Component — zero JS sent for static content
export default async function ProductPage({ params }: { params: { id: string } }) {
  const product = await fetchProduct(params.id)

  return (
    <div>
      <h1>{product.name}</h1>
      <p>{product.description}</p>
      <ProductSpecs specs={product.specs} />
      <ReviewsList reviews={product.reviews} />
      {/* Only this small piece is a Client Component */}
      <DetailsToggle product={product} />
    </div>
  )
}

// components/DetailsToggle.tsx
'use client'
import { useState } from 'react'

export function DetailsToggle({ product }: { product: Product }) {
  const [showDetails, setShowDetails] = useState(false)

  return (
    <>
      <button onClick={() => setShowDetails(!showDetails)}>
        {showDetails ? 'Hide' : 'Show'} Details
      </button>
      {showDetails && <Details product={product} />}
    </>
  )
}
```

**When you DO need 'use client':**

- `useState`, `useReducer`, `useEffect`, `useRef` and other React hooks
- Event handlers (`onClick`, `onChange`, `onSubmit`)
- Browser APIs (`window`, `document`, `localStorage`, `navigator`)
- Third-party libraries that use hooks or browser APIs

**Detection hints:**

```bash
# Find client components that might not need to be
grep -rn "'use client'" src/ --include="*.tsx" -l | while read f; do
  if ! grep -qE "useState|useEffect|useReducer|useRef|useCallback|useMemo|onClick|onChange|onSubmit|addEventListener" "$f"; then
    echo "Possibly unnecessary 'use client': $f"
  fi
done
```

Reference: [Next.js Server and Client Components](https://nextjs.org/docs/app/building-your-application/rendering/composition-patterns)
