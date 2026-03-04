---
title: Avoid Barrel File Imports in Client Components
description: "Barrel file imports in Client Components force bundlers to load entire libraries. Use direct imports or Next.js optimizePackageImports."
impact: HIGH
impact_description: 200-800ms import cost reduction, significantly faster builds and cold starts
tags: [performance, bundle-size, imports, tree-shaking, nextjs]
detection_grep: "from 'lucide-react'|from '@mui/material'|from 'lodash'|from 'react-icons'"
---

## Avoid Barrel File Imports in Client Components

**Impact: HIGH (200-800ms import cost reduction, faster builds and cold starts)**

Barrel files (`index.ts` that re-exports everything) force bundlers to load entire libraries even when you only use one export. Icon and component libraries can have thousands of re-exports, adding megabytes to your client bundle. This is especially costly in Client Components where every byte ships to the browser.

**Incorrect (imports entire library via barrel file):**

```tsx
'use client'

// ❌ Loads all 1,500+ icons even though you use 3
import { Check, X, Menu } from 'lucide-react'

// ❌ Loads entire MUI library
import { Button, TextField } from '@mui/material'

// ❌ Loads all of lodash
import { debounce, throttle } from 'lodash'
```

**Correct (direct deep imports):**

```tsx
'use client'

// ✅ Loads only the 3 icons you need
import Check from 'lucide-react/dist/esm/icons/check'
import X from 'lucide-react/dist/esm/icons/x'
import Menu from 'lucide-react/dist/esm/icons/menu'

// ✅ Direct component imports
import Button from '@mui/material/Button'
import TextField from '@mui/material/TextField'

// ✅ Individual lodash function imports
import debounce from 'lodash/debounce'
import throttle from 'lodash/throttle'
```

**Best (Next.js optimizePackageImports):**

```javascript
// next.config.js — let Next.js handle it automatically
module.exports = {
  experimental: {
    optimizePackageImports: [
      'lucide-react',
      '@mui/material',
      '@mui/icons-material',
      'lodash',
      'date-fns',
      'react-icons',
      '@radix-ui/react-icons',
    ],
  },
}

// Now barrel imports are automatically tree-shaken at build time:
import { Check, X, Menu } from 'lucide-react' // ✅ Only loads 3 icons
```

**Commonly affected libraries:** `lucide-react`, `@mui/material`, `@mui/icons-material`, `@tabler/icons-react`, `react-icons`, `@headlessui/react`, `@radix-ui/*`, `lodash`, `ramda`, `date-fns`, `rxjs`.

**Detection hints:**

```bash
# Find barrel imports of known heavy libraries in client components
grep -rn "'use client'" src/ --include="*.tsx" -l | \
  xargs grep -l "from 'lucide-react'\|from '@mui/material'\|from 'lodash'\|from 'react-icons'"
```

Reference: [How we optimized package imports in Next.js](https://vercel.com/blog/how-we-optimized-package-imports-in-next-js)
