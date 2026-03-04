---
title: Use Dynamic Imports for Heavy Client Components
description: "Large client libraries loaded synchronously block the initial page load. Use next/dynamic or React.lazy to code-split and load them on demand."
impact: HIGH
impact_description: reduces initial JavaScript bundle by deferring heavy libraries until needed
tags: [performance, code-splitting, dynamic-imports, bundle-size, lazy-loading, nextjs]
detection_grep: "import.*chart|import.*editor|import.*map|import.*pdf|import.*markdown"
---

## Use Dynamic Imports for Heavy Client Components

**Impact: HIGH (reduces initial JavaScript bundle by deferring heavy libraries until needed)**

Importing heavy client-side libraries at the top of a file forces the entire library into the initial bundle — even if the component is below the fold, behind a tab, or conditionally rendered. `next/dynamic` (Next.js's wrapper around `React.lazy`) code-splits these imports so they load only when needed.

Common offenders: chart libraries (Chart.js, Recharts), rich text editors (TipTap, Slate), map libraries (Leaflet, Mapbox), PDF viewers, syntax highlighters, and markdown renderers.

**Incorrect (everything in the initial bundle):**

```tsx
'use client'

// ❌ 200KB+ loaded immediately even if chart is below the fold
import { Chart } from 'chart.js/auto'
import { Bar } from 'react-chartjs-2'

// ❌ 500KB+ rich text editor loaded on a page where most users just read
import { Editor } from '@tiptap/react'
import StarterKit from '@tiptap/starter-kit'

// ❌ Heavy map library loaded on every page load
import { MapContainer, TileLayer, Marker } from 'react-leaflet'

export default function AnalyticsPage() {
  return (
    <div>
      <h1>Dashboard</h1>
      <Bar data={chartData} />
      <Editor extensions={[StarterKit]} />
      <MapContainer center={[51.505, -0.09]} zoom={13}>
        <TileLayer url="..." />
      </MapContainer>
    </div>
  )
}
```

**Correct (dynamic imports with loading states):**

```tsx
'use client'

import dynamic from 'next/dynamic'

// ✅ Code-split heavy components — loaded only when rendered
const BarChart = dynamic(
  () => import('react-chartjs-2').then(mod => ({ default: mod.Bar })),
  {
    loading: () => <div className="h-64 animate-pulse bg-gray-100 rounded" />,
    ssr: false, // Chart.js requires browser APIs
  }
)

const RichEditor = dynamic(
  () => import('@/components/RichEditor'),
  {
    loading: () => <div className="h-48 animate-pulse bg-gray-100 rounded" />,
    ssr: false, // Editor requires DOM APIs
  }
)

const Map = dynamic(
  () => import('@/components/LeafletMap'),
  {
    loading: () => <div className="h-96 animate-pulse bg-gray-100 rounded" />,
    ssr: false, // Leaflet requires window
  }
)

export default function AnalyticsPage() {
  return (
    <div>
      <h1>Dashboard</h1>
      <BarChart data={chartData} />
      <RichEditor />
      <Map center={[51.505, -0.09]} zoom={13} />
    </div>
  )
}
```

```tsx
// ✅ Conditionally load heavy components
'use client'

import dynamic from 'next/dynamic'
import { useState } from 'react'

const PdfViewer = dynamic(() => import('@/components/PdfViewer'), {
  ssr: false,
})

export default function DocumentPage({ document }) {
  const [showPdf, setShowPdf] = useState(false)

  return (
    <div>
      <h1>{document.title}</h1>
      <p>{document.summary}</p>

      {/* PDF viewer only loads when user clicks the button */}
      <button onClick={() => setShowPdf(true)}>View PDF</button>
      {showPdf && <PdfViewer url={document.pdfUrl} />}
    </div>
  )
}
```

**When to use `ssr: false`:**

- Libraries that access `window`, `document`, or browser-only APIs
- Canvas-based libraries (charts, maps, drawing)
- Libraries with large WASM modules
- Components that are purely interactive (no SEO value from SSR)

**When NOT to dynamically import:**

- Small components (< 5KB) — the overhead of a separate chunk isn't worth it
- Above-the-fold content critical for LCP
- Components rendered on every page load

**Detection hints:**

```bash
# Find heavy library imports in client components
grep -rn "'use client'" src/ --include="*.tsx" -l | \
  xargs grep -l "chart\|editor\|leaflet\|mapbox\|pdf\|monaco\|codemirror\|markdown"
```

Reference: [Next.js Lazy Loading](https://nextjs.org/docs/app/building-your-application/optimizing/lazy-loading) · [React.lazy](https://react.dev/reference/react/lazy)
