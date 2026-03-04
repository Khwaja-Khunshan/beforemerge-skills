---
title: Use next/font Instead of External Font Loading
description: "External font loading from Google Fonts or CDNs causes layout shift and render-blocking requests. next/font self-hosts fonts with zero layout shift."
impact: MEDIUM
impact_description: eliminates font-related layout shift (CLS) and removes external network dependency
tags: [performance, fonts, core-web-vitals, cls, nextjs]
detection_grep: "fonts.googleapis.com|fonts.google.com|@import.*font|link.*font"
---

## Use next/font Instead of External Font Loading

**Impact: MEDIUM (eliminates font-related layout shift and removes external network dependency)**

Loading fonts from Google Fonts or other CDNs requires DNS lookups, TCP connections, and TLS handshakes to external servers — adding 100-300ms to font loading. During this time, text either flashes from a fallback font (FOUT) or is invisible (FOIT), both causing Cumulative Layout Shift.

`next/font` downloads fonts at build time, self-hosts them from your own domain, and automatically generates `size-adjust` CSS to match the fallback font's metrics — eliminating layout shift entirely.

**Incorrect (external font loading):**

```tsx
// ❌ External CSS link in layout — render-blocking, causes CLS
// app/layout.tsx
export default function RootLayout({ children }) {
  return (
    <html>
      <head>
        <link
          href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap"
          rel="stylesheet"
        />
      </head>
      <body style={{ fontFamily: 'Inter, sans-serif' }}>{children}</body>
    </html>
  )
}
```

```css
/* ❌ @import in CSS — blocks rendering until font CSS is downloaded */
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;700&display=swap');

body {
  font-family: 'Inter', sans-serif;
}
```

```tsx
// ❌ Self-hosted but without size-adjust — still causes layout shift
<style>{`
  @font-face {
    font-family: 'CustomFont';
    src: url('/fonts/custom.woff2');
    font-display: swap; /* Text visible immediately, but shifts when font loads */
  }
`}</style>
```

**Correct (next/font with automatic optimization):**

```tsx
// app/layout.tsx
// ✅ Google Fonts — downloaded at build time, self-hosted
import { Inter } from 'next/font/google'

const inter = Inter({
  subsets: ['latin'],
  display: 'swap',
  // Automatically generates size-adjust for zero CLS
})

export default function RootLayout({ children }) {
  return (
    <html lang="en" className={inter.className}>
      <body>{children}</body>
    </html>
  )
}
```

```tsx
// ✅ Multiple weights and variable fonts
import { Inter, Fira_Code } from 'next/font/google'

const inter = Inter({
  subsets: ['latin'],
  variable: '--font-inter', // CSS variable for Tailwind
})

const firaCode = Fira_Code({
  subsets: ['latin'],
  variable: '--font-mono',
})

export default function RootLayout({ children }) {
  return (
    <html lang="en" className={`${inter.variable} ${firaCode.variable}`}>
      <body>{children}</body>
    </html>
  )
}
```

```tsx
// ✅ Local/custom fonts
import localFont from 'next/font/local'

const customFont = localFont({
  src: [
    { path: './fonts/Custom-Regular.woff2', weight: '400', style: 'normal' },
    { path: './fonts/Custom-Bold.woff2', weight: '700', style: 'normal' },
  ],
  variable: '--font-custom',
})
```

```javascript
// tailwind.config.js — use the CSS variables
module.exports = {
  theme: {
    extend: {
      fontFamily: {
        sans: ['var(--font-inter)', 'system-ui', 'sans-serif'],
        mono: ['var(--font-mono)', 'monospace'],
      },
    },
  },
}
```

**Detection hints:**

```bash
# Find external font loading
grep -rn "fonts.googleapis.com\|fonts.google.com" src/ --include="*.tsx" --include="*.css" --include="*.html"
# Find @import font rules in CSS
grep -rn "@import.*font" src/ --include="*.css" --include="*.scss"
```

Reference: [Next.js Font Optimization](https://nextjs.org/docs/app/building-your-application/optimizing/fonts) · [Web.dev CLS and Fonts](https://web.dev/articles/optimize-cls#web-fonts)
