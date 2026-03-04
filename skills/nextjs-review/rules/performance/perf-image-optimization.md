---
title: Use next/image Instead of Raw img Tags
description: "Raw <img> tags skip automatic optimization, lazy loading, and responsive sizing. next/image provides WebP/AVIF conversion, blur placeholders, and CLS prevention."
impact: HIGH
impact_description: 40-80% image size reduction and elimination of Cumulative Layout Shift
tags: [performance, images, core-web-vitals, cls, lcp, nextjs]
detection_grep: "<img |<img>"
---

## Use next/image Instead of Raw img Tags

**Impact: HIGH (40-80% image size reduction and elimination of Cumulative Layout Shift)**

Images are typically the largest assets on a web page. Raw `<img>` tags force the browser to download full-size images regardless of viewport, cause layout shift (CLS) when they load, and serve unoptimized formats. The `next/image` component provides:

- **Automatic format conversion** — serves WebP/AVIF when the browser supports it
- **Responsive sizing** — generates multiple sizes and uses `srcset` for the right one
- **Lazy loading by default** — only loads images when they enter the viewport
- **Layout shift prevention** — reserves space based on dimensions, preventing CLS
- **Blur placeholders** — shows a blurred preview while the full image loads

**Incorrect (raw img tags):**

```tsx
// ❌ Full-size image downloaded on every device, causes layout shift
export default function ProductCard({ product }) {
  return (
    <div>
      <img src={product.imageUrl} alt={product.name} />
      <h3>{product.name}</h3>
    </div>
  )
}

// ❌ CSS background images skip all optimization
<div style={{ backgroundImage: `url(${hero.url})` }} />

// ❌ Eager loading large images in below-the-fold content
<img src="/huge-banner.jpg" alt="Banner" loading="eager" />
```

**Correct (next/image with proper configuration):**

```tsx
import Image from 'next/image'

// ✅ Local images — dimensions inferred automatically
export default function ProductCard({ product }) {
  return (
    <div>
      <Image
        src={product.imageUrl}
        alt={product.name}
        width={400}
        height={300}
        sizes="(max-width: 768px) 100vw, 400px"
      />
      <h3>{product.name}</h3>
    </div>
  )
}

// ✅ Hero/LCP images — set priority to preload
<Image
  src="/hero.jpg"
  alt="Welcome to our store"
  width={1200}
  height={600}
  priority              // Preloads the image, disables lazy loading
  sizes="100vw"
  placeholder="blur"    // Shows blurred version while loading
  blurDataURL={blurHash} // Base64 blur placeholder
/>

// ✅ Fill mode for unknown dimensions (e.g., user uploads)
<div className="relative aspect-video">
  <Image
    src={user.avatarUrl}
    alt={user.name}
    fill
    className="object-cover"
    sizes="(max-width: 768px) 100vw, (max-width: 1200px) 50vw, 33vw"
  />
</div>
```

**Configure remote image domains:**

```javascript
// next.config.js
module.exports = {
  images: {
    remotePatterns: [
      {
        protocol: 'https',
        hostname: 'images.example.com',
        pathname: '/uploads/**',
      },
    ],
  },
}
```

**Key rules:**

1. **Always provide `width` and `height`** (or use `fill`) — this prevents CLS
2. **Always provide `sizes`** — tells the browser which image size to download at each viewport width
3. **Set `priority` on LCP images** — above-the-fold hero images, product images on landing pages
4. **Use `placeholder="blur"`** for a better loading experience on large images
5. **Configure `remotePatterns`** — not `domains` (deprecated) — for external images

**Detection hints:**

```bash
# Find raw img tags that should use next/image
grep -rn "<img " src/ --include="*.tsx" --include="*.jsx" | grep -v "node_modules"
# Find Image components missing sizes prop
grep -rn "<Image" src/ --include="*.tsx" -A 5 | grep -B 3 "width=" | grep -L "sizes="
```

Reference: [Next.js Image Optimization](https://nextjs.org/docs/app/building-your-application/optimizing/images) · [Web.dev CLS Guide](https://web.dev/articles/cls)
