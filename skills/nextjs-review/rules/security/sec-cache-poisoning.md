---
title: Prevent Cache Poisoning in ISR and SSR Routes
description: "Misconfigured caching of Next.js ISR/SSR responses allows attackers to poison cached pages with blank or malicious content, causing DoS for all users."
impact: HIGH
impact_description: denial of service or content injection affecting all users via poisoned cache
tags: [security, caching, isr, ssr, cdn, nextjs, cve]
cwe: ["CWE-444"]
owasp: ["A05:2021"]
detection_grep: "revalidate|s-maxage|Cache-Control"
---

## Prevent Cache Poisoning in ISR and SSR Routes

**Impact: HIGH (denial of service or content injection affecting all users via poisoned cache)**

Next.js has had multiple cache poisoning vulnerabilities where a single crafted request could poison the cache for an ISR or SSR page, serving blank or malicious content to all subsequent visitors:

- **CVE-2025-49826** (CVSS 7.5): A race condition in Next.js 15.1.0–15.1.7 allowed a 204 response to be cached for ISR pages, serving blank pages to all users. Fixed in 15.1.8.
- **CVE-2024-46982** (CVSS 7.5): Non-dynamic Pages Router SSR pages incorrectly received `s-maxage=1` cache headers, allowing upstream CDNs to cache and serve attacker-influenced responses. Affected 13.5.1–13.5.6 and 14.0.0–14.2.9.

Even on patched versions, cache misconfiguration remains a risk. Understand what's cached, for how long, and who can influence it.

**Incorrect (dangerous cache patterns):**

```typescript
// ❌ Long revalidation on user-specific content
// app/dashboard/page.tsx
export const revalidate = 3600 // Caches for 1 hour — but content varies by user!

export default async function Dashboard() {
  const session = await auth()
  const data = await getUserData(session.user.id)
  return <DashboardView data={data} /> // User A sees User B's cached dashboard
}
```

```typescript
// ❌ Setting permissive cache headers on dynamic API routes
// app/api/user/route.ts
export async function GET(request: NextRequest) {
  const user = await getCurrentUser(request)
  return NextResponse.json(user, {
    headers: {
      'Cache-Control': 'public, s-maxage=60', // CDN caches user-specific data!
    },
  })
}
```

```typescript
// ❌ ISR page that renders differently based on cookies/headers
// app/pricing/page.tsx
export const revalidate = 600

export default async function Pricing() {
  const country = headers().get('x-country') // Varies by request
  const prices = await getPrices(country)     // But ISR caches one version!
  return <PriceTable prices={prices} />
}
```

**Correct (safe caching patterns):**

```typescript
// ✅ Never cache user-specific content with ISR
// app/dashboard/page.tsx
export const dynamic = 'force-dynamic' // No caching

export default async function Dashboard() {
  const session = await auth()
  const data = await getUserData(session.user.id)
  return <DashboardView data={data} />
}
```

```typescript
// ✅ Private cache headers for user-specific API responses
// app/api/user/route.ts
export async function GET(request: NextRequest) {
  const user = await getCurrentUser(request)
  return NextResponse.json(user, {
    headers: {
      'Cache-Control': 'private, no-store', // Never cached by CDN
    },
  })
}
```

```typescript
// ✅ Use generateStaticParams for known variants, not request-based branching
// app/pricing/[country]/page.tsx
export async function generateStaticParams() {
  return [{ country: 'us' }, { country: 'eu' }, { country: 'uk' }]
}

export default async function Pricing({ params }: { params: { country: string } }) {
  const prices = await getPrices(params.country)
  return <PriceTable prices={prices} />
}
```

**Cache safety checklist:**

1. **Never use `revalidate` on pages that read cookies, headers, or session data** — use `dynamic = 'force-dynamic'` instead
2. **Set `Cache-Control: private, no-store`** on API responses containing user-specific data
3. **Keep Next.js updated** — cache poisoning CVEs have affected multiple major versions
4. **If using a CDN, configure it to not cache 204 responses** and to respect `Vary` headers
5. **Test ISR pages in incognito** — verify cached content doesn't leak between users

**Detection hints:**

```bash
# Find ISR pages that also read cookies or headers (likely misconfigured)
grep -rn "revalidate" src/app --include="*.ts" --include="*.tsx" -l | \
  xargs grep -l "cookies\|headers\|auth\|session"
# Find API routes setting public cache headers
grep -rn "s-maxage\|public.*max-age" src/app/api --include="*.ts"
```

Reference: [CVE-2025-49826](https://github.com/vercel/next.js/security/advisories/GHSA-67rr-84xm-4c7r) · [CVE-2024-46982](https://github.com/advisories/GHSA-gp8f-8m3g-qvj9) · [CWE-444: Inconsistent Interpretation of HTTP Requests](https://cwe.mitre.org/data/definitions/444.html)
