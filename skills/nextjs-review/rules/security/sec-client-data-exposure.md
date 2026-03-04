---
title: Never Pass Secrets or Sensitive Data to Client Components
description: "Props passed to Client Components are visible in the browser. Never pass API keys, tokens, or full database records to client code."
impact: CRITICAL
impact_description: prevents exposure of API keys, tokens, and internal data to browsers
tags: [security, server-components, client-components, data-exposure, nextjs]
cwe: ["CWE-200"]
owasp: ["A01:2021"]
detection_grep: "process\\.env\\."
---

## Never Pass Secrets or Sensitive Data to Client Components

**Impact: CRITICAL (prevents exposure of API keys, tokens, and internal data to browsers)**

Any prop passed from a Server Component to a Client Component is serialized into the HTML response and visible in the browser. This includes the RSC payload, which is inspectable in the network tab. Never pass API keys, internal IDs, full database records, or any data the client doesn't need.

**Incorrect (leaking secrets via props):**

```typescript
// app/page.tsx (Server Component)
export default async function Page() {
  const config = {
    apiKey: process.env.STRIPE_SECRET_KEY,   // ❌ Secret key!
    dbUrl: process.env.DATABASE_URL,          // ❌ Connection string!
    internalUserId: 'usr_admin_29384',        // ❌ Internal ID!
  }

  return <Dashboard config={config} />
}

// components/Dashboard.tsx
'use client'
export function Dashboard({ config }) {
  // All of config is now in the browser HTML and RSC payload
}
```

**Also incorrect (over-fetching database records):**

```typescript
// ❌ Passing entire user record to client
async function Page() {
  const user = await db.user.findUnique({
    where: { id: userId },
  }) // Returns 30+ fields including passwordHash, ssn, etc.

  return <Profile user={user} />
}
```

**Correct (pass only what the client needs):**

```typescript
// app/page.tsx (Server Component)
export default async function Page() {
  // ✅ Keep secrets server-side, pass only public config
  const publishableKey = process.env.NEXT_PUBLIC_STRIPE_KEY

  return <Dashboard stripeKey={publishableKey} />
}
```

```typescript
// ✅ Select only the fields the client needs
async function Page() {
  const user = await db.user.findUnique({
    where: { id: userId },
    select: {
      name: true,
      email: true,
      avatarUrl: true,
      // Only fields the UI actually renders
    },
  })

  return <Profile user={user} />
}
```

**Use `server-only` to prevent accidental imports:**

```typescript
// lib/secrets.ts
import 'server-only'

export const config = {
  stripeSecret: process.env.STRIPE_SECRET_KEY!,
  dbUrl: process.env.DATABASE_URL!,
}
// Importing this file in a Client Component will now cause a build error
```

**Detection hints:**

```bash
# Find env vars being passed as props (potential leaks)
grep -rn "process\.env\." src/ --include="*.tsx" | grep -v "NEXT_PUBLIC"
# Find large objects being passed to client components
grep -rn "findUnique\|findFirst\|findMany" src/ --include="*.tsx" | grep -v "select:"
```

Reference: [Next.js Server Components](https://nextjs.org/docs/app/building-your-application/rendering/server-components) · [server-only package](https://nextjs.org/docs/app/building-your-application/rendering/composition-patterns#keeping-server-only-code-out-of-the-client-environment)
