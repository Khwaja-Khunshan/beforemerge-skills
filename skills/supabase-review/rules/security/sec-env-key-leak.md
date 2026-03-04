---
title: Never Expose Service Role Key in Client-Side Code
description: "Using NEXT_PUBLIC_ prefix on SUPABASE_SERVICE_ROLE_KEY or DATABASE_URL embeds secrets into client-side JavaScript bundles, bypassing all RLS."
impact: CRITICAL
impact_description: prevents complete RLS bypass via leaked service role key
tags: [security, supabase, environment-variables, secrets, nextjs]
cwe: ["CWE-798"]
owasp: ["A07:2021"]
detection_grep: "NEXT_PUBLIC_SUPABASE_SERVICE"
---

## Never Expose Service Role Key in Client-Side Code

**Impact: CRITICAL (prevents complete RLS bypass via leaked service role key)**

Next.js embeds any environment variable prefixed with `NEXT_PUBLIC_` into the client-side JavaScript bundle at build time. If `SUPABASE_SERVICE_ROLE_KEY` or `DATABASE_URL` is given a `NEXT_PUBLIC_` prefix, the secret is shipped to every browser that loads the app. Anyone can extract it from the bundle and use it to bypass all Row Level Security policies, gaining full read/write access to every table.

This also applies to `.env` files: variables without the `NEXT_PUBLIC_` prefix are only available server-side, which is the correct behavior for secrets.

**Incorrect (service role key exposed to client):**

```env
# .env.local
# ❌ NEXT_PUBLIC_ prefix ships this to the browser bundle
NEXT_PUBLIC_SUPABASE_URL=https://abc.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJ...anon...
NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=eyJ...service_role...
NEXT_PUBLIC_DATABASE_URL=postgresql://postgres:password@db.abc.supabase.co:5432/postgres
```

```typescript
// lib/supabase/client.ts
// ❌ Service role key accessible in browser — attacker can read it from JS bundle
import { createClient } from '@supabase/supabase-js'

export const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY!  // ❌ Full DB access in browser
)
```

**Correct (server-only env vars for secrets):**

```env
# .env.local
# ✅ Public vars (safe for browser — anon key is designed to be public)
NEXT_PUBLIC_SUPABASE_URL=https://abc.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJ...anon...

# ✅ Server-only vars (no NEXT_PUBLIC_ prefix — never reaches the browser)
SUPABASE_SERVICE_ROLE_KEY=eyJ...service_role...
DATABASE_URL=postgresql://postgres:password@db.abc.supabase.co:5432/postgres
```

```typescript
// lib/supabase/browser.ts
// ✅ Browser client uses only the anon key (public, RLS-enforced)
import { createBrowserClient } from '@supabase/ssr'

export function createClient() {
  return createBrowserClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!
  )
}
```

```typescript
// lib/supabase/service-role.ts
// ✅ Service role client is server-only — import guard prevents client usage
import 'server-only'  // Throws build error if imported from client component

import { createClient } from '@supabase/supabase-js'

export function createServiceRoleClient() {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY  // No NEXT_PUBLIC_ prefix

  if (!url || !key) {
    throw new Error('Missing Supabase service role environment variables')
  }

  return createClient(url, key, {
    auth: {
      autoRefreshToken: false,
      persistSession: false,
    },
  })
}
```

**Validating env vars at startup:**

```typescript
// lib/env.ts
import { z } from 'zod'

// ✅ Validate all env vars at startup — fail fast if misconfigured
const envSchema = z.object({
  NEXT_PUBLIC_SUPABASE_URL: z.string().url(),
  NEXT_PUBLIC_SUPABASE_ANON_KEY: z.string().min(1),
  SUPABASE_SERVICE_ROLE_KEY: z.string().min(1),
  DATABASE_URL: z.string().startsWith('postgresql://'),
})

// This runs at import time — app won't start with missing vars
export const env = envSchema.parse(process.env)
```

**Detection hints:**

```bash
# Find any NEXT_PUBLIC_ vars that look like secrets
grep -rn "NEXT_PUBLIC_.*SERVICE\|NEXT_PUBLIC_.*SECRET\|NEXT_PUBLIC_.*PASSWORD\|NEXT_PUBLIC_.*DATABASE" . --include="*.env*" --include="*.ts"
# Check if service role key is used in any client-side files
grep -rn "SUPABASE_SERVICE_ROLE_KEY" src/components/ src/app/**/page.tsx --include="*.tsx"
# Verify 'server-only' import on service role client
grep -rn "server-only" src/lib/supabase/ --include="*.ts"
```

Reference: [Next.js Environment Variables](https://nextjs.org/docs/app/building-your-application/configuring/environment-variables) · [Supabase API Keys](https://supabase.com/docs/guides/api/api-keys) · [CWE-798: Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
