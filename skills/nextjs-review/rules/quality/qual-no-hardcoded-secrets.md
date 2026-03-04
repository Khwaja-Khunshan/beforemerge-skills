---
title: Never Hardcode Secrets — Use Environment Variables Properly
description: "Hardcoded secrets persist in Git history forever. Use environment variables and never prefix secrets with NEXT_PUBLIC_."
impact: HIGH
impact_description: prevents credential leaks in source control and client bundles
tags: [quality, secrets, environment-variables, configuration, nextjs]
cwe: ["CWE-798"]
owasp: ["A07:2021"]
detection_grep: "sk_live|sk_test|password.*=.*['\"]"
---

## Never Hardcode Secrets — Use Environment Variables Properly

**Impact: HIGH (prevents credential leaks in source control and client bundles)**

Hardcoded API keys, database URLs, and tokens in source code end up in Git history permanently — even if deleted later. In Next.js, any environment variable prefixed with `NEXT_PUBLIC_` is embedded in the client bundle and visible to anyone. Use `.env.local` for secrets, never commit them, and understand which variables are public vs. server-only.

**Incorrect (hardcoded secrets):**

```typescript
// ❌ Hardcoded in source — visible in Git history forever
const stripe = new Stripe('sk_live_abc123realkey456', {
  apiVersion: '2024-01-01',
})

// ❌ Database URL in code
const prisma = new PrismaClient({
  datasources: {
    db: { url: 'postgresql://admin:password@prod-db:5432/myapp' },
  },
})
```

**Incorrect (wrong env var prefix):**

```typescript
// ❌ NEXT_PUBLIC_ prefix makes this visible in the browser bundle!
// .env.local
NEXT_PUBLIC_STRIPE_SECRET=sk_live_abc123

// ❌ Anyone can see this in the browser's JS source
const stripe = new Stripe(process.env.NEXT_PUBLIC_STRIPE_SECRET!)
```

**Correct (server-only env vars):**

```bash
# .env.local (never committed — in .gitignore)
STRIPE_SECRET_KEY=sk_live_abc123
DATABASE_URL=postgresql://admin:password@prod-db:5432/myapp

# Only public/non-sensitive values get the NEXT_PUBLIC_ prefix
NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=pk_live_xyz789
NEXT_PUBLIC_APP_URL=https://myapp.com
```

```typescript
// ✅ Server-only — only accessible in Server Components, API routes, Server Actions
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!, {
  apiVersion: '2024-01-01',
})

// ✅ Validate env vars at startup
import { z } from 'zod'

const envSchema = z.object({
  STRIPE_SECRET_KEY: z.string().startsWith('sk_'),
  DATABASE_URL: z.string().url(),
  NEXT_PUBLIC_APP_URL: z.string().url(),
})

export const env = envSchema.parse(process.env)
```

**Ensure .gitignore includes env files:**

```gitignore
# .gitignore
.env
.env.local
.env.*.local
```

**Detection hints:**

```bash
# Find hardcoded secrets (API keys, tokens, passwords)
grep -rn "sk_live\|sk_test\|password.*=.*['\"]" src/ --include="*.ts" --include="*.tsx"
# Find NEXT_PUBLIC_ vars that look like secrets
grep -rn "NEXT_PUBLIC_.*SECRET\|NEXT_PUBLIC_.*KEY\|NEXT_PUBLIC_.*TOKEN" .env* src/
# Check if .env.local is in .gitignore
grep -q "\.env\.local" .gitignore && echo "OK" || echo "WARNING: .env.local not in .gitignore"
```

Reference: [Next.js Environment Variables](https://nextjs.org/docs/app/building-your-application/configuring/environment-variables) · [CWE-798: Hardcoded Credentials](https://cwe.mitre.org/data/definitions/798.html)
