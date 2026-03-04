---
title: Validate All Redirect URLs
description: "Unvalidated redirect URLs enable phishing attacks via your domain. Always validate against an allowlist or restrict to relative paths."
impact: CRITICAL
impact_description: prevents open redirect attacks used for phishing and credential theft
tags: [security, redirect, validation, nextjs, middleware]
cwe: ["CWE-601"]
owasp: ["A01:2021"]
detection_grep: "redirect|Response.redirect|router.push|router.replace"
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
