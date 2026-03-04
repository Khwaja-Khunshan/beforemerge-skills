---
title: Never Log Sensitive Data
description: "Logging OAuth tokens, API keys, passwords, or PII exposes secrets in log aggregation services and crash reporters. Use scoped loggers with sanitization."
impact: HIGH
impact_description: prevents credential leaks through log aggregation services
tags: [security, supabase, logging, secrets, pii, oauth]
cwe: ["CWE-532"]
owasp: ["A09:2021"]
detection_grep: "console.log"
---

## Never Log Sensitive Data

**Impact: HIGH (prevents credential leaks through log aggregation services)**

Logging sensitive data — OAuth tokens, refresh tokens, API keys, passwords, session IDs, or Personally Identifiable Information (PII) — exposes secrets to anyone with access to your log aggregation service (Datadog, Vercel Logs, CloudWatch, etc.). Supabase applications frequently handle auth tokens, and it is common during debugging to log entire session objects or error payloads that contain secrets.

Logs are often retained for weeks or months, indexed for search, and accessible to broader teams than the database itself. A single `console.log(session)` can expose every user's refresh token.

**Incorrect (logging auth tokens and session data):**

```typescript
// ❌ Logging the entire session object — contains access_token and refresh_token
const { data: { session }, error } = await supabase.auth.getSession()
console.log('Session:', session)
// Output includes: { access_token: "eyJ...", refresh_token: "abc123...", user: { email: "..." } }

// ❌ Logging OAuth callback data
export async function GET(request: Request) {
  const { searchParams } = new URL(request.url)
  const code = searchParams.get('code')
  console.log('OAuth code:', code) // ❌ Authorization codes are sensitive

  const { data, error } = await supabase.auth.exchangeCodeForSession(code!)
  console.log('Exchange result:', data) // ❌ Contains tokens
  console.log('Auth error:', error) // ❌ May contain token fragments in error message
}
```

```typescript
// ❌ Logging user PII
const { data: user } = await supabase.auth.getUser()
console.log('User logged in:', user)
// Logs email, phone, full name, metadata — all PII

// ❌ Logging API keys in error context
try {
  const response = await fetch(url, {
    headers: { Authorization: `Bearer ${process.env.SUPABASE_SERVICE_ROLE_KEY}` },
  })
} catch (err) {
  console.error('Request failed:', { url, headers: { Authorization: `Bearer ${process.env.SUPABASE_SERVICE_ROLE_KEY}` } })
  // ❌ Service role key is now in your logs
}
```

**Correct (scoped logging with sanitization):**

```typescript
// ✅ Log only non-sensitive identifiers
const { data: { user }, error } = await supabase.auth.getUser()

if (error) {
  console.error('Auth failed:', { code: error.status, message: error.message })
} else {
  console.log('User authenticated:', { userId: user.id })
  // Only log the user ID — not email, name, or tokens
}
```

```typescript
// ✅ Create a sanitized logger utility
const SENSITIVE_KEYS = new Set([
  'access_token', 'refresh_token', 'token', 'password',
  'secret', 'authorization', 'cookie', 'session_id',
  'email', 'phone', 'ssn', 'api_key', 'service_role',
])

function sanitize(obj: Record<string, unknown>): Record<string, unknown> {
  const sanitized: Record<string, unknown> = {}
  for (const [key, value] of Object.entries(obj)) {
    if (SENSITIVE_KEYS.has(key.toLowerCase())) {
      sanitized[key] = '[REDACTED]'
    } else if (typeof value === 'object' && value !== null) {
      sanitized[key] = sanitize(value as Record<string, unknown>)
    } else {
      sanitized[key] = value
    }
  }
  return sanitized
}

// Usage
console.log('Auth result:', sanitize(data as Record<string, unknown>))
```

```typescript
// ✅ Use error IDs for grouping instead of logging details
import { randomUUID } from 'crypto'

export async function handleAuthCallback(code: string) {
  const errorId = randomUUID()

  const { data, error } = await supabase.auth.exchangeCodeForSession(code)

  if (error) {
    // Log the error ID and category — not the token or code
    console.error('Auth callback failed:', {
      errorId,
      errorCode: error.status,
      errorName: error.name,
      // NOT: code, token, refresh_token, user email
    })

    // Return errorId to the client for support correlation
    return { error: 'Authentication failed', errorId }
  }

  console.log('Auth callback succeeded:', { userId: data.user.id, errorId })
  return { success: true }
}
```

**Detection hints:**

```bash
# Find console.log/error calls that might contain sensitive data
grep -rn "console\.\(log\|error\|warn\)" src/ --include="*.ts" --include="*.tsx"
# Look for logging of session, token, or key variables
grep -rn "console.*\(session\|token\|key\|password\|secret\)" src/ --include="*.ts"
```

Reference: [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) · [CWE-532: Information Exposure Through Log Files](https://cwe.mitre.org/data/definitions/532.html)
