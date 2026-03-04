---
title: Use getUser() Instead of getSession() for Auth Checks
description: "getSession() reads from cookies and can be spoofed. getUser() verifies the token with the Supabase Auth server, making it tamper-proof."
impact: CRITICAL
impact_description: prevents authentication bypass via cookie tampering
tags: [security, supabase, authentication, session, cookies]
cwe: ["CWE-287"]
owasp: ["A07:2021"]
detection_grep: "getSession"
---

## Use getUser() Instead of getSession() for Auth Checks

**Impact: CRITICAL (prevents authentication bypass via cookie tampering)**

`supabase.auth.getSession()` reads the session from cookies/local storage **without** verifying the JWT with the Supabase Auth server. An attacker can forge or tamper with the session cookie to impersonate any user. `supabase.auth.getUser()` sends the access token to Supabase Auth for server-side verification, making it the only safe method for authentication checks.

The Supabase docs explicitly warn: "Never trust `getSession()` inside server-side code such as middleware, server components, or route handlers. It isn't guaranteed to revalidate the auth token."

**Incorrect (getSession can be spoofed from cookies):**

```typescript
// app/api/profile/route.ts
import { createClient } from '@/lib/supabase/server'

export async function GET() {
  const supabase = await createClient()

  // ❌ getSession() reads from cookies — attacker can forge this
  const { data: { session } } = await supabase.auth.getSession()

  if (!session) {
    return Response.json({ error: 'Unauthorized' }, { status: 401 })
  }

  // ❌ session.user.id could be any user ID the attacker chose
  const { data: profile } = await supabase
    .from('profiles')
    .select('*')
    .eq('id', session.user.id)
    .single()

  return Response.json(profile)
}
```

**Correct (getUser verifies with Supabase Auth server):**

```typescript
// app/api/profile/route.ts
import { createClient } from '@/lib/supabase/server'

export async function GET() {
  const supabase = await createClient()

  // ✅ getUser() sends the token to Supabase Auth for verification
  const { data: { user }, error } = await supabase.auth.getUser()

  if (error || !user) {
    return Response.json({ error: 'Unauthorized' }, { status: 401 })
  }

  // ✅ user.id is verified by the auth server — cannot be spoofed
  const { data: profile } = await supabase
    .from('profiles')
    .select('id, display_name, avatar_url')
    .eq('id', user.id)
    .single()

  return Response.json(profile)
}
```

**When getSession() is acceptable:**

`getSession()` is safe for **non-security** purposes only — such as reading the session to display UI elements (showing a username in a nav bar) or checking if a user is logged in for client-side routing. Never use it for:
- Authorization decisions (can this user do X?)
- Data access control (fetching data scoped to a user)
- Server-side auth checks (middleware, route handlers, server actions)

**Detection hints:**

```bash
# Find all getSession() calls — each one needs review
grep -rn "getSession" src/ --include="*.ts" --include="*.tsx"
# Find server-side files using getSession (high-priority)
grep -rn "getSession" src/app/api/ src/app/actions/ src/middleware.ts --include="*.ts"
```

Reference: [Supabase Auth — getUser()](https://supabase.com/docs/reference/javascript/auth-getuser) · [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
