---
title: Authenticate Server Actions Like API Routes
description: "Server Actions are public HTTP endpoints not protected by middleware or layout guards. Always verify authentication inside each action."
impact: CRITICAL
impact_description: prevents unauthorized access to server mutations
tags: [security, server-actions, authentication, authorization, nextjs]
cwe: ["CWE-862"]
owasp: ["A01:2021"]
detection_grep: "\"use server\""
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
