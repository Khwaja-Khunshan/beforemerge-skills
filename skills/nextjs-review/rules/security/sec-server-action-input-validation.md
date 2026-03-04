---
title: Validate All Server Action Inputs at the Boundary
description: "Server Action arguments are deserialized from untrusted HTTP requests. Validate every input with Zod to prevent type confusion and injection attacks."
impact: CRITICAL
impact_description: prevents remote code execution and type confusion from untrusted deserialized input
tags: [security, server-actions, input-validation, deserialization, zod, nextjs, cve]
cwe: ["CWE-20", "CWE-502"]
owasp: ["A08:2021"]
detection_grep: "\"use server\""
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
