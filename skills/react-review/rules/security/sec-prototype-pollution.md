---
title: Prevent Prototype Pollution from Untrusted Input
description: "Spreading or Object.assign-ing untrusted user input into objects can pollute Object.prototype and lead to security bypasses."
impact: CRITICAL
impact_description: prevents prototype pollution leading to privilege escalation or denial of service
tags: [security, react, prototype-pollution, object-spread]
cwe: ["CWE-1321"]
detection_grep: "Object.assign"
---

## Prevent Prototype Pollution from Untrusted Input

**Impact: CRITICAL (prevents prototype pollution leading to privilege escalation or denial of service)**

When you spread or `Object.assign` untrusted data (API responses, form submissions, URL params) directly into an object, an attacker can inject `__proto__`, `constructor`, or `prototype` keys. This pollutes the global `Object.prototype`, affecting every object in the application. Consequences include authentication bypasses (`isAdmin` becoming truthy on all objects), denial of service, or remote code execution in server-side contexts.

**Incorrect (spreading untrusted API data directly into state or config):**

```tsx
// ❌ API response spread directly — attacker can send { "__proto__": { "isAdmin": true } }
async function updateProfile(userId: string) {
  const data = await fetch(`/api/users/${userId}`).then(r => r.json())
  const profile = { ...defaultProfile, ...data }
  return profile
}

// ❌ Form data spread without filtering
function handleSubmit(formData: Record<string, unknown>) {
  const settings = Object.assign({}, currentSettings, formData)
  saveSettings(settings)
}
```

**Correct (validate and pick only known keys):**

```tsx
import { z } from 'zod'

const ProfileSchema = z.object({
  name: z.string().max(100),
  email: z.string().email(),
  bio: z.string().max(500).optional(),
})

// ✅ Parse with a schema — unknown keys are stripped
async function updateProfile(userId: string) {
  const raw = await fetch(`/api/users/${userId}`).then(r => r.json())
  const data = ProfileSchema.parse(raw)
  const profile = { ...defaultProfile, ...data }
  return profile
}

// ✅ Alternatively, pick only known keys explicitly
function handleSubmit(formData: Record<string, unknown>) {
  const safeData = {
    theme: typeof formData.theme === 'string' ? formData.theme : currentSettings.theme,
    locale: typeof formData.locale === 'string' ? formData.locale : currentSettings.locale,
  }
  saveSettings({ ...currentSettings, ...safeData })
}
```

**Additional context:**

- Libraries like Zod, Yup, and Valibot strip unknown keys by default during `.parse()`, making them a natural defense.
- `Object.create(null)` creates objects without a prototype, which can serve as safe containers for dynamic keys.
- This applies to any context where external data is merged: API responses, WebSocket messages, URL search params, localStorage, postMessage events.

**Detection hints:**

```bash
# Find Object.assign with dynamic data
grep -rn "Object\.assign" src/ --include="*.ts" --include="*.tsx"
# Find spread of variables from fetch/API calls
grep -rn "\.\.\.data\|\.\.\.response\|\.\.\.body\|\.\.\.payload" src/ --include="*.ts" --include="*.tsx"
```

Reference: [CWE-1321: Improperly Controlled Modification of Object Prototype Attributes](https://cwe.mitre.org/data/definitions/1321.html)
