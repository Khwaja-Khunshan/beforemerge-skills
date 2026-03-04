---
title: Use Cryptographic Randomness for Tokens and IDs
description: "Math.random() is not cryptographically secure. Use crypto.randomUUID() or crypto.getRandomValues() for tokens, IDs, and security-sensitive values."
impact: CRITICAL
impact_description: prevents predictable tokens that enable session hijacking or enumeration attacks
tags: [security, react, randomness, crypto]
cwe: ["CWE-338"]
detection_grep: "Math.random()"
---

## Use Cryptographic Randomness for Tokens and IDs

**Impact: CRITICAL (prevents predictable tokens that enable session hijacking or enumeration attacks)**

`Math.random()` uses a pseudo-random number generator (PRNG) that is not cryptographically secure. Its output can be predicted if an attacker observes enough values, and some engines seed it with low-entropy sources. When used to generate session tokens, CSRF tokens, password reset links, unique IDs for access control, or nonces, an attacker can predict or brute-force subsequent values.

**Incorrect (using Math.random() for security-sensitive values):**

```tsx
// ❌ Predictable token generation
function generateToken(): string {
  return Math.random().toString(36).substring(2)
}

// ❌ Predictable unique IDs used for access control
function createInviteLink(teamId: string): string {
  const code = Math.random().toString(36).slice(2, 10)
  return `https://app.example.com/invite/${teamId}/${code}`
}

// ❌ Predictable CSRF nonce
function generateNonce(): string {
  return `nonce-${Math.random()}`
}
```

**Correct (using crypto APIs for secure randomness):**

```tsx
// ✅ crypto.randomUUID() — available in all modern browsers and Node 19+
function generateToken(): string {
  return crypto.randomUUID()
}

// ✅ crypto.getRandomValues() for custom-length tokens
function generateSecureCode(length: number = 32): string {
  const array = new Uint8Array(length)
  crypto.getRandomValues(array)
  return Array.from(array, (b) => b.toString(16).padStart(2, '0')).join('')
}

// ✅ Secure invite link
function createInviteLink(teamId: string): string {
  const code = crypto.randomUUID()
  return `https://app.example.com/invite/${teamId}/${code}`
}
```

**Additional context:**

- `Math.random()` is fine for non-security purposes: shuffling UI elements, generating placeholder data, animations, or randomizing display order.
- `crypto.randomUUID()` is available in browsers (all major since 2022) and Node.js 19+. For older Node.js, use `require('crypto').randomUUID()`.
- If you need a nanoid-style short ID, the `nanoid` package uses `crypto.getRandomValues()` internally and is a safe alternative.

**Detection hints:**

```bash
# Find Math.random() used near token/id/key generation
grep -rn "Math\.random()" src/ --include="*.ts" --include="*.tsx"
```

Reference: [MDN crypto.randomUUID()](https://developer.mozilla.org/en-US/docs/Web/API/Crypto/randomUUID)
