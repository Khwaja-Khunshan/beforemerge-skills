---
title: Never Use eval() or new Function() with User Input
description: "Using eval(), new Function(), or innerHTML with user-controlled strings enables arbitrary code execution in the browser."
impact: CRITICAL
impact_description: prevents arbitrary JavaScript execution in the user's browser
tags: [security, react, eval, code-injection]
cwe: ["CWE-95"]
owasp: ["A03:2021"]
detection_grep: "eval("
---

## Never Use eval() or new Function() with User Input

**Impact: CRITICAL (prevents arbitrary JavaScript execution in the user's browser)**

`eval()`, `new Function()`, `setTimeout(string)`, and `setInterval(string)` all parse and execute strings as JavaScript. If any part of the string originates from user input — URL parameters, form fields, API responses, postMessage events — an attacker can execute arbitrary code in the user's browser context. This grants access to cookies, localStorage, the DOM, and any API the user can call.

**Incorrect (executing user-controlled strings):**

```tsx
// ❌ eval with user input for "dynamic filtering"
function applyFilter(filterExpression: string, data: any[]) {
  return data.filter((item) => eval(filterExpression))
}

// ❌ new Function() with user-controlled template
function renderTemplate(template: string, context: Record<string, unknown>) {
  const fn = new Function('ctx', `return \`${template}\``)
  return fn(context)
}

// ❌ setTimeout with string argument
function scheduleAction(userCode: string) {
  setTimeout(userCode, 1000)
}

// ❌ innerHTML with user content (bypasses React's escaping)
function RawContent({ html }: { html: string }) {
  const ref = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (ref.current) {
      ref.current.innerHTML = html  // ❌ XSS vector
    }
  }, [html])
  return <div ref={ref} />
}
```

**Correct (use safe alternatives):**

```tsx
// ✅ Use a predefined set of filter functions instead of eval
const FILTERS: Record<string, (item: Product) => boolean> = {
  inStock: (item) => item.quantity > 0,
  onSale: (item) => item.discount > 0,
  premium: (item) => item.price > 100,
}

function applyFilter(filterName: string, data: Product[]) {
  const filterFn = FILTERS[filterName]
  if (!filterFn) throw new Error(`Unknown filter: ${filterName}`)
  return data.filter(filterFn)
}

// ✅ Use template literals with explicit interpolation
function renderTemplate(template: string, context: Record<string, string>) {
  return template.replace(/\{\{(\w+)\}\}/g, (_, key) => {
    return context[key] ?? ''
  })
}

// ✅ setTimeout with function reference, not string
function scheduleAction(action: () => void) {
  setTimeout(action, 1000)
}

// ✅ Use dangerouslySetInnerHTML with DOMPurify (see sec-dangerouslysetinnerhtml rule)
import DOMPurify from 'dompurify'

function RawContent({ html }: { html: string }) {
  const clean = DOMPurify.sanitize(html)
  return <div dangerouslySetInnerHTML={{ __html: clean }} />
}
```

**Additional context:**

- CSP (Content Security Policy) headers with `script-src` directives can block `eval()` and `new Function()` at the browser level, providing defense in depth. Set `'unsafe-eval'` only if absolutely necessary.
- If you truly need a sandboxed expression evaluator (e.g., for a spreadsheet formula feature), use a dedicated parser like `expr-eval` or `mathjs` that does not execute arbitrary JavaScript.
- ESLint rule `no-eval` catches `eval()` but not `new Function()` — enable `no-new-func` as well.

**Detection hints:**

```bash
# Find eval, new Function, and string-based setTimeout/setInterval
grep -rn "eval(\|new Function(\|setTimeout(\s*['\"\`]\|setInterval(\s*['\"\`]" src/ --include="*.ts" --include="*.tsx"
# Find direct innerHTML assignments
grep -rn "\.innerHTML\s*=" src/ --include="*.ts" --include="*.tsx"
```

Reference: [MDN eval() — Never use eval!](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval#never_use_eval!)
