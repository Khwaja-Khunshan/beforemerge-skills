---
title: Do Not Mix Controlled and Uncontrolled Input Patterns
description: "Switching between controlled (value prop) and uncontrolled (defaultValue/no value) patterns on the same input causes React warnings and unpredictable behavior."
impact: MEDIUM
impact_description: prevents form input bugs and React reconciliation warnings
tags: [quality, react, forms, controlled-components, uncontrolled-components]
detection_grep: "defaultValue"
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
