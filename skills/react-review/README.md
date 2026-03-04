# BeforeMerge: React Review

Code review rules for React applications (framework-agnostic).

## Install as Agent Skill

```bash
npx skills add BeforeMerge/beforemerge --skill react-review
```

## Rules

### 1. Security (CRITICAL)

| Rule | Impact | CWE | Description |
|------|--------|-----|-------------|
| `sec-dangerouslysetinnerhtml` | CRITICAL | CWE-79 | Sanitize content before dangerouslySetInnerHTML |
| `sec-prototype-pollution` | CRITICAL | CWE-1321 | Prevent prototype pollution from untrusted input |
| `sec-insecure-randomness` | CRITICAL | CWE-338 | Use cryptographic randomness for tokens and IDs |
| `sec-eval-injection` | CRITICAL | CWE-95 | Never use eval() or new Function() with user input |

### 2. Performance (HIGH)

| Rule | Impact | Description |
|------|--------|-------------|
| `perf-unnecessary-rerenders` | HIGH | Avoid inline object/array/function creation in JSX props |
| `perf-expensive-computations` | HIGH | Memoize expensive computations with useMemo |
| `perf-large-lists` | HIGH | Virtualize large lists instead of rendering all items |
| `perf-context-splitting` | HIGH | Split large contexts to prevent unnecessary consumer re-renders |

### 3. Architecture (MEDIUM)

| Rule | Impact | Description |
|------|--------|-------------|
| `arch-prop-drilling` | MEDIUM | Eliminate prop drilling through 3+ component levels |
| `arch-component-composition` | MEDIUM | Prefer composition over monolithic conditional rendering |
| `arch-custom-hooks` | MEDIUM | Extract duplicated stateful logic into custom hooks |
| `arch-state-colocation` | MEDIUM | Colocate state with the components that use it |

### 4. Quality (MEDIUM)

| Rule | Impact | Description |
|------|--------|-------------|
| `qual-error-boundaries` | MEDIUM | Add error boundaries around unreliable UI sections |
| `qual-key-prop` | MEDIUM | Never use array index as key for dynamic lists |
| `qual-useeffect-cleanup` | MEDIUM | Always clean up useEffect side effects |
| `qual-controlled-vs-uncontrolled` | MEDIUM | Do not mix controlled and uncontrolled input patterns |

## Building

```bash
node scripts/build.js react-review
```

This compiles all rule files into `AGENTS.md` for AI agent consumption.

## Contributing

See [CONTRIBUTING.md](../../CONTRIBUTING.md) in the repo root.
