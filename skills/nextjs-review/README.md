# BeforeMerge: Next.js Review

Code review rules for Next.js, React, and TypeScript applications.

## Install as Agent Skill

```bash
npx skills add BeforeMerge/beforemerge --skill nextjs-review
```

## Rules

### 1. Security (CRITICAL)

| Rule | Impact | CWE | Description |
|------|--------|-----|-------------|
| `sec-server-action-auth` | CRITICAL | CWE-862 | Authenticate Server Actions like API routes |
| `sec-sql-injection` | CRITICAL | CWE-89 | Never build queries with string concatenation |
| `sec-client-data-exposure` | CRITICAL | CWE-200 | Never pass secrets to Client Components |
| `sec-open-redirect` | CRITICAL | CWE-601 | Validate all redirect URLs |
| `sec-xss-dangerouslysetinnerhtml` | CRITICAL | CWE-79 | Sanitize HTML before dangerouslySetInnerHTML |

### 2. Performance (HIGH)

| Rule | Impact | Description |
|------|--------|-------------|
| `perf-n-plus-one` | CRITICAL | Eliminate N+1 database queries |
| `perf-parallel-async` | CRITICAL | Parallelize independent async operations |
| `perf-server-vs-client` | HIGH | Prefer Server Components over Client Components |
| `perf-barrel-imports` | HIGH | Avoid barrel file imports in Client Components |

### 3. Architecture (MEDIUM)

| Rule | Impact | Description |
|------|--------|-------------|
| `arch-god-components` | MEDIUM | Break up god components into focused units |
| `arch-error-boundaries` | MEDIUM | Add error boundaries around unreliable content |

### 4. Quality (LOW-MEDIUM)

| Rule | Impact | CWE | Description |
|------|--------|-----|-------------|
| `qual-no-hardcoded-secrets` | HIGH | CWE-798 | Never hardcode secrets |
| `qual-validate-boundaries` | MEDIUM | CWE-20 | Validate data at system boundaries |

## Building

```bash
node scripts/build.js
```

This compiles all rule files into `AGENTS.md` for AI agent consumption.

## Contributing

See [CONTRIBUTING.md](../../CONTRIBUTING.md) in the repo root.
