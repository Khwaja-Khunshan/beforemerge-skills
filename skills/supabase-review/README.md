# BeforeMerge: Supabase Review

Code review rules for Supabase applications.

## Install as Agent Skill

```bash
npx skills add BeforeMerge/beforemerge --skill supabase-review
```

## Rules

### 1. Security (CRITICAL)

| Rule | Impact | CWE | Description |
|------|--------|-----|-------------|
| `sec-getuser-not-getsession` | CRITICAL | CWE-287 | Use getUser() instead of getSession() for auth checks |
| `sec-rls-every-table` | CRITICAL | CWE-862 | Every table must have RLS enabled with policies |
| `sec-service-role-exposure` | CRITICAL | CWE-269 | Never use service role client in auth-context routes |
| `sec-sql-injection` | CRITICAL | CWE-89 | Prevent SQL injection in custom RPC functions |
| `sec-env-key-leak` | CRITICAL | CWE-798 | Never expose service role key in client-side code |
| `sec-rls-policy-gaps` | HIGH | -- | Ensure policies cover all CRUD operations |
| `sec-migration-not-mcp` | HIGH | -- | Always use migration files, never MCP/dashboard SQL |
| `sec-sensitive-data-logging` | HIGH | CWE-532 | Never log tokens, keys, passwords, or PII |

### 2. Performance (HIGH)

| Rule | Impact | Description |
|------|--------|-------------|
| `perf-n-plus-one` | HIGH | Use relation queries instead of loops |
| `perf-missing-indexes` | HIGH | Always index filtered, ordered, and RLS columns |
| `perf-select-star` | HIGH | Select only the columns you need |
| `perf-connection-pooling` | HIGH | Use Supavisor pooler in serverless |
| `perf-cursor-pagination` | HIGH | Use cursor pagination for large datasets |
| `perf-batch-operations` | HIGH | Batch inserts/upserts instead of looping |

### 3. Architecture (MEDIUM)

| Rule | Impact | Description |
|------|--------|-------------|
| `arch-client-selection` | HIGH | Use the correct Supabase client for each context |
| `arch-type-generation` | MEDIUM | Generate types from schema, never hand-write |
| `arch-migration-structure` | MEDIUM | Follow canonical migration file structure |

### 4. Quality (LOW-MEDIUM)

| Rule | Impact | CWE | Description |
|------|--------|-----|-------------|
| `qual-unchecked-errors` | HIGH | CWE-252 | Always check error before using data |
| `qual-zod-input-validation` | HIGH | CWE-20 | Validate input at runtime, never use `as` assertions |
| `qual-error-handling` | MEDIUM | CWE-209 | Map Supabase errors to safe user-facing messages |

## Building

```bash
node scripts/build.js
```

This compiles all rule files into `AGENTS.md` for AI agent consumption.

## Contributing

See [CONTRIBUTING.md](../../CONTRIBUTING.md) in the repo root.
