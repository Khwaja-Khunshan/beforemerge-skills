# BeforeMerge: Fullstack Architecture Review

Code review rules for DRY/SOLID layered architecture in fullstack TypeScript applications.

## Install as Agent Skill

```bash
npx skills add BeforeMerge/beforemerge --skill fullstack-architecture-review
```

## Layer Diagram

```
┌──────────────────────────────────────────────┐
│  Presentation Layer                          │
│  React Components, Pages, Layouts            │
├──────────────────────────────────────────────┤
│  API Layer                                   │
│  Route Handlers, Server Actions, Middleware  │
├──────────────────────────────────────────────┤
│  Service Layer                               │
│  Business Logic, Orchestration, Validation   │
├──────────────────────────────────────────────┤
│  Repository Layer                            │
│  Data Access, Query Building, Row Mapping    │
├──────────────────────────────────────────────┤
│  Domain Layer                                │
│  Entities, Value Objects, Interfaces, Types  │
└──────────────────────────────────────────────┘

Dependencies flow DOWNWARD only.
Higher layers depend on lower layers via interfaces.
Domain layer has ZERO external dependencies.
```

## Rules

### 1. Security (CRITICAL)

| Rule | Impact | CWE | Description |
|------|--------|-----|-------------|
| `sec-thin-controllers` | CRITICAL | CWE-1064 | Keep API route handlers thin — delegate to services |
| `sec-rate-limit-every-route` | HIGH | CWE-770 | Rate limit every API route with appropriate buckets |
| `sec-csrf-mutations` | HIGH | CWE-352 | Validate CSRF tokens on all state-changing requests |
| `sec-error-message-leaks` | MEDIUM | CWE-209 | Never expose raw errors or stack traces to clients |

### 2. Performance (HIGH)

| Rule | Impact | Description |
|------|--------|-------------|
| `perf-parallel-data-fetching` | HIGH | Use Promise.all for independent data fetches |
| `perf-minimal-client-components` | HIGH | Keep 'use client' on smallest possible leaf components |
| `perf-suspense-boundaries` | MEDIUM | Stream slow content with Suspense boundaries |
| `perf-useeffect-data-fetching` | HIGH | Prefer Server Components over useEffect + fetch |

### 3. Architecture (CRITICAL-MEDIUM)

| Rule | Impact | Description |
|------|--------|-------------|
| `arch-dependency-direction` | CRITICAL | Dependencies flow downward only — never import upward |
| `arch-service-layer` | HIGH | Centralize business logic in service classes |
| `arch-repository-pattern` | HIGH | Abstract data access behind repository interfaces |
| `arch-factory-injection` | MEDIUM | Wire dependencies via factories, not direct instantiation |
| `arch-domain-entities` | MEDIUM | Keep domain entities pure — zero framework dependencies |
| `arch-interface-segregation` | MEDIUM | Split large interfaces into focused, role-based ones |
| `arch-build-order` | MEDIUM | Build bottom-up: types, domain, repo, service, API, UI |

### 4. Quality (MEDIUM-HIGH)

| Rule | Impact | Description |
|------|--------|-------------|
| `qual-dry-three-strikes` | HIGH | Extract duplicated logic after the third occurrence |
| `qual-service-result-pattern` | MEDIUM | Use consistent ServiceResult type for all service returns |
| `qual-search-before-creating` | MEDIUM | Search existing code before creating new utilities |
| `qual-scoped-logging` | MEDIUM | Use scoped loggers with structured context |

## Building

```bash
node scripts/build.js
```

This compiles all rule files into `AGENTS.md` for AI agent consumption.

## Contributing

See [CONTRIBUTING.md](../../CONTRIBUTING.md) in the repo root.
