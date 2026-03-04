---
name: beforemerge-fullstack-architecture-review
description: Code review rules for DRY/SOLID layered architecture in fullstack TypeScript applications. Covers dependency direction, service/repository patterns, factory injection, domain entities, security hardening, performance optimization, and code quality patterns. Use this skill when reviewing, writing, or refactoring fullstack TypeScript code with layered architecture — especially before merging pull requests. Triggers on tasks involving code review, architecture review, SOLID principles, clean architecture, or quality checks for fullstack TypeScript projects.
license: MIT
metadata:
  author: beforemerge
  version: "0.1.0"
  website: https://beforemerge.dev
---

# BeforeMerge: Fullstack Architecture Review

Code review knowledge base for DRY/SOLID layered architecture in fullstack TypeScript applications. Contains rules across 4 categories — security, performance, architecture, and quality — prioritized by impact. Framework-agnostic principles illustrated with Next.js + Supabase examples.

## When to Apply

Reference these rules when:
- Reviewing pull requests for fullstack TypeScript projects
- Designing or refactoring service/repository layers
- Auditing API routes for proper separation of concerns
- Building new features following clean architecture principles
- Running pre-merge quality checks on layered codebases

## Rule Categories by Priority

| Priority | Category | Impact | Prefix | Focus |
|----------|----------|--------|--------|-------|
| 1 | Security | CRITICAL | `sec-` | Thin controllers, rate limiting, CSRF, error handling |
| 2 | Performance | HIGH | `perf-` | Parallel fetching, minimal client components, streaming |
| 3 | Architecture | CRITICAL-MEDIUM | `arch-` | SOLID patterns, dependency direction, layered design |
| 4 | Quality | MEDIUM-HIGH | `qual-` | DRY, consistency, logging, discoverability |

## How to Use

Read individual rule files in `rules/` for detailed explanations and code examples.

Each rule contains:
- Brief explanation of why it matters
- Incorrect code example with explanation
- Correct code example with explanation
- CWE/OWASP mapping where applicable
- References to official documentation

For the complete compiled guide: `AGENTS.md`
