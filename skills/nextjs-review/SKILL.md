---
name: beforemerge-nextjs-review
description: Comprehensive code review rules for Next.js, React, and TypeScript applications. Covers security anti-patterns, performance pitfalls, architecture mistakes, and code quality issues. Use this skill when reviewing, writing, or refactoring Next.js/React code — especially before merging pull requests. Triggers on tasks involving code review, PR review, security audit, performance review, or quality checks for React/Next.js/TypeScript projects.
license: MIT
metadata:
  author: beforemerge
  version: "0.1.0"
  website: https://beforemerge.dev
---

# BeforeMerge: Next.js Review

Comprehensive code review knowledge base for Next.js, React, and TypeScript applications. Contains rules across 4 categories — security, performance, architecture, and quality — prioritized by impact.

## When to Apply

Reference these rules when:
- Reviewing pull requests for Next.js/React/TypeScript projects
- Writing new components, API routes, or server actions
- Auditing existing code for security vulnerabilities
- Refactoring code for performance or maintainability
- Running pre-merge quality checks

## Rule Categories by Priority

| Priority | Category | Impact | Prefix | Focus |
|----------|----------|--------|--------|-------|
| 1 | Security | CRITICAL | `sec-` | OWASP/CWE mapped anti-patterns |
| 2 | Performance | HIGH | `perf-` | Runtime and build-time optimization |
| 3 | Architecture | MEDIUM | `arch-` | Design patterns and code organization |
| 4 | Quality | LOW-MEDIUM | `qual-` | Maintainability and code health |

## How to Use

Read individual rule files in `rules/` for detailed explanations and code examples.

Each rule contains:
- Brief explanation of why it matters
- Incorrect code example with explanation
- Correct code example with explanation
- CWE/OWASP mapping where applicable
- References to official documentation

For the complete compiled guide: `AGENTS.md`
