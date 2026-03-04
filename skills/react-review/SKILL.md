---
name: beforemerge-react-review
description: Comprehensive code review rules for React applications (framework-agnostic). Covers security anti-patterns, performance pitfalls, architecture mistakes, and code quality issues. Use this skill when reviewing, writing, or refactoring React code — especially before merging pull requests. Triggers on tasks involving code review, PR review, security audit, performance review, or quality checks for React/TypeScript projects. Does not cover Next.js-specific patterns (see nextjs-review for that).
license: MIT
metadata:
  author: beforemerge
  version: "0.1.0"
  website: https://beforemerge.dev
---

# BeforeMerge: React Review

Comprehensive code review knowledge base for React applications (framework-agnostic). Contains rules across 4 categories — security, performance, architecture, and quality — prioritized by impact.

## When to Apply

Reference these rules when:
- Reviewing pull requests for React/TypeScript projects
- Writing new components, hooks, or utilities
- Auditing existing code for security vulnerabilities
- Refactoring code for performance or maintainability
- Running pre-merge quality checks

## Rule Categories by Priority

| Priority | Category | Impact | Prefix | Focus |
|----------|----------|--------|--------|-------|
| 1 | Security | CRITICAL | `sec-` | CWE-mapped anti-patterns |
| 2 | Performance | HIGH | `perf-` | Runtime rendering optimization |
| 3 | Architecture | MEDIUM | `arch-` | Design patterns and code organization |
| 4 | Quality | MEDIUM | `qual-` | Maintainability and code health |

## How to Use

Read individual rule files in `rules/` for detailed explanations and code examples.

Each rule contains:
- Brief explanation of why it matters
- Incorrect code example with explanation
- Correct code example with explanation
- CWE mapping where applicable
- References to official documentation

For the complete compiled guide: `AGENTS.md`
