---
name: beforemerge-wordpress-review
description: Comprehensive code review rules for WordPress plugin and theme development. Covers security anti-patterns, performance pitfalls, architecture mistakes, and code quality issues. Use this skill when reviewing, writing, or refactoring WordPress/PHP code — especially before merging pull requests. Triggers on tasks involving code review, PR review, security audit, performance review, or quality checks for WordPress projects.
license: MIT
metadata:
  author: beforemerge
  version: "0.1.0"
  website: https://beforemerge.dev
---

# BeforeMerge: WordPress Review

Comprehensive code review knowledge base for WordPress plugin and theme development. Contains rules across 4 categories — security, performance, architecture, and quality — prioritized by impact.

## When to Apply

Reference these rules when:
- Reviewing pull requests for WordPress plugins or themes
- Writing new plugins, themes, widgets, or custom post types
- Auditing existing WordPress code for security vulnerabilities
- Refactoring code for performance or maintainability
- Running pre-merge quality checks on WordPress projects

## Rule Categories by Priority

| Priority | Category | Impact | Prefix | Focus |
|----------|----------|--------|--------|-------|
| 1 | Security | CRITICAL | `sec-` | OWASP/CWE mapped anti-patterns |
| 2 | Performance | HIGH | `perf-` | Database queries, caching, asset loading |
| 3 | Architecture | MEDIUM | `arch-` | WordPress APIs, hooks, and code organization |
| 4 | Quality | LOW-MEDIUM | `qual-` | Sanitization, i18n, error handling |

## How to Use

Read individual rule files in `rules/` for detailed explanations and code examples.

Each rule contains:
- Brief explanation of why it matters
- Incorrect PHP code example with explanation
- Correct PHP code example with explanation
- CWE/OWASP mapping where applicable
- References to official WordPress documentation

For the complete compiled guide: `AGENTS.md`
