---
name: beforemerge-supabase-review
description: Comprehensive code review rules for Supabase applications including RLS security, auth patterns, query performance, migration workflows, and type safety. Use this skill when reviewing, writing, or refactoring Supabase-backed code — especially before merging pull requests. Triggers on tasks involving code review, PR review, security audit, performance review, or quality checks for Supabase/PostgreSQL projects.
license: MIT
metadata:
  author: beforemerge
  version: "0.1.0"
  website: https://beforemerge.dev
---

# BeforeMerge: Supabase Review

Comprehensive code review knowledge base for Supabase applications. Contains rules across 4 categories — security, performance, architecture, and quality — prioritized by impact.

## When to Apply

Reference these rules when:
- Reviewing pull requests that touch Supabase queries, RLS policies, or migrations
- Writing new database tables, policies, or server-side Supabase calls
- Auditing existing code for RLS gaps, auth misuse, or query anti-patterns
- Refactoring Supabase integration for performance or maintainability
- Running pre-merge quality checks on Supabase-related changes

## Rule Categories by Priority

| Priority | Category | Impact | Prefix | Focus |
|----------|----------|--------|--------|-------|
| 1 | Security | CRITICAL | `sec-` | RLS, auth, service role, migration safety |
| 2 | Performance | HIGH | `perf-` | Query optimization, connection pooling, pagination |
| 3 | Architecture | MEDIUM | `arch-` | Client selection, type generation, migration structure |
| 4 | Quality | LOW-MEDIUM | `qual-` | Error handling, input validation, unchecked errors |

## How to Use

Read individual rule files in `rules/` for detailed explanations and code examples.

Each rule contains:
- Brief explanation of why it matters
- Incorrect code example with explanation
- Correct code example with explanation
- CWE/OWASP mapping where applicable
- References to official documentation

For the complete compiled guide: `AGENTS.md`
