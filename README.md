# BeforeMerge

**The comprehensive, AI-native code review knowledge base.**

Know what to check — *before you merge.*

BeforeMerge is a structured collection of code review rules, anti-patterns, and best practices designed for AI coding agents and human reviewers. Each rule includes bad → good code examples, impact ratings, CWE/OWASP mappings, and detection hints.

## Why BeforeMerge?

Existing code review resources are fragmented:

- **Linters** catch syntax issues but don't educate.
- **AI review tools** are shallow — no structured knowledge base behind them.
- **OWASP/CWE docs** are exhaustive but not actionable or AI-consumable.

BeforeMerge combines **detection + education + AI-native format** in one place.

## Quick Start

Install as an Agent Skill (works with Claude Code, Cursor, Codex, OpenCode):

```bash
# Pick a skill
npx skills add BeforeMerge/beforemerge-skills --skill nextjs-review
npx skills add BeforeMerge/beforemerge-skills --skill supabase-review
npx skills add BeforeMerge/beforemerge-skills --skill fullstack-architecture-review
npx skills add BeforeMerge/beforemerge-skills --skill wordpress-review
```

Or browse the rules directly in `skills/*/rules/`.

## Available Skills

| Skill | Rules | Focus | Status |
|-------|-------|-------|--------|
| [`nextjs-review`](skills/nextjs-review/) | 31 | Security (XSS, CSRF, auth), performance (RSC, dynamic imports, closures), architecture | ✅ Ready |
| [`supabase-review`](skills/supabase-review/) | 20 | RLS security, auth patterns, query performance, migrations, type safety | ✅ Ready |
| [`fullstack-architecture-review`](skills/fullstack-architecture-review/) | 19 | DRY/SOLID, layered architecture, service/repository patterns, factory DI | ✅ Ready |
| [`wordpress-review`](skills/wordpress-review/) | 18 | SQL injection, XSS, CSRF nonces, query optimization, caching | ✅ Ready |

**88 rules** total across 4 skills.

## Structure

```
skills/
├── nextjs-review/                      # Next.js / React / TypeScript
├── supabase-review/                    # Supabase / PostgreSQL / RLS
├── fullstack-architecture-review/      # DRY / SOLID / Clean Architecture
└── wordpress-review/                   # WordPress / PHP
    ├── SKILL.md             # Agent-facing metadata + trigger description
    ├── AGENTS.md            # Compiled output (all rules in one doc)
    ├── metadata.json        # Version and organization info
    ├── README.md            # Skill-specific documentation
    └── rules/
        ├── _sections.md     # Section metadata and ordering
        ├── _template.md     # Template for contributing new rules
        ├── security/        # Security anti-patterns (CWE/OWASP mapped)
        ├── performance/     # Performance patterns
        ├── architecture/    # Architecture and design patterns
        └── quality/         # Code quality and maintainability
```

## Rule Format

Each rule is a markdown file with YAML frontmatter:

```markdown
---
title: Descriptive Rule Title
description: "One-line summary for search results"
impact: CRITICAL | HIGH | MEDIUM | LOW
tags: [security, nextjs, server-actions]
cwe: ["CWE-862"]
owasp: ["A01:2021"]
detection_grep: "pattern-to-find-violations"
---

## Rule Title

Why this matters and what to look for.

**Incorrect (what's wrong and why):**

\```typescript
// Bad code example with explanation
\```

**Correct (what's right and why):**

\```typescript
// Good code example with explanation
\```

Reference: [link to official docs]
```

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

1. Pick a skill and category (`security/`, `performance/`, `architecture/`, `quality/`)
2. Copy `rules/_template.md` to the appropriate directory
3. Follow the naming convention: `prefix-description.md` (e.g., `sec-sql-injection.md`)
4. Include bad → good code examples with explanations
5. Add CWE/OWASP mappings where applicable
6. Submit a PR

## Philosophy

- **Framework-specific:** Generic advice is useless. Rules target specific frameworks with specific code.
- **AI-native:** Structured for consumption by Claude Code, Cursor, Codex, and other AI agents.
- **Education-first:** Every rule explains *why*, not just *what*.
- **Formally mapped:** Rules link to CWE, OWASP, and other standards where applicable.
- **Community-driven:** Open source. The more teams contribute patterns, the better everyone's code gets.

## License

MIT — use it, fork it, improve it.

---

Built by [BeforeMerge](https://beforemerge.dev) • Created by [Peter Krzyzek](https://github.com/peterkrzyzek)
