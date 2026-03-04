# BeforeMerge

**The comprehensive, AI-native code review knowledge base.**

Know what to check — *before you merge.*

BeforeMerge is a structured collection of code review rules, anti-patterns, and best practices designed for AI coding agents and human reviewers. Each rule includes bad → good code examples, impact ratings, and references to formal weakness IDs (CWE/OWASP).

## Why BeforeMerge?

Existing code review resources are fragmented:

- **Linters** catch syntax issues but don't educate.
- **AI review tools** are shallow — no structured knowledge base behind them.
- **OWASP/CWE docs** are exhaustive but not actionable or AI-consumable.

BeforeMerge combines **detection + education + AI-native format** in one place.

## Quick Start

Install as an Agent Skill (works with Claude Code, Cursor, Codex, OpenCode):

```bash
npx skills add BeforeMerge/beforemerge --skill nextjs-review
```

Or browse the rules directly in `skills/nextjs-review/rules/`.

## Structure

```
skills/
└── nextjs-review/          # Next.js / React / TypeScript review skill
    ├── SKILL.md             # Agent-facing metadata + trigger description
    ├── AGENTS.md            # Compiled output (all rules in one doc)
    ├── metadata.json        # Version and organization info
    ├── rules/               # Individual rule files
    │   ├── _sections.md     # Section metadata and ordering
    │   ├── _template.md     # Template for contributing new rules
    │   ├── security/        # Security anti-patterns (OWASP/CWE mapped)
    │   ├── performance/     # Performance patterns
    │   ├── architecture/    # Architecture and design patterns
    │   └── quality/         # Code quality and maintainability
    └── README.md            # Skill-specific documentation
```

## Rule Format

Each rule is a markdown file with YAML frontmatter:

```markdown
---
title: Descriptive Rule Title
impact: CRITICAL | HIGH | MEDIUM | LOW
tags: [security, nextjs, server-actions]
cwe: CWE-862    # Optional: formal weakness ID
owasp: A01:2021  # Optional: OWASP Top 10 mapping
---

## Rule Title

Why this matters and what to look for.

**Incorrect (what's wrong and why):**

\```typescript
// Bad code example
\```

**Correct (what's right and why):**

\```typescript
// Good code example
\```

Reference: [link to docs]
```

## Available Skills

| Skill | Rules | Categories | Status |
|-------|-------|------------|--------|
| `nextjs-review` | 10+ | Security, Performance, Architecture, Quality | 🚧 In Progress |
| `php-review` | — | — | 📋 Planned |
| `rails-review` | — | — | 📋 Planned |

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

1. Copy `rules/_template.md` to the appropriate category directory
2. Follow the naming convention: `category-description.md`
3. Include bad → good code examples with explanations
4. Add CWE/OWASP mappings where applicable
5. Submit a PR

## Philosophy

- **Framework-specific:** Generic advice is useless. Rules target specific frameworks with specific code.
- **AI-native:** Structured for consumption by Claude Code, Cursor, Codex, and other AI agents.
- **Education-first:** Every rule explains *why*, not just *what*.
- **Formally mapped:** Rules link to CWE, OWASP, and other standards where applicable.
- **Community-driven:** Open source. The more teams contribute patterns, the better everyone's code gets.

## License

MIT — use it, fork it, improve it.

---

Built by [Chykalophia](https://chykalophia.com) • Created by [Peter Krzyzek](https://github.com/peterkrzyzek)
