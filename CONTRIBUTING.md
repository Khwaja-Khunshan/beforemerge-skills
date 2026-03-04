# Contributing to BeforeMerge

Thanks for your interest in contributing! BeforeMerge is better when more teams share the patterns they've learned.

## How to Contribute a New Rule

### 1. Pick a Category

| Prefix | Category | Focus |
|--------|----------|-------|
| `sec-` | Security | Vulnerabilities, OWASP/CWE mapped |
| `perf-` | Performance | Runtime, bundle, load time |
| `arch-` | Architecture | Design, structure, patterns |
| `qual-` | Quality | Maintainability, testing, readability |

### 2. Copy the Template

```bash
cp skills/nextjs-review/rules/_template.md skills/nextjs-review/rules/CATEGORY/PREFIX-description.md
```

Example: `skills/nextjs-review/rules/security/sec-csrf-protection.md`

### 3. Write Your Rule

Every rule must include:

- **YAML frontmatter** with `title`, `impact`, and `tags`
- **Why it matters** — a brief explanation
- **Incorrect example** — realistic bad code with explanation
- **Correct example** — the fix, showing minimal changes
- **CWE/OWASP mapping** (for security rules)
- **Detection hints** (optional but encouraged)
- **Reference link** to official docs

### 4. Quality Standards

- **Framework-specific:** Rules should target a specific framework/library, not generic advice.
- **Real code:** Examples should look like code you'd find in a real PR, not contrived demos.
- **Concise:** Each rule should be self-contained and readable in under 2 minutes.
- **Actionable:** A developer should know exactly what to change after reading the rule.

### 5. Build and Test

```bash
node scripts/build.js nextjs-review
```

Verify the generated `AGENTS.md` includes your rule correctly.

### 6. Submit a PR

- One rule per PR (or a small batch of related rules)
- Include a brief description of why this pattern matters
- Reference any real-world incidents or CVEs if applicable

## Proposing a New Skill

Want to add rules for a new framework (e.g., `php-review`, `rails-review`)?

1. Open an issue describing the framework and initial rule ideas
2. Create the skill directory structure following the `nextjs-review` pattern
3. Start with at least 5 high-impact rules
4. Submit a PR

## Code of Conduct

Be kind. Be helpful. We're all here to write better code.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
