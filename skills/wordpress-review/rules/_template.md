---
title: Rule Title Here
description: "One-line summary for search results and SEO (~160 chars max)"
impact: CRITICAL | HIGH | MEDIUM | LOW
impact_description: Optional explanation of why this impact level
tags: [category, wordpress, specific-topic]
cwe: ["CWE-XXX"]
owasp: ["A0X:2021"]
detection_grep: "pattern-to-search-for"
detection_semgrep: "pattern: $EXPR"
---

## Rule Title Here

**Impact: LEVEL (impact description)**

Brief explanation of the rule and why it matters. This should be clear and concise, explaining what can go wrong and who is affected.

**Incorrect (description of what's wrong):**

```php
// Bad code example here
// Include enough context for the pattern to be recognizable
```

**Correct (description of what's right):**

```php
// Good code example here
// Show the minimal change needed to fix the issue
```

**Additional context** (optional):

Extra notes, edge cases, or alternative approaches worth mentioning.

**Detection hints** (optional):

```
grep -r "pattern_to_search_for" wp-content/plugins/
```

Reference: [Link to official documentation](https://developer.wordpress.org/)
