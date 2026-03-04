# Sections

This file defines all sections, their ordering, impact levels, and descriptions.
The section ID (in parentheses) is the filename prefix used to group rules.

---

## 1. Security Anti-Patterns (sec)

**Impact:** CRITICAL
**Description:** Security vulnerabilities that can lead to data breaches, unauthorized access, or system compromise. Rules are mapped to CWE and OWASP Top 10 where applicable. WordPress-specific patterns include SQL injection via $wpdb, XSS via missing escaping functions, CSRF via missing nonces, and PHP object injection. These should be caught before any code reaches production.

## 2. Performance Patterns (perf)

**Impact:** HIGH
**Description:** Patterns that cause slow page loads, excessive database queries, high memory usage, or server-side bottlenecks. Focus on WordPress-specific patterns like N+1 queries in post loops, missing transient/object caching, autoloaded option bloat, and improper asset enqueueing.

## 3. Architecture Patterns (arch)

**Impact:** MEDIUM
**Description:** Design decisions that affect maintainability, portability, and compatibility with the WordPress ecosystem. Includes proper use of WordPress APIs, correct hook timing, avoiding hardcoded paths, and following WordPress coding patterns.

## 4. Code Quality (qual)

**Impact:** LOW-MEDIUM
**Description:** Patterns that affect readability, security hygiene, internationalization, and long-term code health. Includes proper input sanitization, translation-ready strings, and idiomatic WordPress error handling.
