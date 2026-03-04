# Sections

This file defines all sections, their ordering, impact levels, and descriptions.
The section ID (in parentheses) is the filename prefix used to group rules.

---

## 1. Security Anti-Patterns (sec)

**Impact:** CRITICAL
**Description:** Security vulnerabilities that arise from improper layering, missing middleware, or leaked implementation details. Covers thin controllers, rate limiting, CSRF protection, and error message hygiene. Rules are mapped to CWE and OWASP Top 10 where applicable.

## 2. Performance Patterns (perf)

**Impact:** HIGH
**Description:** Patterns that cause slow page loads, unnecessary client-side JavaScript, request waterfalls, or blocked rendering. Focus on parallel data fetching, minimal client components, Suspense streaming, and proper data fetching boundaries.

## 3. Architecture Patterns (arch)

**Impact:** CRITICAL-MEDIUM
**Description:** SOLID and clean architecture patterns for layered fullstack applications. Covers dependency direction, service layer extraction, repository abstraction, factory injection, domain entity purity, interface segregation, and bottom-up build order.

## 4. Code Quality (qual)

**Impact:** MEDIUM-HIGH
**Description:** DRY patterns, consistent error handling, code discoverability, and structured logging. Ensures the codebase remains maintainable, searchable, and debuggable as the team and feature set grow.
