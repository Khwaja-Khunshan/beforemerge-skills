# Sections

This file defines all sections, their ordering, impact levels, and descriptions.
The section ID (in parentheses) is the filename prefix used to group rules.

---

## 1. Security Anti-Patterns (sec)

**Impact:** CRITICAL
**Description:** Security vulnerabilities specific to Supabase applications — RLS misconfigurations, auth bypass via getSession(), service role key exposure, and schema drift from untracked changes. Rules are mapped to CWE and OWASP Top 10 where applicable. These must be caught before any code reaches production.

## 2. Performance Patterns (perf)

**Impact:** HIGH
**Description:** Query anti-patterns that cause slow responses, connection exhaustion, or database overload in Supabase applications. Covers N+1 queries, missing indexes, wasteful selects, pagination strategies, connection pooling, and batch operations.

## 3. Architecture Patterns (arch)

**Impact:** MEDIUM
**Description:** Structural decisions around Supabase client usage, type generation, and migration workflows that affect maintainability and correctness over time. Includes client selection rules for Next.js contexts, automated type generation, and migration file conventions.

## 4. Code Quality (qual)

**Impact:** LOW-MEDIUM
**Description:** Patterns that affect reliability, debuggability, and long-term code health in Supabase applications. Covers error handling for Supabase query responses, unchecked error destructuring, and runtime input validation.
