# Sections

This file defines all sections, their ordering, impact levels, and descriptions.
The section ID (in parentheses) is the filename prefix used to group rules.

---

## 1. Security Anti-Patterns (sec)

**Impact:** CRITICAL
**Description:** Security vulnerabilities that can lead to data breaches, unauthorized access, or system compromise. Rules are mapped to CWE and OWASP Top 10 where applicable. These should be caught before any code reaches production.

## 2. Performance Patterns (perf)

**Impact:** HIGH
**Description:** Patterns that cause slow page loads, poor Core Web Vitals, excessive bundle sizes, or server-side bottlenecks. Focus on measurable impact to user experience and system resources.

## 3. Architecture Patterns (arch)

**Impact:** MEDIUM
**Description:** Design decisions that affect maintainability, scalability, and team productivity over time. Includes component design, state management, data flow, and separation of concerns.

## 4. Code Quality (qual)

**Impact:** LOW-MEDIUM
**Description:** Patterns that affect readability, testability, error handling, and long-term code health. Important for team velocity and reducing bugs over time.
