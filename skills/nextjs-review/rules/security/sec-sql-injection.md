---
title: Never Build Database Queries with String Concatenation
description: "String concatenation in database queries creates injection vulnerabilities. Always use parameterized queries or ORM query builders."
impact: CRITICAL
impact_description: prevents SQL injection and NoSQL injection attacks
tags: [security, sql-injection, database, prisma, drizzle, nextjs]
cwe: ["CWE-89"]
owasp: ["A03:2021"]
detection_grep: "\\$queryRaw|execute(|query("
---

## Never Build Database Queries with String Concatenation

**Impact: CRITICAL (prevents SQL injection and NoSQL injection attacks)**

Constructing database queries by concatenating or interpolating user input creates injection vulnerabilities. This applies to raw SQL, ORM queries with raw segments, and NoSQL operations. Always use parameterized queries or ORM methods that handle escaping.

**Incorrect (string interpolation in raw SQL):**

```typescript
// ❌ Direct interpolation — classic SQL injection vector
export async function getUser(name: string) {
  const result = await prisma.$queryRaw`
    SELECT * FROM users WHERE name = '${name}'
  `
  return result
}

// ❌ String concatenation in query builder
export async function searchProducts(term: string) {
  const query = `SELECT * FROM products WHERE name LIKE '%${term}%'`
  const result = await db.execute(query)
  return result
}
```

**Correct (parameterized queries):**

```typescript
// ✅ Prisma tagged template (auto-parameterized)
export async function getUser(name: string) {
  const result = await prisma.$queryRaw(
    Prisma.sql`SELECT * FROM users WHERE name = ${name}`
  )
  return result
}

// ✅ Better: use the ORM's query builder
export async function getUser(name: string) {
  return prisma.user.findFirst({
    where: { name },
  })
}

// ✅ Drizzle parameterized query
export async function searchProducts(term: string) {
  return db
    .select()
    .from(products)
    .where(like(products.name, `%${term}%`))
}
```

**Also watch for Supabase:**

```typescript
// ❌ String interpolation in Supabase RPC
const { data } = await supabase.rpc('search_users', {
  query: `%${userInput}%`  // Could be safe depending on the function, but risky pattern
})

// ✅ Use Supabase query builder
const { data } = await supabase
  .from('users')
  .select('*')
  .ilike('name', `%${userInput}%`)  // Properly parameterized by the SDK
```

**Detection hints:**

```bash
# Find potential SQL injection patterns
grep -rn '\$queryRaw`' src/ --include="*.ts" --include="*.tsx" | grep '\${'
grep -rn "execute(" src/ --include="*.ts" | grep -E "(\+|concat|\`)"
grep -rn "query(" src/ --include="*.ts" | grep -E "(\+|concat|\`)"
```

Reference: [OWASP SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html) · [Prisma Raw Queries](https://www.prisma.io/docs/orm/prisma-client/using-raw-sql/raw-queries)
