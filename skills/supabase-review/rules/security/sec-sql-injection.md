---
title: Prevent SQL Injection in Custom RPC Functions
description: "String interpolation in .rpc() calls or custom PostgreSQL functions allows attackers to inject arbitrary SQL. Always use parameterized queries."
impact: CRITICAL
impact_description: prevents arbitrary SQL execution via user-controlled input
tags: [security, supabase, sql-injection, rpc, postgresql]
cwe: ["CWE-89"]
owasp: ["A03:2021"]
detection_grep: ".rpc("
---

## Prevent SQL Injection in Custom RPC Functions

**Impact: CRITICAL (prevents arbitrary SQL execution via user-controlled input)**

Supabase's PostgREST layer handles parameterization for standard CRUD queries (`.from().select()`, `.insert()`, etc.), making them safe from SQL injection. However, custom RPC functions called via `.rpc()` that build SQL with string concatenation or interpolation inside `EXECUTE` statements are fully vulnerable to SQL injection.

This is especially dangerous because RPC functions run with the caller's permissions (or the function owner's, if `SECURITY DEFINER`), and a successful injection can read, modify, or delete any data the function has access to.

**Incorrect (string concatenation in EXECUTE):**

```sql
-- ❌ SQL injection via string concatenation in PostgreSQL function
CREATE OR REPLACE FUNCTION search_rules(search_term text)
RETURNS SETOF rule AS $$
BEGIN
  -- Attacker can inject: ' OR 1=1 --
  -- Or worse: '; DROP TABLE rule; --
  RETURN QUERY EXECUTE
    'SELECT * FROM rule WHERE title LIKE ''%' || search_term || '%''';
END;
$$ LANGUAGE plpgsql;
```

```typescript
// app/api/rules/search/route.ts
export async function GET(request: Request) {
  const { searchParams } = new URL(request.url)
  const query = searchParams.get('q') ?? ''

  // ❌ User input goes directly into the vulnerable function
  const { data } = await supabase.rpc('search_rules', {
    search_term: query  // attacker sends: "' OR 1=1 --"
  })

  return Response.json(data)
}
```

**Correct (parameterized query with EXECUTE ... USING):**

```sql
-- ✅ Parameterized query prevents injection
CREATE OR REPLACE FUNCTION search_rules(search_term text)
RETURNS SETOF rule AS $$
BEGIN
  RETURN QUERY EXECUTE
    'SELECT * FROM rule WHERE title ILIKE $1'
    USING '%' || search_term || '%';
END;
$$ LANGUAGE plpgsql;
```

**Correct (avoid EXECUTE entirely when possible):**

```sql
-- ✅ Static SQL with parameters — no EXECUTE needed
CREATE OR REPLACE FUNCTION search_rules(search_term text)
RETURNS SETOF rule AS $$
  SELECT * FROM rule
  WHERE title ILIKE '%' || search_term || '%'
  ORDER BY created_at DESC
  LIMIT 50;
$$ LANGUAGE sql STABLE;
```

**Dynamic column names (allowlist pattern):**

```sql
-- ✅ Dynamic ORDER BY with format('%I') for identifier escaping
CREATE OR REPLACE FUNCTION list_rules(
  sort_column text DEFAULT 'created_at',
  sort_dir text DEFAULT 'desc'
)
RETURNS SETOF rule AS $$
BEGIN
  -- Validate sort_column against allowlist
  IF sort_column NOT IN ('created_at', 'title', 'impact', 'updated_at') THEN
    RAISE EXCEPTION 'Invalid sort column: %', sort_column;
  END IF;

  IF sort_dir NOT IN ('asc', 'desc') THEN
    RAISE EXCEPTION 'Invalid sort direction: %', sort_dir;
  END IF;

  -- %I safely quotes identifiers (prevents injection)
  RETURN QUERY EXECUTE
    format('SELECT * FROM rule ORDER BY %I %s LIMIT 100', sort_column, sort_dir);
END;
$$ LANGUAGE plpgsql STABLE;
```

**Detection hints:**

```bash
# Find all RPC calls that might pass user input
grep -rn ".rpc(" src/ --include="*.ts" --include="*.tsx"
# Find EXECUTE statements in migrations (check for parameterization)
grep -rn "EXECUTE" supabase/migrations/ --include="*.sql"
# Find string concatenation in SQL functions
grep -rn "||" supabase/migrations/ --include="*.sql"
```

Reference: [PostgreSQL EXECUTE](https://www.postgresql.org/docs/current/plpgsql-statements.html#PLPGSQL-STATEMENTS-EXECUTING-DYN) · [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html) · [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
