---
title: Avoid select('*') — Request Only the Columns You Need
description: "Using .select('*') fetches all columns including large text/json fields, wastes bandwidth, leaks data shape, and prevents index-only scans."
impact: HIGH
impact_description: reduces payload size 2-10x, enables index-only scans, prevents data leakage
tags: [performance, supabase, queries, select, bandwidth]
detection_grep: "select('*')"
---

## Avoid select('*') — Request Only the Columns You Need

**Impact: HIGH (reduces payload size 2-10x, enables index-only scans, prevents data leakage)**

Using `.select('*')` in Supabase queries fetches every column from the table, including large `text`, `jsonb`, and `bytea` fields that your UI may never render. This creates three problems:

1. **Wasted bandwidth** — large columns (markdown content, JSON metadata, file data) inflate every response. A table with a `content` column averaging 5KB per row turns a 100-row list query from ~20KB to ~500KB.
2. **No index-only scans** — PostgreSQL can satisfy queries entirely from an index if you only request indexed columns. `SELECT *` forces a heap fetch for every row, which is significantly slower on large tables.
3. **Data leakage** — even with RLS, `select('*')` exposes the full table schema and may return sensitive columns (internal notes, soft-delete flags, audit fields) that the frontend should never see.

**Incorrect (select all columns for a list view):**

```typescript
// ❌ Fetches all columns including large 'content' and 'metadata' fields
export async function getArticles(supabase: SupabaseClient) {
  const { data, error } = await supabase
    .from('articles')
    .select('*')
    .eq('published', true)
    .order('published_at', { ascending: false })
    .limit(20)

  if (error) throw error
  return data
}
// Each article has a 'content' column (avg 8KB of markdown)
// and a 'metadata' column (avg 2KB of JSON)
// List view only shows title, excerpt, and date
// Payload: ~200KB instead of ~15KB
```

**Incorrect (select all in server component data fetching):**

```typescript
// ❌ Fetches full user profile including fields never displayed
async function MemberList({ teamId }: { teamId: string }) {
  const supabase = await createClient()
  const { data: members } = await supabase
    .from('profiles')
    .select('*')  // ❌ Returns: id, full_name, email, avatar_url, bio,
                   //           settings (jsonb), onboarding_state (jsonb),
                   //           stripe_customer_id, internal_notes, ...
    .in('id', teamMemberIds)

  return (
    <ul>
      {members?.map((m) => (
        <li key={m.id}>
          <Avatar url={m.avatar_url} />
          <span>{m.full_name}</span>
        </li>
      ))}
    </ul>
  )
}
// Only uses 3 columns, fetches 15+
```

**Correct (select only the columns needed):**

```typescript
// ✅ Request only columns the list view actually renders
export async function getArticles(supabase: SupabaseClient) {
  const { data, error } = await supabase
    .from('articles')
    .select('id, title, excerpt, slug, published_at, author:profiles(full_name, avatar_url)')
    .eq('published', true)
    .order('published_at', { ascending: false })
    .limit(20)

  if (error) throw error
  return data
}
// Payload: ~15KB — only the fields rendered in the card grid
// PostgreSQL can use an index-only scan on (published, published_at) covering (id, title, excerpt, slug)
```

**Correct (targeted select for member list):**

```typescript
// ✅ Only the 3 columns actually used in the UI
async function MemberList({ teamId }: { teamId: string }) {
  const supabase = await createClient()
  const { data: members, error } = await supabase
    .from('team_members')
    .select(`
      role,
      user:profiles (
        id,
        full_name,
        avatar_url
      )
    `)
    .eq('team_id', teamId)
    .order('role')

  if (error) throw error

  return (
    <ul>
      {members?.map((m) => (
        <li key={m.user.id}>
          <Avatar url={m.user.avatar_url} />
          <span>{m.user.full_name}</span>
          <Badge>{m.role}</Badge>
        </li>
      ))}
    </ul>
  )
}
// No sensitive fields ever leave the database
```

**Correct (full detail view — select('*') is acceptable here):**

```typescript
// ✅ Fetching all columns is fine for a single-record detail view
export async function getArticleBySlug(supabase: SupabaseClient, slug: string) {
  const { data, error } = await supabase
    .from('articles')
    .select(`
      id,
      title,
      content,
      excerpt,
      slug,
      published_at,
      metadata,
      author:profiles (
        id,
        full_name,
        avatar_url,
        bio
      )
    `)
    .eq('slug', slug)
    .single()

  if (error) throw error
  return data
}
// Single record — even with large content column, this is fine
// Still explicitly name columns to avoid leaking internal fields
```

**Detection hints:**

```bash
# Find all select('*') calls
grep -rn "select('*')" src/ --include="*.ts" --include="*.tsx"
# Find select("*") with double quotes
grep -rn 'select("*")' src/ --include="*.ts" --include="*.tsx"
# Find .select() with no arguments (defaults to *)
grep -rn "\.select()" src/ --include="*.ts" --include="*.tsx"
```

Reference: [Supabase Select Query](https://supabase.com/docs/reference/javascript/select) · [PostgreSQL Index-Only Scans](https://www.postgresql.org/docs/current/indexes-index-only-scans.html)
