---
title: Use Cursor-Based Pagination Instead of Offset Pagination
description: "Using .range() offset pagination for large datasets forces PostgreSQL to scan all skipped rows. Use cursor-based pagination with .gt()/.lt() for constant-time page fetches."
impact: HIGH
impact_description: constant-time pagination vs. linear degradation on large datasets
tags: [performance, supabase, pagination, cursor, queries]
detection_grep: ".range("
---

## Use Cursor-Based Pagination Instead of Offset Pagination

**Impact: HIGH (constant-time pagination vs. linear degradation on large datasets)**

Supabase's `.range(from, to)` method translates to PostgreSQL's `OFFSET ... LIMIT ...`. While simple to implement, offset pagination has a critical performance flaw: PostgreSQL must scan and discard all rows before the offset. Page 1 scans 20 rows. Page 100 scans 2,000 rows and discards 1,980. Page 10,000 scans 200,000 rows. Query time grows linearly with page depth.

Cursor-based pagination uses a `WHERE` clause to start reading from a known position (the last item on the previous page). PostgreSQL jumps directly to that position using an index, making page 10,000 just as fast as page 1.

**Incorrect (offset pagination with .range()):**

```typescript
// ❌ Offset pagination — performance degrades on deep pages
import { createClient } from '@/lib/supabase/server'

export async function GET(request: Request) {
  const supabase = await createClient()
  const { searchParams } = new URL(request.url)
  const page = parseInt(searchParams.get('page') ?? '1')
  const pageSize = 20
  const from = (page - 1) * pageSize
  const to = from + pageSize - 1

  // ❌ .range() uses OFFSET — scans all skipped rows
  const { data: posts, error, count } = await supabase
    .from('posts')
    .select('id, title, excerpt, published_at, author:profiles(full_name)', { count: 'exact' })
    .eq('published', true)
    .order('published_at', { ascending: false })
    .range(from, to)

  if (error) throw error

  return Response.json({
    posts,
    page,
    totalPages: Math.ceil((count ?? 0) / pageSize),
  })
}
// Page 1:    OFFSET 0    → scans 20 rows   → ~2ms
// Page 500:  OFFSET 9980 → scans 10,000 rows → ~150ms
// Page 5000: OFFSET 99980 → scans 100,000 rows → ~1,500ms
```

**Incorrect (offset pagination in infinite scroll):**

```typescript
// ❌ Client-side infinite scroll using offset — gets slower as user scrolls
'use client'

import { useState, useEffect } from 'react'
import { createClient } from '@/lib/supabase/client'

export function InfinitePostList() {
  const [posts, setPosts] = useState<Post[]>([])
  const [page, setPage] = useState(0)
  const supabase = createClient()

  async function loadMore() {
    const pageSize = 20
    // ❌ Deep offsets cause increasingly slow queries
    const from = page * pageSize
    const to = from + pageSize - 1

    const { data } = await supabase
      .from('posts')
      .select('id, title, excerpt, published_at')
      .eq('published', true)
      .order('published_at', { ascending: false })
      .range(from, to)

    setPosts((prev) => [...prev, ...(data ?? [])])
    setPage((prev) => prev + 1)
  }

  // After loading 100 pages (2000 posts), each "load more" takes 1+ seconds
}
```

**Correct (cursor-based pagination with .gt()/.lt()):**

```typescript
// ✅ Cursor-based pagination — constant time regardless of page depth
import { createClient } from '@/lib/supabase/server'

export async function GET(request: Request) {
  const supabase = await createClient()
  const { searchParams } = new URL(request.url)
  const cursor = searchParams.get('cursor') // ISO timestamp of last item
  const pageSize = 20

  let query = supabase
    .from('posts')
    .select('id, title, excerpt, published_at, author:profiles(full_name)')
    .eq('published', true)
    .order('published_at', { ascending: false })
    .limit(pageSize + 1) // ✅ Fetch one extra to detect if there's a next page

  // ✅ If cursor is provided, start after the last seen item
  if (cursor) {
    query = query.lt('published_at', cursor)
  }

  const { data: posts, error } = await query

  if (error) throw error

  const hasNextPage = (posts?.length ?? 0) > pageSize
  const results = hasNextPage ? posts!.slice(0, pageSize) : (posts ?? [])
  const nextCursor = hasNextPage
    ? results[results.length - 1].published_at
    : null

  return Response.json({
    posts: results,
    nextCursor, // Client passes this back as ?cursor= for the next page
    hasNextPage,
  })
}
// Page 1:    WHERE published_at < NOW()       → index scan → ~2ms
// Page 5000: WHERE published_at < '2023-...'  → index scan → ~2ms (same speed!)
```

**Correct (cursor-based infinite scroll on the client):**

```typescript
// ✅ Client-side infinite scroll with cursor — stays fast at any depth
'use client'

import { useState, useCallback } from 'react'
import { createClient } from '@/lib/supabase/client'

export function InfinitePostList() {
  const [posts, setPosts] = useState<Post[]>([])
  const [nextCursor, setNextCursor] = useState<string | null>(null)
  const [hasMore, setHasMore] = useState(true)
  const [isLoading, setIsLoading] = useState(false)
  const supabase = createClient()

  const loadMore = useCallback(async () => {
    if (isLoading || !hasMore) return
    setIsLoading(true)

    const pageSize = 20
    let query = supabase
      .from('posts')
      .select('id, title, excerpt, published_at')
      .eq('published', true)
      .order('published_at', { ascending: false })
      .limit(pageSize + 1)

    // ✅ Use cursor to fetch next page — no offset
    if (nextCursor) {
      query = query.lt('published_at', nextCursor)
    }

    const { data, error } = await query
    if (error) {
      console.error('Failed to load posts:', error)
      setIsLoading(false)
      return
    }

    const hasNextPage = (data?.length ?? 0) > pageSize
    const newPosts = hasNextPage ? data!.slice(0, pageSize) : (data ?? [])

    setPosts((prev) => [...prev, ...newPosts])
    setNextCursor(
      hasNextPage ? newPosts[newPosts.length - 1].published_at : null
    )
    setHasMore(hasNextPage)
    setIsLoading(false)
  }, [nextCursor, hasMore, isLoading, supabase])

  // Even after scrolling through 10,000 posts, loadMore stays <5ms
}
```

**Correct (compound cursor for non-unique sort columns):**

```typescript
// ✅ When the sort column isn't unique, use a compound cursor (column + id)
export async function GET(request: Request) {
  const supabase = await createClient()
  const { searchParams } = new URL(request.url)
  const cursorDate = searchParams.get('cursor_date')
  const cursorId = searchParams.get('cursor_id')
  const pageSize = 20

  let query = supabase
    .from('posts')
    .select('id, title, published_at')
    .eq('published', true)
    .order('published_at', { ascending: false })
    .order('id', { ascending: false }) // ✅ Tiebreaker on unique column
    .limit(pageSize + 1)

  if (cursorDate && cursorId) {
    // ✅ Compound cursor: skip past items with same timestamp using id
    query = query.or(
      `published_at.lt.${cursorDate},and(published_at.eq.${cursorDate},id.lt.${cursorId})`
    )
  }

  const { data: posts, error } = await query
  if (error) throw error

  const hasNextPage = (posts?.length ?? 0) > pageSize
  const results = hasNextPage ? posts!.slice(0, pageSize) : (posts ?? [])
  const lastItem = results[results.length - 1]

  return Response.json({
    posts: results,
    nextCursor: hasNextPage
      ? { date: lastItem.published_at, id: lastItem.id }
      : null,
    hasNextPage,
  })
}
```

**When offset pagination is acceptable:**

- Small datasets (< 1,000 rows) where performance difference is negligible
- Admin/backoffice pages where users need to jump to specific page numbers
- When total count and page number display are hard requirements

**Detection hints:**

```bash
# Find .range() calls — likely offset pagination
grep -rn ".range(" src/ --include="*.ts" --include="*.tsx"
# Find page number patterns that suggest offset pagination
grep -rn "page.*pageSize\|offset.*limit" src/ --include="*.ts" --include="*.tsx"
```

Reference: [Supabase Pagination](https://supabase.com/docs/guides/database/pagination) · [Use the Index, Luke — Pagination](https://use-the-index-luke.com/no-offset)
