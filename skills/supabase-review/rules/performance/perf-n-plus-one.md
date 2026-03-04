---
title: Avoid N+1 Queries with Supabase Relational Selects
description: "Fetching parent records then looping to fetch children creates N+1 HTTP requests. Use Supabase nested .select('*, children(*)') to resolve in a single query."
impact: HIGH
impact_description: 10-100x query reduction, eliminates serial HTTP round trips
tags: [performance, supabase, n-plus-one, queries, postgresql]
cwe: ["CWE-400"]
detection_grep: "forEach.*from("
---

## Avoid N+1 Queries with Supabase Relational Selects

**Impact: HIGH (10-100x query reduction, eliminates serial HTTP round trips)**

N+1 queries are the most common performance killer in Supabase applications. The pattern occurs when you fetch a list of parent records (1 query), then iterate over each parent to fetch its children individually (N queries). Because every Supabase `.from().select()` call is a full HTTP request to the PostgREST API, this creates N+1 network round trips — not just N+1 database queries. With 200 parent records, you send 201 HTTP requests when a single request would suffice.

Supabase supports PostgREST's resource embedding, allowing you to fetch nested relations through foreign keys in one `.select()` call.

**Incorrect (N+1 — forEach loop firing individual queries):**

```typescript
// ❌ API route that creates N+1 HTTP requests to Supabase
import { createClient } from '@/lib/supabase/server'

export async function GET(request: Request) {
  const supabase = await createClient()
  const { searchParams } = new URL(request.url)
  const orgId = searchParams.get('org_id')

  // 1 query: fetch all teams in the org
  const { data: teams } = await supabase
    .from('teams')
    .select('id, name, slug')
    .eq('org_id', orgId!)

  const teamsWithMembers: TeamWithMembers[] = []

  // ❌ N queries: forEach fires one request per team
  teams?.forEach(async (team) => {
    const { data: members } = await supabase
      .from('team_members')
      .select('id, role, user:profiles(id, full_name, avatar_url)')
      .eq('team_id', team.id)

    teamsWithMembers.push({ ...team, members: members ?? [] })
  })

  // Bug: forEach with async doesn't await — response may be empty
  return Response.json(teamsWithMembers)
}
// 30 teams = 31 HTTP requests, plus a race condition bug
```

**Incorrect (hidden N+1 in React Server Components):**

```typescript
// ❌ Parent component fetches list, child component fetches per-item
async function OrderHistory({ userId }: { userId: string }) {
  const supabase = await createClient()
  const { data: orders } = await supabase
    .from('orders')
    .select('id, status, total, created_at')
    .eq('user_id', userId)
    .order('created_at', { ascending: false })

  return (
    <div>
      {orders?.map((order) => (
        // Each OrderRow independently queries for its line items
        <OrderRow key={order.id} orderId={order.id} />
      ))}
    </div>
  )
}

async function OrderRow({ orderId }: { orderId: string }) {
  const supabase = await createClient()
  // ❌ Fires once per order — N additional queries
  const { data: items } = await supabase
    .from('order_items')
    .select('id, quantity, product:products(name, price, image_url)')
    .eq('order_id', orderId)

  return <div>{items?.length} items</div>
}
```

**Correct (single query with Supabase nested select):**

```typescript
// ✅ One HTTP request fetches teams + members + profile data
import { createClient } from '@/lib/supabase/server'

export async function GET(request: Request) {
  const supabase = await createClient()
  const { searchParams } = new URL(request.url)
  const orgId = searchParams.get('org_id')

  // ✅ Nested select resolves all relations in a single PostgREST call
  const { data: teams, error } = await supabase
    .from('teams')
    .select(`
      id,
      name,
      slug,
      team_members (
        id,
        role,
        joined_at,
        user:profiles (
          id,
          full_name,
          avatar_url
        )
      )
    `)
    .eq('org_id', orgId!)
    .order('name')

  if (error) {
    return Response.json({ error: error.message }, { status: 500 })
  }

  return Response.json(teams)
}
// 30 teams = 1 HTTP request with all members and profiles embedded
```

**Correct (fix the server component N+1):**

```typescript
// ✅ Fetch all data at the parent level, pass down as props
async function OrderHistory({ userId }: { userId: string }) {
  const supabase = await createClient()

  const { data: orders, error } = await supabase
    .from('orders')
    .select(`
      id,
      status,
      total,
      created_at,
      order_items (
        id,
        quantity,
        product:products (
          name,
          price,
          image_url
        )
      )
    `)
    .eq('user_id', userId)
    .order('created_at', { ascending: false })

  if (error) throw error

  return (
    <div>
      {orders?.map((order) => (
        // ✅ No Supabase call in child — data already resolved
        <OrderRow key={order.id} order={order} />
      ))}
    </div>
  )
}

function OrderRow({ order }: { order: OrderWithItems }) {
  return <div>{order.order_items.length} items</div>
}
```

**Correct (batch with .in() when no foreign key relation exists):**

```typescript
// ✅ Two queries instead of N+1 when tables aren't directly related
async function getProductsWithReviewCounts(categoryId: string) {
  const supabase = await createClient()

  const { data: products } = await supabase
    .from('products')
    .select('id, name, price')
    .eq('category_id', categoryId)

  const productIds = products?.map((p) => p.id) ?? []

  // ✅ Single query for all review counts
  const { data: reviewCounts } = await supabase
    .rpc('get_review_counts', { product_ids: productIds })

  const countsMap = new Map(reviewCounts?.map((r) => [r.product_id, r.count]))

  return products?.map((product) => ({
    ...product,
    reviewCount: countsMap.get(product.id) ?? 0,
  }))
}
// 100 products = 2 HTTP requests (not 101)
```

**Detection hints:**

```bash
# Find queries inside forEach — classic N+1 pattern
grep -rn "forEach.*from(" src/ --include="*.ts" --include="*.tsx"
# Find async map callbacks that call Supabase
grep -rn "\.map(async" src/ --include="*.ts" --include="*.tsx" -A 5 | grep "\.from("
# Find Supabase calls inside child server components
grep -rn "await.*supabase" src/ --include="*.tsx" -B 3 | grep "function.*{.*:.*string"
```

Reference: [PostgREST Resource Embedding](https://docs.postgrest.org/en/stable/references/api/resource_embedding.html) · [Supabase Querying Joins](https://supabase.com/docs/guides/database/joins-and-nesting)
