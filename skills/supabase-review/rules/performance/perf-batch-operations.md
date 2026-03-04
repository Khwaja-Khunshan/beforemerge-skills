---
title: Use Batch Operations Instead of Single-Row Loops
description: "Inserting or updating rows one at a time in a loop creates N HTTP requests. Use .insert([...]) or .upsert([...]) to batch into a single request."
impact: HIGH
impact_description: N HTTP requests reduced to 1, prevents timeouts and connection exhaustion
tags: [performance, supabase, batch, bulk, insert, upsert]
detection_grep: "for.*insert("
---

## Use Batch Operations Instead of Single-Row Loops

**Impact: HIGH (N HTTP requests reduced to 1, prevents timeouts and connection exhaustion)**

Every Supabase `.insert()`, `.update()`, or `.upsert()` call is an HTTP request to the PostgREST API. When you perform these operations inside a loop — inserting rows one by one, or updating records individually — you create N HTTP round trips where a single batch call would suffice. This wastes network bandwidth, adds cumulative latency (each round trip adds 50-200ms), and can trigger rate limits or timeouts on serverless platforms with 10-second execution limits.

Supabase's `.insert()` and `.upsert()` natively accept arrays of objects, batching the entire operation into a single HTTP request and a single SQL transaction.

**Incorrect (inserting rows one at a time in a loop):**

```typescript
// ❌ One HTTP request per row — O(n) network round trips
export async function importProducts(
  supabase: SupabaseClient,
  csvRows: ProductRow[]
) {
  const results: ImportResult[] = []

  for (const row of csvRows) {
    // ❌ Each iteration fires a separate HTTP request
    const { data, error } = await supabase
      .from('products')
      .insert({
        name: row.name,
        sku: row.sku,
        price: parseFloat(row.price),
        category_id: row.category_id,
        description: row.description,
        stock_quantity: parseInt(row.stock),
      })
      .select('id')
      .single()

    results.push({
      sku: row.sku,
      success: !error,
      id: data?.id,
      error: error?.message,
    })
  }

  return results
}
// 500 products = 500 HTTP requests = ~50 seconds at 100ms per request
// Serverless timeout hit at ~100 rows
```

**Incorrect (updating records one at a time):**

```typescript
// ❌ Updating order statuses one by one
export async function markOrdersAsShipped(
  supabase: SupabaseClient,
  orderIds: string[],
  trackingNumbers: Map<string, string>
) {
  for (const orderId of orderIds) {
    // ❌ Each update is a separate HTTP request
    await supabase
      .from('orders')
      .update({
        status: 'shipped',
        shipped_at: new Date().toISOString(),
        tracking_number: trackingNumbers.get(orderId),
      })
      .eq('id', orderId)
  }
}
// 200 orders = 200 HTTP requests
```

**Incorrect (Promise.all doesn't fix the underlying problem):**

```typescript
// ❌ Promise.all reduces wall time but still creates N connections
export async function createNotifications(
  supabase: SupabaseClient,
  userIds: string[],
  message: string
) {
  // ❌ Still N HTTP requests — just concurrent instead of sequential
  await Promise.all(
    userIds.map((userId) =>
      supabase.from('notifications').insert({
        user_id: userId,
        message,
        read: false,
        created_at: new Date().toISOString(),
      })
    )
  )
}
// 1000 users = 1000 concurrent HTTP requests = potential rate limiting
```

**Correct (batch insert with array):**

```typescript
// ✅ Single HTTP request for all rows
export async function importProducts(
  supabase: SupabaseClient,
  csvRows: ProductRow[]
) {
  // ✅ Transform all rows first, then insert in one batch
  const products = csvRows.map((row) => ({
    name: row.name,
    sku: row.sku,
    price: parseFloat(row.price),
    category_id: row.category_id,
    description: row.description,
    stock_quantity: parseInt(row.stock),
  }))

  const { data, error } = await supabase
    .from('products')
    .insert(products)  // ✅ Array of objects — single HTTP request
    .select('id, sku')

  if (error) throw error
  return data
}
// 500 products = 1 HTTP request = ~200ms total
```

**Correct (batch upsert with conflict handling):**

```typescript
// ✅ Upsert batch — insert or update based on unique constraint
export async function syncInventoryFromWarehouse(
  supabase: SupabaseClient,
  inventoryUpdates: InventoryUpdate[]
) {
  const records = inventoryUpdates.map((update) => ({
    sku: update.sku,
    stock_quantity: update.quantity,
    warehouse_id: update.warehouseId,
    last_synced_at: new Date().toISOString(),
  }))

  // ✅ Single request — inserts new SKUs, updates existing ones
  const { data, error } = await supabase
    .from('inventory')
    .upsert(records, {
      onConflict: 'sku,warehouse_id',     // ✅ Unique constraint columns
      ignoreDuplicates: false,              // ✅ Update existing rows
    })
    .select('sku, stock_quantity')

  if (error) throw error
  return data
}
// 1000 inventory updates = 1 HTTP request + 1 SQL transaction
```

**Correct (chunked batching for very large datasets):**

```typescript
// ✅ For very large datasets, chunk into batches of ~1000 rows
export async function bulkCreateNotifications(
  supabase: SupabaseClient,
  userIds: string[],
  notification: { title: string; message: string; type: string }
) {
  const BATCH_SIZE = 1000 // ✅ PostgREST handles up to ~1000 rows per request efficiently
  const records = userIds.map((userId) => ({
    user_id: userId,
    title: notification.title,
    message: notification.message,
    type: notification.type,
    read: false,
    created_at: new Date().toISOString(),
  }))

  const results: { inserted: number; errors: string[] } = {
    inserted: 0,
    errors: [],
  }

  // ✅ Process in chunks — N/1000 requests instead of N requests
  for (let i = 0; i < records.length; i += BATCH_SIZE) {
    const chunk = records.slice(i, i + BATCH_SIZE)
    const { data, error } = await supabase
      .from('notifications')
      .insert(chunk)
      .select('id')

    if (error) {
      results.errors.push(
        `Batch ${Math.floor(i / BATCH_SIZE) + 1}: ${error.message}`
      )
    } else {
      results.inserted += data.length
    }
  }

  return results
}
// 10,000 users = 10 HTTP requests (not 10,000)
```

**Correct (batch update using upsert for multiple different values):**

```typescript
// ✅ When each row needs a different update value, use upsert
export async function markOrdersAsShipped(
  supabase: SupabaseClient,
  shipments: { orderId: string; trackingNumber: string }[]
) {
  const now = new Date().toISOString()

  // ✅ Build array of full row updates
  const updates = shipments.map((s) => ({
    id: s.orderId,
    status: 'shipped' as const,
    shipped_at: now,
    tracking_number: s.trackingNumber,
  }))

  // ✅ Single request — upsert matches on primary key (id)
  const { data, error } = await supabase
    .from('orders')
    .upsert(updates, { onConflict: 'id' })
    .select('id, status, tracking_number')

  if (error) throw error
  return data
}
// 200 orders = 1 HTTP request (not 200)
```

**Detection hints:**

```bash
# Find insert/upsert calls inside for loops
grep -rn "for.*insert(" src/ --include="*.ts" --include="*.tsx"
grep -rn "for.*upsert(" src/ --include="*.ts" --include="*.tsx"
# Find insert/update inside .map() or .forEach() callbacks
grep -rn "\.map(.*\.insert\|\.forEach(.*\.insert" src/ --include="*.ts" --include="*.tsx"
# Find Promise.all wrapping individual inserts
grep -rn "Promise.all" src/ --include="*.ts" -A 5 | grep "\.insert\|\.upsert\|\.update"
```

Reference: [Supabase Insert](https://supabase.com/docs/reference/javascript/insert) · [Supabase Upsert](https://supabase.com/docs/reference/javascript/upsert) · [PostgREST Bulk Insert](https://docs.postgrest.org/en/stable/references/api/tables_views.html#bulk-insert)
