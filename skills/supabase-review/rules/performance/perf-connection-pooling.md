---
title: Use Connection Pooling (Supavisor) for Serverless Deployments
description: "Each serverless invocation opening a direct database connection exhausts PostgreSQL's connection limit. Use Supavisor pooler URLs for all serverless environments."
impact: HIGH
impact_description: prevents connection exhaustion and database downtime under load
tags: [performance, supabase, connection-pooling, serverless, supavisor]
detection_grep: "NEXT_PUBLIC_SUPABASE_URL"
---

## Use Connection Pooling (Supavisor) for Serverless Deployments

**Impact: HIGH (prevents connection exhaustion and database downtime under load)**

PostgreSQL has a hard limit on the number of simultaneous connections (default ~60 on Supabase's Micro plan, ~200 on Pro). In serverless environments — Next.js Edge Runtime, Vercel Serverless Functions, Supabase Edge Functions, AWS Lambda — every invocation can create a new connection. A traffic spike of 100 concurrent requests means 100 simultaneous PostgreSQL connections, which can instantly exhaust the pool and crash your database with `FATAL: too many connections for role` errors.

Supabase provides Supavisor, a connection pooler that sits between your application and PostgreSQL. Instead of each function opening a direct connection, they all share a pool of connections through Supavisor. This is the difference between your app handling 60 concurrent users and 10,000+.

For the Supabase JS client (`@supabase/supabase-js`), connection pooling is handled automatically through the REST API (PostgREST). The pooling concern primarily applies when using direct database connections via `postgres`, `pg`, Prisma, or Drizzle ORMs.

**Incorrect (direct database connection in serverless function):**

```typescript
// ❌ Direct connection string in a Vercel Serverless Function
// lib/db.ts
import { Pool } from 'pg'

// ❌ Direct connection — each invocation opens a new connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  // postgresql://postgres.[ref]:[password]@aws-0-us-east-1.pooler.supabase.com:5432/postgres
  // Port 5432 = direct connection — no pooling
})

export async function getActiveUsers() {
  const client = await pool.connect()
  try {
    const result = await client.query(
      'SELECT id, email, last_seen FROM profiles WHERE last_seen > NOW() - INTERVAL \'5 minutes\''
    )
    return result.rows
  } finally {
    client.release()
  }
}
// 100 concurrent requests = 100 PostgreSQL connections
// Supabase Micro plan has ~60 connections → instant failure
```

**Incorrect (Prisma without connection pooling in serverless):**

```typescript
// ❌ Prisma with direct connection in Next.js API route
// lib/prisma.ts
import { PrismaClient } from '@prisma/client'

// ❌ Direct connection — no pooler, and globalThis trick doesn't help in serverless
const prisma = new PrismaClient({
  datasources: {
    db: {
      url: process.env.DATABASE_URL,
      // ❌ postgresql://postgres.[ref]:[password]@aws-0-us-east-1.pooler.supabase.com:5432/postgres
    },
  },
})

export default prisma
```

```typescript
// ❌ Edge Function with direct Postgres connection
// supabase/functions/process-webhook/index.ts
import { Pool } from 'https://deno.land/x/postgres/mod.ts'

// ❌ Each edge function invocation creates a new connection
const pool = new Pool(Deno.env.get('DATABASE_URL'), 1)

Deno.serve(async (req) => {
  const connection = await pool.connect()
  try {
    const result = await connection.queryObject(
      'INSERT INTO webhook_events (payload) VALUES ($1) RETURNING id',
      [await req.json()]
    )
    return new Response(JSON.stringify(result.rows[0]))
  } finally {
    connection.release()
  }
})
```

**Correct (Supavisor pooler URL for serverless):**

```typescript
// ✅ Use Supavisor pooler URL (port 6543) for serverless
// lib/db.ts
import { Pool } from 'pg'

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  // ✅ Supavisor pooler URL — port 6543 for transaction mode
  // postgresql://postgres.[ref]:[password]@aws-0-us-east-1.pooler.supabase.com:6543/postgres?pgbouncer=true
  max: 1, // ✅ Serverless: only 1 connection per invocation
})

export async function getActiveUsers() {
  const client = await pool.connect()
  try {
    const result = await client.query(
      'SELECT id, email, last_seen FROM profiles WHERE last_seen > NOW() - INTERVAL \'5 minutes\''
    )
    return result.rows
  } finally {
    client.release()
  }
}
// 100 concurrent requests share a pool of ~15 actual database connections
```

**Correct (Prisma with pooler and direct URLs):**

```typescript
// ✅ Prisma configuration with Supavisor pooler
// lib/prisma.ts
import { PrismaClient } from '@prisma/client'

const globalForPrisma = globalThis as unknown as { prisma: PrismaClient }

const prisma =
  globalForPrisma.prisma ||
  new PrismaClient({
    datasources: {
      db: {
        // ✅ Pooler URL for queries (port 6543, transaction mode)
        url: process.env.DATABASE_URL,
      },
    },
  })

if (process.env.NODE_ENV !== 'production') globalForPrisma.prisma = prisma

export default prisma
```

```
# ✅ .env — separate URLs for pooled queries vs. migrations
# Pooled connection for application queries (port 6543)
DATABASE_URL="postgresql://postgres.[ref]:[password]@aws-0-us-east-1.pooler.supabase.com:6543/postgres?pgbouncer=true"

# Direct connection for migrations only (port 5432)
DIRECT_URL="postgresql://postgres.[ref]:[password]@aws-0-us-east-1.pooler.supabase.com:5432/postgres"
```

```prisma
// ✅ schema.prisma — use directUrl for migrations
datasource db {
  provider  = "postgresql"
  url       = env("DATABASE_URL")       // Pooled — for runtime queries
  directUrl = env("DIRECT_URL")         // Direct — for prisma migrate only
}
```

**Correct (Supabase JS client — already pooled via REST API):**

```typescript
// ✅ Supabase JS client uses PostgREST (HTTP), not direct connections
// This is already connection-pooling-safe — no changes needed
import { createClient } from '@supabase/supabase-js'

export const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,     // REST API endpoint
  process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY! // Public anon key
)
// PostgREST handles its own connection pool to PostgreSQL
// Safe for serverless — no connection exhaustion risk
```

**Connection strategy by environment:**

```
| Environment               | Use Supabase JS? | Use ORM/pg?                      |
|---------------------------|-------------------|----------------------------------|
| Next.js Serverless Route  | ✅ PostgREST      | ✅ Pooler URL (port 6543)        |
| Next.js Edge Runtime      | ✅ PostgREST      | ✅ Pooler URL (port 6543)        |
| Supabase Edge Function    | ✅ PostgREST      | ✅ Pooler URL (port 6543)        |
| Long-running server       | ✅ PostgREST      | ✅ Direct URL (port 5432) is OK  |
| Migrations/seeding        | N/A               | ✅ Direct URL (port 5432)        |
```

**Detection hints:**

```bash
# Find environment variable references that may use direct connections
grep -rn "NEXT_PUBLIC_SUPABASE_URL" src/ --include="*.ts" --include="*.tsx"
grep -rn "DATABASE_URL" src/ --include="*.ts" --include="*.tsx"
# Find direct connection port in env files
grep -rn ":5432" . --include="*.env*"
# Find pg Pool or Client instantiation
grep -rn "new Pool\|new Client" src/ --include="*.ts"
```

Reference: [Supabase Connection Pooling](https://supabase.com/docs/guides/database/connecting-to-postgres#connection-pooler) · [Supavisor Documentation](https://supabase.com/docs/guides/platform/custom-postgres-config) · [Prisma with Supabase](https://supabase.com/partners/integrations/prisma)
