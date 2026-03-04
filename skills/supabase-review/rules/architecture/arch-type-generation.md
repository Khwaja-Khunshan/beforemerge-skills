---
title: Generate Database Types from Schema
description: "Hand-writing TypeScript interfaces for database tables leads to drift between code and schema. Use supabase gen types to generate types automatically."
impact: MEDIUM
impact_description: prevents type drift between application code and database schema
tags: [architecture, supabase, typescript, types, codegen, schema]
detection_grep: "Database"
---

## Generate Database Types from Schema

**Impact: MEDIUM (prevents type drift between application code and database schema)**

Hand-writing TypeScript interfaces for your database tables is a maintenance burden that inevitably drifts from the actual schema. When a migration adds a column, changes a type, or makes a field nullable, the hand-written interface stays stale — leading to runtime errors that TypeScript was supposed to prevent.

Supabase CLI generates types directly from your database schema, ensuring your TypeScript types always match reality. These generated types also provide autocomplete for `.from()` table names, `.select()` column names, and `.eq()` filter values.

**Incorrect (hand-written types that drift from schema):**

```typescript
// ❌ Manually defined — will drift from actual schema
interface User {
  id: string
  email: string
  name: string       // Column was renamed to display_name in migration 042
  avatar: string     // Column is actually avatar_url and nullable
  created_at: string // Column is timestamptz, not string
}

interface Document {
  id: string
  userId: string     // Column is actually user_id (snake_case in PostgreSQL)
  title: string
  content: string    // Column was changed to nullable in migration 038
  tags: string[]     // Column is actually jsonb, not string[]
}

// ❌ No type safety on queries
const { data } = await supabase
  .from('documents')   // No autocomplete for table names
  .select('*')         // No type checking on returned shape
  .eq('userId', id)    // Runtime error — column is user_id, not userId
```

**Correct (generate types from schema):**

```bash
# Step 1: Generate types from local database
supabase gen types typescript --local > src/types/database.ts

# Or from remote (if not using local development)
supabase gen types typescript --project-id your-project-ref > src/types/database.ts
```

```typescript
// src/types/database.ts (auto-generated — do not edit manually)
export type Json = string | number | boolean | null | { [key: string]: Json | undefined } | Json[]

export interface Database {
  public: {
    Tables: {
      documents: {
        Row: {
          id: string
          user_id: string
          title: string
          content: string | null
          tags: Json
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          user_id: string
          title: string
          content?: string | null
          tags?: Json
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          user_id?: string
          title?: string
          content?: string | null
          tags?: Json
          updated_at?: string
        }
      }
      // ... other tables
    }
  }
}
```

```typescript
// ✅ Type-safe Supabase client
import { createClient } from '@supabase/supabase-js'
import type { Database } from '@/types/database'

export const supabase = createClient<Database>(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!
)

// Now all queries are type-safe:
const { data } = await supabase
  .from('documents')                    // ✅ Autocomplete for table names
  .select('id, title, created_at')      // ✅ Autocomplete for column names
  .eq('user_id', userId)                // ✅ Type error if column doesn't exist

// data is typed as: { id: string; title: string; created_at: string }[] | null
```

**Derive application types from generated types:**

```typescript
// ✅ Derive types from the generated Database type — never hand-write
type Document = Database['public']['Tables']['documents']['Row']
type DocumentInsert = Database['public']['Tables']['documents']['Insert']
type DocumentUpdate = Database['public']['Tables']['documents']['Update']

// ✅ Create application-specific types as intersections
type DocumentWithAuthor = Document & {
  author: Database['public']['Tables']['profiles']['Row']
}

// ✅ Use Pick for view-specific subsets
type DocumentListItem = Pick<Document, 'id' | 'title' | 'created_at'>
```

**Add type generation to your workflow:**

```json
// package.json
{
  "scripts": {
    "db:types": "supabase gen types typescript --local > src/types/database.ts",
    "db:migrate": "supabase db push && npm run db:types",
    "db:reset": "supabase db reset && npm run db:types"
  }
}
```

```bash
# After every migration, regenerate types:
supabase migration new add_status_to_documents
# ... write migration SQL ...
supabase db push
npm run db:types
git add supabase/migrations/ src/types/database.ts
git commit -m "feat: add status column to documents"
```

**Detection hints:**

```bash
# Find hand-written interfaces that might represent database tables
grep -rn "interface.*{" src/types/ --include="*.ts" | grep -v "database.ts"
# Check if database.ts exists and is recent
ls -la src/types/database.ts
# Find any type definitions that might shadow generated types
grep -rn "type.*Row\|interface.*Table" src/ --include="*.ts" | grep -v "database.ts\|node_modules"
```

Reference: [Supabase Type Generation](https://supabase.com/docs/guides/api/rest/generating-types) · [Supabase CLI Reference](https://supabase.com/docs/reference/cli/supabase-gen-types)
