---
title: Domain Entities Must Be Framework-Independent
description: "Domain entities should be pure TypeScript classes/interfaces with no framework dependencies like Supabase, React, or Next.js"
impact: MEDIUM
impact_description: Framework-coupled entities break portability, testability, and violate clean architecture boundaries
tags: [architecture, domain, entities, clean-architecture, solid]
detection_grep: "interface.*Entity"
---

## Domain Entities Must Be Framework-Independent

**Impact: MEDIUM (Framework-coupled entities break portability, testability, and violate clean architecture boundaries)**

Domain entities represent core business concepts -- User, Rule, Scan, Organization -- and encapsulate domain validation logic. They sit at the center of your architecture and should have zero knowledge of infrastructure concerns like databases, ORMs, UI frameworks, or HTTP. When domain entities import from `@supabase/supabase-js`, `react`, or `next`, every layer that depends on them inherits those framework dependencies, making the codebase rigid and difficult to test or migrate.

**Incorrect (domain entity coupled to Supabase types and database schema):**

```typescript
// src/domain/entities/user.ts
import { Database } from '@supabase/supabase-js'; // ❌ Framework dependency in domain layer

// ❌ Entity shape is dictated by the database schema, not business requirements
type UserRow = Database['public']['Tables']['users']['Row'];

export interface UserEntity extends UserRow { // ❌ Domain entity extends infrastructure type
  // Business logic is mixed with database concerns
  full_name: string; // ❌ Using snake_case from DB column names
  created_at: string; // ❌ String type because that's what Supabase returns
  subscription_tier: 'free' | 'pro' | 'enterprise';
}

// ❌ Validation logic depends on Supabase types
export function validateUser(user: UserRow): boolean {
  return user.full_name.length > 0 && user.email.includes('@');
}
```

**Correct (pure TypeScript domain entity with a separate mapping layer):**

```typescript
// src/domain/entities/user.ts
// ✅ Zero imports -- pure TypeScript, no framework dependencies

export interface UserEntity {
  id: string;
  fullName: string; // ✅ Domain uses camelCase, not DB column names
  email: string;
  subscriptionTier: SubscriptionTier;
  createdAt: Date; // ✅ Proper Date type, not a string
}

export type SubscriptionTier = 'free' | 'pro' | 'enterprise';

// ✅ Domain validation logic lives with the entity, uses no external types
export function validateUser(user: UserEntity): ValidationResult {
  const errors: string[] = [];

  if (!user.fullName || user.fullName.trim().length === 0) {
    errors.push('Full name is required');
  }

  if (!user.email || !user.email.includes('@')) {
    errors.push('A valid email address is required');
  }

  return { valid: errors.length === 0, errors };
}

export interface ValidationResult {
  valid: boolean;
  errors: string[];
}
```

```typescript
// src/infrastructure/mappers/user-mapper.ts
import type { Database } from '@/lib/supabase/types'; // ✅ Infrastructure import stays in infrastructure
import type { UserEntity } from '@/domain/entities/user';

type UserRow = Database['public']['Tables']['users']['Row'];

// ✅ Mapping layer translates between infrastructure and domain
export function toUserEntity(row: UserRow): UserEntity {
  return {
    id: row.id,
    fullName: row.full_name,
    email: row.email,
    subscriptionTier: row.subscription_tier,
    createdAt: new Date(row.created_at),
  };
}

export function toUserRow(entity: UserEntity): Omit<UserRow, 'id' | 'created_at'> {
  return {
    full_name: entity.fullName,
    email: entity.email,
    subscription_tier: entity.subscriptionTier,
  };
}
```

Reference: [Clean Architecture by Robert C. Martin](https://blog.cleancoder.com/uncle-bob/2012/08/13/the-clean-architecture.html)
