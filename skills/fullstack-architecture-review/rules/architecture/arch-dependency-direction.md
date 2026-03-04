---
title: Dependency Direction Violation
description: "Dependencies must flow inward: Presentation -> Controller -> Service -> Repository -> Domain. Never import upward across layers."
impact: CRITICAL
impact_description: Inverted dependencies create circular coupling, break testability, and make refactoring cascade across the entire codebase
tags: [architecture, solid, clean-architecture, dependency-inversion]
cwe: ["CWE-1047"]
detection_grep: "import.*from.*app/api"
---

## Dependency Direction Violation

**Impact: CRITICAL (Inverted dependencies create circular coupling, break testability, and make refactoring cascade across the entire codebase)**

Clean Architecture enforces a strict dependency rule: source code dependencies must point inward. Each layer may only import from the layer directly below it or from shared domain types. The dependency hierarchy is:

```
Presentation (Components, Pages)
  -> Controllers (Route Handlers, Server Actions)
    -> Services (Business Logic)
      -> Repositories (Data Access)
        -> Domain (Types, Entities, Value Objects)
```

When a service imports from a route handler, or a repository imports from a service, the dependency arrow points outward. This creates tight coupling between layers that should be independent, makes unit testing impossible without spinning up HTTP infrastructure, and means changes in the outer layer break inner layers that should be stable.

**Incorrect (service imports from a route handler and accesses request-level concerns):**

```typescript
// ❌ lib/services/billing-service.ts
// VIOLATION: Service layer imports from the API route (controller) layer
import { validateApiKey } from "@/app/api/billing/route";
// VIOLATION: Service layer depends on Next.js request infrastructure
import { headers } from "next/headers";

export class BillingService {
  async createInvoice(customerId: string, amount: number) {
    // ❌ Service reaches into the HTTP layer to get auth context
    const headersList = await headers();
    const apiKey = headersList.get("x-api-key");

    // ❌ Service calls a function defined in a route handler file
    const isValid = await validateApiKey(apiKey);
    if (!isValid) {
      throw new Error("Unauthorized");
    }

    // ❌ Service is now untestable without mocking Next.js headers()
    const invoice = await this.generateInvoice(customerId, amount);
    return invoice;
  }
}
```

```typescript
// ❌ lib/repositories/user-repository.ts
// VIOLATION: Repository imports from the service layer
import { UserService } from "@/lib/services/user-service";
import { supabase } from "@/lib/supabase/client";

export class UserRepository {
  // ❌ Repository depends on a service to compute derived data
  async findActiveUsers() {
    const userService = new UserService();
    const users = await supabase.from("users").select("*");

    // ❌ Repository delegates business logic to a service it shouldn't know about
    return users.data?.filter((u) => userService.isUserActive(u));
  }
}
```

**Correct (each layer only imports from layers below it):**

```typescript
// ✅ Domain layer — no dependencies on any other layer
// lib/domain/types/billing.ts
export interface Invoice {
  id: string;
  customerId: string;
  amount: number;
  status: "draft" | "sent" | "paid";
  createdAt: Date;
}

export interface CreateInvoiceInput {
  customerId: string;
  amount: number;
}
```

```typescript
// ✅ Repository layer — depends only on Domain types
// lib/repositories/invoice-repository.ts
import type { Invoice, CreateInvoiceInput } from "@/lib/domain/types/billing";
import { createClient } from "@/lib/supabase/server";

export class InvoiceRepository {
  async create(input: CreateInvoiceInput): Promise<Invoice> {
    const supabase = await createClient();
    const { data, error } = await supabase
      .from("invoices")
      .insert({
        customer_id: input.customerId,
        amount: input.amount,
        status: "draft",
      })
      .select()
      .single();

    if (error) throw new Error(`Failed to create invoice: ${error.message}`);
    return this.toDomain(data);
  }

  private toDomain(row: Record<string, unknown>): Invoice {
    return {
      id: row.id as string,
      customerId: row.customer_id as string,
      amount: row.amount as number,
      status: row.status as Invoice["status"],
      createdAt: new Date(row.created_at as string),
    };
  }
}
```

```typescript
// ✅ Service layer — depends on Repository and Domain, never on Controllers
// lib/services/billing-service.ts
import type { Invoice, CreateInvoiceInput } from "@/lib/domain/types/billing";
import type { InvoiceRepository } from "@/lib/repositories/invoice-repository";

export interface ServiceResult<T> {
  success: boolean;
  data?: T;
  error?: string;
}

export class BillingService {
  constructor(private readonly invoiceRepo: InvoiceRepository) {}

  // ✅ Service receives already-authenticated context, no HTTP concerns
  async createInvoice(input: CreateInvoiceInput): Promise<ServiceResult<Invoice>> {
    if (input.amount <= 0) {
      return { success: false, error: "Invoice amount must be positive" };
    }

    const invoice = await this.invoiceRepo.create(input);
    return { success: true, data: invoice };
  }
}
```

```typescript
// ✅ Controller layer — depends on Service and Domain, handles HTTP concerns
// app/api/billing/invoices/route.ts
import { NextRequest, NextResponse } from "next/server";
import { ServiceFactory } from "@/lib/factories/service-factory";
import { authenticate } from "@/lib/middleware/auth";

export async function POST(request: NextRequest) {
  // ✅ Authentication lives in the controller/middleware layer
  const auth = await authenticate(request);
  if (!auth.success) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const body = await request.json();

  // ✅ Controller delegates to the service layer
  const billingService = ServiceFactory.createBillingService();
  const result = await billingService.createInvoice({
    customerId: body.customerId,
    amount: body.amount,
  });

  if (!result.success) {
    return NextResponse.json({ error: result.error }, { status: 400 });
  }

  return NextResponse.json(result.data, { status: 201 });
}
```

Reference: [Clean Architecture by Robert C. Martin](https://blog.cleancoder.com/uncle-bob/2012/08/13/the-clean-architecture.html)
