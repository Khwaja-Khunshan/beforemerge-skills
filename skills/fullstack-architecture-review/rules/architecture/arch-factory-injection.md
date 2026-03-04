---
title: Missing Factory for Dependency Injection
description: "Use factory classes (ServiceFactory, RepositoryFactory) for dependency wiring instead of direct instantiation or imports in consuming code."
impact: MEDIUM
impact_description: Direct instantiation couples callers to concrete implementations, making it impossible to swap dependencies for testing or configuration
tags: [architecture, factory, dependency-injection, testing, solid]
detection_grep: "Factory"
---

## Missing Factory for Dependency Injection

**Impact: MEDIUM (Direct instantiation couples callers to concrete implementations, making it impossible to swap dependencies for testing or configuration)**

When a route handler or server action calls `new UserService(new UserRepository())` inline, three problems emerge: (1) every call site must know the full dependency graph of the service it creates, (2) swapping a real repository for a mock requires changing production code or complex module-level mocking, and (3) if `UserService` gains a new dependency, every call site must be updated.

Factory classes centralize dependency wiring. A `RepositoryFactory` creates repositories, and a `ServiceFactory` creates services by pulling their repository dependencies from the `RepositoryFactory`. Route handlers and server actions call `ServiceFactory.createUserService()` and receive a fully wired instance. In tests, you can create the service with mock repositories directly -- the factory is only the default wiring, not a required path.

**Incorrect (direct instantiation scattered across route handlers and server actions):**

```typescript
// ❌ app/api/users/[id]/route.ts
import { NextRequest, NextResponse } from "next/server";
import { UserService } from "@/lib/services/user-service";
import { UserRepository } from "@/lib/repositories/user-repository";
import { AuditLogRepository } from "@/lib/repositories/audit-log-repository";
import { EmailService } from "@/lib/services/email-service";
import { NotificationRepository } from "@/lib/repositories/notification-repository";

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  // ❌ Route handler knows the entire dependency graph
  const userRepo = new UserRepository();
  const auditRepo = new AuditLogRepository();
  const notificationRepo = new NotificationRepository();
  const emailService = new EmailService();
  const userService = new UserService(userRepo, auditRepo, notificationRepo, emailService);

  const { id } = await params;
  const result = await userService.getUser(id);
  return NextResponse.json(result);
}
```

```typescript
// ❌ app/actions/user.ts
"use server";

import { UserService } from "@/lib/services/user-service";
import { UserRepository } from "@/lib/repositories/user-repository";
import { AuditLogRepository } from "@/lib/repositories/audit-log-repository";
import { EmailService } from "@/lib/services/email-service";
import { NotificationRepository } from "@/lib/repositories/notification-repository";

export async function updateUserProfile(formData: FormData) {
  // ❌ Exact same wiring duplicated in a second file
  const userRepo = new UserRepository();
  const auditRepo = new AuditLogRepository();
  const notificationRepo = new NotificationRepository();
  const emailService = new EmailService();
  const userService = new UserService(userRepo, auditRepo, notificationRepo, emailService);

  // If UserService adds a new dependency, BOTH files break
  return userService.updateProfile(/* ... */);
}
```

```typescript
// ❌ lib/services/__tests__/user-service.test.ts
import { UserService } from "../user-service";

// ❌ Must use jest.mock to intercept module imports — brittle and opaque
jest.mock("@/lib/repositories/user-repository");
jest.mock("@/lib/repositories/audit-log-repository");
jest.mock("@/lib/repositories/notification-repository");
jest.mock("@/lib/services/email-service");

// Tests become tightly coupled to file paths and module structure
```

**Correct (factory classes centralize wiring; tests inject mocks directly through constructors):**

```typescript
// ✅ lib/factories/repository-factory.ts
import { UserRepository } from "@/lib/repositories/user-repository";
import { AuditLogRepository } from "@/lib/repositories/audit-log-repository";
import { NotificationRepository } from "@/lib/repositories/notification-repository";

export class RepositoryFactory {
  static createUserRepository(): UserRepository {
    return new UserRepository();
  }

  static createAuditLogRepository(): AuditLogRepository {
    return new AuditLogRepository();
  }

  static createNotificationRepository(): NotificationRepository {
    return new NotificationRepository();
  }
}
```

```typescript
// ✅ lib/factories/service-factory.ts
import { UserService } from "@/lib/services/user-service";
import { EmailService } from "@/lib/services/email-service";
import { TeamService } from "@/lib/services/team-service";
import { RepositoryFactory } from "./repository-factory";

export class ServiceFactory {
  // ✅ Single place that knows how to wire UserService
  static createUserService(): UserService {
    return new UserService(
      RepositoryFactory.createUserRepository(),
      RepositoryFactory.createAuditLogRepository(),
      RepositoryFactory.createNotificationRepository(),
      new EmailService()
    );
  }

  // ✅ Adding a new dependency to UserService only changes this file
  static createTeamService(): TeamService {
    return new TeamService(
      RepositoryFactory.createUserRepository(),
      new EmailService()
    );
  }
}
```

```typescript
// ✅ app/api/users/[id]/route.ts — clean, no wiring knowledge
import { NextRequest, NextResponse } from "next/server";
import { ServiceFactory } from "@/lib/factories/service-factory";

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  // ✅ One line — route handler does not know about repositories
  const userService = ServiceFactory.createUserService();

  const { id } = await params;
  const result = await userService.getUser(id);

  if (!result.success) {
    return NextResponse.json({ error: result.error }, { status: 404 });
  }

  return NextResponse.json(result.data);
}
```

```typescript
// ✅ app/actions/user.ts — same one-liner, zero duplication
"use server";

import { ServiceFactory } from "@/lib/factories/service-factory";

export async function updateUserProfile(formData: FormData) {
  const userService = ServiceFactory.createUserService();
  return userService.updateProfile(/* ... */);
}
```

```typescript
// ✅ lib/services/__tests__/user-service.test.ts — no jest.mock needed
import { UserService } from "../user-service";
import type { UserRepository } from "@/lib/repositories/user-repository";
import type { AuditLogRepository } from "@/lib/repositories/audit-log-repository";
import type { NotificationRepository } from "@/lib/repositories/notification-repository";
import type { EmailService } from "@/lib/services/email-service";

describe("UserService", () => {
  // ✅ Create lightweight mocks that satisfy the interface
  const mockUserRepo: jest.Mocked<Pick<UserRepository, "findById" | "update">> = {
    findById: jest.fn(),
    update: jest.fn(),
  };

  const mockAuditRepo: jest.Mocked<Pick<AuditLogRepository, "log">> = {
    log: jest.fn(),
  };

  const mockNotificationRepo: jest.Mocked<Pick<NotificationRepository, "create">> = {
    create: jest.fn(),
  };

  const mockEmailService: jest.Mocked<Pick<EmailService, "sendEmail">> = {
    sendEmail: jest.fn(),
  };

  // ✅ Inject mocks via constructor — no module-level patching
  const userService = new UserService(
    mockUserRepo as unknown as UserRepository,
    mockAuditRepo as unknown as AuditLogRepository,
    mockNotificationRepo as unknown as NotificationRepository,
    mockEmailService as unknown as EmailService
  );

  it("returns NOT_FOUND when user does not exist", async () => {
    mockUserRepo.findById.mockResolvedValue(null);

    const result = await userService.getUser("nonexistent-id");

    expect(result).toEqual({
      success: false,
      error: "User not found",
      code: "NOT_FOUND",
    });
    // ✅ Easy to assert exact calls without framework magic
    expect(mockUserRepo.findById).toHaveBeenCalledWith("nonexistent-id");
  });
});
```

Reference: [Dependency Injection Principles, Practices, and Patterns (Manning)](https://www.manning.com/books/dependency-injection-principles-practices-patterns)
