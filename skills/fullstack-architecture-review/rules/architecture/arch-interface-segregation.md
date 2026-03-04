---
title: Segregate Repository Interfaces by Consumer Need
description: "Split large repository interfaces into focused, role-specific contracts so consumers only depend on the methods they use"
impact: MEDIUM
impact_description: Monolithic interfaces increase coupling, bloat test mocks, and make refactoring risky
tags: [architecture, solid, interface-segregation, typescript]
detection_grep: "interface.*Repository"
---

## Segregate Repository Interfaces by Consumer Need

**Impact: MEDIUM (Monolithic interfaces increase coupling, bloat test mocks, and make refactoring risky)**

The Interface Segregation Principle (ISP) states that no client should be forced to depend on methods it does not use. When a single repository interface defines every possible operation -- read, write, search, aggregate, archive -- every consumer and every test mock must account for that entire surface area. A service that only reads data still depends on an interface that includes `delete` and `bulkUpdate`. Splitting interfaces into focused contracts (ReadRepository, WriteRepository, SearchRepository) reduces coupling, simplifies testing, and makes it obvious what capabilities each consumer actually requires.

**Incorrect (monolithic repository interface that forces all consumers to depend on everything):**

```typescript
// src/domain/repositories/scan-repository.ts

// ❌ One massive interface with 15+ methods
export interface ScanRepository {
  findById(id: string): Promise<Scan | null>;
  findByUserId(userId: string): Promise<Scan[]>;
  findByOrganization(orgId: string): Promise<Scan[]>;
  search(query: string, filters: ScanFilters): Promise<PaginatedResult<Scan>>;
  getAggregateStats(orgId: string): Promise<ScanStats>;
  create(scan: CreateScanInput): Promise<Scan>;
  update(id: string, data: Partial<Scan>): Promise<Scan>;
  bulkUpdate(ids: string[], data: Partial<Scan>): Promise<Scan[]>;
  delete(id: string): Promise<void>;
  bulkDelete(ids: string[]): Promise<void>;
  archive(id: string): Promise<void>;
  restore(id: string): Promise<void>;
  getHistory(id: string): Promise<ScanHistoryEntry[]>;
  export(orgId: string, format: ExportFormat): Promise<Buffer>;
  getRunningScans(): Promise<Scan[]>;
}
```

```typescript
// src/services/scan-summary-service.ts
import type { ScanRepository } from '@/domain/repositories/scan-repository';

export class ScanSummaryService {
  // ❌ This service only calls findById and getAggregateStats,
  //    but depends on the full 15-method interface
  constructor(private readonly scanRepo: ScanRepository) {}

  async getSummary(orgId: string): Promise<OrgScanSummary> {
    const stats = await this.scanRepo.getAggregateStats(orgId);
    return { organizationId: orgId, ...stats };
  }
}
```

```typescript
// src/__tests__/scan-summary-service.test.ts

// ❌ Test mock must implement all 15 methods even though the service uses 1
const mockRepo: ScanRepository = {
  findById: jest.fn(),
  findByUserId: jest.fn(),
  findByOrganization: jest.fn(),
  search: jest.fn(),
  getAggregateStats: jest.fn().mockResolvedValue(mockStats),
  create: jest.fn(),
  update: jest.fn(),
  bulkUpdate: jest.fn(),
  delete: jest.fn(),
  bulkDelete: jest.fn(),
  archive: jest.fn(),
  restore: jest.fn(),
  getHistory: jest.fn(),
  export: jest.fn(),
  getRunningScans: jest.fn(),
};
```

**Correct (segregated interfaces composed where needed):**

```typescript
// src/domain/repositories/scan-read-repository.ts

// ✅ Focused interface for read-only access
export interface ScanReadRepository {
  findById(id: string): Promise<Scan | null>;
  findByUserId(userId: string): Promise<Scan[]>;
  findByOrganization(orgId: string): Promise<Scan[]>;
}
```

```typescript
// src/domain/repositories/scan-write-repository.ts

// ✅ Focused interface for write operations
export interface ScanWriteRepository {
  create(scan: CreateScanInput): Promise<Scan>;
  update(id: string, data: Partial<Scan>): Promise<Scan>;
  delete(id: string): Promise<void>;
}
```

```typescript
// src/domain/repositories/scan-search-repository.ts

// ✅ Focused interface for search and aggregation
export interface ScanSearchRepository {
  search(query: string, filters: ScanFilters): Promise<PaginatedResult<Scan>>;
  getAggregateStats(orgId: string): Promise<ScanStats>;
}
```

```typescript
// src/domain/repositories/scan-lifecycle-repository.ts

// ✅ Focused interface for lifecycle management
export interface ScanLifecycleRepository {
  archive(id: string): Promise<void>;
  restore(id: string): Promise<void>;
  getHistory(id: string): Promise<ScanHistoryEntry[]>;
}
```

```typescript
// src/services/scan-summary-service.ts
import type { ScanSearchRepository } from '@/domain/repositories/scan-search-repository';

export class ScanSummaryService {
  // ✅ Depends only on the interface it actually uses
  constructor(private readonly scanSearch: ScanSearchRepository) {}

  async getSummary(orgId: string): Promise<OrgScanSummary> {
    const stats = await this.scanSearch.getAggregateStats(orgId);
    return { organizationId: orgId, ...stats };
  }
}
```

```typescript
// src/__tests__/scan-summary-service.test.ts

// ✅ Test mock only implements the 2 methods in ScanSearchRepository
const mockSearchRepo: ScanSearchRepository = {
  search: jest.fn(),
  getAggregateStats: jest.fn().mockResolvedValue(mockStats),
};

const service = new ScanSummaryService(mockSearchRepo);
```

```typescript
// src/infrastructure/repositories/supabase-scan-repository.ts

// ✅ The concrete implementation can still satisfy multiple interfaces
export class SupabaseScanRepository
  implements ScanReadRepository, ScanWriteRepository, ScanSearchRepository, ScanLifecycleRepository
{
  constructor(private readonly supabase: SupabaseClient) {}

  async findById(id: string): Promise<Scan | null> { /* ... */ }
  async findByUserId(userId: string): Promise<Scan[]> { /* ... */ }
  async findByOrganization(orgId: string): Promise<Scan[]> { /* ... */ }
  async search(query: string, filters: ScanFilters): Promise<PaginatedResult<Scan>> { /* ... */ }
  async getAggregateStats(orgId: string): Promise<ScanStats> { /* ... */ }
  async create(scan: CreateScanInput): Promise<Scan> { /* ... */ }
  async update(id: string, data: Partial<Scan>): Promise<Scan> { /* ... */ }
  async delete(id: string): Promise<void> { /* ... */ }
  async archive(id: string): Promise<void> { /* ... */ }
  async restore(id: string): Promise<void> { /* ... */ }
  async getHistory(id: string): Promise<ScanHistoryEntry[]> { /* ... */ }
}
```

Reference: [Interface Segregation Principle -- Robert C. Martin](https://web.archive.org/web/20150905081110/http://www.objectmentor.com/resources/articles/isp.pdf)
