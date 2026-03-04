---
title: Build Features Bottom-Up from Domain to Presentation
description: "Build in dependency order: Domain, Interface, Repository, Service, Controller, Presentation. Top-down builds couple UI to data."
impact: MEDIUM
impact_description: Top-down development lets UI concerns leak into data models, creating tightly coupled systems
tags: [architecture, clean-architecture, build-order, planning]
detection_grep: "from.*components"
---

## Build Features Bottom-Up from Domain to Presentation

**Impact: MEDIUM (Top-down development lets UI concerns leak into data models, creating tightly coupled systems)**

When building a new feature, the order in which you create the layers matters. Building top-down -- starting with the UI and working backward to the database -- causes the page layout to dictate the shape of your data model. Fields get added to entities because a form needs them. API routes return whatever the component expects. The result is a system where changing the UI requires changing the database schema and vice versa.

Build bottom-up instead: **Domain -> Interface -> Repository -> Service -> Controller/Route -> Presentation**. Define the business entity first, then the contract for accessing it, then the implementation, and finally the UI that consumes it. Each layer depends only on the layer below it, and no layer dictates the shape of another.

**Incorrect (top-down: page component drives everything, directly queries the database):**

```typescript
// src/app/scans/page.tsx

// ❌ Building top-down: the page component IS the feature
// UI concerns, data fetching, business logic, and presentation all in one file
import { createServerClient } from '@supabase/ssr';
import { cookies } from 'next/headers';

export default async function ScansPage() {
  const cookieStore = await cookies();
  const supabase = createServerClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
    { cookies: { getAll: () => cookieStore.getAll() } }
  );

  // ❌ Raw database query inside a React component
  const { data: scans, error } = await supabase
    .from('scans')
    .select(`
      id,
      repo_url,
      status,
      created_at,
      scan_results (
        id,
        rule_id,
        severity,
        line_number,
        file_path,
        message
      )
    `)
    .eq('user_id', (await supabase.auth.getUser()).data.user?.id)
    .order('created_at', { ascending: false });

  if (error) {
    return <div>Error loading scans</div>; // ❌ No proper error boundary
  }

  // ❌ Business logic computed inline in the component
  const scansWithStats = scans?.map((scan) => ({
    ...scan,
    criticalCount: scan.scan_results.filter((r) => r.severity === 'critical').length,
    highCount: scan.scan_results.filter((r) => r.severity === 'high').length,
    totalFindings: scan.scan_results.length,
    // ❌ UI display concern mixed with data transformation
    statusLabel: scan.status === 'in_progress' ? 'Running...' : scan.status,
    statusColor: scan.status === 'completed' ? 'green' : scan.status === 'failed' ? 'red' : 'yellow',
  }));

  return (
    <div className="space-y-4">
      <h1>Your Scans</h1>
      {scansWithStats?.map((scan) => (
        <div key={scan.id} className="border p-4 rounded">
          <p>{scan.repo_url}</p>
          <span style={{ color: scan.statusColor }}>{scan.statusLabel}</span>
          <p>{scan.criticalCount} critical, {scan.highCount} high, {scan.totalFindings} total</p>
        </div>
      ))}
    </div>
  );
}
```

**Correct (bottom-up: domain first, then repository, service, and finally the page):**

```typescript
// Step 1: Domain Entity -- define the business concept first
// src/domain/entities/scan.ts

// ✅ Pure TypeScript, no framework imports
export interface ScanEntity {
  id: string;
  repositoryUrl: string;
  status: ScanStatus;
  createdAt: Date;
  findings: ScanFinding[];
}

export type ScanStatus = 'pending' | 'in_progress' | 'completed' | 'failed';

export interface ScanFinding {
  id: string;
  ruleId: string;
  severity: FindingSeverity;
  lineNumber: number;
  filePath: string;
  message: string;
}

export type FindingSeverity = 'critical' | 'high' | 'medium' | 'low';

// ✅ Domain logic lives with the entity
export function computeScanStats(scan: ScanEntity): ScanStats {
  return {
    criticalCount: scan.findings.filter((f) => f.severity === 'critical').length,
    highCount: scan.findings.filter((f) => f.severity === 'high').length,
    totalFindings: scan.findings.length,
  };
}

export interface ScanStats {
  criticalCount: number;
  highCount: number;
  totalFindings: number;
}
```

```typescript
// Step 2: Repository Interface -- define the contract
// src/domain/repositories/scan-repository.ts

import type { ScanEntity } from '@/domain/entities/scan';

// ✅ Interface depends only on domain types
export interface ScanRepository {
  findByUserId(userId: string): Promise<ScanEntity[]>;
  findById(id: string): Promise<ScanEntity | null>;
}
```

```typescript
// Step 3: Repository Implementation -- infrastructure details
// src/infrastructure/repositories/supabase-scan-repository.ts

import type { SupabaseClient } from '@supabase/supabase-js';
import type { ScanRepository } from '@/domain/repositories/scan-repository';
import type { ScanEntity } from '@/domain/entities/scan';

// ✅ Framework imports stay in the infrastructure layer
export class SupabaseScanRepository implements ScanRepository {
  constructor(private readonly supabase: SupabaseClient) {}

  async findByUserId(userId: string): Promise<ScanEntity[]> {
    const { data, error } = await this.supabase
      .from('scans')
      .select('id, repo_url, status, created_at, scan_results (id, rule_id, severity, line_number, file_path, message)')
      .eq('user_id', userId)
      .order('created_at', { ascending: false });

    if (error) throw new Error(`Failed to fetch scans: ${error.message}`);

    // ✅ Map from database shape to domain shape
    return (data ?? []).map((row) => ({
      id: row.id,
      repositoryUrl: row.repo_url,
      status: row.status,
      createdAt: new Date(row.created_at),
      findings: row.scan_results.map((r) => ({
        id: r.id,
        ruleId: r.rule_id,
        severity: r.severity,
        lineNumber: r.line_number,
        filePath: r.file_path,
        message: r.message,
      })),
    }));
  }

  async findById(id: string): Promise<ScanEntity | null> {
    // ... similar mapping logic
    return null;
  }
}
```

```typescript
// Step 4: Service -- orchestrates business logic
// src/services/scan-list-service.ts

import type { ScanRepository } from '@/domain/repositories/scan-repository';
import { computeScanStats, type ScanEntity, type ScanStats } from '@/domain/entities/scan';

export interface ScanListItem {
  scan: ScanEntity;
  stats: ScanStats;
}

// ✅ Service depends on repository interface, not implementation
export class ScanListService {
  constructor(private readonly scanRepo: ScanRepository) {}

  async getUserScans(userId: string): Promise<ScanListItem[]> {
    const scans = await this.scanRepo.findByUserId(userId);

    return scans.map((scan) => ({
      scan,
      stats: computeScanStats(scan), // ✅ Uses domain logic from the entity module
    }));
  }
}
```

```typescript
// Step 5: Presentation -- consumes the service, handles only display concerns
// src/app/scans/page.tsx

import { ScanListService } from '@/services/scan-list-service';
import { createScanRepository } from '@/infrastructure/factories/scan-repository-factory';
import { getAuthenticatedUser } from '@/lib/auth';
import { ScanCard } from '@/components/scans/scan-card';

// ✅ Page component is thin -- it wires dependencies and renders
export default async function ScansPage() {
  const user = await getAuthenticatedUser();
  const scanRepo = createScanRepository();
  const service = new ScanListService(scanRepo);
  const items = await service.getUserScans(user.id);

  return (
    <div className="space-y-4">
      <h1>Your Scans</h1>
      {items.map(({ scan, stats }) => (
        <ScanCard key={scan.id} scan={scan} stats={stats} />
      ))}
    </div>
  );
}
```

Reference: [The Clean Architecture -- Robert C. Martin](https://blog.cleancoder.com/uncle-bob/2012/08/13/the-clean-architecture.html)
