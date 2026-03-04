---
title: Prevent Path Traversal in API Routes and File Operations
description: "API routes that construct file paths from user input without sanitization allow attackers to read or write arbitrary files using ../ sequences."
impact: CRITICAL
impact_description: arbitrary file read/write on the server leading to credential theft or code execution
tags: [security, path-traversal, file-system, api, nextjs]
cwe: ["CWE-22"]
owasp: ["A01:2021"]
detection_grep: "fs.readFile|fs.writeFile|path.join.*params|path.resolve.*params"
---

## Prevent Path Traversal in API Routes and File Operations

**Impact: CRITICAL (arbitrary file read/write on the server leading to credential theft or code execution)**

API routes that use user input to construct file paths — download endpoints, file serving, template loading — are vulnerable to path traversal attacks. An attacker sends `../../etc/passwd` or `../.env.local` to read files outside the intended directory. This is consistently in the OWASP Top 10.

**Incorrect (user input in file paths):**

```typescript
// app/api/files/[...path]/route.ts
// ❌ User controls the file path entirely
import { readFile } from 'fs/promises'
import path from 'path'

export async function GET(
  request: NextRequest,
  { params }: { params: { path: string[] } }
) {
  const filePath = path.join(process.cwd(), 'uploads', ...params.path)
  const file = await readFile(filePath) // ../../.env.local → reads your secrets!
  return new NextResponse(file)
}
```

```typescript
// app/api/download/route.ts
// ❌ Query param used in file path
export async function GET(request: NextRequest) {
  const filename = request.nextUrl.searchParams.get('file')
  const filePath = path.join('/var/data', filename!) // ../../../etc/shadow
  const content = await readFile(filePath)
  return new NextResponse(content)
}
```

**Correct (validate and constrain file paths):**

```typescript
// app/api/files/[...path]/route.ts
import { readFile, stat } from 'fs/promises'
import path from 'path'

const UPLOADS_DIR = path.resolve(process.cwd(), 'uploads')

export async function GET(
  request: NextRequest,
  { params }: { params: { path: string[] } }
) {
  // 1. Reject path segments that contain traversal patterns
  if (params.path.some(segment => segment.includes('..') || segment.includes('\0'))) {
    return NextResponse.json({ error: 'Invalid path' }, { status: 400 })
  }

  // 2. Resolve to absolute path
  const filePath = path.resolve(UPLOADS_DIR, ...params.path)

  // 3. Verify the resolved path is still within the allowed directory
  if (!filePath.startsWith(UPLOADS_DIR + path.sep)) {
    return NextResponse.json({ error: 'Access denied' }, { status: 403 })
  }

  // 4. Verify file exists and is a regular file (not a symlink to outside)
  try {
    const stats = await stat(filePath)
    if (!stats.isFile()) {
      return NextResponse.json({ error: 'Not a file' }, { status: 400 })
    }
  } catch {
    return NextResponse.json({ error: 'Not found' }, { status: 404 })
  }

  const file = await readFile(filePath)
  return new NextResponse(file)
}
```

```typescript
// ✅ Even better: use a lookup table instead of file paths
// app/api/download/route.ts
const ALLOWED_FILES: Record<string, string> = {
  'report-2024': '/var/data/reports/annual-2024.pdf',
  'guide': '/var/data/docs/user-guide.pdf',
}

export async function GET(request: NextRequest) {
  const fileId = request.nextUrl.searchParams.get('id')

  const filePath = ALLOWED_FILES[fileId ?? '']
  if (!filePath) {
    return NextResponse.json({ error: 'File not found' }, { status: 404 })
  }

  const file = await readFile(filePath)
  return new NextResponse(file)
}
```

**Key defenses:**

1. **`path.resolve()` + prefix check** — resolve the full path, then verify it starts with the allowed directory
2. **Reject `..` and null bytes** — catch traversal before path resolution
3. **Use allowlists** — map IDs to paths instead of using user input in paths
4. **Check `stat().isFile()`** — prevent serving directories or following symlinks out of the sandbox

**Detection hints:**

```bash
# Find file operations using user input
grep -rn "readFile\|writeFile\|createReadStream\|readdir" src/app/api --include="*.ts" | grep -i "params\|searchParams\|query"
# Find path.join with dynamic segments
grep -rn "path.join.*params\|path.resolve.*params" src/ --include="*.ts"
```

Reference: [CWE-22: Improper Limitation of a Pathname](https://cwe.mitre.org/data/definitions/22.html) · [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
