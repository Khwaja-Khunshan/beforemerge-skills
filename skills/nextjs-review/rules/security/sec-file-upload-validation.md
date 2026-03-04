---
title: Validate File Uploads (Type, Size, Name, Content)
description: "Accepting file uploads without validating MIME type, size, extension, and filename sanitization enables code execution, storage abuse, and path traversal."
impact: HIGH
impact_description: prevents remote code execution, storage exhaustion, and malicious file serving
tags: [security, file-upload, validation, api, nextjs]
cwe: ["CWE-434"]
owasp: ["A04:2021"]
detection_grep: "formData.get.*file|request.formData|File|Blob"
---

## Validate File Uploads (Type, Size, Name, Content)

**Impact: HIGH (prevents remote code execution, storage exhaustion, and malicious file serving)**

Next.js route handlers accept `FormData` with files but provide zero built-in validation. Developers commonly check `file.type` (which is client-spoofable), skip size limits, and pass filenames directly to `fs.writeFile`. A malicious upload can:

- Execute server-side code if saved with a dangerous extension (`.js`, `.sh`, `.php`)
- Exhaust disk space with oversized files
- Traverse directories via crafted filenames (`../../etc/cron.d/malicious`)
- Serve malware to other users if re-served without content-type restrictions

**Incorrect (no validation):**

```typescript
// app/api/upload/route.ts
// ❌ Trusts everything from the client
export async function POST(request: NextRequest) {
  const formData = await request.formData()
  const file = formData.get('file') as File

  const bytes = await file.arrayBuffer()
  const buffer = Buffer.from(bytes)

  // ❌ Uses original filename — could be "../../.env" or "shell.js"
  await writeFile(path.join('uploads', file.name), buffer)

  return NextResponse.json({ url: `/uploads/${file.name}` })
}
```

**Correct (comprehensive validation):**

```typescript
// app/api/upload/route.ts
import { writeFile } from 'fs/promises'
import path from 'path'
import { randomUUID } from 'crypto'

const ALLOWED_TYPES = new Set(['image/jpeg', 'image/png', 'image/webp', 'application/pdf'])
const MAX_SIZE = 5 * 1024 * 1024 // 5 MB
const UPLOAD_DIR = path.resolve(process.cwd(), 'uploads')

// Magic bytes for common image types
const MAGIC_BYTES: Record<string, number[]> = {
  'image/jpeg': [0xFF, 0xD8, 0xFF],
  'image/png': [0x89, 0x50, 0x4E, 0x47],
  'image/webp': [0x52, 0x49, 0x46, 0x46], // RIFF
  'application/pdf': [0x25, 0x50, 0x44, 0x46], // %PDF
}

function validateMagicBytes(buffer: Buffer, claimedType: string): boolean {
  const expected = MAGIC_BYTES[claimedType]
  if (!expected) return false
  return expected.every((byte, i) => buffer[i] === byte)
}

export async function POST(request: NextRequest) {
  const formData = await request.formData()
  const file = formData.get('file')

  // 1. Verify it's actually a File object
  if (!file || !(file instanceof File)) {
    return NextResponse.json({ error: 'No file provided' }, { status: 400 })
  }

  // 2. Check file size BEFORE reading into memory
  if (file.size > MAX_SIZE) {
    return NextResponse.json({ error: 'File too large (max 5MB)' }, { status: 413 })
  }

  // 3. Check MIME type against allowlist
  if (!ALLOWED_TYPES.has(file.type)) {
    return NextResponse.json({ error: 'File type not allowed' }, { status: 415 })
  }

  const bytes = await file.arrayBuffer()
  const buffer = Buffer.from(bytes)

  // 4. Validate magic bytes (file.type is client-spoofable)
  if (!validateMagicBytes(buffer, file.type)) {
    return NextResponse.json({ error: 'File content does not match type' }, { status: 415 })
  }

  // 5. Generate a safe filename (never use the original)
  const ext = path.extname(file.name).toLowerCase()
  const safeExtensions = new Set(['.jpg', '.jpeg', '.png', '.webp', '.pdf'])
  if (!safeExtensions.has(ext)) {
    return NextResponse.json({ error: 'Invalid file extension' }, { status: 400 })
  }

  const safeFilename = `${randomUUID()}${ext}`
  const filePath = path.resolve(UPLOAD_DIR, safeFilename)

  // 6. Verify path is within upload directory
  if (!filePath.startsWith(UPLOAD_DIR + path.sep)) {
    return NextResponse.json({ error: 'Invalid path' }, { status: 400 })
  }

  await writeFile(filePath, buffer)
  return NextResponse.json({ url: `/uploads/${safeFilename}` })
}
```

**Validation checklist:**

| Check | Why | How |
|-------|-----|-----|
| File size | Prevent storage exhaustion | Compare `file.size` before reading |
| MIME type | Reject dangerous file types | Allowlist with `Set` |
| Magic bytes | Detect spoofed MIME types | Check first bytes of file content |
| Extension | Prevent executable uploads | Allowlist of safe extensions |
| Filename | Prevent path traversal | Generate UUID, never use original |
| Output path | Defense-in-depth | `path.resolve()` + prefix check |

**Detection hints:**

```bash
# Find upload handlers without validation
grep -rn "formData.get\|request.formData" src/app/api --include="*.ts" -l | \
  xargs grep -L "ALLOWED_TYPES\|MAX_SIZE\|magic\|validate"
# Find direct use of file.name in paths
grep -rn "file.name\|originalFilename" src/ --include="*.ts" | grep -i "join\|resolve\|write"
```

Reference: [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html) · [CWE-434: Unrestricted Upload](https://cwe.mitre.org/data/definitions/434.html)
