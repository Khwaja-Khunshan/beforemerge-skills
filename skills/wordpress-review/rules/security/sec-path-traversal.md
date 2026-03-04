---
title: Prevent Path Traversal in File Operations and Includes
description: "User input in include/require or file read/write paths allows attackers to read wp-config.php, delete files, or execute arbitrary PHP via ../ sequences."
impact: CRITICAL
impact_description: arbitrary file read, write, or deletion on the server including wp-config.php
tags: [security, path-traversal, file-system, include, wordpress]
cwe: ["CWE-22"]
owasp: ["A01:2021"]
detection_grep: "include.*$_|require.*$_|readfile.*$_|file_get_contents.*$_"
---

## Prevent Path Traversal in File Operations and Includes

**Impact: CRITICAL (arbitrary file read, write, or deletion on the server including wp-config.php)**

Any file operation that uses user-supplied input — `include`, `require`, `readfile`, `file_get_contents`, `unlink` — without path validation is vulnerable to traversal attacks. An attacker sends `../../wp-config.php` to read database credentials, or `../../.htaccess` to modify access rules.

CVE-2024-10470 (WPLMS theme, CVSS 9.8) — unauthenticated path traversal via a download parameter used directly in `readfile()` and `unlink()`, allowing attackers to delete `wp-config.php` and trigger a WordPress reinstall. CVE-2024-9047 (WordPress File Upload plugin) — unauthenticated file read and deletion via path traversal.

**Incorrect (user input in file paths):**

```php
// ❌ Template inclusion with user-controlled value
$template = $_GET['template'];
include WP_CONTENT_DIR . '/plugins/my-plugin/templates/' . $template . '.php';
// Attacker: ?template=../../../../wp-config → reads wp-config.php

// ❌ File download with user-supplied filename
$file = $_GET['download'];
$path = WP_CONTENT_DIR . '/uploads/' . $file;
if ( file_exists( $path ) ) {
    readfile( $path ); // Reads any file on the server
}

// ❌ File deletion with user input
$filename = $_POST['file'];
unlink( WP_CONTENT_DIR . '/exports/' . $filename );
// Attacker: file=../../../wp-config.php → deletes wp-config.php
```

**Correct (allowlist or realpath validation):**

```php
// ✅ Allowlist approach — only permit known values
$allowed_templates = [ 'header', 'footer', 'sidebar', 'content' ];
$template = sanitize_key( $_GET['template'] );

if ( ! in_array( $template, $allowed_templates, true ) ) {
    wp_die( 'Invalid template.' );
}

include WP_CONTENT_DIR . '/plugins/my-plugin/templates/' . $template . '.php';
```

```php
// ✅ Realpath validation — verify the resolved path stays within allowed directory
$base_dir  = realpath( WP_CONTENT_DIR . '/uploads/exports/' );
$requested = sanitize_file_name( $_GET['download'] );
$full_path = realpath( $base_dir . '/' . $requested );

// Three checks: path resolved, is within base dir, file exists
if ( false === $full_path || 0 !== strpos( $full_path, $base_dir . DIRECTORY_SEPARATOR ) ) {
    wp_die( 'Access denied.' );
}

if ( ! is_file( $full_path ) ) {
    wp_die( 'File not found.' );
}

// Safe to serve
header( 'Content-Type: application/octet-stream' );
header( 'Content-Disposition: attachment; filename="' . basename( $full_path ) . '"' );
readfile( $full_path );
exit;
```

```php
// ✅ sanitize_file_name() strips path separators and dangerous characters
$filename = sanitize_file_name( $_POST['file'] );
// "../../wp-config.php" becomes "wp-config.php"
// But ALWAYS combine with realpath check for defense-in-depth

// ✅ For file deletion, use lookup table instead of user-supplied paths
$export_id = absint( $_POST['export_id'] );
$export = get_post( $export_id );

if ( ! $export || 'export' !== $export->post_type ) {
    wp_die( 'Invalid export.' );
}

$file_path = get_post_meta( $export_id, '_file_path', true );
if ( $file_path && file_exists( $file_path ) ) {
    wp_delete_file( $file_path ); // WordPress's safe file deletion
}
```

**Key defenses:**

1. **Allowlist** — restrict to known filenames; best for templates and includes
2. **`realpath()` + prefix check** — verify the resolved path is within the allowed directory
3. **`sanitize_file_name()`** — strips path separators (`/`, `\`, `..`) but use as defense-in-depth, not sole protection
4. **Lookup table** — map IDs to paths stored in the database; users never supply paths directly
5. **`wp_delete_file()`** — WordPress's safe deletion function with hooks for cleanup

**Detection hints:**

```bash
# Find include/require with user input
grep -rn "include.*\\\$_\|require.*\\\$_" wp-content/plugins/ --include="*.php"
# Find file operations with user input
grep -rn "readfile.*\\\$_\|file_get_contents.*\\\$_\|unlink.*\\\$_" wp-content/plugins/ --include="*.php"
# Find file operations without realpath validation
grep -rn "readfile\|file_get_contents" wp-content/plugins/ --include="*.php" | grep -v "realpath"
```

Reference: [sanitize_file_name()](https://developer.wordpress.org/reference/functions/sanitize_file_name/) · [CWE-22: Path Traversal](https://cwe.mitre.org/data/definitions/22.html)
