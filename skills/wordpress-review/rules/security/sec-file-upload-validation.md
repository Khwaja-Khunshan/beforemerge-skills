---
title: Use wp_handle_upload() with MIME Allowlists for File Uploads
description: "Direct move_uploaded_file() with only client-supplied MIME checks enables shell upload. Use wp_handle_upload() which validates both extension and file content."
impact: HIGH
impact_description: prevents remote code execution and malicious file serving through unrestricted uploads
tags: [security, file-upload, validation, mime, wordpress]
cwe: ["CWE-434"]
owasp: ["A04:2021"]
detection_grep: "move_uploaded_file|$_FILES"
---

## Use wp_handle_upload() with MIME Allowlists for File Uploads

**Impact: HIGH (prevents remote code execution and malicious file serving through unrestricted uploads)**

WordPress provides `wp_handle_upload()` which validates file extensions against the allowed MIME types, checks file content via `finfo`, generates unique filenames, and places files in the correct uploads directory. Using `move_uploaded_file()` directly bypasses all of these protections.

CVE-2024-43243 (JobBoard plugin) — `mime_content_type()` was the only check, allowing `.php` files disguised as images. CVE-2024-13342 (Booster for WooCommerce) — double-extension files bypassed the MIME whitelist.

**Incorrect (direct file handling):**

```php
// ❌ Only checks client-supplied MIME type (spoofable)
if ( $_FILES['upload']['type'] === 'image/jpeg' ) {
    move_uploaded_file(
        $_FILES['upload']['tmp_name'],
        WP_CONTENT_DIR . '/uploads/' . $_FILES['upload']['name'] // Original filename = path traversal risk
    );
}

// ❌ Blacklist approach (always incomplete)
$blacklist = [ 'php', 'php3', 'phtml', 'exe' ];
$ext = pathinfo( $_FILES['upload']['name'], PATHINFO_EXTENSION );
if ( ! in_array( strtolower( $ext ), $blacklist ) ) {
    move_uploaded_file( ... ); // pHP, php4, php7, phar, shtml all bypass this
}

// ❌ Using PHP's mime_content_type alone (checks content but not extension)
$mime = mime_content_type( $_FILES['upload']['tmp_name'] );
if ( strpos( $mime, 'image/' ) !== false ) {
    move_uploaded_file( $_FILES['upload']['tmp_name'], $dir . $_FILES['upload']['name'] );
    // shell.php with JPEG header bytes passes the content check!
}
```

**Correct (WordPress upload handler with MIME allowlist):**

```php
// ✅ Use wp_handle_upload() — validates extension + content + generates safe filename
function handle_file_upload() {
    check_admin_referer( 'my_plugin_upload' );

    if ( ! current_user_can( 'upload_files' ) ) {
        wp_die( 'Unauthorized' );
    }

    if ( empty( $_FILES['my_file'] ) ) {
        return new WP_Error( 'no_file', 'No file uploaded.' );
    }

    // Restrict to specific MIME types
    $overrides = [
        'test_form' => false, // Skip referer check (we already verified nonce)
        'mimes'     => [
            'jpg|jpeg|jpe' => 'image/jpeg',
            'png'          => 'image/png',
            'pdf'          => 'application/pdf',
        ],
    ];

    $result = wp_handle_upload( $_FILES['my_file'], $overrides );

    if ( isset( $result['error'] ) ) {
        return new WP_Error( 'upload_error', $result['error'] );
    }

    // $result contains: 'file' (path), 'url' (URL), 'type' (MIME)
    return $result;
}
```

```php
// ✅ To also register in the media library:
function handle_media_upload() {
    require_once ABSPATH . 'wp-admin/includes/file.php';
    require_once ABSPATH . 'wp-admin/includes/media.php';
    require_once ABSPATH . 'wp-admin/includes/image.php';

    $attachment_id = media_handle_upload( 'my_file', 0, [], [
        'test_form' => false,
        'mimes'     => [
            'jpg|jpeg|jpe' => 'image/jpeg',
            'png'          => 'image/png',
        ],
    ]);

    if ( is_wp_error( $attachment_id ) ) {
        return $attachment_id;
    }

    return wp_get_attachment_url( $attachment_id );
}
```

```php
// ✅ Restrict global upload types for your plugin's context
add_filter( 'upload_mimes', function( $mimes ) {
    // Remove dangerous types
    unset( $mimes['svg'] );  // SVG can contain JavaScript
    unset( $mimes['swf'] );  // Flash (shouldn't exist but sometimes allowed)
    return $mimes;
});
```

**What `wp_handle_upload()` does that you shouldn't replicate:**

1. Validates file extension against the MIME allowlist
2. Checks file content via `finfo` (magic bytes) if available
3. Generates a unique filename via `wp_unique_filename()`
4. Moves the file to the correct `wp-content/uploads/YYYY/MM/` directory
5. Sets proper file permissions
6. Applies the `wp_handle_upload` filter for plugin extensions

**Detection hints:**

```bash
# Find direct move_uploaded_file (should use wp_handle_upload instead)
grep -rn "move_uploaded_file" wp-content/plugins/ --include="*.php"
# Find $_FILES usage without WordPress upload functions
grep -rn "\$_FILES" wp-content/plugins/ --include="*.php" -l | xargs grep -L "wp_handle_upload\|media_handle_upload"
```

Reference: [wp_handle_upload()](https://developer.wordpress.org/reference/functions/wp_handle_upload/) · [CWE-434: Unrestricted Upload](https://cwe.mitre.org/data/definitions/434.html)
