---
title: Use WordPress APIs Instead of Raw PHP Functions
description: "Direct SQL, curl, file_put_contents, and mail() bypass WordPress caching, hooks, security filters, and host compatibility. Use WP_Query, wp_remote_get, WP_Filesystem, and wp_mail."
impact: MEDIUM
impact_description: ensures compatibility with caching layers, managed hosts, security plugins, and multisite
tags: [architecture, apis, compatibility, best-practices, wordpress]
detection_grep: "curl_init|file_put_contents|file_get_contents.*http|\\bmail\\("
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
