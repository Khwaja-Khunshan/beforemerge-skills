---
title: Sanitize All User Input with Type-Appropriate Functions
description: "Raw $_GET/$_POST/$_REQUEST data can contain anything. WordPress provides type-specific sanitization functions — use the right one for each data type before storage or use."
impact: HIGH
impact_description: prevents injection attacks and data corruption by ensuring input matches expected types
tags: [quality, sanitization, input-validation, security, wordpress]
cwe: ["CWE-20"]
owasp: ["A03:2021"]
detection_grep: "$_POST[|$_GET[|$_REQUEST["
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
