---
title: Secure AJAX Handlers with Nonce and Capability Checks
description: "WordPress AJAX handlers are public endpoints. wp_ajax_ fires for any logged-in user regardless of role. Always verify nonces and capabilities inside each handler."
impact: CRITICAL
impact_description: prevents unauthorized data access and modification through AJAX endpoints
tags: [security, ajax, authentication, authorization, nonce, wordpress]
cwe: ["CWE-862"]
owasp: ["A01:2021"]
detection_grep: "wp_ajax_|wp_ajax_nopriv_"
---

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
