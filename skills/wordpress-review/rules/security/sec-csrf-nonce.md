---
title: Verify Nonces on All State-Changing Actions
description: "WordPress nonces prevent CSRF attacks. Every form submission, AJAX call, and admin action that modifies data must verify a nonce before processing."
impact: CRITICAL
impact_description: prevents cross-site request forgery enabling unauthorized settings changes and data modification
tags: [security, csrf, nonce, forms, wordpress]
cwe: ["CWE-352"]
owasp: ["A01:2021"]
detection_grep: "admin_post_|admin_init.*$_POST|wp_ajax_"
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
