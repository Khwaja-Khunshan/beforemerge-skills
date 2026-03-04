---
title: Always Check Capabilities Before Privileged Operations
description: "WordPress capabilities (current_user_can) are the authorization layer. Missing checks in REST endpoints, admin handlers, and AJAX allow subscribers to perform admin actions."
impact: CRITICAL
impact_description: prevents privilege escalation allowing low-role users to perform admin-level operations
tags: [security, authorization, capabilities, rest-api, wordpress]
cwe: ["CWE-862"]
owasp: ["A01:2021"]
detection_grep: "register_rest_route|admin_post_|current_user_can"
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
