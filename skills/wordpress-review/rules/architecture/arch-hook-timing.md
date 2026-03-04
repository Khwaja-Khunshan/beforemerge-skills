---
title: Use the Correct WordPress Hook for Each Operation
description: "Registering CPTs on plugins_loaded, enqueueing scripts on init, or running admin-only code on every request wastes resources and causes subtle bugs."
impact: MEDIUM
impact_description: prevents wasted queries on frontend, failed registrations from wrong timing, and race conditions
tags: [architecture, hooks, actions, filters, timing, wordpress]
detection_grep: "add_action.*init.*enqueue|add_action.*plugins_loaded.*register_post_type"
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
