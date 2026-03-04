---
title: Enqueue Scripts and Styles Properly with Conditional Loading
description: "Inline script tags bypass WordPress dependency management and load on every page. Use wp_enqueue_script with conditions to load assets only where needed."
impact: HIGH
impact_description: reduces unnecessary HTTP requests and JavaScript parse time on pages that don't need plugin assets
tags: [performance, scripts, styles, enqueue, assets, wordpress]
detection_grep: "echo.*<script|echo.*<link.*stylesheet|wp_head.*script"
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
