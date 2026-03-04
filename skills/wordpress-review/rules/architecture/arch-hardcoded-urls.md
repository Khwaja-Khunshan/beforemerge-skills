---
title: Use WordPress Path and URL Functions — Never Hardcode
description: "Hardcoded URLs and filesystem paths break across environments (local/staging/prod), subdirectory installs, multisite, and custom wp-content directories."
impact: MEDIUM
impact_description: prevents broken paths across environments, subdirectory installs, and multisite configurations
tags: [architecture, paths, urls, portability, wordpress]
detection_grep: "https?://.*wp-content|/var/www|/home/"
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
