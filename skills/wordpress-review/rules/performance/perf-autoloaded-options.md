---
title: Disable Autoload for Large or Infrequently Used Options
description: "All autoloaded options are loaded into memory on every page request. Large serialized arrays in autoloaded options waste memory and slow every page."
impact: HIGH
impact_description: reduces memory usage and page load time by preventing megabytes of unused data from loading on every request
tags: [performance, database, options, autoload, memory, wordpress]
detection_grep: "add_option|update_option"
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
