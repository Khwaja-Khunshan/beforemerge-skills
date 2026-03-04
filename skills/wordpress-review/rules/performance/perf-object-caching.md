---
title: Use Object Cache for Repeated Expensive Queries
description: "wp_cache_get/set with a persistent backend (Redis/Memcached) eliminates redundant database queries across requests. Without it, identical queries run on every page load."
impact: MEDIUM
impact_description: eliminates repeated database queries for frequently accessed data across multiple requests
tags: [performance, caching, object-cache, redis, memcached, wordpress]
detection_grep: "wp_cache_get|wp_cache_set|new WP_Query"
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
