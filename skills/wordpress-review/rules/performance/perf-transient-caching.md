---
title: Cache Expensive Operations with Transients
description: "External API calls, complex calculations, and aggregation queries should use set_transient/get_transient to avoid repeating expensive work on every page load."
impact: HIGH
impact_description: reduces page load time by 200-2000ms for pages making external API calls or complex queries
tags: [performance, caching, transients, api, wordpress]
detection_grep: "wp_remote_get|wp_remote_post|$wpdb->get_results"
---

## Cache Expensive Operations with Transients

**Impact: HIGH (reduces page load time by 200-2000ms for pages making external API calls or complex queries)**

WordPress transients are key-value pairs with an expiration time, stored in `wp_options` (or in a persistent object cache like Redis if configured). Any operation that is slow and returns the same result for a period of time should be cached: external API calls, complex database aggregations, third-party SDK queries, and computationally expensive transformations.

**Incorrect (uncached expensive operations on every request):**

```php
// ❌ HTTP request on every page load — 200-2000ms latency each time
function get_exchange_rates() {
    $response = wp_remote_get( 'https://api.exchangerate.host/latest' );
    if ( is_wp_error( $response ) ) {
        return [];
    }
    return json_decode( wp_remote_retrieve_body( $response ), true );
}

// ❌ Complex aggregation query on every request
function get_sales_stats() {
    global $wpdb;
    return $wpdb->get_results(
        "SELECT DATE(post_date) as date, COUNT(*) as orders, SUM(meta_value) as revenue
         FROM {$wpdb->posts} p
         JOIN {$wpdb->postmeta} pm ON p.ID = pm.post_id AND pm.meta_key = '_order_total'
         WHERE p.post_type = 'shop_order' AND p.post_status = 'wc-completed'
         GROUP BY DATE(post_date)
         ORDER BY date DESC
         LIMIT 30"
    );
    // Runs a JOIN + GROUP BY on every page load
}
```

**Correct (transient caching with proper patterns):**

```php
// ✅ Cache external API calls
function get_exchange_rates() {
    $cache_key = 'my_plugin_exchange_rates';
    $cached = get_transient( $cache_key );

    if ( false !== $cached ) {
        return $cached; // Cache hit
    }

    $response = wp_remote_get( 'https://api.exchangerate.host/latest', [
        'timeout' => 10,
    ]);

    if ( is_wp_error( $response ) ) {
        // On failure, try to use expired cache (stale-while-revalidate pattern)
        $stale = get_option( '_transient_stale_' . $cache_key );
        return $stale ?: [];
    }

    $data = json_decode( wp_remote_retrieve_body( $response ), true );

    // Cache for 1 hour; store a stale copy as backup
    set_transient( $cache_key, $data, HOUR_IN_SECONDS );
    update_option( '_transient_stale_' . $cache_key, $data, 'no' ); // autoload=no

    return $data;
}
```

```php
// ✅ Cache complex queries with cache invalidation on data change
function get_sales_stats() {
    $cache_key = 'my_plugin_sales_stats';
    $cached = get_transient( $cache_key );

    if ( false !== $cached ) {
        return $cached;
    }

    global $wpdb;
    $results = $wpdb->get_results(
        $wpdb->prepare(
            "SELECT DATE(post_date) as date, COUNT(*) as orders, SUM(meta_value) as revenue
             FROM {$wpdb->posts} p
             JOIN {$wpdb->postmeta} pm ON p.ID = pm.post_id AND pm.meta_key = %s
             WHERE p.post_type = %s AND p.post_status = %s
             GROUP BY DATE(post_date)
             ORDER BY date DESC
             LIMIT 30",
            '_order_total',
            'shop_order',
            'wc-completed'
        )
    );

    set_transient( $cache_key, $results, 15 * MINUTE_IN_SECONDS );
    return $results;
}

// Invalidate when new orders are placed
add_action( 'woocommerce_order_status_completed', function() {
    delete_transient( 'my_plugin_sales_stats' );
});
```

**WordPress time constants:**

| Constant | Seconds |
|----------|---------|
| `MINUTE_IN_SECONDS` | 60 |
| `HOUR_IN_SECONDS` | 3,600 |
| `DAY_IN_SECONDS` | 86,400 |
| `WEEK_IN_SECONDS` | 604,800 |

**When NOT to use transients:**

- Data that changes on every request (user-specific session data)
- Small/fast operations (a single indexed query is faster than transient overhead)
- Sensitive data (transients are stored in `wp_options`, accessible on shared object caches)

**Detection hints:**

```bash
# Find API calls without transient caching
grep -rn "wp_remote_get\|wp_remote_post" wp-content/plugins/ --include="*.php" -l | xargs grep -L "get_transient\|set_transient"
# Find complex queries without caching
grep -rn "GROUP BY\|JOIN.*JOIN\|UNION" wp-content/plugins/ --include="*.php" -l | xargs grep -L "transient\|wp_cache"
```

Reference: [Transients API](https://developer.wordpress.org/apis/transients/) · [WordPress Performance Best Practices](https://developer.wordpress.org/advanced-administration/performance/)
