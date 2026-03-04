---
title: Keep Database Queries Out of Templates — Use pre_get_posts
description: "Direct $wpdb queries and query_posts() in template files create redundant queries, bypass caching, and mix data logic with presentation."
impact: HIGH
impact_description: eliminates redundant database queries and ORDER BY RAND() full table scans in templates
tags: [performance, database, templates, queries, pre-get-posts, wordpress]
detection_grep: "query_posts|\\$wpdb.*template|ORDER BY RAND"
---

## Keep Database Queries Out of Templates — Use pre_get_posts

**Impact: HIGH (eliminates redundant database queries and ORDER BY RAND() full table scans in templates)**

Template files (`single.php`, `archive.php`, template parts) should only render data — not fetch it. Direct `$wpdb` queries and `query_posts()` in templates cause:

- **`query_posts()`** overwrites the main query, wasting the original SQL query and breaking pagination
- **Direct `$wpdb`** queries bypass object caching, capability filtering, and post status checks
- **`ORDER BY RAND()`** causes a full table scan with filesort — catastrophic on large tables

**Incorrect (queries in templates):**

```php
<!-- single.php -->
<?php
// ❌ query_posts() overwrites the main query — the original query was wasted
query_posts( 'post_type=product&posts_per_page=10' );
while ( have_posts() ) : the_post();
    the_title();
endwhile;
// Pagination is broken, global state is corrupted
?>

<!-- sidebar.php -->
<?php
// ❌ Direct SQL in template — bypasses caching and object permissions
global $wpdb;
$popular = $wpdb->get_results(
    "SELECT ID, post_title FROM wp_posts
     WHERE post_type = 'post' AND post_status = 'publish'
     ORDER BY RAND() LIMIT 5"
);
// ORDER BY RAND() = full table scan on every page load
?>

<!-- archive.php -->
<?php
// ❌ Custom query overriding the main loop instead of modifying it
$custom = new WP_Query([
    'post_type'      => 'post',
    'posts_per_page' => 12,
    'category_name'  => 'featured',
]);
// The original archive query already ran and was thrown away
?>
```

**Correct (modify main query via pre_get_posts or use secondary queries properly):**

```php
// functions.php — modify the main query BEFORE it runs
function my_theme_customize_main_query( WP_Query $query ) {
    if ( is_admin() || ! $query->is_main_query() ) {
        return; // Only modify the main frontend query
    }

    // Customize archive pages
    if ( $query->is_archive() ) {
        $query->set( 'posts_per_page', 12 );
    }

    // Customize category pages
    if ( $query->is_category( 'featured' ) ) {
        $query->set( 'orderby', 'date' );
        $query->set( 'order', 'DESC' );
    }

    // Customize search
    if ( $query->is_search() ) {
        $query->set( 'post_type', [ 'post', 'page', 'product' ] );
    }
}
add_action( 'pre_get_posts', 'my_theme_customize_main_query' );
```

```php
// ✅ When a secondary query IS needed (sidebar widgets, related posts),
// use WP_Query (NEVER query_posts) and reset properly
<?php
$related = new WP_Query([
    'post_type'      => 'post',
    'posts_per_page' => 5,
    'post__not_in'   => [ get_the_ID() ],
    'category__in'   => wp_get_post_categories( get_the_ID() ),
    'no_found_rows'  => true, // Skip pagination count — saves one query
]);

if ( $related->have_posts() ) :
    while ( $related->have_posts() ) : $related->the_post();
        get_template_part( 'template-parts/card' );
    endwhile;
    wp_reset_postdata(); // Always reset after secondary WP_Query loops
endif;
?>
```

```php
// ✅ Instead of ORDER BY RAND(), use a cached random selection
function get_random_posts_cached( $count = 5 ) {
    $cache_key = 'random_posts_' . $count;
    $cached = get_transient( $cache_key );

    if ( false !== $cached ) {
        return $cached;
    }

    $posts = get_posts([
        'post_type'   => 'post',
        'numberposts' => $count,
        'orderby'     => 'rand',
        'no_found_rows' => true,
    ]);

    set_transient( $cache_key, $posts, 15 * MINUTE_IN_SECONDS );
    return $posts;
}
```

**Detection hints:**

```bash
# Find query_posts (almost always wrong)
grep -rn "query_posts\s*(" wp-content/themes/ wp-content/plugins/ --include="*.php"
# Find direct $wpdb in template files
grep -rn "\$wpdb->" wp-content/themes/ --include="*.php"
# Find ORDER BY RAND
grep -rn "ORDER BY RAND\|orderby.*rand" wp-content/ --include="*.php"
```

Reference: [pre_get_posts](https://developer.wordpress.org/reference/hooks/pre_get_posts/) · [When to use WP_Query vs query_posts](https://developer.wordpress.org/reference/functions/query_posts/)
