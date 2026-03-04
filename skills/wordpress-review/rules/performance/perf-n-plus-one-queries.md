---
title: Avoid N+1 Queries in Post Loops
description: "Calling get_post_meta() inside loops without cache priming generates one database query per post. Use update_post_meta_cache or meta_query to batch lookups."
impact: HIGH
impact_description: reduces database queries from N+1 to 2 in post loops, critical for archive pages
tags: [performance, database, queries, n-plus-one, meta, wordpress]
detection_grep: "get_post_meta.*get_the_ID|get_post_meta.*\\$post->ID"
---

## Avoid N+1 Queries in Post Loops

**Impact: HIGH (reduces database queries from N+1 to 2 in post loops, critical for archive pages)**

When you loop through posts and call `get_post_meta()` for each one, WordPress executes a separate database query per post — unless the meta cache has been primed. With 50 posts, that's 51 queries instead of 2. On archive pages, category pages, and search results, this is the single most impactful query anti-pattern in WordPress.

**Incorrect (N+1 queries):**

```php
// ❌ Explicitly disabling meta cache priming, then reading meta in loop
$query = new WP_Query([
    'post_type'              => 'product',
    'posts_per_page'         => 50,
    'update_post_meta_cache' => false, // Disables bulk cache prime
]);

while ( $query->have_posts() ) {
    $query->the_post();
    $price = get_post_meta( get_the_ID(), '_price', true );    // Query #2
    $sku   = get_post_meta( get_the_ID(), '_sku', true );      // Query #3
    $stock = get_post_meta( get_the_ID(), '_stock', true );     // Query #4
    // × 50 posts = 150 extra queries!
    echo esc_html( "$sku: $$price ($stock in stock)" );
}

// ❌ get_posts() with suppress_filters disabling cache
$posts = get_posts([
    'post_type'              => 'product',
    'numberposts'            => 100,
    'update_post_meta_cache' => false,
]);
foreach ( $posts as $post ) {
    $featured_image = get_post_thumbnail_id( $post->ID ); // 1 query per post
}
```

**Correct (cache-primed queries):**

```php
// ✅ Keep update_post_meta_cache enabled (the default)
// WordPress runs one bulk query: SELECT * FROM wp_postmeta WHERE post_id IN (1,2,3,...)
$query = new WP_Query([
    'post_type'              => 'product',
    'posts_per_page'         => 50,
    'update_post_meta_cache' => true,  // Default — primes meta cache in one query
]);

while ( $query->have_posts() ) {
    $query->the_post();
    $price = get_post_meta( get_the_ID(), '_price', true );    // Cache hit — no query
    $sku   = get_post_meta( get_the_ID(), '_sku', true );      // Cache hit — no query
    echo esc_html( "$sku: $$price" );
}
```

```php
// ✅ When you only need posts matching specific meta values, use meta_query
$query = new WP_Query([
    'post_type'      => 'product',
    'posts_per_page' => 50,
    'meta_query'     => [
        [
            'key'     => '_price',
            'value'   => 100,
            'compare' => '>=',
            'type'    => 'NUMERIC',
        ],
        [
            'key'     => '_stock',
            'value'   => 0,
            'compare' => '>',
            'type'    => 'NUMERIC',
        ],
    ],
]);
```

```php
// ✅ Manually prime meta cache for a custom set of post IDs
$post_ids = [ 1, 2, 3, 4, 5 ];
update_meta_cache( 'post', $post_ids ); // One bulk query for all

foreach ( $post_ids as $id ) {
    $title = get_post_meta( $id, 'custom_title', true ); // All cache hits
}

// ✅ Disable term cache if you don't need terms (save one query)
$query = new WP_Query([
    'post_type'              => 'product',
    'posts_per_page'         => 50,
    'update_post_term_cache' => false, // Skip if not displaying categories/tags
    'no_found_rows'          => true,  // Skip SQL_CALC_FOUND_ROWS if no pagination
]);
```

**Query optimization reference:**

| WP_Query arg | Default | Set to | Saves |
|-------------|---------|--------|-------|
| `update_post_meta_cache` | `true` | Keep `true` | N meta queries → 1 bulk |
| `update_post_term_cache` | `true` | `false` if unused | 1 term query |
| `no_found_rows` | `false` | `true` if no pagination | 1 COUNT query |
| `fields` | `all` | `'ids'` if only IDs needed | Reduced memory |

**Detection hints:**

```bash
# Find loops with meta calls that might be N+1
grep -rn "get_post_meta" wp-content/plugins/ wp-content/themes/ --include="*.php" -l | xargs grep -l "have_posts\|foreach.*\$posts"
# Find queries with disabled meta cache
grep -rn "update_post_meta_cache.*false" wp-content/ --include="*.php"
```

Reference: [WP_Query](https://developer.wordpress.org/reference/classes/wp_query/) · [update_meta_cache()](https://developer.wordpress.org/reference/functions/update_meta_cache/)
