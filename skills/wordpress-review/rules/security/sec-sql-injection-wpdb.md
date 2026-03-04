---
title: Always Use $wpdb->prepare() for Database Queries
description: "Passing user input directly into SQL queries via $wpdb enables SQL injection. Always use $wpdb->prepare() with typed placeholders (%d, %s, %f, %i)."
impact: CRITICAL
impact_description: prevents SQL injection enabling full database read/write and potential server compromise
tags: [security, sql-injection, database, wpdb, wordpress]
cwe: ["CWE-89"]
owasp: ["A03:2021"]
detection_grep: "$wpdb->query|$wpdb->get_results|$wpdb->get_row|$wpdb->get_var"
---

## Always Use $wpdb->prepare() for Database Queries

**Impact: CRITICAL (prevents SQL injection enabling full database read/write and potential server compromise)**

WordPress provides `$wpdb->prepare()` to safely parameterize SQL queries. Any query that includes user-controlled values — `$_GET`, `$_POST`, function parameters, URL slugs — without `prepare()` is vulnerable to SQL injection. This is the #1 vulnerability class in WordPress plugins.

CVE-2024-27956 (WP Automatic plugin, CVSS 9.8) demonstrated unauthenticated SQL injection through direct query construction, allowing attackers to create admin accounts. CVE-2024-2879 (LayerSlider, CVSS 9.8) was another unauthenticated SQLi from the same pattern.

**Incorrect (user input in query strings):**

```php
// ❌ Direct variable interpolation — classic SQL injection
$id = $_GET['id'];
$results = $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}users WHERE ID = $id" );
// Attacker sends: ?id=1 UNION SELECT user_login,user_pass FROM wp_users--

// ❌ String concatenation
$search = $_POST['search'];
$results = $wpdb->get_results(
    "SELECT * FROM {$wpdb->prefix}posts WHERE post_title LIKE '%" . $search . "%'"
);

// ❌ Variable inside prepare() string (not as a parameter)
$wpdb->query( $wpdb->prepare(
    "SELECT * FROM {$wpdb->prefix}posts WHERE post_status = %s AND ID = $id",
    'publish'
) );
// $id is still interpolated before prepare() sees it!

// ❌ Using sprintf instead of prepare (no escaping)
$sql = sprintf( "DELETE FROM %s WHERE id = %d", $wpdb->prefix . 'logs', $_GET['id'] );
$wpdb->query( $sql );
```

**Correct (all values through prepare()):**

```php
// ✅ Integer value: %d
$id = absint( $_GET['id'] ); // absint() as defense-in-depth
$result = $wpdb->get_row(
    $wpdb->prepare(
        "SELECT * FROM {$wpdb->prefix}users WHERE ID = %d",
        $id
    )
);

// ✅ String value: %s (auto-quoted and escaped)
$search = sanitize_text_field( $_POST['search'] );
$results = $wpdb->get_results(
    $wpdb->prepare(
        "SELECT * FROM {$wpdb->prefix}posts WHERE post_title LIKE %s",
        '%' . $wpdb->esc_like( $search ) . '%'
    )
);

// ✅ Multiple values with mixed types
$results = $wpdb->get_results(
    $wpdb->prepare(
        "SELECT * FROM {$wpdb->prefix}posts WHERE post_author = %d AND post_status = %s AND post_date > %s",
        $author_id,
        'publish',
        '2024-01-01'
    )
);

// ✅ Table/column identifiers: %i (WordPress 6.1+)
$column = sanitize_key( $_GET['sort_by'] );
$results = $wpdb->get_results(
    $wpdb->prepare(
        "SELECT ID, post_title FROM {$wpdb->prefix}posts ORDER BY %i DESC",
        $column
    )
);

// ✅ IN clause with array of IDs
$ids = array_map( 'absint', $_POST['ids'] );
$placeholders = implode( ',', array_fill( 0, count( $ids ), '%d' ) );
$results = $wpdb->get_results(
    $wpdb->prepare(
        "SELECT * FROM {$wpdb->prefix}posts WHERE ID IN ($placeholders)",
        ...$ids
    )
);
```

**Placeholder reference:**

| Placeholder | Type | Example |
|-------------|------|---------|
| `%d` | Integer | `WHERE ID = %d` |
| `%s` | String (auto-quoted) | `WHERE name = %s` |
| `%f` | Float | `WHERE price = %f` |
| `%i` | Identifier (WP 6.1+) | `ORDER BY %i` |
| `%%` | Literal % | `LIKE '%%%s%%'` |

**For LIKE queries**, always use `$wpdb->esc_like()` to escape `%` and `_` wildcards in the search term, then wrap with `%` outside.

**Detection hints:**

```bash
# Find $wpdb calls without prepare()
grep -rn "\$wpdb->query\|\$wpdb->get_results\|\$wpdb->get_row\|\$wpdb->get_var" wp-content/plugins/ --include="*.php" | grep -v "prepare"
# Find variable interpolation inside SQL strings
grep -rn "\$wpdb->.*\"SELECT.*\\\$" wp-content/plugins/ --include="*.php"
```

Reference: [wpdb::prepare()](https://developer.wordpress.org/reference/classes/wpdb/prepare/) · [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
