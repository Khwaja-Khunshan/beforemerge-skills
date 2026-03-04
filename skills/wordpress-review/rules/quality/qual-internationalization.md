---
title: Make All User-Facing Strings Translatable
description: "Hardcoded English strings prevent localization. Use __(), _e(), and esc_html__() with a text domain. Always escape translated output — translators can inject HTML."
impact: MEDIUM
impact_description: enables translation to other languages and prevents XSS through malicious translation files
tags: [quality, internationalization, i18n, localization, translation, wordpress]
detection_grep: "echo.*'[A-Z]|_e\\(|__\\("
---

## Make All User-Facing Strings Translatable

**Impact: MEDIUM (enables translation to other languages and prevents XSS through malicious translation files)**

Every user-facing string in a WordPress plugin or theme should be wrapped in a translation function with a text domain. Without this, your code cannot be translated to other languages — a requirement for the WordPress.org plugin/theme directory.

Critically, **always use escaped variants** (`esc_html__()`, `esc_html_e()`, `esc_attr__()`) when outputting translated strings. Third-party translators can inject HTML through `.po` translation files, creating a stored XSS vector.

**Incorrect (hardcoded English strings):**

```php
// ❌ Not translatable
echo '<h2>Settings</h2>';
echo '<p>Welcome back, ' . $username . '!</p>';
echo '<button>Save Changes</button>';
echo '<input placeholder="Enter your name">';

// ❌ Translatable but not escaped — XSS via malicious translation file
echo '<h2>' . __( 'Settings', 'my-plugin' ) . '</h2>';
_e( 'Save Changes', 'my-plugin' ); // _e() echoes without escaping

// ❌ Variables inside translated strings (untranslatable word order)
echo __( 'Found ', 'my-plugin' ) . $count . __( ' results', 'my-plugin' );
// "Found 5 results" — word order is English-specific
```

**Correct (translatable and escaped):**

```php
// ✅ Escaped translated output
echo '<h2>' . esc_html__( 'Settings', 'my-plugin' ) . '</h2>';
esc_html_e( 'Save Changes', 'my-plugin' );
echo '<input placeholder="' . esc_attr__( 'Enter your name', 'my-plugin' ) . '">';

// ✅ Variables in translated strings — use printf with placeholders
printf(
    /* translators: %s: username */
    esc_html__( 'Welcome back, %s!', 'my-plugin' ),
    esc_html( $username )
);

// ✅ Plural forms (different languages have different plural rules)
printf(
    esc_html( _n(
        '%d result found',
        '%d results found',
        $count,
        'my-plugin'
    ) ),
    $count
);

// ✅ Context disambiguation (same English word, different meaning)
$post_noun = _x( 'Post', 'noun: a blog post', 'my-plugin' );
$post_verb = _x( 'Post', 'verb: to publish', 'my-plugin' );

// ✅ URLs in translated strings
printf(
    wp_kses(
        /* translators: %s: documentation URL */
        __( 'Read the <a href="%s">documentation</a> for more info.', 'my-plugin' ),
        [ 'a' => [ 'href' => [] ] ]
    ),
    esc_url( 'https://docs.example.com' )
);
```

**Translation function reference:**

| Context | Return | Echo |
|---------|--------|------|
| Plain string | `__( $text, $domain )` | `_e( $text, $domain )` |
| HTML-escaped | `esc_html__( $text, $domain )` | `esc_html_e( $text, $domain )` |
| Attribute-escaped | `esc_attr__( $text, $domain )` | `esc_attr_e( $text, $domain )` |
| Plural forms | `_n( $single, $plural, $count, $domain )` | — (use with printf) |
| With context | `_x( $text, $context, $domain )` | `_ex( $text, $context, $domain )` |

**Key rules:**

1. **Always use the text domain** — the second parameter matching your plugin/theme slug
2. **Never concatenate translated fragments** — use printf placeholders instead
3. **Always escape translated output** — use `esc_html__()` not `__()`
4. **Add translator comments** before strings with placeholders: `/* translators: %s: username */`
5. **Never include HTML in translated strings** unless you use `wp_kses()` on the output

**Detection hints:**

```bash
# Find hardcoded English strings in PHP output
grep -rn "echo\s*'[A-Z]\|echo\s*\"[A-Z]" wp-content/plugins/my-plugin/ --include="*.php" | grep -v "__\|_e\|esc_"
# Find unescaped translation output
grep -rn "\b_e\s*(\|echo\s*__\s*(" wp-content/plugins/ --include="*.php"
```

Reference: [WordPress Internationalization](https://developer.wordpress.org/plugins/internationalization/) · [How to Internationalize Your Plugin](https://developer.wordpress.org/plugins/internationalization/how-to-internationalize-your-plugin/)
