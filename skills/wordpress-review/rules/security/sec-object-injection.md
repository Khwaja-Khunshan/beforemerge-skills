---
title: Never Unserialize User-Controlled Data
description: "PHP's unserialize() instantiates arbitrary classes and triggers magic methods. Deserialization of user input enables remote code execution via gadget chains."
impact: CRITICAL
impact_description: prevents remote code execution through PHP object injection and gadget chain exploitation
tags: [security, deserialization, object-injection, php, wordpress]
cwe: ["CWE-502"]
owasp: ["A08:2021"]
detection_grep: "unserialize|maybe_unserialize"
---

## Never Unserialize User-Controlled Data

**Impact: CRITICAL (prevents remote code execution through PHP object injection and gadget chain exploitation)**

PHP's `unserialize()` reconstructs objects from a serialized string, invoking magic methods (`__wakeup`, `__destruct`, `__toString`) on the instantiated classes. In a WordPress environment, the large number of loaded classes from core, plugins, and themes creates an extensive "gadget chain" surface. An attacker who controls the serialized string can chain these magic methods to achieve arbitrary file read/write, file deletion, or remote code execution.

CVE-2024-5932 (GiveWP, CVSS 10.0) — unauthenticated PHP object injection via a POST parameter, leading to RCE. CVE-2024-10957 (UpdraftPlus, 3M+ installs) — object injection allowing unauthenticated file deletion and data exfiltration.

**Incorrect (deserializing user-controlled data):**

```php
// ❌ Unserializing cookie data — attacker controls the cookie value
$prefs = unserialize( base64_decode( $_COOKIE['user_prefs'] ) );

// ❌ maybe_unserialize() on POST data — same vulnerability
$config = maybe_unserialize( $_POST['config_data'] );
// maybe_unserialize() calls unserialize() internally when it detects serialized format

// ❌ Unserializing data from a user-editable field
$cached = get_user_meta( $user_id, 'cached_data', true );
$data = unserialize( $cached );
// If a user can set their own meta (via profile form), this is exploitable

// ❌ Accepting serialized data in a REST API endpoint
function handle_import( WP_REST_Request $request ) {
    $data = unserialize( $request->get_param( 'payload' ) );
    process_import( $data );
}
```

**Correct (use JSON or let WordPress handle serialization internally):**

```php
// ✅ Use JSON for data interchange — not deserializable into objects
$prefs = json_decode( stripslashes( $_COOKIE['user_prefs'] ), true );
if ( ! is_array( $prefs ) ) {
    $prefs = []; // Default on invalid data
}

// ✅ Store structured data as arrays via WordPress APIs
// WordPress serializes/deserializes internally when storing arrays
update_user_meta( $user_id, 'preferences', [
    'theme' => 'dark',
    'notifications' => true,
]);
$prefs = get_user_meta( $user_id, 'preferences', true ); // Returns array

// ✅ For REST API imports, accept JSON
function handle_import( WP_REST_Request $request ) {
    $data = $request->get_json_params(); // Already parsed as array
    if ( ! is_array( $data ) ) {
        return new WP_Error( 'invalid_payload', 'Expected JSON array', [ 'status' => 400 ] );
    }
    process_import( $data );
}

// ✅ If you must handle serialized data from trusted internal sources,
// validate the source is truly not user-controllable
// NEVER unserialize data that a user could have influenced
```

**Key principles:**

1. **Never call `unserialize()` on user input** — `$_GET`, `$_POST`, `$_COOKIE`, `$_REQUEST`, or any data derived from them
2. **`maybe_unserialize()` is equally dangerous** — it calls `unserialize()` internally
3. **Use `json_encode()`/`json_decode()` for data interchange** — JSON cannot instantiate PHP objects
4. **Let WordPress handle serialization** — `update_option()`, `update_post_meta()`, `update_user_meta()` serialize arrays automatically and are safe when the stored value doesn't originate from raw user input
5. **Audit anywhere serialized data is stored** — if a user can control the value that gets serialized into the database, they can exploit it when it's unserialized

**Detection hints:**

```bash
# Find all unserialize calls
grep -rn "unserialize\s*(" wp-content/plugins/ --include="*.php"
# Find maybe_unserialize calls
grep -rn "maybe_unserialize\s*(" wp-content/plugins/ --include="*.php"
# Check if any are on user-controlled data
grep -rn "unserialize.*\\\$_\|maybe_unserialize.*\\\$_" wp-content/plugins/ --include="*.php"
```

Reference: [PHP Object Injection](https://owasp.org/www-community/vulnerabilities/PHP_Object_Injection) · [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
