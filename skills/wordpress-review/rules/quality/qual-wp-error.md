---
title: Use WP_Error for Error Handling — Not Exceptions or False
description: "Returning false on failure hides what went wrong. WP_Error provides structured error codes, messages, and data — matching WordPress core's error handling pattern."
impact: MEDIUM
impact_description: enables proper error reporting, debugging, and user-facing error messages
tags: [quality, error-handling, wp-error, debugging, wordpress]
detection_grep: "WP_Error|is_wp_error|return false"
---

## Use WP_Error for Error Handling — Not Exceptions or False

**Impact: MEDIUM (enables proper error reporting, debugging, and user-facing error messages)**

WordPress core doesn't use PHP exceptions for error handling — it uses `WP_Error` objects. Functions like `wp_insert_post()`, `wp_remote_get()`, and `wp_create_user()` return `WP_Error` on failure. Your plugin code should follow the same pattern: return `WP_Error` with a structured code, message, and optional data instead of returning `false` or throwing exceptions.

**Incorrect (ambiguous error returns):**

```php
// ❌ Returning false — caller has no idea what went wrong
function create_invoice( int $order_id, array $data ): int|false {
    if ( empty( $data['amount'] ) ) {
        return false; // Why? Missing amount? Invalid amount? Permission issue?
    }

    $order = get_post( $order_id );
    if ( ! $order ) {
        return false; // Same false for a completely different error
    }

    // ...
    return $invoice_id;
}

// Caller has no useful error info
$invoice = create_invoice( $order_id, $data );
if ( ! $invoice ) {
    // What happened? We have no idea. Can't show a useful message.
    echo 'Something went wrong.';
}
```

```php
// ❌ Throwing exceptions (not idiomatic WordPress)
function process_payment( float $amount ): void {
    if ( $amount <= 0 ) {
        throw new \InvalidArgumentException( 'Invalid amount' );
    }
    // WordPress core and most plugins don't catch exceptions
    // Unhandled exception = white screen of death
}
```

```php
// ❌ Not checking wp_remote_get for errors before using result
$response = wp_remote_get( 'https://api.example.com/data' );
$body = json_decode( wp_remote_retrieve_body( $response ), true );
// If $response is WP_Error → wp_remote_retrieve_body returns '' → json_decode returns null → crash
```

**Correct (structured WP_Error returns):**

```php
// ✅ Return WP_Error with code, message, and data
function create_invoice( int $order_id, array $data ): int|WP_Error {
    if ( empty( $data['amount'] ) || $data['amount'] <= 0 ) {
        return new WP_Error(
            'invalid_amount',                                    // Error code (string slug)
            __( 'Invoice amount must be a positive number.', 'my-plugin' ), // Human-readable
            [ 'order_id' => $order_id, 'amount' => $data['amount'] ?? null ] // Debug data
        );
    }

    $order = get_post( $order_id );
    if ( ! $order || 'shop_order' !== $order->post_type ) {
        return new WP_Error(
            'invalid_order',
            __( 'Order not found.', 'my-plugin' ),
            [ 'order_id' => $order_id ]
        );
    }

    if ( ! current_user_can( 'edit_shop_orders' ) ) {
        return new WP_Error(
            'unauthorized',
            __( 'You do not have permission to create invoices.', 'my-plugin' ),
            [ 'status' => 403 ]
        );
    }

    $invoice_id = wp_insert_post([
        'post_type'   => 'invoice',
        'post_status' => 'publish',
        'post_parent' => $order_id,
    ]);

    if ( is_wp_error( $invoice_id ) ) {
        return $invoice_id; // Propagate WordPress's own error
    }

    return $invoice_id;
}
```

```php
// ✅ Caller handles errors with full context
$result = create_invoice( $order_id, $data );

if ( is_wp_error( $result ) ) {
    $code    = $result->get_error_code();    // 'invalid_amount'
    $message = $result->get_error_message(); // 'Invoice amount must be...'
    $data    = $result->get_error_data();    // ['order_id' => 42, 'amount' => -5]

    // In REST API:
    return $result; // WordPress auto-converts to proper JSON error response

    // In admin:
    add_settings_error( 'my_plugin', $code, $message, 'error' );

    // In AJAX:
    wp_send_json_error( $message, $data['status'] ?? 400 );
}

// Success
$invoice_id = $result;
```

```php
// ✅ Always check wp_remote_get before using the result
$response = wp_remote_get( 'https://api.example.com/data' );

if ( is_wp_error( $response ) ) {
    error_log( 'API call failed: ' . $response->get_error_message() );
    return $response; // Propagate the error
}

$code = wp_remote_retrieve_response_code( $response );
if ( 200 !== $code ) {
    return new WP_Error(
        'api_error',
        sprintf( __( 'API returned status %d', 'my-plugin' ), $code ),
        [ 'status' => $code ]
    );
}

$body = json_decode( wp_remote_retrieve_body( $response ), true );
```

```php
// ✅ Collecting multiple errors
$errors = new WP_Error();

if ( empty( $data['email'] ) ) {
    $errors->add( 'missing_email', __( 'Email is required.', 'my-plugin' ) );
}
if ( ! empty( $data['email'] ) && ! is_email( $data['email'] ) ) {
    $errors->add( 'invalid_email', __( 'Email address is invalid.', 'my-plugin' ) );
}
if ( empty( $data['name'] ) ) {
    $errors->add( 'missing_name', __( 'Name is required.', 'my-plugin' ) );
}

if ( $errors->has_errors() ) {
    return $errors; // Contains all validation failures
}
```

**Detection hints:**

```bash
# Find functions returning false on error (candidates for WP_Error)
grep -rn "return false" wp-content/plugins/my-plugin/ --include="*.php" -B 2 | grep -i "error\|fail\|invalid\|missing"
# Find wp_remote_get without is_wp_error check
grep -rn "wp_remote_get\|wp_remote_post" wp-content/plugins/ --include="*.php" -l | xargs grep -L "is_wp_error"
```

Reference: [WP_Error](https://developer.wordpress.org/reference/classes/wp_error/) · [WordPress Error Handling](https://developer.wordpress.org/plugins/security/data-validation/)
