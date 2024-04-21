# What?

This a very simple wrapper for public and private keys used in Fedineko.

Intention is to support (eventually) all types of HTTP Signature Algorithms
as defined in https://www.rfc-editor.org/rfc/rfc9421.html#name-initial-contents.

Currently, only subset of algorithms from the registry above is supported.

Signature verification:
* `rsa-pss-sha512`
* `rsa-v1_5-sha256`
* `hmac-sha256`
* `ecdsa-p256-sha256`
* `ed25519`

Signing:
* `rsa-v1_5-sha256`
* `hmac-sha256`
* `ed25519`

# How?

API is basic: load key then sign/verify.

The only thing to note is `hint` to specify crypto algorithm.
If it is not set or is not known, then `puprik` will try different supported
algorithms one by one until it succeeds or fails with no more algorithm to try.

## Signing
```rust
use puprik::private_key::PrivateKey;

let private_key = PrivateKey::from_pem_text(
    "test-key-ecc-p256",        // key ID
    PRIVATE_KEY_TEXT,           // PEM text
    Some("ecdsa-p256-sha256"),  // hint
).unwrap();

let message: &[u8] = ...;

// signs slice and returns vector of u8.
let signature = private_key.sign(message).unwrap();
```

## Verifying
```rust
use puprik::public_key::PublicKey;

let public_key = PublicKey::from_pem_text(
    "test-key-rsa-pss",         // key ID
    PUBLIC_KEY_TEXT,            // PEM text
    None,                       // algorithm hint
).unwrap();

let message: &str = "...";
let signature: &str = "...";

// verifies base64-encoded signature for message.
let is_valid = public_key.verify_base64(message, signature);
```

# License
MIT or Apache 2.0.
