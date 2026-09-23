# Test-only OIDC signing keys

`oidc_signing.pem` / `oidc_signing.n` and `oidc_attacker.pem` / `oidc_attacker.n` are
throwaway 2048-bit RSA keys generated for the demo-hub integration tests. They exist only so
the mock identity provider in `tests/oauth_lifecycle.rs` can sign real RS256 ID tokens (and a
forged one with an unpublished key). They protect nothing, are not used by any deployment, and
must never be configured as real credentials. The `.n` files hold each key's base64url modulus
(the public exponent is `AQAB`) for the mock JWKS document.
