# Demo hub authorization architecture

Status: implemented gateway slice, 2026-09-21. This note records the component
decision and the protocol boundary for issue #164. It does not claim live Google
evidence, deployment, or operation of a tester's account.

## Boundary and ownership

`agentpalace-demo-hub` is the dedicated gateway crate and `demo-hub` is its
local gateway binary. The gateway is the only place where
Google-specific login belongs. It receives verified upstream identity evidence,
maps it to the existing provider-neutral `AuthenticatedOwner` (`owner_id`,
issuer, subject, and email-at-write), and later issues credentials whose
audience is the configured AgentPalace resource. A Google ID/access token is
never a hub REST bearer token.

The crate's `GatewayConfig::validate` is intentionally fail-closed: secure
origins are HTTPS, while HTTP is accepted only for the exact configured
localhost/127.0.0.1 loopback demo mode. Google is fixed to
`https://accounts.google.com` and exactly `openid` plus `email`. Native clients
are public and callback-constrained to loopback. Secrets are server-side and
excluded from serialized output.

## Maintained component choices

| Concern | Selected component | Boundary owned by AgentPalace |
|---|---|---|
| HTTP routing and middleware | Axum 0.8 with Tokio | Route inventory, HTTPS/loopback rule, no `/mcp` or broad REST forwarding |
| OAuth authorization-code/device protocol | Axum form handlers with RFC 8252 PKCE and RFC 8628 state machines | One-time code binding, consent, resource/client checks, polling limits and error semantics |
| Google ID-token exchange and validation | `reqwest` plus `jsonwebtoken` in `GoogleOidcVerifierAdapter`, injected through the async `GoogleOidcVerifier` trait | Server-side code exchange at Google's fixed token endpoint with the exact hub callback; RS256-only signature check against the JWKS key named by `kid`; issuer, audience, expiry (no leeway), nonce, verified-email and subject checks; server-held state and nonce; no Google token admission. OIDC discovery documents are not fetched: the endpoints are fixed |
| Opaque hub grant handles | Cryptographically random in-memory handles | Hub issuer/resource binding, 15-minute access lifetime, seven-day grant ceiling, rotation and revocation; JWT signing/key rotation is not claimed |
| Browser sessions and CSRF | Axum cookie/session routes | Per-transaction browser-binding cookie, Secure cookies outside loopback demo mode, CSRF on consent and revocation forms, own-connection filtering. See the admin-scope note below |
| In-memory grants, admissions, and revocation | `GatewayState` maps owned by the gateway | Immutable owner/issuer/subject binding, email-change handling, refresh reuse detection and fail-closed admission policy; durable SQLite storage is not claimed |

The selected libraries provide maintained protocol primitives; they do not
decide AgentPalace's authorization. The gateway code remains responsible for
the resource audience, native-client registration, explicit consent, role
ceilings, grant ownership, and provenance separation. Dependency versions are
introduced with the endpoint slices so the lockfile changes remain reviewable
and each protocol surface has matching tests.

## Implemented gateway surfaces

The gateway advertises protected-resource and authorization-server metadata,
native registration, authorization/token/revocation, and device
authorization/verification endpoints. The in-memory demo state implements the
protocol invariants below; a durable adapter must persist the same records
atomically before deployment:

* authorization codes bound to client, redirect, S256 challenge, owner,
  resource, and consent, then consumed once and expired quickly;
* RFC 8628 device grants that are expiring, rate-limited, client-bound, and
  return `authorization_pending`, `slow_down` (adding five seconds to the
  interval), `access_denied`, and `expired_token`. The user code is drawn
  independently of the private device code from an unambiguous consonant
  alphabet. `Gateway::with_device_timing` sets the interval and lifetime
  (defaults: 5 seconds and 10 minutes);
* hub access tokens lasting 15 minutes and rotating refresh tokens with a
  seven-day absolute grant expiry, reuse detection, and revocation;
* browser sessions protected by CSRF, with connection lists/revocation limited
  to the authenticated owner's grants (recent-authentication administration is
  an open scope decision, below);
* a fail-closed admission-policy interface. The default denies every identity;
  an access-control adapter must admit only verified email plus stable
  issuer/subject and immutable owner ID. Verified email is evidence; the immutable owner ID and
  issuer/subject binding are authoritative. Email changes and subject
  reassignment require explicit admission handling, and external non-Gmail or
  non-Workspace mailboxes require the design's additional mailbox proof.

The HTTP `/authorize` handler creates a server-held browser transaction; it does
not accept an identity object or caller-supplied expected state/nonce. The
configured OIDC adapter exchanges the Google authorization code and validates
the returned ID token at `/auth/google/callback` (or
`/auth/google/device-callback` for RFC 8628 verification), after which the
gateway consumes the transaction and returns a hub authorization code or marks
the device grant approved. A Google ID
token or access token is never accepted by `/token` or by the protected
resource.

Refusals always reach the waiting native client. In the browser flow, an
upstream cancellation, an ID token that fails verification, a declined consent,
or an identity the admission policy refuses ends the transaction and redirects
to the client's loopback callback with `error=access_denied` (any other
upstream error becomes `server_error`). In the device flow, a declined consent,
an upstream cancellation, or a refused identity marks the grant denied, so the
next poll returns `access_denied` instead of waiting for expiry.

## Open scope decisions

* **Recent-authentication administration (issue #164).** The original issue
  asks for recent authentication before administration, but #164 defines no
  administrative HTTP operation and access-list administration is issue #165.
  The gateway therefore provides only the library boundary —
  `Gateway::create_admin_session` and `Gateway::require_recent_auth` — and no
  HTTP route creates an admin session or performs an administrative action. No
  admin endpoint was invented here; the route and its re-authentication step
  belong with the #165 administration surface.
* **Connection revocation handles.** `GET /connections` lists the signed-in
  owner's grants and uses each grant's current refresh token as its revocation
  handle for `POST /connections/revoke`. The list is owner-scoped and requires
  the session cookie; revocation additionally requires the session CSRF value.
  A separate opaque handle that never reveals the refresh token is deferred:
  no unauthorized disclosure path has been demonstrated, and changing it needs
  the durable grant store.

## Test evidence

`crates/agentpalace-demo-hub/tests/oauth_lifecycle.rs` drives the real
`RemoteClient` against the real `Gateway::router()` over loopback HTTP. The
gateway's `GoogleOidcVerifierAdapter` exchanges codes with a mock Google
provider that signs RS256 ID tokens with a test-only fixture key and serves the
matching JWKS; each simulated browser keeps its own cookie jar; the protected
resource is a test-only read that authorizes bearers with
`Gateway::authorize_rest`. The tests cover: browser login over an ephemeral
loopback port through to an authorized read; distinct upstream redirect URIs
for browser sign-in and device verification; declined, cancelled, unadmitted,
unverified-email, and forged-signature logins reaching the client as denials;
stolen callbacks and consent forms, forged CSRF, consent replay, and hub code
exchange with a wrong redirect, wrong PKCE verifier, or replayed code; device
pending-then-approval, denials, mixed browser/transaction attempts that leave
unrelated grants untouched, `slow_down` and expiry, and client cancellation;
refresh rotation, reuse detection that revokes the family including issued
access tokens, logout revocation, bounded recovery of a server-rejected but
unexpired token, two-issuer isolation in one credential store, exact
trailing-slash resource identity through login, reuse, refresh, and logout;
and every ID-token claim and signature failure plus exchange and network
failures. Live Google sign-in remains unverified by this repository.

## Explicit exclusions

This slice does not add REST forwarding, `/mcp`, a memory dashboard, Docker or
deployment resources, Google Cloud resources, account operations, or issue
#165 access administration. Offline defaults and the existing bearer-token
path remain unchanged. The shared palace may be visible to admitted users,
but provenance never becomes permission or truth by implication.
