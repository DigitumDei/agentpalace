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
| OAuth authorization-code/device protocol | `oauth2` maintained Rust implementation, with RFC 8252 PKCE and RFC 8628 handlers | One-time code binding, consent, resource/client checks, polling limits and error semantics |
| Google OIDC discovery and ID-token validation | `openidconnect` maintained Rust implementation, injected through `GoogleOidcVerifier` | Exact issuer/audience/expiry/signature/verified-email checks, server-held state and nonce, and no Google token admission |
| Hub JWT signing/key rotation | `jsonwebtoken` with a server-side key ring | Hub issuer/resource claims, 15-minute access lifetime, seven-day grant ceiling, key rotation and revocation |
| Browser sessions and CSRF | `tower-sessions` plus Axum middleware | Secure cookie policy, CSRF on mutations, recent-auth admin boundary and own-connection filtering |
| Durable grants, admissions, and revocation | Existing SQLite/Rusqlite storage boundary | Immutable owner/issuer/subject binding, email-change handling, refresh reuse detection and fail-closed admission policy |

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
* RFC 8628 user/device codes that are expiring, rate-limited, client-bound,
  and correctly return `authorization_pending`/`slow_down`;
* hub access tokens lasting 15 minutes and rotating refresh tokens with a
  seven-day absolute grant expiry, reuse detection, and revocation;
* browser sessions protected by CSRF, with recent authentication required for
  administration and connection lists/revocation limited to the authenticated
  owner's grants;
* a fail-closed admission-policy interface. The default denies every identity;
  an access-control adapter must admit only verified email plus stable
  issuer/subject and immutable owner ID. Verified email is evidence; the immutable owner ID and
  issuer/subject binding are authoritative. Email changes and subject
  reassignment require explicit admission handling, and external non-Gmail or
  non-Workspace mailboxes require the design's additional mailbox proof.

The HTTP `/authorize` handler creates a server-held browser transaction; it does
not accept an identity object or caller-supplied expected state/nonce. The
configured OIDC adapter exchanges the Google authorization code and validates
the returned ID token at `/auth/google/callback`, after which the gateway
consumes the transaction and returns a hub authorization code. A Google ID
token or access token is never accepted by `/token` or by the protected
resource.

## Explicit exclusions

This slice does not add REST forwarding, `/mcp`, a memory dashboard, Docker or
deployment resources, Google Cloud resources, account operations, or issue
#165 access administration. Offline defaults and the existing bearer-token
path remain unchanged. The shared palace may be visible to admitted users,
but provenance never becomes permission or truth by implication.
