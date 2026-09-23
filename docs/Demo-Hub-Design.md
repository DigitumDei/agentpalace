# Demo hub design

Status: gateway, persistent access policy, REST forwarding, and a local Compose package are implemented in `agentpalace-demo-hub` and `demo-hub/`. Live Google sign-in still requires tester-owned credentials and has not been verified here. AgentPalace is not ready for 1.0.

A tester supplies their own Google OAuth credentials and admin email, starts
the Docker example, and connects a local palace. Public hosting, retention,
and backup operations are outside the package.

## Agreed requirements

- A lightweight, self-run local Docker demo for testing and learning.
- One shared palace per demo instance, visible to everyone explicitly admitted.
- Expose the existing remote REST API plus authentication/access-administration
  plumbing. MCP remains on the client side; no hub MCP endpoint is planned.
- Google authentication plus an email allowlist assigning admin, write, or readonly.
- Automatic remote-client OAuth discovery, desktop browser login, device-code
  login for WSL/SSH/headless use, secure tokens, refresh, and revocation;
  provider-neutral for Google-backed and enterprise hubs.
- Only admins may change access through an API. Operators may edit the list on
  the container's persistent volume.
- Admins and writers may store memories; readonly users only read palace content.
- Every memory written through the hub retains the authenticated account of the
  LLM's owner, separately from the LLM's claimed agent name.
- HTTPS, login, and deployment-specific identity policy belong to the hosting
  layer. An enterprise deployment can use its own layer, such as Okta.
- The local package is implemented for testing; no deployment or live Google-account validation is performed by this work.

## Current foundations and gaps

Inspection baseline: main commit 4988583372fea3393d19c7cb6aa31276347e6f16.

| Area | Current implementation | Hub implication |
|---|---|---|
| REST | HTTP with bearer authentication and hot-reloaded scoped tokens | Wrap with Google login; localhost HTTP for the explicit local demo |
| Remote client | Configured bearer token; 401 becomes Unauthorized without discovery | Add provider-neutral OAuth login and token lifecycle support |
| Drawer writes/ingest | Token identity prefixes caller-asserted agent attribution | Reuse this foundation; a composite string is not a complete owner record |
| Knowledge graph | Authenticated actor recorded in change events; no owner envelope on fact/query records | Persist ownership alongside facts and return it on reads |
| Search | REST drawer search currently omits added_by | Fix retrieval as well as storage |
| HTTP MCP | Separate from the remote REST API | Outside the hub scope; no MCP changes are required for this demo |
| Diaries | Local-only; federation rejects diary-shaped writes | Preserve that boundary; sharing diaries requires an explicit separate change |

Evidence: [HTTP server](../crates/agentpalace-server/src/lib.rs),
[MCP transport](../crates/agentpalace-cli/src/transport.rs),
[KG types](../crates/agentpalace-graph/src/lib.rs),
[federation contract](Federation.md).

## Local Docker demo package

Ship a small, reproducible Docker Compose example containing the demo gateway
and a pinned AgentPalace container. One command starts the local example after
the tester fills in the Google credentials and their admin email. No public
hostname, TLS operator, cloud hosting, retention policy, or backup service is
required. This package is for testing and learning, not a managed deployment.

~~~mermaid
flowchart LR
    L[LLM client] -->|Local MCP| C[Local AgentPalace federation client]
    C -->|Local remote REST URL| H[Docker demo gateway on localhost]
    B[Browser on test machine] -->|Sign-in and access administration| H
    H <-->|HTTPS OpenID Connect| G[Google]
    H --> A[Local allowlist and account bindings]
    H -->|Private HTTP with owner-scoped credential| P[AgentPalace container]
    P --> S[Local demo data volume]
~~~

Proposed defaults: http://localhost:8080 for the gateway and
http://localhost:8080/auth/google/callback for its Google callback. The Compose
file publishes the gateway only to host loopback, for example
127.0.0.1:8080:8080, and does not publish the palace container's port or forward
/mcp. The gateway may listen on its container interface; the host publication
must stay loopback-only. Use current Docker and verify this in the smoke test.
[Docker port publishing](https://docs.docker.com/engine/network/port-publishing/).

The package's explicit local-demo mode permits HTTP only for its configured
loopback resource/issuer and endpoints. This is a development exception to the
OAuth discovery HTTPS requirements, not a production OAuth deployment profile.
Both gateway and client must opt into that exact local origin; do not disable
TLS validation or allow arbitrary HTTP remotes. Google requests still use HTTPS.
Outside this local demo, a host supplies its own secure transport and identity
layer; implementing that deployment is outside this package.

Include:

- Compose/build files with pinned engine version and startup/health checks.
- An example environment file for the tester's Google client ID/secret and
  initial admin email, with real secrets ignored by Git.
- An editable, mounted access-list file; bootstrap the tester's admin entry
  only when the list does not exist, never overwrite later role changes.
- A local data volume so a container restart does not erase the experiment.
- A short setup/run/stop/reset guide and a role/provenance walkthrough.
- A [Google OAuth setup guide](Demo-Hub-Google-Setup.md) the tester follows
  themselves. No cloud deployment or Google account changes are performed for them.

The sample includes no predefined person, real credential, or shared demo
Google OAuth application. Each tester creates their own Google application.
The runnable package and exact commands are in [demo-hub/README.md](../demo-hub/README.md).

Google-specific code and access-list administration remain in the gateway.
Provider-neutral OAuth client and owner-provenance support belong in AgentPalace,
so a separately built Okta wrapper can reuse them. The gateway uses maintained
auth libraries, strips caller-supplied identity headers, selects upstream
credentials itself, and forwards only to its configured private palace.

## Sign-in and automatic client connection

Automatic authentication discovery is a **demo launch requirement**, not a
manual-token setup exercise. The user's flow is: configure the remote URL,
connect, sign in in the browser, and return to the agent. No copying a Google
token or hub API key into the local palace is required.

### Challenge and discovery

An unauthenticated remote REST request receives this proposed response
(proposed loopback demo origin; non-demo remotes use HTTPS):

~~~http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="http://localhost:8080/.well-known/oauth-protected-resource"
Content-Type: application/json
Cache-Control: no-store

{"error":"authentication_required"}
~~~

The local remote client preserves and interprets this challenge instead of
discarding it as a generic Unauthorized error. It fetches the public protected
resource metadata, validates that the resource identifies the configured hub,
and discovers the advertised authorization server. That server's metadata
supplies the authorization and token endpoints. The API does not redirect a
REST request to an HTML login page.
See [protected resource discovery](https://www.rfc-editor.org/rfc/rfc9728.html)
and [authorization-server metadata](https://www.rfc-editor.org/rfc/rfc8414.html).

For the demo, the authorization issuer is the hub's authentication layer, which
uses Google for user sign-in and issues tokens for the hub REST resource.
Google ID/access tokens are not hub access tokens. At work, the wrapper can
advertise an enterprise authorization server and accept tokens intended for its
palace resource; the local client needs no Google- or Okta-specific login code.

The demo pre-registers an AgentPalace native/public client with a public client
ID and constrained loopback redirect URIs; it embeds no client secret. Enterprise
deployments supply their own registered public client ID through local auth
configuration. Client registration is separate from endpoint discovery; do not
assume discovery creates a client registration. Dynamic registration is not a
demo requirement.

### Browser login and completion

1. The local client creates state and an S256 PKCE verifier/challenge, starts a
   short-lived loopback callback listener, and opens the discovered authorization
   endpoint in the user's system browser for an interactive connect/login.
2. The hub authentication layer signs the user in through Google, validates the
   identity, checks the allowlist, and obtains consent for the local client's
   requested access. A pre-existing Google browser session alone must not
   silently grant a new client authorization.
3. The hub returns a short-lived, single-use authorization code to that client's
   registered callback. Bind the code to client ID, redirect URI, PKCE challenge,
   owner, requested permissions, and hub resource.
4. The local client validates state and exchanges the code plus verifier at the
   token endpoint. Tokens arrive in the response body, never the callback
   URL. The callback listener then closes.
5. Store the tokens securely and continue the remote request within the retry
   rules below. The agent's local MCP connection remains unchanged.

Use a maintained OAuth implementation and follow
[native-app browser/loopback guidance](https://www.rfc-editor.org/rfc/rfc8252.html).
Enforce HTTPS for non-demo discovery and authorization/token endpoints. The
explicit loopback demo-origin exception above and native loopback callback are
the only HTTP exceptions; never enable a general insecure mode. Validate metadata
issuer equality and approved resource/issuer relationships, constrain discovered
URLs and redirects against network probes, and never send an existing token to
a newly advertised origin. A changed issuer requires a new authorization.
Use separate state/nonce validation for the hub-to-Google sign-in leg.

An MCP-triggered or unattended background request must not launch repeated
browsers or block indefinitely. Surface a structured authentication-required
result identifying the remote and an actionable way to start/complete login;
interactive connection setup opens the browser. Deduplicate concurrent login
attempts for the same remote. Cancellation, timeout, and denial leave the
operation unapplied and give a clear result. When browser/callback login is
unavailable, provide the device-code flow below without repeatedly launching
browsers. An unattended agent surfaces the user-facing login action; it does
not approve its own grant.

The shared client exposes `login_mode` as `browser`, `device`, or `auto` (default
`auto`), and `auth login` accepts the same values through `--mode`. The command
starts from the protected-resource `resource_metadata` URL in the authentication
challenge; it does not discover from an unrelated hub URL. An explicit mode is
honored once. Automatic mode makes one browser/callback usability decision and
selects device authorization when that path is unavailable, so a headless or WSL
client does not repeatedly launch a browser. Bearer-token remotes and offline
defaults remain unchanged.

### Device-code login for WSL, SSH, and headless clients

Device authorization is also a **demo launch requirement**. Offer normal
browser/PKCE login on desktop hosts and device-code login when a browser or
loopback callback is unavailable, or when the user explicitly selects it.
WSL may use either flow; device login requires no inbound callback setup.

1. The client discovers the authorization server's device_authorization_endpoint
   and requests a device grant for its registered public client and hub resource.
2. The auth service returns a private device_code plus a user_code,
   verification_uri, expiry, and polling interval. The client shows only the
   user-facing link/code and keeps the device_code out of MCP output and logs.
3. The user opens the hub verification page in a Windows browser or another
   browser that can reach the hub, signs in through Google, and approves the displayed
   client/resource request and matching code. Apply the same allowlist and role
   checks as desktop login.
4. The WSL/SSH/headless client polls the configured token endpoint (HTTPS except
   for the explicit loopback demo mode).
   Approval returns its own hub tokens directly to that process. No inbound
   callback, port forwarding, or manual token transfer is needed.

The hub auth component implements the standard
[OAuth device authorization grant](https://www.rfc-editor.org/rfc/rfc8628.html)
and advertises it in authorization-server metadata. Google remains the browser
identity provider; do not assume Google's own device API is available or needed.
An enterprise issuer must advertise and support device authorization before the
client offers it; otherwise report the unsupported mode explicitly.

For the localhost package, use a browser on the Docker host. A phone cannot
reach that machine through a localhost link. WSL/client and browser reachability
to the same configured hub origin must be tested; device authorization removes
the inbound client callback, not this connectivity requirement. Remote hosting
and tunnel setup are outside this package.

Respect authorization_pending and slow_down, expiry, denial, cancellation,
and bounded backoff on network errors. Rate-limit grant creation, code entry,
and polling; codes expire and cannot authorize multiple grants. Completing
device authorization grants access only to the requesting client and approved
resource/permission ceiling. Never ask users to approve unsolicited codes.

Reuse the same token storage, refresh, revocation, and retry rules for both
flows. Tokens belong to the initiating Linux/WSL process, not the browser's
Windows account. Device login does not imply a Linux credential store is
available: retain the explicit secure-store/in-memory behavior below.
The CLI and background federation use the platform OS credential store; embedding
applications may inject another secure backend. If that backend is unavailable,
the operation reports the unavailable outcome (distinct from a corrupt record,
a backend failure, or no stored grant). `allow_in_memory` remains an explicit
volatile outcome and is never selected implicitly. After recovering from a
definite 401, the implemented client re-sends the identical request once —
reads and mutations alike, a mutation keeping its operation ID and body — and
never replays a mutation whose outcome is unknown.

### Tokens, permissions, and retries

Proposed defaults: 15-minute hub access tokens and rotating refresh tokens with
a seven-day absolute grant expiry. The maintained auth component issues and
validates them, detects refresh-token reuse, and supports grant revocation.
Refresh does not require another browser login while the grant remains valid.
Refresh failure requiring interaction returns authentication-required once,
without an infinite retry/login loop.
See [OAuth security practice](https://www.rfc-editor.org/rfc/rfc9700.html).

Store credentials in the operating-system credential store, isolated by
configured remote resource, issuer, public client ID, and account. Keep only
credential references in ordinary config; never expose tokens through MCP
results, prompts, command-line arguments, logs, repository files, or URLs.
If secure persistent storage is unavailable, allow an explicit in-memory session
or report the limitation; do not silently fall back to plaintext storage.
Logout revokes the grant where supported and clears local credentials.

Every protected request checks the current allowlist and role, including requests
using existing access tokens. Token/grant permissions are ceilings: the effective
permission is their intersection with the owner's current role. Downgrading or
removing access applies to subsequent requests; promotion does not silently
expand an existing grant. Admin-owned agent grants are capped at write. Access
list administration requires a recently authenticated admin browser session.

The authentication layer rejects unauthenticated requests before any upstream
mutation. Following login/refresh, retry only a read or an operation definitively
rejected before execution, with a bounded retry count. Preserve the exact
operation ID and body for mutations. A timeout, lost response, or other unknown
outcome must use the existing idempotency/recovery contract; it must not cause
a fresh write under a new ID or a browser-login attempt. A valid credential
lacking permission produces 403 and does not trigger repeated sign-in.

Existing explicitly configured bearer-token remotes continue to work. OAuth is
an additional configured remote-auth mode, not a forced migration for private
deployments. Discovery/login failures do not silently downgrade authentication
or redirect remote-only writes to local storage.

### Google identity and browser administration

Use Google OpenID Connect authorization-code login with openid/email scopes,
an exact registered callback, state and nonce validation, and a maintained
library validating signature, issuer, audience, expiry, and verified email.
Identify accounts by issuer plus subject (sub); emails can change.
[Google OpenID Connect](https://developers.google.com/identity/openid-connect/openid-connect).

Match the verified email to the allowlist and bind it to the Google subject
on first admission. Subject changes require explicit admin reassignment.
For external non-Gmail/non-Workspace mailboxes, require additional mailbox
verification at enrollment because email_verified alone may not establish
current mailbox ownership.
[Google ID-token verification](https://developers.google.com/identity/gsi/web/guides/verify-google-id-token).

Proposed administrative browser sessions last eight hours, with HttpOnly
SameSite cookies and CSRF protection for mutations. The explicit HTTP loopback
demo uses HttpOnly/SameSite cookies without Secure; secure deployments require
Secure cookies. This exception must not apply to arbitrary hosts. Recheck membership on every
request. Removing access also disables existing sessions and OAuth grants for
subsequent requests; it does not undo committed writes. Users may list/revoke
their own authorized agent connections without gaining shared-memory write
permissions.

The hub exposes remote REST and authentication/access plumbing only. OAuth here
authorizes the remote REST client; there is no hub MCP endpoint or browser
memory dashboard.

## Roles and administration

Everyone admitted reads the same shared content. Attribution does not make a
memory private, true, or an instruction the reader may execute.

| Capability | readonly | write | admin |
|---|---|---|---|
| Read/search shared memories, KG, and exposed task records | Yes | Yes | Yes |
| Add memories, KG facts, and ingest content | No | Yes | Yes |
| Correct/invalidate memories; mutate exposed task records | No | Yes | Yes |
| Hard-delete memories | No | No | Yes |
| List/change membership or roles | No | No | Yes, admin session |
| Authorize/revoke own agent connections | Read ceiling | Write ceiling | Write ceiling |

Admin-only hard deletion is a proposed demo default, not a confirmed user
decision. Writers collaborate on shared records; changes retain the original
creator and attribute each modifying owner.

Current REST scope mapping, on all wings of this shared palace:

- readonly: read and coordination_read.
- write: additionally write, ingest, coordination_write, coordination_claim.
- browser-admin operations: additionally delete.

Always emit explicit scopes: omitted scopes currently mean unrestricted access.
The gateway also checks the current role and operation before forwarding.
POST search is a read; HTTP method alone does not determine permission.
Unknown routes/operations fail closed. Every accepted remote REST mutation,
including batch ingest and invalidation, must follow the same operation inventory
(see [canonical REST inventory](Demo-Hub-REST-Inventory.md)).
Do not forward /mcp or add generic tool-execution routes.

The gateway stores the editable policy at `/data/hub/access.json` by default.
Its actual format is a revisioned email map plus an audit chain:

~~~json
{
  "format": 1,
  "revision": 2,
  "users": {
    "admin@gmail.com": {"role": "admin", "enabled": true, "mailbox_proven": false},
    "writer@gmail.com": {"role": "write", "enabled": true, "mailbox_proven": false},
    "reader@gmail.com": {"role": "readonly", "enabled": true, "mailbox_proven": false}
  },
  "audit": [
    {"actor": "bootstrap", "occurred_at": "<unix-seconds>", "action": "bootstrap_admin_created", "before": null,
     "after": {"admin@gmail.com": {"role": "admin", "enabled": true, "mailbox_proven": false}}},
    {"actor": "operator-id", "occurred_at": "<unix-seconds>", "action": "policy_replaced",
     "before": {"admin@gmail.com": {"role": "admin", "enabled": true, "mailbox_proven": false}},
     "after": {"admin@gmail.com": {"role": "admin", "enabled": true, "mailbox_proven": false},
               "writer@gmail.com": {"role": "write", "enabled": true, "mailbox_proven": false},
               "reader@gmail.com": {"role": "readonly", "enabled": true, "mailbox_proven": false}}}
  ]
}
~~~

The first admin entry is created only when the policy file is absent and a
bootstrap email is configured. Existing malformed or unreadable policy never
falls back to bootstrap. Subject bindings and immutable owner IDs live in the
separate `/data/hub/bindings.json`; the gateway assigns an owner ID when a
listed identity first signs in. Trim outer whitespace and lowercase the domain;
preserve the local part and do not collapse dots, plus tags, or aliases. Gmail
addresses need no extra mailbox flag. For a custom-domain bootstrap admin,
set `BootstrapAdmin.mailbox_proven=true` only after an operator has checked
current mailbox ownership; it defaults to false. Set an access entry's
`mailbox_proven` only after the same proof for any other non-Gmail address.
Email changes require an explicit binding update, without rewriting historical
provenance.

The implemented hub access routes are:

| Endpoint | Authorization and behavior |
|---|---|
| GET `/hub/v1/access` | Recent admin browser session; returns users, revision, ETag, and the session CSRF token |
| PUT `/hub/v1/access/{email}` | Recent admin browser session, `x-csrf-token`, and `If-Match`; body is one `{role, enabled, mailbox_proven}` entry |
| DELETE `/hub/v1/access/{email}` | Same checks; removes one email entry |

The admin browser session is created only after a fresh Google sign-in resolves
to an enabled admin. Mutations require the session CSRF token and current ETag.
The API refuses to remove or demote the last enabled admin. It writes audit
records with the immutable actor ID, time, before/after policy, and no secrets.

For a manual edit, stop any concurrent editor and take the same exclusive lock
as the API on `/data/hub/access.json.lock`. Keep `format` unchanged, make the
policy change, increment `revision` by one, and append an `operator_file_edit`
audit event whose `actor` identifies the operator, `occurred_at` is Unix seconds,
`before` is the previous full `users` map, and `after` is the edited full map.
Keep the previous audit chain intact; the final `after` must match `users` and
`revision` must equal the audit-event count. Validate canonical email keys,
roles, proof flags, and the enabled-admin rule. Write a sibling temporary file,
flush it, call `fsync`, then atomically replace `access.json` and sync the parent
directory before releasing the lock. Never edit `bindings.json` to change a
role. Missing, unreadable, or malformed policy denies protected requests.
Manual file edits are operator events and must not be attributed to Google.
The complete policy file, including its full-snapshot audit chain, is capped at
4 MiB, matching the fail-closed read limit. An edit whose serialized result
would reach that limit is rejected before atomic replacement, preserving the
last valid policy; operators should plan edits while there is room for another
full before/after snapshot. Audit rotation is future work before this demo
policy is used for long-lived production administration.

Admin-only hard deletion remains the proposed demo default, not a confirmed
user decision. It requires a recent admin browser session and CSRF token;
OAuth bearer grants are capped at write even for admins. Configure
`Gateway::with_hard_delete_policy(HardDeletePolicy::Disabled)` to disable hard
delete; `RecentAdminBrowser` is the current default. Forwarding accepts only
the closed inventory in
[Demo-Hub-REST-Inventory.md](Demo-Hub-REST-Inventory.md); unknown routes and
`/mcp` are not exposed.

## Owner provenance is a launch requirement

One shared service token plus an email in a request body is insufficient.
The LLM must not be able to select its owner. Proposed structured envelope:

~~~json
{
  "owner": {
    "id": "hub-generated-immutable-owner-id",
    "issuer": "https://accounts.google.com",
    "subject": "verified-google-subject",
    "email_at_write": "writer@example.com"
  },
  "actor": {"agent_name": "codex", "assurance": "caller_asserted"},
  "recorded_at": "server-assigned-UTC-timestamp",
  "operation_id": "owner-scoped-idempotency-key",
  "source_refs": []
}
~~~

Owner fields come from authenticated context. The agent name stays
caller-asserted unless independently verified. Attribution identifies the
credential holder; it does not prove personal approval of each LLM action.

Extend authenticated server token entries with optional, validated,
provider-neutral owner metadata. Generate private upstream credentials per
owner/effective privilege ceiling, retaining a stable identity across rotation
for coordination ownership. Only the gateway provisions that private token file.
Never trust owner fields from writable request payloads. The current
foundation ignores extra `owner` fields on legacy-compatible REST DTOs and
provides `reject_payload_owner_claim` for handlers that explicitly validate
untyped or extended payloads; neither path allows a payload to establish
authenticated ownership. Older installations without metadata continue to
return explicitly unknown ownership. Durable owner-scoped persistence and
receipt integration are deferred to issue #161, while OAuth/device/gateway
work is deferred to issues #162–#164.

Required storage coverage:

- Drawers, mined chunks, imports, and derived memories: keep source authors and
  source references separate from the authenticated submitting owner.
- KG facts: retain owner provenance on the fact, not only a change log.
  Deduplication preserves the original creator and records additional submissions
  without transferring ownership to the latest caller.
- Tasks, messages, artifacts, results, and transitions exposed by the hub:
  distinguish human owner from agent/executor identity.
- Any other record accepted through the existing remote REST surface: the same
  invariant. Local-only diaries and MCP-only operations stay outside the hub.

Inventory every existing remote REST mutation before implementation (published
in [Demo-Hub-REST-Inventory.md](Demo-Hub-REST-Inventory.md)). Each must
support authenticated provenance before it is made available through the hub.
All accepted memory types need attribution, not just ordinary drawer writes.
This project does not add remote versions of currently local-only/MCP-only
features; any later API expansion must meet the same owner-provenance contract.

Persist provenance with the mutation's receipt/commit protocol. A crash must
not leave a successful or visible ownerless record. Reuse recovery machinery
across stores; do not assume LanceDB and SQLite share a transaction. Scope
idempotency keys, client-supplied record/ingest IDs, and receipt lookups to the
owner so one user's retries cannot collide with or replay another user's write.
Retries preserve original attribution without duplicate writes. Corrections
append modifier history; deletion preserves an attributed tombstone/audit record
for the local experiment. No retention-management feature is included.

Expose consistent provenance on get/list/search, KG query/timeline, and relevant
task reads. Store issuer/subject for audit; ordinary shared responses can show
owner ID and email-at-write without raw Google subjects. Container restarts preserve
attribution in the local volume. Federated copies preserve original provenance and separately record
the authenticated submitting owner; remote claims remain distinct from local
authentication. Legacy ownership remains unknown, never fabricated.

### Dependency on issue #157

The owner-provenance slice of [issue #157](https://github.com/DigitumDei/agentpalace/issues/157)
is a **demo launch prerequisite**, not an optional follow-up. Implement it as a
shared engine contract rather than a separate hub-only envelope:

- Distinguish authenticated human owner, caller-asserted agent, source author,
  and storage origin.
- Preserve attribution across every accepted memory type, mutation/retry path,
  and get/list/search response; explicitly mark legacy ownership unknown.
- Carry original source references through imports/copies where available.
- Never interpret attribution as evidence that a claim is true or as permission
  to execute instructions found in a memory.

The broader issue remains open for evidence-status semantics, richer derivation
lineage, and correction/supersession integration with #156. Completing the demo
slice does not justify closing all of #157. Coordinate stable IDs and temporal
fields with #89 and #147 rather than inventing competing response formats.

Preserve #157's research attribution requirements for work derived from it:
credit Deepak Akkil et al., *Emergence World: Adversarial Stress-Testing of
Long-Horizon Multi-Agent Systems*, [arXiv:2609.17320](https://arxiv.org/abs/2609.17320),
and distinguish the paper's findings from AgentPalace adaptations. These hub
requirements originate in Dion's deployment use case; Google login is not
validation of memory truth.

## Implementation slices and acceptance evidence

1. Engine prerequisite: owner context, durable provenance, retries, and retrieval
   for the agreed remote surface. No provider-specific authentication dependency.
2. Local remote client: OAuth challenge/metadata discovery, public-client
   registration configuration, browser/PKCE callback, device authorization/polling,
   secure credential storage, refresh/revocation, authentication-required results, and bounded safe retries.
3. Gateway: resource/authorization metadata, native-client authorization and
   token/device-authorization and verification endpoints, Google enrollment,
   roles/bindings, grant lifecycle, admin API, scope mapping, and private upstream access.
4. Local package: Docker Compose, loopback-only publishing and demo auth mode,
   an example config, local volumes, the Google setup how-to, start/stop/reset
   instructions, and a small sign-in/connection page. Demonstrate roles and
   owner attribution through existing clients and remote REST responses.
5. End-to-end verification against the compiled engine, including real Google
   sign-in with two distinct accounts and an unlisted account. Mock tests
   complement, but do not replace, this verification.

Evidence required for the runnable local example:

- A clean client configured with only the demo remote URL and registered client
  information completes challenge discovery, browser sign-in, token exchange,
  and an authorized REST request without manual token copying.
- A WSL/SSH/headless client completes device login from a separate browser with
  no inbound callback or manual token copying. Test pending, slow-down, expired,
  denied, reused-code, cancellation, and unsupported-issuer outcomes.
- Expiry refreshes without browser prompts; revocation, cancellation, denied
  consent, wrong state/PKCE, replayed codes, and callback timeout fail cleanly.
- Concurrent login/refresh requests do not create token races or repeated browser
  windows. Headless/secure-store-unavailable cases have explicit outcomes.
- Metadata/resource/issuer mismatch and malicious discovery URLs are rejected.
  Static bearer remotes still work; a second standards-compliant test issuer
  proves the client is not hard-coded to Google. Actual Okta deployment requires
  its own registration/configuration and later integration verification.
- Reads resume after login; mutation retries retain operation IDs and cannot
  duplicate an operation after a lost response or other unknown outcome.

- Unlisted/disabled accounts and invalid tokens cannot read content. Role
  changes affect subsequent requests through existing sessions/credentials.
- Readonly cannot mutate through any supported REST route, replay, or batch;
  writers cannot change membership or hard-delete.
- Admin API and manual list edits persist across restart; stale updates conflict
  and malformed policy fails closed.
- Identical agent names under different owners retain distinct provenance.
  Forged headers/owner fields/IDs/operation keys cannot impersonate another owner.
- Every supported memory kind retains owner attribution after retry, crash
  recovery, deduplication, container restart, and search/retrieval.
- Only the gateway is published to host loopback; palace and /mcp remain private. CSRF, credential
  leakage, and arbitrary upstream URLs are rejected.
- External Google-account mailboxes, email changes, and subject mismatches do
  not allow unexpected accounts to inherit membership.

Package inputs supplied by each tester: their own Google web OAuth client ID
and secret, the documented localhost callback registration, and their admin
email. Provide these through the example local configuration. A public hostname,
TLS operator, hosting target, retention policy, and backups are not requirements
and are outside scope. Dion will perform his Google setup himself using the
[how-to](Demo-Hub-Google-Setup.md); do not create cloud resources on his behalf.

## Release note

The sole release-series input is release/version.toml: major 0, minor 2.
The first mainline commit introducing this series derives **0.2.0**; subsequent
builds derive patch versions automatically. Editing the file creates no release
tag or signed artifact. Cargo package versions remain the development fallback
under the existing [release contract](Release-Operations.md#release-versions).
