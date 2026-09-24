# Demo hub acceptance evidence — 2026-09-23

This record covers issue #167 against the merged #162–#166 implementation. It distinguishes fixture-based automated results from the tester's live Google/WSL checks. A green CI run is evidence for the named tests only; it does not clear the live launch blocker.

## Reproduce the automated checks

From a clean checkout at the PR commit:

```sh
cargo test -p agentpalace-demo-hub --locked
cargo test -p agentpalace-remote --test remote_client_e2e --locked
cargo test -p agentpalace-server --lib --locked
cargo clippy --workspace --all-targets --locked
```

The [demo hub Compose smoke](../.github/workflows/demo-hub.yml) builds the gateway from the PR checkout and the private engine pinned by the Dockerfile, boots both, checks loopback/private routing and unauthenticated denial, and verifies volumes after restart. It uses fixture-only credentials. The new `compiled_gateway_acceptance` test starts the compiled gateway router and real persistent engine with a deterministic local embedding provider. It synthesizes verified Google identity claims and issues gateway grants through the library API; the separate OAuth suite exercises browser/device choreography with a mock verifier. Neither route is a substitute for real Google or WSL evidence.

## Local result on 2026-09-23

On the clean issue-167 worktree, the targeted gateway suite passed 44 unit tests, 5 admin tests, 1 compiled gateway/engine test, 1 forwarding test and 21 OAuth lifecycle tests. The graph suite passed 16 tests; the remote REST E2E suite passed 18; core provenance/model tests passed 65; and the server library suite passed 171. The new gateway test uses a deterministic local embedding provider and checks real persistent storage before and after reopening the engine. Full workspace Clippy exited successfully (existing warnings remain). The new integration test passes a focused rustfmt check and the PR diff passes `git diff --check`; repository-wide `cargo fmt --all -- --check` still reports formatting differences in unrelated baseline files such as `crates/agentpalace-storage/src/sqlite.rs`. The local Docker daemon was unreachable at `127.0.0.1:2375`, so the Compose smoke must be judged from the PR's GitHub CI result, not claimed as a local pass.

## Evidence matrix

| Design acceptance path | Automated evidence | Current limit |
| --- | --- | --- |
| Browser discovery, dynamic callback, code/PKCE exchange and authenticated read | `oauth_lifecycle::browser_login_uses_a_dynamic_loopback_and_reaches_the_protected_resource` | Mock Google verifier; live browser pending. |
| Device authorization, separate browser, pending/slow-down/expiry/denial/cancellation/reuse | `oauth_lifecycle` device tests named `device_login_*`, `device_polling_*`, `device_expiry_*`, `device_refusals_*`, `mixed_device_*` | Mock Google and same-machine test; WSL pending. |
| Refresh, revoked family, logout, bounded rejected-access recovery | `oauth_lifecycle::refresh_rotates_and_reuse_revokes_the_family_including_issued_access`, `logout_revokes_at_the_hub_and_rejects_every_issued_token`, `server_rejected_unexpired_access_recovers_with_one_bounded_refresh` | No live Google token lifetime test. |
| Second issuer, exact resource identity, malformed discovery, static bearer compatibility | `oauth_lifecycle::grants_from_two_issuers_stay_isolated_in_one_credential_store`, `trailing_slash_resource_identity_is_exact_through_login_reuse_refresh_and_logout`; remote-client static bearer E2E and discovery unit tests | Actual Okta/other deployed issuer remains outside this demo. |
| Concurrent login/refresh and secure-store failure | `client::stored_session_reloads_into_a_new_remote_client_under_the_exact_resource`, `grant_rotated_by_another_process_is_adopted_without_refreshing`, `persistence_failure_is_reported_and_the_new_grant_stays_in_process` | Simultaneous interactive logins and a real platform-keychain outage are **not** yet exercised; do not infer them from these adjacent tests. |
| Unlisted/disabled and current role policy | `admin_gateway::existing_grants_observe_demotion_revocation_promotion_ceiling_and_manual_edits`; `compiled_gateway_acceptance::public_gateway_enforces_current_roles_and_persists_owner_provenance` | Live external mailboxes pending. |
| Readonly, writer, admin boundaries and CSRF | `admin_gateway::admin_api_requires_recent_google_session_csrf_and_current_etag`, `public_gateway_forwarding_is_closed_authenticated_and_owner_scoped`; `compiled_gateway_acceptance` | Automated fixture covers selected real REST writes; the forwarding unit test inventories every allowed method/path. |
| Owner spoofing, owner-scoped receipts and attribution | `compiled_gateway_acceptance` proves forged owner claims fail, two owners can reuse one operation ID for distinct KG facts, and the shared drawer/KG reads retain the true creator; `forwarding_provenance` covers restart | This is a **shared** palace: admitted users may read each other's records. Owner separation is attribution and operation namespace, not a read ACL. |
| Idempotent retry, lost response, crash recovery, durable restart | `compiled_gateway_acceptance` retries a drawer operation and restarts the engine; server receipt/recovery tests exercise the crash windows | Real process kill at each persistence boundary is not exercised by the gateway test. |
| KG, coordination, ingest and change REST operations | `compiled_gateway_acceptance` covers KG query/timeline provenance, batch ingest/search, and task/message/artifact/result provenance through the gateway and persistent engine; `remote_client_e2e` covers static-bearer changes and coordination round trip | Not every coordination transition/ack or ingest failure mode runs through the gateway fixture. |
| Federated copy source vs owner identity | The redacted provenance DTO retains distinct creator, local submitter, and original-source fields in core/server tests | No two-engine federated-copy acceptance run through the demo gateway is recorded here. |
| Host loopback and private engine/MCP, secrets and CSRF | Compose smoke; `admin_gateway`; `forwarding` origin/spoof/redaction tests | Host networking is proved on CI's Docker runner, not Dion's machine. |
| Google two admitted accounts and unlisted account, desktop plus WSL | Manual procedure below | **PENDING — launch blocker.** No credentials or Google resources are in this repository. |

> **2026-09-24 annotation.** Live Google results for admin A, readonly B and writer D on desktop and WSL are recorded in [Live results — 2026-09-24](#live-results--2026-09-24). The unlisted account C was refused through device and browser login; disabling B cut off its active grant; and a Compose restart kept the policy, content and attribution. D's delete/membership limits and a WSL sign-in after the restart are still pending, so the last row remains a launch blocker.

The limitations above are explicit work remaining before anyone describes the full #159 design as accepted. Do not close #157, merge, release, deploy, or mark the demo complete on the strength of this record.

## Live tester handoff (Dion)

Use only tester-owned Google resources. Do not put client secrets, access/refresh tokens, cookies, or browser screenshots containing them in this issue or PR.

1. Follow [Google setup](Demo-Hub-Google-Setup.md) and [Compose instructions](../demo-hub/README.md). Register the two exact localhost callback URLs, configure the Google web client ID and local secret file, set the bootstrap admin email, and add the required Google test users. Keep the gateway's host binding at `127.0.0.1:8080`.
2. Choose account A (bootstrap admin), account B (admitted readonly), and account C (Google test user but **not** hub-listed). These are distinct Google subjects. Record only opaque account labels A/B/C in the evidence. If testing the standalone writer role as well, use a fourth admitted account D with role write.
3. Start Compose. Record the image/commit, `docker compose ps`, host `curl http://localhost:8080/v1/health`, and the same health request from WSL. Confirm the engine has no published host port and `http://localhost:8080/mcp` returns 404. Record pass/fail and time, never secrets.
4. Append the documented `demo` OAuth remote and `wing_demo` route to the desktop AgentPalace MCP configuration, preserving the existing remotes and routes. Restart the MCP connection. Call `agentpalace_search` with `wing: "wing_demo"`; on `authentication_required`, call `agentpalace_remote_auth_start` with `remote: "demo"`. With browser-capable desktop `auto` mode, confirm the system browser opens (or use the returned `authorization_url` if it does not) and complete consent as A; if the tool returns device mode, present its verification link and user code instead. Poll `agentpalace_remote_auth_status` until authenticated, then retry the MCP search. Create a small disposable Git checkout with one README containing a unique test phrase, then run `agentpalace mine PATH_TO_CHECKOUT --mode projects --wing wing_demo --project-id demo-acceptance --full`. Search that phrase through the same remote; inspect the returned drawer/change metadata and record its creator and authenticated submitter IDs (opaque IDs only). As of 2026-09-24 the `mine` step cannot pass against this package: the pinned engine has no `server.checkouts` mapping for `wing_demo`, so locator-backed batches are rejected with HTTP 409 `checkout_unavailable` before anything is stored. Until that is fixed, write a content-only drawer with `agentpalace_add_drawer` to `wing_demo` instead. MCP search only shows the attribution fields once [#180](https://github.com/DigitumDei/agentpalace/pull/180) is merged; before that, inspect the engine's stored record.
5. In the current admin session, add B as readonly using the admin access API with the session CSRF value and current `If-Match` revision, as documented in the package README. Use a separate browser profile for B. Verify B can authenticate and read permitted content, cannot write a drawer/KG fact/coordination task/ingest batch, and cannot modify the access list. Record status codes, not credentials. If D is used, verify D can write but cannot hard-delete or modify membership.
The administrator can perform the role edit in the browser developer console while signed in to the local hub. Replace the placeholder mailbox with B's actual address; keep the response in that local console and record only the status. Repeat with a fresh GET/ETag and `enabled: false` for the later disable check.

Two conditions apply, both found during the 2026-09-24 run. First, the admin API only accepts a browser session whose Google sign-in completed in the last five minutes, and it answers `403` otherwise; an older MCP sign-in is not enough. To get a fresh session, run `agentpalace auth login --remote demo --resource-metadata http://localhost:8080/.well-known/oauth-protected-resource --mode browser` (or complete a device verification) in the same browser, then run the snippet straight away. Second, only `@gmail.com` addresses are admitted with `mailbox_proven: false`. For any other domain, set `mailbox_proven: true` once you have confirmed you control that mailbox; otherwise the entry is stored but sign-in is refused.

```js
(async () => {
const email = "reader@example.com";
const policy = await fetch("/hub/v1/access", { credentials: "same-origin" });
const { csrf_token } = await policy.json();
const edit = await fetch("/hub/v1/access/" + encodeURIComponent(email), {
  method: "PUT",
  credentials: "same-origin",
  headers: {
    "Content-Type": "application/json",
    "X-CSRF-Token": csrf_token,
    "If-Match": policy.headers.get("ETag")
  },
  body: JSON.stringify({ role: "readonly", enabled: true, mailbox_proven: false })
});
console.log(edit.status);
})();
```

6. From WSL, confirm `curl http://localhost:8080/v1/health` succeeds, then use an independent WSL AgentPalace MCP configuration with the `demo` remote and route. Start sign-in with `agentpalace_remote_auth_start` through that MCP connection. Open its returned verification URL in a separate Windows browser profile signed in as B, enter the displayed user code, and approve. Poll `agentpalace_remote_auth_status` and verify an authenticated MCP read from WSL without an inbound callback or copied token. Repeat with denial/cancel and record the safe error outcome.
7. In a fresh browser profile signed in as C, try browser and device login. Both must end at hub access denial despite Google's own test-user admission. Disable B in the hub policy and verify its existing grant loses access on the next request; restore B only after recording the result. Try a second subject using B's old email only if that controlled test identity is available; it must not inherit B's binding.
8. Restart Compose without deleting volumes. Re-authenticate if in-memory sessions ended, then verify policy, stored content and original owner attribution persist. Test logout/revocation, and ensure the old grant is rejected. Record the command, UTC time, sanitized result/status, and any unexpected behavior for each step.

Until the live record has A/B/C, desktop browser and WSL device outcomes, mark real-Google acceptance **pending** and treat launch as blocked. The maintainer, not automation, decides any later merge or deployment.

## Live results — 2026-09-24

Tester: Dion, using tester-owned Google accounts and the local Compose stack (engine image `agentpalace-demo-engine:ba2bb3d`, gateway built from #179). Clients: Windows desktop MCP running candidate `v0.2.11-nightly.a2541eeced6c594ffb3e96e6a8aa4ff39008b8f3`, and a separate WSL (Ubuntu 24.04) install of the same candidate. Docker Engine runs inside the WSL distribution, and the gateway on `127.0.0.1:8080` was reachable from both Windows and WSL. Accounts are labelled as in step 2: A is the bootstrap admin (a Gmail address), B is admitted `readonly` and D is admitted `write`; B and D are non-Gmail Google accounts admitted with `mailbox_proven: true` (policy revisions 2 and 3). C is a Google test user deliberately not on the hub list. Times are UTC. No credentials, codes or email addresses are recorded here.

| Step | UTC | Client | Result |
| --- | --- | --- | --- |
| 3 Health and privacy | 15:35 | WSL | Pass: `/v1/health` returned ok and `/mcp` returned 404. |
| 4 Browser sign-in as A | before 13:40 | Windows MCP | Pass: `agentpalace_remote_auth_start` opened the system browser, Google consent and the hub's Continue page completed, status became `authenticated`, and a `wing_demo` search succeeded. |
| 4 Mine into `wing_demo` | 13:40 | Windows CLI | **Fail (package gap):** HTTP 409 `checkout_unavailable`, because the engine has no `server.checkouts` entry for `wing_demo`. Nothing was stored. |
| 4 Attribution via content-only drawer | 13:41:16 | Windows MCP | Pass: an `agentpalace_add_drawer` call with a deliberately false `added_by` was stored with `creator` and `authenticated_submitter` both bound to A's Google-backed owner ID (`owner-6a34c81a…`). The claimed name is kept only as a suffix after the authenticated identity, and the change log actor and the owner-scoped mutation receipt carry the same owner. Checked by reading the engine's stored drawer, change log and receipt records, because MCP search dropped these fields (fixed by #180). |
| 5 Admin role edits | afternoon | Windows browser | Pass after two corrections: the first attempt returned `403` because the admin session's Google sign-in was older than five minutes, and non-Gmail B and D needed `mailbox_proven: true`. |
| 6 WSL install | 15:35–15:53 | WSL | Pass after workarounds: the installer's migrate step refused to run while the demo engine process existed ([#181](https://github.com/DigitumDei/agentpalace/issues/181)) and while an old cache symlink pointed outside its home. The engine was stopped from 15:50:26 to 15:53:20 for the install. |
| 6 WSL sign-in without keyring | 15:55 | WSL MCP | Refused before any code was issued, because no Secret Service provider was running. Search reported `credential_store`; `agentpalace_remote_auth_start` and `agentpalace_remote_auth_status` returned plain errors without a classification. |
| 6 WSL device sign-in as B | 16:00–16:01 | WSL MCP | Pass once gnome-keyring was running: `authentication_required`, then a device code approved in a separate Windows browser profile, then `authenticated`, with no inbound callback and no copied token. |
| 5/6 B readonly boundary | 16:01–16:02 | WSL MCP | Pass: B's search found the attribution drawer; `add_drawer` was rejected with HTTP 403 (empty body, no classification). |
| 6 Logout | 16:02, 16:04 | WSL CLI | Pass: `agentpalace auth logout` cleared the local grant and revoked it at the hub; the next search returned `authentication_required`. The command needs `--issuer`, which was read from `/.well-known/oauth-authorization-server`. |
| 5/6 D writer | 16:03–16:04 | WSL MCP | Pass: D signed in by device code, searched, and `add_drawer` succeeded. D's delete and membership-edit limits were not tested. |
| 6 Device denial | 16:10 | WSL MCP | Pass: status `failed`, "device authorization was denied". An earlier attempt (16:04–16:09) ended as "expired" before the Deny was clicked. |
| 6 Device timeout | 16:10–16:16 | WSL MCP | Pass: `pending`, then `failed` with "device authorization expired", and no session was left behind. |
| 7 Unlisted C, device login | 16:39–16:42 | WSL MCP | Pass: C, a Google test user not on the hub list, approved in the browser and the hub page showed access denied. No grant or session was created, and the next search still returned `authentication_required`. The client reported status `failed`, "device authorization was denied", with no classification. |
| 7 Disable B with an active grant | ~16:49–16:50 | Windows browser, WSL MCP | Pass: with B signed in on WSL, the admin set B `enabled: false` (policy revision 4, after a fresh admin sign-in; the first attempt ran on a `127.0.0.1:8080` tab, which does not carry the `localhost:8080` session cookie, and returned `403`). B's next `wing_demo` search was refused immediately. The gateway answered the REST request itself with HTTP 400 `{"error":"access_denied"}` (a disabled owner has no current role in `effective_role`), and MCP classified the degradation as `rejected` with no sign-in hint. `agentpalace_remote_auth_status` returned a tool error, not a status, and the refused grant stays stored. |
| 7 Re-enable B | ~16:51 | Windows browser, WSL MCP | B was re-enabled (policy revision 5), and B's existing WSL grant worked again without a new sign-in. This matches the design, which rechecks membership on every request: disabling suspends existing grants rather than revoking them. To cut off a device for good, log out or revoke it at `/hub/connections`. The tester confirmed B was still limited to `readonly` after re-enabling. |
| 7 Unlisted C, browser login | 17:01:36–17:01:53 | Windows CLI, C's browser profile | Pass: `agentpalace auth login --mode browser` was completed in a browser profile signed in as C. The hub returned `access_denied` to the CLI's loopback callback, whose page said only "Login was not completed; you may close this window." The CLI exited 1 with "OAuth authorization was denied" and stored nothing, and the existing A grant in the same credential store stayed `authenticated`. |
| 8 Compose restart | 16:56:15–16:56:34 | WSL shell | Pass: `docker compose -p agentpalace-demo restart` kept the `engine_tokens`, `hub_state` and `palace_data` volumes; both containers returned healthy, `/v1/health` was ok and `/mcp` still returned 404. |
| 8 Sign-ins after restart | 16:56–16:58 | Windows MCP | Pass: A's pre-restart grant was refused with `authentication_required` and a sign-in hint, because gateway sessions and grants are in memory. A new browser sign-in as A succeeded at 16:57. |
| 8 Persistence after restart | 16:57–17:00 | Windows MCP, browser | Pass: all four `wing_demo` drawers were still searchable, and the stored `creator`/`authenticated_submitter` of each was unchanged: A's owner ID on the 13:41 attribution drawer and D's (`owner-2da70e6c…`) on the three WSL drawers; none belong to B. The access policy was still at revision 5 with A admin, B readonly and enabled, and D write. |

### Findings from the live run

- **Mining against the demo hub** returns HTTP 409 until the package provides a `wing_demo` checkout; steps 4 and the package README still describe mining. Tracked under #167.
- **MCP search hid attribution.** The hub stored and returned redacted provenance, but MCP search dropped it. Fixed in [#180](https://github.com/DigitumDei/agentpalace/pull/180).
- **Installer migration** blocks on any process named `agentpalace`, including a container's, and on a cache symlink pointing outside the migrated home; it cannot be skipped. [#181](https://github.com/DigitumDei/agentpalace/issues/181).
- **WSL needs a Secret Service keyring** such as gnome-keyring for any OAuth sign-in, because the Linux credential store has no file fallback. The README's WSL guidance now says so.
- **Error classification is uneven.** `credential_store` is classified on search but not on `remote_auth_start`/`remote_auth_status`; denial, expiry and the readonly write rejection (`403`, empty body) carry no classification, so clients must match message text. A hub refusal of an unlisted account reaches the client as exactly the same "device authorization was denied" as the user clicking Deny, so only the browser page tells the user their account is not admitted. In the browser flow even that is missing: the loopback callback page says only "Login was not completed", so an unlisted user gets no indication of why.
- **Disabled accounts get OAuth-style 400s.** Every gateway REST refusal of a disabled owner is HTTP 400 `{"error":"access_denied"}`, where a protected resource would normally use 401/403. MCP reports it as `rejected` without saying the account was disabled or suggesting signing out, `agentpalace_remote_auth_status` errors instead of reporting the grant's state, and the unusable grant stays in the credential store.
- **Admin console origin.** The admin session cookie belongs to `http://localhost:8080`; running the admin snippet from `http://127.0.0.1:8080` returns `403`.
- **Device-code timing.** The client stops polling at the lower of `oauth.login_timeout_seconds` (default 300) and the hub's `expires_in` (600), and reports its own deadline as "device authorization expired", the same message as a server-side `expired_token`. A tester who takes more than five minutes sees "expired" whatever they clicked.
- **Setup and WSL interop.** `agentpalace setup` in WSL tried to register with a Windows `gemini` executable found on `PATH` through interop; the call failed and nothing on Windows changed.

### Still pending

D's delete and membership-edit rejection; and a WSL device sign-in after the restart. Real-Google acceptance stays **pending** until these are recorded.
