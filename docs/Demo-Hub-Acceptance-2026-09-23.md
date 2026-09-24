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

The limitations above are explicit work remaining before anyone describes the full #159 design as accepted. Do not close #157, merge, release, deploy, or mark the demo complete on the strength of this record.

## Live tester handoff (Dion)

Use only tester-owned Google resources. Do not put client secrets, access/refresh tokens, cookies, or browser screenshots containing them in this issue or PR.

1. Follow [Google setup](Demo-Hub-Google-Setup.md) and [Compose instructions](../demo-hub/README.md). Register the two exact localhost callback URLs, configure the Google web client ID and local secret file, set the bootstrap admin email, and add the required Google test users. Keep the gateway's host binding at `127.0.0.1:8080`.
2. Choose account A (bootstrap admin), account B (admitted readonly), and account C (Google test user but **not** hub-listed). These are distinct Google subjects. Record only opaque account labels A/B/C in the evidence. If testing the standalone writer role as well, use a fourth admitted account D with role write.
3. Start Compose. Record the image/commit, `docker compose ps`, host `curl http://localhost:8080/v1/health`, and the same health request from WSL. Confirm the engine has no published host port and `http://localhost:8080/mcp` returns 404. Record pass/fail and time, never secrets.
4. Append the documented `demo` OAuth remote and `wing_demo` route to the desktop AgentPalace MCP configuration, preserving the existing remotes and routes. Restart the MCP connection. Call `agentpalace_search` with `wing: "wing_demo"`; on `authentication_required`, call `agentpalace_remote_auth_start` with `remote: "demo"`. With browser-capable desktop `auto` mode, confirm the system browser opens (or use the returned `authorization_url` if it does not) and complete consent as A; if the tool returns device mode, present its verification link and user code instead. Poll `agentpalace_remote_auth_status` until authenticated, then retry the MCP search. Create a small disposable Git checkout with one README containing a unique test phrase, then run `agentpalace mine PATH_TO_CHECKOUT --mode projects --wing wing_demo --project-id demo-acceptance --full`. Search that phrase through the same remote; inspect the returned drawer/change metadata and record its creator and authenticated submitter IDs (opaque IDs only).
5. In the current admin session, add B as readonly using the admin access API with the session CSRF value and current `If-Match` revision, as documented in the package README. Use a separate browser profile for B. Verify B can authenticate and read permitted content, cannot write a drawer/KG fact/coordination task/ingest batch, and cannot modify the access list. Record status codes, not credentials. If D is used, verify D can write but cannot hard-delete or modify membership.
The administrator can perform the role edit in the browser developer console while signed in to the local hub. Replace the placeholder mailbox with B's actual address; keep the response in that local console and record only the status. Repeat with a fresh GET/ETag and `enabled: false` for the later disable check.

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
