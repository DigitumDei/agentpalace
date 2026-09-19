# Demo Hub: Canonical Remote REST Inventory and Implementation Contract

**Document Version:** 1.1.15<br>
**Release Series:** 0.2.0 (`release/version.toml`)<br>
**Federation API Version:** 1 (`agentpalace_federation::FEDERATION_API_VERSION`)<br>
**Status:** Approved Implementation Contract for AgentPalace #160 (parent issue #159)<br>
**Date:** 2026-09-18
**Authoritative Sources:** `crates/agentpalace-server/src/lib.rs`, `crates/agentpalace-federation/src/lib.rs`, `docs/Demo-Hub-Design.md`

---

## 1. Executive Summary and Scope Boundaries

This document defines the canonical inventory of all remote REST operations exposed by `agentpalace-server`. It forms the authoritative implementation contract for the Demo Hub (AgentPalace #159 / #160) and subsequent implementation slices.

### 1.1 Strict Allowlist and Fail-Closed Policy

The remote REST routes enumerated in this document constitute the **complete, closed allowlist** of remote operations supported by the AgentPalace server.
- **Fail-closed rule:** Any HTTP method, path, or operation not explicitly listed in this inventory is **not demo-enabled** and must be rejected rather than forwarded (normally `404 Not Found`; an unsupported method may surface as `405 Method Not Allowed`, and authorization failures as `403 Forbidden`).
- **Gateway enforcement:** The Demo Hub gateway acts as an authenticating reverse proxy and must reject or fail closed on any request attempting to reach unlisted or unsupported paths before forwarding upstream.

### 1.2 Explicit Exclusions

The following subsystems and operations are strictly outside the remote REST demo surface:
1. **Local-Only Diaries:**
   - Diaries are personal, local-first continuity records.
   - The remote REST API does not expose diary reads, writes, or searches.
   - Rather than a blanket rejection across all endpoints, actual behavior varies by interaction pattern:
     - **Collection/search reads** filter diary records (`POST /v1/drawers/search`, `POST /v1/drawers/check_duplicate`, `GET /v1/drawers`, `GET /v1/changes`, `GET /v1/taxonomy`, `GET /v1/rooms`, `GET /v1/coordination/tasks`, `GET /v1/coordination/inbox`, `GET /v1/coordination/events`).
     - **Resource lookups** mask them as `404 Not Found` (`GET /v1/drawers/{id}`, `DELETE /v1/drawers/{id}`, and coordination resource lookups such as `GET /v1/coordination/tasks/{id}`) to eliminate existence oracles.
     - **Relevant mutation inputs** are rejected with `422 Unprocessable Entity` (`ServerError::DiaryNotFederated`) when diary wings, rooms, or topics are targeted (`POST /v1/drawers`, `POST /v1/ingest/preflight`, `POST /v1/ingest/batch`, `POST /v1/coordination/tasks`, and mutation/claim attempts targeting diary-owned coordination tasks).
2. **HTTP MCP Transport:**
   - Model Context Protocol (MCP) transport (`/mcp`) is handled locally by `agentpalace-cli/transport.rs` and remains on the client side.
   - The demo hub gateway loopback proxy does not publish, forward, or expose `/mcp`.
3. **MCP-Only Tools and Operations:**
   - Over twenty local MCP tools operate exclusively within the client-side runtime and do not map to remote REST routes. These include:
     - Wake-up and orientation (`agentpalace_wake_up`, `agentpalace_identity_read`, `agentpalace_identity_update`, `agentpalace_identity_packet`)
     - Graph navigation (`agentpalace_traverse`, `agentpalace_find_tunnels`, `agentpalace_get_aaak_spec`)
     - Diary management (`agentpalace_diary_write`, `agentpalace_diary_read`)
     - Governance and procedures (`agentpalace_skill_*`, `agentpalace_delegation_*`, `agentpalace_lineage_set`, `agentpalace_self_observation_*`, `agentpalace_migration_record`)
     - Protocol adapters (`agentpalace_a2a_*`, `agentpalace_mcp_tasks_*`)
   - None of these MCP tools are exposed via remote REST.

---

## 2. Core Architectural Invariants

### 2.1 Separation of Provenance Dimensions

In accordance with `docs/Demo-Hub-Design.md` and issue #157, the Demo Hub enforces strict separation between six distinct provenance dimensions:
1. **Authenticated Human Owner:** The verified account holder identity established at authentication time (`owner.id`, `issuer`, `subject`, `email_at_write`). This is derived exclusively from server-validated credential context and **never** accepted from writable request payload fields.
2. **Caller-Asserted Agent:** The agent or harness identity claimed in request payloads (`added_by`, `created_by`, `sender`, `worker`, `actor`). When this claim differs from the authenticated identity, the server namespaces the claim as `{identity}:{claimed}`.
3. **Immutable Creator versus Later Actors:** The authenticated owner recorded when a durable resource is first created is its immutable creator. Later submitters, modifiers, invalidators, deleters, lease holders, or other callers are recorded as later actors and must not replace the creator. A caller-asserted agent label identifies the acting agent or harness, not the human owner.
4. **Original Source Author & References:** File paths, repository commits, and external citations associated with ingested content. Source attribution describes where content came from and is not an authenticated owner claim.
5. **Execution Authority & Ceilings:** The effective role (`readonly`, `write`, `admin`) restricting which operations a caller may execute. Authority is independent of creator, source author, evidence status, and agent attribution.
6. **Evidence & Truth Status:** Provenance records attribution only; it does not attest that a claim is true, nor does it grant permission for an autonomous agent to execute instructions embedded in a stored memory.

### 2.2 Token Operations and Demo Hub Role Mappings

`agentpalace-server` enforces a closed set of operations across its route gates:
- `read`
- `write`
- `delete`
- `ingest`
- `coordination_read`
- `coordination_write`
- `coordination_claim` (one-way implication: implies `coordination_write` on the same wing)

The Demo Hub maps its user roles to these operations as follows:

| Demo Role | Permitted Operations | Scope Behavior |
|---|---|---|
| **`readonly`** | `read`, `coordination_read` | Permitted to read/search memories, query the knowledge graph, and inspect exposed coordination tasks/inbox. Strictly denied all write, ingest, claim, and delete routes. |
| **`write`** | `read`, `coordination_read`, `write`, `ingest`, `coordination_write`, `coordination_claim` | Permitted full collaboration: add/search drawers, batch ingest, add/invalidate KG facts, create tasks, send messages, attach artifacts and task results. Denied hard delete. |
| **`admin`** | All operations above, plus `delete` | Permitted all write capabilities plus hard deletion of drawers (`DELETE /v1/drawers/{id}`). Gateway administrative session routes (`/hub/v1/*`) are reserved for authenticated admin browser sessions. |

### 2.3 Wing Authorization Models

Every remote route follows one of four authorization models:
- **Public / Unauthenticated:** Open probe route (`GET /v1/health`).
- **Category D (Server-Wide):** Authenticated via token middleware; no wing scoping is evaluated (e.g., `GET /v1/info`, all `/v1/kg/*` operations).
- **Category A (Request-Specified Wing):** The target wing is declared in the request body or query parameters. The operation gate and handler verify `auth.allows_wing(op, wing)` directly. Any scope mismatch returns `403 Forbidden` (e.g., `POST /v1/drawers`, `POST /v1/ingest/batch`, `POST /v1/ingest/preflight`, `POST /v1/coordination/tasks`).
- **Category B (Lookup-then-Authorize):** The target wing is discovered by loading the resource by ID. If the resource is missing OR the caller lacks permission on the resolved wing, the route returns `404 Not Found` (never `403`) to eliminate existence oracles (e.g., `GET /v1/drawers/{id}`, `DELETE /v1/drawers/{id}`, coordination resource getters and lease mutations).
- **Category C (Aggregate / Filtered Feed):** Cross-wing queries and change feeds. The handler filters records against `auth.visible_wings(op)` rather than rejecting with `403`. Missing or unauthorized wing filters evaluate to empty result sets (e.g., `GET /v1/taxonomy`, `GET /v1/wings`, `GET /v1/rooms`, `GET /v1/changes`, `POST /v1/drawers/check_duplicate`, `GET /v1/drawers`, `GET /v1/coordination/tasks`, `GET /v1/coordination/inbox`, `GET /v1/coordination/events`).

---

## 3. Master Inventory Summary Table (34 Registrations, 51 Method/Path Pairs)

The table below catalogs all 34 explicit production registrations in `build_router` (`crates/agentpalace-server/src/lib.rs`):

| # | Method | Path | Token Operation | Auth Category | Demo Roles | Durable Store(s) | Idempotency / Receipt Key | Provenance Status |
|---|---|---|---|---|---|---|---|---|
| 1 | `GET`, `HEAD` | `/v1/health` | None | Public | All (public) | In-memory | Naturally idempotent | N/A (unauthenticated) |
| 2 | `GET`, `HEAD` | `/v1/info` | None (auth only) | D (Server-wide) | `readonly`, `write`, `admin` | In-memory / Config | Naturally idempotent | Available now |
| 3 | `POST` | `/v1/drawers/search` | `read` | A/C (Hybrid) | `readonly`, `write`, `admin` | LanceDB + Storage | Naturally idempotent | Gap: `added_by` omitted |
| 4 | `POST` | `/v1/drawers/check_duplicate` | `read` | C (Aggregate) | `readonly`, `write`, `admin` | LanceDB | Naturally idempotent | Available now |
| 5 | `POST` | `/v1/drawers` | `write` | A (Body wing) | `write`, `admin` | LanceDB + SQLite | `operation_id` (receipt) | Available now / storage deferred |
| 6 | `GET`, `HEAD` | `/v1/drawers` | `read` | A/C (Hybrid) | `readonly`, `write`, `admin` | LanceDB / Storage | Naturally idempotent | Available now (`added_by`) |
| 7 | `GET`, `HEAD` | `/v1/drawers/{id}` | `read` | B (Lookup 404) | `readonly`, `write`, `admin` | LanceDB / Storage | Naturally idempotent | Available now (`added_by`) |
| 8 | `DELETE` | `/v1/drawers/{id}` | `delete` | B (Lookup 404) | `admin` | LanceDB + SQLite | `operation_id` (receipt) | Tombstone deferred |
| 9 | `POST` | `/v1/kg/query` | `read` | D (Server-wide) | `readonly`, `write`, `admin` | SQLite (`kg_facts`) | Naturally idempotent | No owner envelope |
| 10 | `POST` | `/v1/kg/facts` | `write` | D (Server-wide) | `write`, `admin` | SQLite (`kg_facts`, receipts) | `operation_id` / triple dedupe | Actor in change log only |
| 11 | `POST` | `/v1/kg/facts/invalidate` | `write` | D (Server-wide) | `write`, `admin` | SQLite (`kg_facts`, receipts) | `operation_id` / serial lock | Actor in change log only |
| 12 | `GET`, `HEAD` | `/v1/kg/timeline` | `read` | D (Server-wide) | `readonly`, `write`, `admin` | SQLite (`kg_facts`) | Naturally idempotent | No owner envelope |
| 13 | `GET`, `HEAD` | `/v1/kg/stats` | `read` | D (Server-wide) | `readonly`, `write`, `admin` | SQLite (`kg_facts`) | Naturally idempotent | N/A (aggregate stats) |
| 14 | `GET`, `HEAD` | `/v1/taxonomy` | `read` | C (Aggregate) | `readonly`, `write`, `admin` | Storage count stream | Naturally idempotent | N/A (structural counts) |
| 15 | `GET`, `HEAD` | `/v1/wings` | `read` | C (Aggregate) | `readonly`, `write`, `admin` | Storage count stream | Naturally idempotent | N/A (structural counts) |
| 16 | `GET`, `HEAD` | `/v1/rooms` | `read` | C (Aggregate) | `readonly`, `write`, `admin` | Storage count stream | Naturally idempotent | N/A (structural counts) |
| 17 | `GET`, `HEAD` | `/v1/changes` | `read` | C (Aggregate) | `readonly`, `write`, `admin` | SQLite (`changes`) | Naturally idempotent | `actor` in event DTO |
| 18 | `POST` | `/v1/ingest/preflight` | `ingest` | A (Body wing) | `write`, `admin` | Filesystem checkouts | Naturally idempotent | Content-free hash check |
| 19 | `POST` | `/v1/ingest/batch` | `ingest` | A (Body wing) | `write`, `admin` | LanceDB + SQLite + Filesystem | `record_id` (source lock) | Available now / storage deferred |
| 20 | `POST` | `/v1/coordination/tasks` | `coordination_write` | A (Body wing) | `write`, `admin` | SQLite (`coordination_tasks`) | `(created_by, idempotency_key)` | Available now / storage deferred |
| 21 | `GET`, `HEAD` | `/v1/coordination/tasks` | `coordination_read` | C (Aggregate) | `readonly`, `write`, `admin` | SQLite (`coordination_tasks`) | Naturally idempotent | `created_by`, `owner` |
| 22 | `GET`, `HEAD` | `/v1/coordination/tasks/{id}` | `coordination_read` | B (Lookup 404) | `readonly`, `write`, `admin` | SQLite (`coordination_tasks`) | Naturally idempotent | `created_by`, `owner` |
| 23 | `POST` | `/v1/coordination/tasks/{id}/claim` | `coordination_claim` | B (Lookup 404) | `write`, `admin` | SQLite (`coordination_tasks`) | `expected_revision` CAS | Worker namespaced |
| 24 | `POST` | `/v1/coordination/tasks/{id}/renew` | `coordination_claim` | B (Lookup 404) | `write`, `admin` | SQLite (`coordination_tasks`) | `expected_revision` CAS | Worker namespaced |
| 25 | `POST` | `/v1/coordination/tasks/{id}/transition` | `coordination_claim` | B (Lookup 404) | `write`, `admin` | SQLite (`coordination_tasks`) | `expected_revision` CAS | Actor namespaced |
| 26 | `POST` | `/v1/coordination/messages` | `coordination_write` | B (Task wing) | `write`, `admin` | SQLite (`coordination_messages`) | `(sender, idempotency_key)` | Sender namespaced |
| 27 | `GET`, `HEAD` | `/v1/coordination/messages/{id}` | `coordination_read` | B (Task wing) | `readonly`, `write`, `admin` | SQLite (`coordination_messages`) | Naturally idempotent | Sender / recipient |
| 28 | `POST` | `/v1/coordination/messages/{id}/ack` | `coordination_write` | B (Task wing) | `write`, `admin` | SQLite (`coordination_messages`) | Recipient match check | Actor namespaced |
| 29 | `GET`, `HEAD` | `/v1/coordination/inbox` | `coordination_read` | C (Aggregate) | `readonly`, `write`, `admin` | SQLite (`coordination_messages`) | Naturally idempotent | Sender / recipient |
| 30 | `POST` | `/v1/coordination/artifacts` | `coordination_write` | B (Task wing) | `write`, `admin` | SQLite (`coordination_artifacts`) | `(created_by, idempotency_key)` | Creator namespaced |
| 31 | `GET`, `HEAD` | `/v1/coordination/artifacts/{id}` | `coordination_read` | B (Task wing) | `readonly`, `write`, `admin` | SQLite (`coordination_artifacts`) | Naturally idempotent | Content hash + creator |
| 32 | `POST` | `/v1/coordination/results` | `coordination_write` | B (Task wing) | `write`, `admin` | SQLite (`coordination_task_results`) | `(created_by, idempotency_key)` | Creator namespaced |
| 33 | `GET`, `HEAD` | `/v1/coordination/results/{id}` | `coordination_read` | B (Task wing) | `readonly`, `write`, `admin` | SQLite (`coordination_task_results`) | Naturally idempotent | Creator namespaced |
| 34 | `GET`, `HEAD` | `/v1/coordination/events` | `coordination_read` | C (Aggregate) | `readonly`, `write`, `admin` | SQLite (`coordination_events`) | Naturally idempotent | `actor` in event DTO |

### 3.1 Route-registration audit

This inventory was checked against the production `build_router` registration in
`crates/agentpalace-server/src/lib.rs` on 2026-09-18. The audit found 34 explicit
production method/path registrations: 2 infrastructure/discovery, 6 drawer/search, 5
knowledge-graph, 4 taxonomy/change-feed, 2 ingest, 6 coordination-task/lease,
4 messaging/inbox, and 5 artifact/result/event routes. The two ingest routes are
included even though they are assembled in their own body-limited sub-router.
Axum also serves HEAD for every GET registration, yielding 51 accepted method/path
pairs. The 17 HEAD operations are explicitly listed alongside GET in the table.

The `/test/*` routes registered only by test helpers are not production routes and
are not part of this demo inventory. `/mcp` and all MCP-only operations are also
outside the remote REST router. Consequently, a method/path pair absent from the
table (including each listed HEAD operation) is not demo-enabled, even if an internal handler or test helper exists
for it; the gateway and server must fail closed rather than forward it (normally
`404 Not Found`; unsupported methods may surface as `405 Method Not Allowed`).

Each numbered route specification below preserves the same contract fields:
operation privilege and scope authorization, request and retrieval surfaces,
durable store, receipt/idempotency behavior, crash/recovery invariant, and the
currently available versus deferred provenance retrieval path. This makes the
summary table an allowlist and the detailed sections the implementation contract,
including POST search, writes, batches, invalidation, deletion, ingest, and all
coordination reads and mutations.

### HEAD behavior and authorization

Every GET path in the table also accepts HEAD through Axum's GET registration.
HEAD executes the matching GET handler and applies the same authentication,
operation gate, wing filtering, lookup masking, and demo-role policy. The response
retains the GET status and headers but has no body, including on errors; it does
not return the GET provenance payload. This includes public HEAD /v1/health,
authenticated HEAD /v1/info, and the read/coordination-read routes listed above.
HEAD never permits a write or bypasses authentication. The gateway must explicitly
allow these listed HEAD operations under the matching GET policy, and reject
unlisted methods/paths. No implicit HEAD operation exists for POST-only routes.

### 3.2 Reconfirmation audit ledger

The 2026-09-17 reconfirmation read the complete production registration in
`build_router` (including the separately assembled, body-limited ingest router)
and matched the 34 explicit registrations to the numbered rows above. The
2026-09-18 correction adds the 17 implicit HEAD operations omitted from that
earlier count; each is listed in the same row as its GET registration:

| Registration set | Count | Required privilege | Contract check |
|---|---:|---|---|
| Public liveness | 1 | none | Stateless health response; no receipt or provenance |
| Authenticated discovery | 1 | authenticated token | Config/runtime read; no mutation receipt |
| Read-gated REST | 18 | `read` or `coordination_read` | Read-only store access; cursor/filtered retrieval where applicable |
| Standard writes | 3 | `write` | KG/drawer receipts and recovery rules are specified per route |
| Deletion | 1 | `delete` | Owner-scope lookup, receipt detail capture, and delete-event recovery |
| Ingest | 2 | `ingest` | Checkout/read validation or resumable `record_id` batch recovery |
| Coordination claims | 3 | `coordination_claim` | Revision CAS and lease/transition recovery rules |
| Coordination writes | 5 | `coordination_write` | Task/message/artifact/result transaction and replay rules |
| Implicit HEAD operations | 17 | Same gate and authorization as the matching GET | Same handler/status/headers; no response body |
| **Total accepted method/path pairs** | **51** |  | **No unlisted production method/path pair is demo-enabled** |

For each row, the audit checked the gate attached at registration, the handler's
wing or lookup authorization, the durable store actually called by the handler,
whether the operation is naturally idempotent or has a receipt/CAS key, the
state left visible after a crash, and the route through which attribution can be
retrieved. The provenance crosswalk is intentionally bounded:

- Drawer list/get return stored `added_by` and `filed_at`; drawer search exposes
  the response fields but currently returns those provenance fields as `null`.
  The change feed exposes the current actor for drawer writes/deletes.
- KG writes and invalidations expose their result and actor through the change
  feed; KG query/timeline/stats do not fabricate an owner envelope.
- Ingest returns per-file status only; attribution is retrieved from the
  resulting drawer rows and change feed after a successful batch.
- Coordination DTOs and coordination events expose namespaced agent/actor,
  creator, sender, recipient, worker, or owner strings as specified in the
  route rows. They do not yet expose verified human-owner metadata.
- Health and info have no durable resource provenance. Token owner introspection
  remains a gateway/storage-slice concern, and no route in this inventory claims
  durable human-owner attribution before that slice lands.

This audit deliberately does not count local-only diaries, the local HTTP MCP
transport, MCP-only operations, or test-helper routes. A method/path absent from
the table remains outside the allowlist and must fail closed; a handler existing
in the crate is not by itself a remote contract.

### 3.3 Issue #161 reconciliation matrix

The following matrix is the implemented provenance cross-route view of the
approved inventory: every
remote mutation is paired with the reads that must expose its committed result.
“Legacy” means a token without validated `owner` metadata; it remains usable,
but its authenticated owner is explicitly unknown and must never be inferred
from a token name, caller label, source author, email, or record ID.

| Mutation route(s) | Matching read/search route(s) | Store of record | Owner scope and history | Receipt / recovery requirement | Legacy behavior |
|---|---|---|---|---|---|
| `POST /v1/drawers` | `POST /v1/drawers/search`; `GET /v1/drawers`; `GET /v1/drawers/{id}`; `GET /v1/changes` | LanceDB drawer row plus SQLite `mutation_receipts` and `change_log`; persisted provenance keeps creator, submitter, source refs, and history separate | Preserve authenticated creator; append later modifiers/deleters; keep `added_by` as caller-asserted agent and source fields separate | Owner-scoped `operation_id`; commit receipt with drawer row and change event; recover an ownerless-visible partial write as pending/failed, never success | Accept existing static tokens with `owner: null`/omitted; return explicit unknown owner and preserve legacy receipt namespace |
| `DELETE /v1/drawers/{id}` | `GET /v1/changes`; lookup returns `404` after deletion | LanceDB drawer row (physically removed) plus SQLite `mutation_receipts` and `change_log`; attributed deletion history is retained in the provenance record before removal | Retain original creator and append deleting owner; source references remain distinct from deletion actor | Owner-scoped delete receipt captures target incarnation before deletion; recovery uses `mutation_receipts` details and restores the missing `change_log` deletion event before success; no LanceDB tombstone exists | Legacy delete remains attributable only to unknown authenticated owner; never transfer creator to deleter |
| `POST /v1/kg/facts` | `POST /v1/kg/query`; `GET /v1/kg/timeline`; `GET /v1/kg/stats`; `GET /v1/changes` | SQLite `knowledge_graph_facts` plus current `mutation_receipts` and `change_log`; persisted provenance is separate from source drawer/file references | Preserve original fact submitter; append later authenticated modifiers; source drawer/reference is not owner provenance | Owner-scoped receipt and triple dedupe; replay/recovery must restore the fact event before completing the receipt | Existing facts without owner metadata read as explicitly unknown; canonical triple dedupe must not bind them to a later owner |
| `POST /v1/kg/facts/invalidate` | `POST /v1/kg/query`; `GET /v1/kg/timeline`; `GET /v1/changes` | SQLite `knowledge_graph_facts` plus current `mutation_receipts` and `change_log`; invalidation provenance is retained separately from validity dates | Preserve original creator; append invalidating owner and evidence/date separately | Owner-scoped serialized receipt; recover the invalidation event and exact effective date before success | Legacy invalidation remains valid but owner is unknown; it must not rewrite original creator metadata |
| `POST /v1/ingest/preflight` | No content mutation; subsequent `POST /v1/ingest/batch` result is read through drawer/search routes | Checkout/filesystem inspection only | No durable creator is established by a content-free preflight | Naturally retryable; no mutation receipt and no visible provenance claim | Works unchanged for legacy tokens; no owner is fabricated from checkout/source metadata |
| `POST /v1/ingest/batch` | `POST /v1/drawers/search`; `GET /v1/drawers`; `GET /v1/drawers/{id}`; `GET /v1/changes` | Filesystem checkout, LanceDB drawer rows, SQLite `mutation_receipts` and `change_log`; each chunk carries the authenticated submitter separately from source provenance | Record authenticated submitting owner separately from source author, commit, path, and federated original provenance; preserve per-chunk creator history | Owner-scoped `record_id` receipt/source lock; resumable recovery must reconcile committed chunks and events before success | Existing unowned mined rows remain unknown; retries cannot adopt them or change their original source provenance |
| `POST /v1/coordination/tasks` | `GET /v1/coordination/tasks`; `GET /v1/coordination/tasks/{id}`; `GET /v1/coordination/events` | SQLite `coordination_tasks`, `mutation_receipts`, and `coordination_events`; the `provenance_json` sidecar exists but is not populated by the coordination routes yet | Preserve authenticated creator; keep `created_by` as agent attribution and source/federation origin separate | Owner-scoped `(idempotency_key, record identity)`; task and creation event must be recoverable as one visible commit | Legacy `created_by`/owner strings remain readable, with human owner explicitly unknown |
| `POST /v1/coordination/tasks/{id}/claim`; `/renew`; `/transition` | `GET /v1/coordination/tasks/{id}`; task list; `GET /v1/coordination/events` | SQLite task row, revision/lease fields, coordination events | Preserve creator; append authenticated claimant/actor history and keep worker/actor labels distinct | Revision CAS plus owner-scoped mutation receipt where supplied; no successful response until the state and event agree | Existing agent-owned leases continue to work; unknown human owner never becomes the authenticated owner of a legacy task |
| `POST /v1/coordination/messages` | `GET /v1/coordination/messages/{id}`; `GET /v1/coordination/inbox`; `GET /v1/coordination/events` | SQLite `coordination_messages`, `mutation_receipts`, and `coordination_events`; the `provenance_json` sidecar exists but is not populated by the coordination routes yet | Preserve authenticated sender owner; retain sender/recipient agent identities and federated source separately; append acknowledger history | Owner-scoped `(idempotency_key, sender)`; recover message and event together before success | Legacy sender/recipient values remain visible; owner field is explicitly unknown |
| `POST /v1/coordination/messages/{id}/ack` | `GET /v1/coordination/messages/{id}`; inbox; events | SQLite message row and coordination event | Preserve original sender and append authenticated recipient/ack actor; do not replace creator | Recipient authorization plus durable ack event; retry must replay only within the same owner scope | Legacy recipient matching remains unchanged and does not establish human ownership |
| `POST /v1/coordination/artifacts` | `GET /v1/coordination/artifacts/{id}`; `GET /v1/coordination/events` | SQLite `coordination_artifacts`, `mutation_receipts`, and `coordination_events`; the `provenance_json` sidecar exists but is not populated by the coordination routes yet | Preserve authenticated creator; retain content hash, source reference, and federated original provenance independently | Owner-scoped `(idempotency_key, created_by)`; artifact and event must recover together | Existing artifacts expose creator agent but unknown human owner |
| `POST /v1/coordination/results` | `GET /v1/coordination/results/{id}`; `GET /v1/coordination/events` | SQLite `coordination_results` plus coordination events; the `provenance_json` sidecar exists but is not populated by the coordination routes yet | Preserve authenticated submitter and original task/artifact provenance; append later modifiers if supported | Owner-scoped `(idempotency_key, created_by)`; result/event recovery precedes successful receipt completion | Existing results remain readable with explicit unknown human owner |

The following approved reads have no corresponding remote mutation and therefore
must never be treated as provenance-bearing writes: `GET /v1/health`,
`GET /v1/info`, `GET /v1/taxonomy`, `GET /v1/wings`, `GET /v1/rooms`,
`POST /v1/drawers/check_duplicate`, and the aggregate portions of
`GET /v1/kg/stats`. They retain their existing filtered/shared semantics. In
particular, shared responses may expose owner ID and `email_at_write` only after
the authenticated provenance storage slice; raw provider subjects are not an
ordinary response field. Diaries, MCP-only operations, and coordination
delegation/telemetry surfaces remain excluded.

---

## 4. Comprehensive Route Specifications

### Group 1: Infrastructure and Discovery

#### 1. `GET /v1/health`
- **Operation Gate:** None (Public router).
- **Wing Authorization:** None.
- **Demo Role Eligibility:** Public (unauthenticated).
- **Request Surface:** Empty `GET` request. No authorization headers required.
- **Retrieval Surface:** `200 OK`, JSON `{"status": "ok"}`.
- **Durable Store:** None (in-memory liveness probe).
- **Idempotency & Receipts:** Naturally idempotent read. No receipts.
- **Crash Recovery:** Stateless; available immediately upon process launch.
- **Provenance Status:** N/A. No identity or provenance is evaluated or emitted.

#### 2. `GET /v1/info`
- **Operation Gate:** None (Requires valid bearer token via `auth_middleware`; no per-route operation gate).
- **Wing Authorization:** Category D (Server-wide).
- **Demo Role Eligibility:** `readonly`, `write`, `admin`.
- **Request Surface:** `GET /v1/info` with `Authorization: Bearer <token>`.
- **Retrieval Surface:** `200 OK`, JSON `InfoResponse`:
  - `server_version`: string (e.g., `"0.2.0"`)
  - `federation_api_version`: u32 (`1`)
  - `embedding_profile`: string (e.g., `"balanced"`)
  - `capabilities`: array of strings (`["drawers", "kg", "changes", "taxonomy", "ingest", "coordination", "coordination_task_list", "idempotent_mutations", "resumable_ingest", "ingest_preflight"]`)
  - `maintenance_enabled`: bool
  - `maintenance_background_enabled`: bool
  - `maintenance_idle_secs`: u64
  - `maintenance_last_run`: Option<Value>
  - `maintenance_status`: `MaintenanceStatus` enum
- **Durable Store:** In-memory server state, static runtime configuration, storage maintenance status.
- **Idempotency & Receipts:** Naturally idempotent read.
- **Crash Recovery:** Rebuilt from runtime config and storage maintenance state on startup.
- **Provenance Status:**
  - *Available now:* Validates token authentication.
  - *Deferred to storage slice:* Owner metadata introspection is delegated to gateway `/hub/v1/me`.

---

### Group 2: Drawers and Semantic Search

#### 3. `POST /v1/drawers/search`
- **Operation Gate:** `read`.
- **Wing Authorization:** Category A/C Hybrid.
  - If `wing` is present in body: checked via `auth.allows_wing(Operation::Read, wing)` -> `403 Forbidden` on mismatch.
  - If `wing` is absent: cross-wing search; candidate matches are filtered post-ranking using `auth.visible_wings(Operation::Read)` and excluding diary rooms (`is_diary_wing_or_room`).
- **Demo Role Eligibility:** `readonly`, `write`, `admin`.
- **Request Surface:** `POST /v1/drawers/search`, JSON `DrawerSearchRequest`:
  - `query`: string (mandatory, max 16,384 bytes; `MAX_SEARCH_QUERY_BYTES`)
  - `wing`: Option<string>
  - `room`: Option<string>
  - `view`: Option<string> (e.g., `"canonical"` or branch view name)
  - `limit`: Option<usize> (default 5, clamped to `[1, effective_search_results_limit]`)
- **Retrieval Surface:** `200 OK`, JSON `DrawerSearchResponse`:
  - `results`: array of `RemoteDrawerResult` (`drawer_id`, `wing`, `room`, `rank`, `score`, `content`, `source_file`, `content_hash`, `filed_at`, `added_by`, `stale`).
- **Durable Store:** LanceDB (vector index search) + storage drawer store.
- **Idempotency & Receipts:** Naturally idempotent read.
- **Crash Recovery:** Pure read against committed LanceDB vector tables.
- **Provenance Status:**
  - *Available now:* Server handler currently omits provenance, hardcoding `content_hash: None`, `filed_at: None`, `added_by: None` (known gap documented in `Demo-Hub-Design.md`).
  - *Deferred to storage slice:* Enriching search retrieval to return stored `added_by` agent attribution and structured `owner` envelope (`owner.id`, `email_at_write`).

#### 4. `POST /v1/drawers/check_duplicate`
- **Operation Gate:** `read`.
- **Wing Authorization:** Category C (Aggregate). No wing in request. Vector matches are filtered against `auth.visible_wings(Operation::Read)` and non-diary rooms before computing `is_duplicate = !matches.is_empty()` to prevent existence oracles.
- **Demo Role Eligibility:** `readonly`, `write`, `admin`.
- **Request Surface:** `POST /v1/drawers/check_duplicate`, JSON `CheckDuplicateRequest`:
  - `content`: string (mandatory, max 256 KiB; `MAX_DRAWER_CONTENT_BYTES`)
  - `threshold`: Option<f32> (default `0.9`; `DEFAULT_DUPLICATE_THRESHOLD`)
- **Retrieval Surface:** `200 OK`, JSON `CheckDuplicateResponse`:
  - `is_duplicate`: bool
  - `matches`: Value (array of matching candidate records)
- **Durable Store:** LanceDB (vector index query).
- **Idempotency & Receipts:** Naturally idempotent read.
- **Crash Recovery:** Pure read against LanceDB.
- **Provenance Status:** Match records reflect candidate rows; owner envelopes deferred.

#### 5. `POST /v1/drawers`
- **Operation Gate:** `write`.
- **Wing Authorization:** Category A (Body wing).
  - Validates `wing` and `room`. Diary wings/rooms and source files starting with `__agentpalace_diary_` are rejected with `422 Unprocessable Entity` (`ServerError::DiaryNotFederated`).
  - Verifies `auth.allows_wing(Operation::Write, wing)` -> `403 Forbidden` on mismatch.
  - Performs duplicate check; candidate matches outside caller's visible wings are ignored to prevent leakages before returning `409 Conflict`.
- **Demo Role Eligibility:** `write`, `admin` (denied to `readonly`).
- **Request Surface:** `POST /v1/drawers`, JSON `AddDrawerRequest`:
  - `wing`: string
  - `room`: string
  - `content`: string (max 256 KiB; `MAX_DRAWER_CONTENT_BYTES`)
  - `source_file`: Option<string>
  - `added_by`: Option<string> (caller-asserted agent name)
  - `drawer_id`: Option<string> (optional client-pinned drawer ID for replication)
  - `operation_id`: Option<string> (idempotency key)
- **Retrieval Surface:** `200 OK`, JSON `AddDrawerResponse` (`success`, `drawer_id`, `wing`, `room`).
  - Errors: `409 Conflict` on near-duplicate content; `409 Conflict` on reused `operation_id` with differing payload; `403 Forbidden`; `422 Unprocessable Entity`.
- **Durable Store:** LanceDB (vector embeddings + drawer content record), SQLite (`receipts` table, `changes` table, operational metadata).
- **Idempotency & Receipts:**
  - When `operation_id` is supplied, server hashes `(wing, room, content, source_file, effective_added_by, drawer_id)`.
  - `receipt_store().begin_receipt()` records the operation with kind `drawer_add` and target `drawer_id`.
  - `ReceiptOutcome::Replay`: Replays saved response without re-executing writes.
  - `ReceiptOutcome::Conflict`: Reused key with mismatched payload returns `409 IdempotencyConflict`.
- **Crash Recovery:**
  - `ReceiptOutcome::Recover`: A prior attempt crashed. If the drawer exists and matches content, the server recovers missing `drawer_added` change events via atomic append-if-absent, marks receipt complete, and returns success. If content differs, returns `409 Conflict`. If absent, proceeds with write using the pinned target ID.
- **Provenance Status:**
  - *Available now:* `effective_added_by` resolves to `{token_id}:{claimed_agent}` when claimed differs from token, or `{token_id}`. Stored on drawer and change event.
  - *Available now:* Validated `owner` metadata on private server token entries is loaded into the authenticated request context; durable persistence of human `owner_id`, `issuer`, `subject`, and `email_at_write`, and scoping `operation_id` to `(owner_id, operation_id)`, remain deferred to the storage slice.

#### 6. `GET /v1/drawers`
- **Operation Gate:** `read`.
- **Wing Authorization:** Category A/C Hybrid.
  - If `wing` is in query: verified via `auth.allows_wing(Operation::Read, wing)` -> `403 Forbidden`.
  - If `wing` is omitted: pushes `auth.visible_wings(Operation::Read)` into storage query (`DrawerFilter::wings`). Empty visible set short-circuits to empty array. Excludes diary rows.
- **Demo Role Eligibility:** `readonly`, `write`, `admin`.
- **Request Surface:** `GET /v1/drawers`, query parameters `ListDrawersQuery`:
  - `wing`: Option<string>
  - `room`: Option<string>
  - `limit`: Option<usize> (default 50, max 200)
  - `cursor`: Option<string>
- **Retrieval Surface:** `200 OK`, JSON `ListDrawersResponse`:
  - `drawers`: array of drawer JSON objects (`id`, `wing`, `room`, `hall`, `date`, `source_file`, `chunk_index`, `ingest_mode`, `added_by`, `filed_at`, `content`, `content_hash`, optional `stale`).
  - `next_cursor`: Option<string> (always `null` in v1; underlying store lacks cursor pagination).
- **Durable Store:** LanceDB / storage drawer store.
- **Idempotency & Receipts:** Naturally idempotent read.
- **Crash Recovery:** Read-only access to committed rows.
- **Provenance Status:**
  - *Available now:* Returns stored `added_by` string and `filed_at` timestamp.
  - *Deferred to storage slice:* Structured `owner` envelope (`owner.id`, `email_at_write`).

#### 7. `GET /v1/drawers/{id}`
- **Operation Gate:** `read`.
- **Wing Authorization:** Category B (Lookup-then-authorize).
  - Fetches drawer by ID. If absent, if in diary wing/room, or if `!auth.allows_wing(Operation::Read, drawer.wing)`: returns `404 Not Found` (never `403`) to mask existence.
- **Demo Role Eligibility:** `readonly`, `write`, `admin`.
- **Request Surface:** `GET /v1/drawers/{id}` with path parameter `id`.
- **Retrieval Surface:** `200 OK`, JSON drawer object with resolved locator `stale` flag. `404 Not Found` on absence or lack of scope.
- **Durable Store:** Storage drawer store (LanceDB).
- **Idempotency & Receipts:** Naturally idempotent read.
- **Crash Recovery:** Read-only.
- **Provenance Status:** Returns `added_by` string; owner envelope deferred.

#### 8. `DELETE /v1/drawers/{id}`
- **Operation Gate:** `delete`.
- **Wing Authorization:** Category B (Lookup-then-authorize).
  - Resolves drawer to find wing. Masks diary drawers as `404 Not Found`. Verifies `auth.allows_wing(Operation::Delete, drawer.wing)` -> `404 Not Found` on mismatch.
- **Demo Role Eligibility:** `admin` only (denied to `readonly` and `write` in Demo Hub).
- **Request Surface:** `DELETE /v1/drawers/{id}`, path parameter `id`, query parameter `operation_id` (Option<string>).
- **Retrieval Surface:** `200 OK`, JSON `{"success": true, "drawer_id": id, "wing": wing, "room": room}`.
  - Errors: `404 Not Found`; `409 Conflict` on idempotency collision.
- **Durable Store:** LanceDB (deletes vector/content record), SQLite (`receipts`, `changes` log).
- **Idempotency & Receipts:**
  - Accepts `operation_id` in `DeleteDrawerQuery`.
  - `begin_receipt()` with target `drawer_id`.
  - `set_receipt_details()` commits target wing/room *before* deleting to survive crashes.
  - Replay checks caller's delete permission against captured wing before returning success.
  - Fresh absent delete returns `404 Not Found` (never fakes success).
- **Crash Recovery:** If crash occurs after LanceDB deletion but before change event/receipt completion: recovered receipt uses pre-recorded details to restore missing `drawer_deleted` event atomically and complete receipt.
- **Provenance Status:**
  - *Available now:* Change event records `actor: token_id`.
  - *Deferred to storage slice:* Attributed deletion tombstone recording both original creator and deleting owner; owner-scoped receipt index.

---

### Group 3: Knowledge Graph

#### 9. `POST /v1/kg/query`
- **Operation Gate:** `read`.
- **Wing Authorization:** Category D (Server-wide; KG has no wing concept).
- **Demo Role Eligibility:** `readonly`, `write`, `admin`.
- **Request Surface:** `POST /v1/kg/query`, JSON `KgQueryRequest`:
  - `entity`: string (mandatory, max 4,096 bytes; `MAX_KG_FIELD_BYTES`)
  - `as_of`: Option<string> (RFC 3339 or `YYYY-MM-DD` date)
  - `direction`: Option<string> (`"outgoing"`, `"incoming"`, `"both"`, defaults to `"both"`)
- **Retrieval Surface:** `200 OK`, JSON:
  - `entity`: string (the queried entity name)
  - `as_of`: Option<string> (effective query date, if specified)
  - `facts`: array of `KnowledgeQueryRow` objects:
    - `direction`: string (`"outgoing"` or `"incoming"`)
    - `subject`: string (non-empty, max 4,096 bytes; `MAX_KG_FIELD_BYTES`)
    - `predicate`: string (non-empty, max 4,096 bytes; `MAX_KG_FIELD_BYTES`)
    - `object`: string (non-empty, max 4,096 bytes; `MAX_KG_FIELD_BYTES`)
    - `valid_from`: Option<string> (start validity date, e.g., `"YYYY-MM-DD"`)
    - `valid_to`: Option<string> (end validity date if ended/invalidated, e.g., `"YYYY-MM-DD"`)
    - `confidence`: f32 (e.g., `1.0`)
    - `source_closet`: Option<string> (source drawer/closet ID if tracked)
    - `current`: bool (whether the fact is currently active as of query date)
  - `count`: usize (number of matching facts returned)
  *(An unknown entity returns `facts: []` and `count: 0`)*.
- **Durable Store:** SQLite operational store (`kg_facts`, `kg_entities`).
- **Idempotency & Receipts:** Naturally idempotent read.
- **Crash Recovery:** Read-only SQLite query.
- **Provenance Status:** `KnowledgeQueryRow` returns graph attributes (`direction`, `subject`, `predicate`, `object`, validity dates `valid_from`/`valid_to`, `confidence`, `source_closet`, `current`). It does not include an authenticated human owner envelope (`owner.id`, `email_at_write`). Durable owner attribution and query-time owner envelope retrieval are deferred to the storage slice.

#### 10. `POST /v1/kg/facts`
- **Operation Gate:** `write`.
- **Wing Authorization:** Category D (Server-wide).
- **Demo Role Eligibility:** `write`, `admin` (denied to `readonly`).
- **Request Surface:** `POST /v1/kg/facts`, JSON `KgAddFactRequest`:
  - `subject`: string (non-empty, max 4,096 bytes; `MAX_KG_FIELD_BYTES`)
  - `predicate`: string (non-empty, max 4,096 bytes; `MAX_KG_FIELD_BYTES`)
  - `object`: string (non-empty, max 4,096 bytes; `MAX_KG_FIELD_BYTES`)
  - `valid_from`: Option<string> (`YYYY-MM-DD` date)
  - `operation_id`: Option<string>
- **Retrieval Surface:** `200 OK`, JSON:
  - `success`: bool (`true`)
  - `triple_id`: string (canonical triple ID, e.g., `"kg:<blake3-hex>"`)
  - `fact`: string (display formatted string, e.g., `"{subject} → {predicate} → {object}"`)
- **Durable Store:** SQLite operational store (`kg_facts`, `kg_entities`, `receipts`, `changes`).
- **Idempotency & Receipts:**
  - Optional `operation_id`.
  - Triple deduplication: `runtime.add_fact()` is naturally idempotent over canonical triples.
  - Receipts prevent duplicate `kg_fact_added` change events on replay.
  - Replay returns cached JSON containing `success`, `triple_id`, and `fact`.
- **Crash Recovery:** In recovery mode, re-application of triple is idempotent; missing change event is appended atomically before completing receipt.
- **Provenance Status:**
  - *Available now:* Change event records `actor: token_id`. The returned response carries `triple_id` and formatted `fact`, but the underlying `kg_facts` row carries no human owner envelope.
  - *Deferred to storage slice:* Persisting owner envelope on fact rows; retaining original submitter across deduplication.

#### 11. `POST /v1/kg/facts/invalidate`
- **Operation Gate:** `write`.
- **Wing Authorization:** Category D (Server-wide).
- **Demo Role Eligibility:** `write`, `admin` (denied to `readonly`).
- **Request Surface:** `POST /v1/kg/facts/invalidate`, JSON `KgInvalidateRequest`:
  - `subject`: string (non-empty, max 4,096 bytes; `MAX_KG_FIELD_BYTES`)
  - `predicate`: string (non-empty, max 4,096 bytes; `MAX_KG_FIELD_BYTES`)
  - `object`: string (non-empty, max 4,096 bytes; `MAX_KG_FIELD_BYTES`)
  - `ended`: Option<string> (`YYYY-MM-DD` date)
  - `operation_id`: Option<string>
- **Retrieval Surface:** `200 OK`, JSON:
  - `success`: bool (`true` for operation-aware requests or when rows were invalidated; `invalidated > 0` for legacy un-keyed requests)
  - `invalidated`: usize (number of fact rows invalidated in the graph, typically `1` or `0`)
  - `fact`: string (display formatted string, e.g., `"{subject} → {predicate} → {object}"`)
  - `ended`: string (effective invalidation date in `"YYYY-MM-DD"` format)
- **Durable Store:** SQLite operational store (`kg_facts`, `receipts`, `changes`).
- **Idempotency & Receipts:**
  - Optional `operation_id`. Serialized via `operation_aware_kg_invalidation_lock` to coordinate SQLite writes.
  - Replay returns cached JSON outcome (`success`, `invalidated`, `fact`, `ended`).
- **Crash Recovery:** Restores missing `kg_fact_invalidated` change event atomically before receipt completion.
- **Provenance Status:**
  - *Available now:* `actor: token_id` recorded on change log event. Invalidation response returns `invalidated`, `fact`, and `ended`.
  - *Deferred to storage slice:* Durable attribution of which human owner invalidated the fact; owner-scoped receipt key.

#### 12. `GET /v1/kg/timeline`
- **Operation Gate:** `read`.
- **Wing Authorization:** Category D (Server-wide).
- **Demo Role Eligibility:** `readonly`, `write`, `admin`.
- **Request Surface:** `GET /v1/kg/timeline`, query parameters `KgTimelineQuery`:
  - `entity`: Option<string> (when present, non-empty and max 4,096 bytes; `MAX_KG_FIELD_BYTES`)
  - `limit`: Option<usize> (default 100, clamped to `[1, 200]`; `DEFAULT_KG_TIMELINE_LIMIT` / `MAX_KG_TIMELINE_LIMIT`)
- **Retrieval Surface:** `200 OK`, JSON:
  - `entity`: string (the queried entity name, or `"all"` if omitted)
  - `timeline`: array of `KnowledgeTimelineRow` objects:
    - `subject`: string (non-empty, max 4,096 bytes; `MAX_KG_FIELD_BYTES`)
    - `predicate`: string (non-empty, max 4,096 bytes; `MAX_KG_FIELD_BYTES`)
    - `object`: string (non-empty, max 4,096 bytes; `MAX_KG_FIELD_BYTES`)
    - `valid_from`: Option<string>
    - `valid_to`: Option<string>
    - `current`: bool
  - `count`: usize (number of timeline rows returned after limit)
  - `total_count`: usize (total timeline events available before limit truncation)
- **Durable Store:** SQLite operational store (`kg_facts`).
- **Idempotency & Receipts:** Naturally idempotent read.
- **Crash Recovery:** Read-only SQLite query.
- **Provenance Status:** Chronological validity timeline; owner provenance deferred to storage slice.

#### 13. `GET /v1/kg/stats`
- **Operation Gate:** `read`.
- **Wing Authorization:** Category D (Server-wide).
- **Demo Role Eligibility:** `readonly`, `write`, `admin`.
- **Request Surface:** `GET /v1/kg/stats`. No query parameters.
- **Retrieval Surface:** `200 OK`, JSON `KnowledgeGraphStats`:
  - `entities`: usize (total distinct entity nodes recorded in the knowledge graph)
  - `triples`: usize (total distinct canonical triples)
  - `current_facts`: usize (count of active/current facts)
  - `expired_facts`: usize (count of invalidated or expired historical facts)
  - `relationship_types`: array of strings (distinct predicate/relationship names present in the graph)
- **Durable Store:** SQLite operational store (`kg_facts`, `kg_entities`).
- **Idempotency & Receipts:** Naturally idempotent read.
- **Crash Recovery:** Read-only aggregation over committed graph tables.
- **Provenance Status:** N/A (aggregate metrics).

---

### Group 4: Taxonomy, Structure, and Change Feeds

#### 14. `GET /v1/taxonomy`
- **Operation Gate:** `read`.
- **Wing Authorization:** Category C (Aggregate). Filters projected counts by `auth.visible_wings(Operation::Read)` and excludes diaries.
- **Demo Role Eligibility:** `readonly`, `write`, `admin`.
- **Request Surface:** `GET /v1/taxonomy`.
- **Retrieval Surface:** `200 OK`, JSON `{"taxonomy": BTreeMap<String, BTreeMap<String, usize>>}`.
- **Durable Store:** Storage drawer count projections.
- **Idempotency & Receipts:** Naturally idempotent read.
- **Crash Recovery:** Live count aggregation.
- **Provenance Status:** N/A (structural metadata).

#### 15. `GET /v1/wings`
- **Operation Gate:** `read`.
- **Wing Authorization:** Category C (Aggregate). Filters wing list to visible wings and excludes diaries.
- **Demo Role Eligibility:** `readonly`, `write`, `admin`.
- **Request Surface:** `GET /v1/wings`.
- **Retrieval Surface:** `200 OK`, JSON `{"wings": BTreeMap<String, usize>}` (wing name to count).
- **Durable Store:** Storage drawer count projections.
- **Idempotency & Receipts:** Naturally idempotent read.
- **Crash Recovery:** Live count aggregation.
- **Provenance Status:** N/A (structural metadata).

#### 16. `GET /v1/rooms`
- **Operation Gate:** `read`.
- **Wing Authorization:** Category C (Aggregate).
  - Optional `?wing=` query param. If specified wing is invisible to token, filters to empty map (does not 403). Excludes diaries.
- **Demo Role Eligibility:** `readonly`, `write`, `admin`.
- **Request Surface:** `GET /v1/rooms`, query parameters `RoomsQuery` (`wing: Option<string>`).
- **Retrieval Surface:** `200 OK`, JSON `{"wing": string, "rooms": BTreeMap<String, usize>}`.
- **Durable Store:** Storage drawer count projections.
- **Idempotency & Receipts:** Naturally idempotent read.
- **Crash Recovery:** Live count aggregation.
- **Provenance Status:** N/A (structural metadata).

#### 17. `GET /v1/changes`
- **Operation Gate:** `read`.
- **Wing Authorization:** Category C (Aggregate). Filters out diary change events (`is_diary_change_event`) and filters events to `auth.visible_wings(Operation::Read)` via `change_event_visible`. Wingless system events pass through.
- **Demo Role Eligibility:** `readonly`, `write`, `admin`.
- **Request Surface:** `GET /v1/changes`, query parameters `ChangesQuery`:
  - `since`: Option<string> (RFC 3339 timestamp)
  - `limit`: Option<usize> (default 50, max 200)
  - `cursor`: Option<string> (opaque `"{rfc3339}|{rowid}"`)
- **Retrieval Surface:** `200 OK`, JSON `ChangesResponse`:
  - `events`: array of `ChangeEventDto` (`event_type`, `occurred_at`, `entity_id`, `actor`, `details`)
  - `next_cursor`: Option<string>
- **Durable Store:** SQLite operational store (`changes` table).
- **Idempotency & Receipts:** Naturally idempotent read.
- **Crash Recovery:** Ordered append-only log with cursor pagination.
- **Provenance Status:**
  - *Available now:* `ChangeEventDto::actor` reflects the acting token identity.
  - *Deferred to storage slice:* Attaching verified human `owner_id` to change events.

---

### Group 5: Ingestion and Checkout Preflight

#### 18. `POST /v1/ingest/preflight`
- **Operation Gate:** `ingest`.
- **Wing Authorization:** Category A (Body wing). Rejects diary wings with `422 Unprocessable Entity`. Checks `auth.allows_wing(Operation::Ingest, wing)` -> `403 Forbidden`.
- **Demo Role Eligibility:** `write`, `admin` (denied to `readonly`).
- **Request Surface:** `POST /v1/ingest/preflight`, JSON `IngestPreflightRequest` (16 MiB limit):
  - `wing`: string
  - `commit_hash`: Option<string>
  - `files`: array of `IngestPreflightFile` (`relative_path`, `file_hash`)
- **Retrieval Surface:** `200 OK`, JSON `IngestPreflightResponse`:
  - `checkout_commit`: Option<string>
- **Durable Store:** Filesystem checkouts configured in server settings (`state.config.server.checkouts`).
- **Idempotency & Receipts:** Naturally idempotent content-free verification.
- **Crash Recovery:** Pure read against filesystem checkouts.
- **Provenance Status:** Validates checkout integrity; stores no memories.

#### 19. `POST /v1/ingest/batch`
- **Operation Gate:** `ingest`.
- **Wing Authorization:** Category A (Body wing). Rejects diary wings and diary chunk rooms with `422 Unprocessable Entity`. Verifies `auth.allows_wing(Operation::Ingest, wing)` -> `403 Forbidden`.
- **Demo Role Eligibility:** `write`, `admin` (denied to `readonly`).
- **Request Surface:** `POST /v1/ingest/batch`, JSON `IngestBatchRequest` (16 MiB limit):
  - `replication`: Option<IngestReplicationIdentity> (`batch_id`, `record_id`, `remove`)
  - `wing`: string
  - `repo_id`: string
  - `agent`: Option<string> (claimed agent)
  - `commit_hash`: Option<string>
  - `files`: array of `IngestFileDto` (paths, hashes, byte ranges, chunk texts)
- **Retrieval Surface:** `200 OK`, JSON `IngestBatchResponse`:
  - `files`: array of `IngestFileResult` (`relative_path`, `status`, `drawers_written`, `error`)
  - `warnings`: array of strings
- **Durable Store:** LanceDB (embeddings and drawers), SQLite (`receipts`, `ingested_files`, `changes`), filesystem checkouts.
- **Idempotency & Receipts:**
  - Uses `replication.record_id` as operation ID.
  - Locks source key `projects:{wing}:{repo_id_hash}:{relative_path}` during execution.
  - Replay returns cached batch result. Conflict returns `409 Conflict`.
- **Crash Recovery:**
  - Recover checks SQLite `ingested_files` for matching committed content hash; if found, skips re-embedding and completes receipt safely.
- **Provenance Status:**
  - *Available now:* Drawer rows receive `added_by: {token_id}:{agent}`.
  - *Deferred to storage slice:* Distinguishing git repository author from submitting human owner and claimed ingest agent.

---

### Group 6: Coordination Tasks and Leases

#### 20. `POST /v1/coordination/tasks`
- **Operation Gate:** `coordination_write`.
- **Wing Authorization:** Category A (Body wing).
  - Wing normalized via `WingId::normalized`. Rejects `wing_agents` (`422 DiaryNotFederated`) and `wing_unscoped` (`422 UnscopedNotFederated`).
  - Checks `auth.allows_wing(Operation::CoordinationWrite, wing)` -> `403 Forbidden`.
  - Authorizes all `dependencies` and `parent_id` via `resolve_owning_task(CoordinationRead)` to prevent existence oracles.
- **Demo Role Eligibility:** `write`, `admin` (denied to `readonly`).
- **Request Surface:** `POST /v1/coordination/tasks`, JSON `NewTaskRequest`:
  - `title`: string
  - `description`: string
  - `wing`: string
  - `idempotency_key`: string
  - `created_by`: Option<string>
  - `parent_id`: Option<string>
  - `dependencies`: Vec<string>
  - `budget`: Option<Value>
  - `expires_at`: Option<string>
- **Retrieval Surface:** `200 OK`, JSON `CoordinationTaskDto` (`task_id`, `title`, `description`, `state: "pending"`, `revision: 1`, `created_by`, `wing`, etc.).
- **Durable Store:** SQLite operational store (`coordination_tasks`, `coordination_events`).
- **Idempotency & Receipts:**
  - Storage scopes `idempotency_key` to resolved `created_by` actor in index `(created_by, idempotency_key)`.
  - Replay returns existing task; re-authorizes wing storage used via `authorize_replay_wing`.
- **Crash Recovery:** Atomic SQLite transaction commits task and `task_created` event.
- **Provenance Status:**
  - *Available now:* `created_by` resolved to `{token_id}:{claimed_created_by}` or `{token_id}`.
  - *Deferred to storage slice:* Distinguishing human owner from agent executor.

#### 21. `GET /v1/coordination/tasks`
- **Operation Gate:** `coordination_read`.
- **Wing Authorization:** Category C (Aggregate). Filtered by `CoordinationReadScope` inside SQLite query (`scope.visibility()`); diary and invisible wings excluded.
- **Demo Role Eligibility:** `readonly`, `write`, `admin`.
- **Request Surface:** `GET /v1/coordination/tasks`, query parameters `CoordinationTasksQuery` (`cursor`, `wing`, `state`, `owner`, `created_by`, `parent_id`, `limit`, `byte_budget`).
- **Retrieval Surface:** `200 OK`, JSON `CoordinationTasksResponse`:
  - `tasks`: array of `CoordinationTaskListItem`
  - `next_cursor`: Option<string>
- **Durable Store:** SQLite operational store (`coordination_tasks`).
- **Idempotency & Receipts:** Naturally idempotent read.
- **Crash Recovery:** Cursor-paginated sequential read.
- **Provenance Status:** Items report `created_by` and `owner` strings.

#### 22. `GET /v1/coordination/tasks/{id}`
- **Operation Gate:** `coordination_read`.
- **Wing Authorization:** Category B (Lookup-then-authorize). Resolves task; returns `404 Not Found` if missing, if in a diary wing (`wing_agents`), or if caller lacks `CoordinationRead` on task's wing.
- **Demo Role Eligibility:** `readonly`, `write`, `admin`.
- **Request Surface:** `GET /v1/coordination/tasks/{id}`, path parameter `id`.
- **Retrieval Surface:** `200 OK`, JSON `CoordinationTaskDto`.
- **Durable Store:** SQLite operational store (`coordination_tasks`).
- **Idempotency & Receipts:** Naturally idempotent read.
- **Crash Recovery:** Read-only.
- **Provenance Status:** Reports `created_by`, `owner`, `executor_affinity` strings.

#### 23. `POST /v1/coordination/tasks/{id}/claim`
- **Operation Gate:** `coordination_claim`.
- **Wing Authorization:** Category B (Lookup-then-authorize). Verifies `CoordinationClaim` on task's wing -> `404 Not Found` on mismatch.
- **Demo Role Eligibility:** `write`, `admin` (denied to `readonly`).
- **Request Surface:** `POST /v1/coordination/tasks/{id}/claim`, JSON `TaskLeaseRequest`:
  - `expected_revision`: i64
  - `lease_seconds`: i64 (evaluated against server clock)
  - `worker`: Option<string>
- **Retrieval Surface:** `200 OK`, JSON `CoordinationTaskDto` (`state: "running"`, incremented `revision`, `lease_expires_at`, `owner`).
  - Errors: `404 Not Found`; `409 Conflict` on revision mismatch (`ServerError::RevisionConflict`).
- **Durable Store:** SQLite operational store (`coordination_tasks`, `coordination_events`).
- **Idempotency & Concurrency:** Compare-and-swap on `expected_revision`.
- **Crash Recovery:** Leases expire automatically by server clock; reclaiming expired lease follows same route.
- **Provenance Status:** Worker namespaced under `{token_id}:{worker}`.

#### 24. `POST /v1/coordination/tasks/{id}/renew`
- **Operation Gate:** `coordination_claim`.
- **Wing Authorization:** Category B (Lookup-then-authorize). Verifies `CoordinationClaim` on task wing.
- **Demo Role Eligibility:** `write`, `admin` (denied to `readonly`).
- **Request Surface:** `POST /v1/coordination/tasks/{id}/renew`, JSON `TaskLeaseRequest` (`expected_revision`, `lease_seconds`, `worker`).
- **Retrieval Surface:** `200 OK`, JSON `CoordinationTaskDto`.
- **Durable Store:** SQLite operational store (`coordination_tasks`, `coordination_events`).
- **Idempotency & Concurrency:** Compare-and-swap on `expected_revision`.
- **Crash Recovery:** Atomic SQLite update.
- **Provenance Status:** Worker namespaced under token.

#### 25. `POST /v1/coordination/tasks/{id}/transition`
- **Operation Gate:** `coordination_claim`.
- **Wing Authorization:** Category B (Lookup-then-authorize). Verifies `CoordinationClaim` on task wing.
- **Demo Role Eligibility:** `write`, `admin` (denied to `readonly`).
- **Request Surface:** `POST /v1/coordination/tasks/{id}/transition`, JSON `TransitionTaskRequest`:
  - `expected_revision`: i64
  - `state`: `CoordinationTaskState`
  - `actor`: Option<string>
  - `details`: Option<Value> (validates `checkpoint_handoff.executor` remains in caller token namespace)
- **Retrieval Surface:** `200 OK`, JSON `CoordinationTaskDto`.
- **Durable Store:** SQLite operational store (`coordination_tasks`, `coordination_events`).
- **Idempotency & Concurrency:** Compare-and-swap on `expected_revision`.
- **Crash Recovery:** Atomic SQLite update and `task_transitioned` event.
- **Provenance Status:** Acting identity namespaced; owner attribution deferred.

---

### Group 7: Coordination Messaging and Inbox

#### 26. `POST /v1/coordination/messages`
- **Operation Gate:** `coordination_write`.
- **Wing Authorization:** Category B (Lookup task to determine wing). Verifies `CoordinationWrite` on `task.wing` -> `404 Not Found` on mismatch.
- **Demo Role Eligibility:** `write`, `admin` (denied to `readonly`).
- **Request Surface:** `POST /v1/coordination/messages`, JSON `NewMessageRequest`:
  - `task_id`: string
  - `recipient`: string
  - `kind`: string
  - `payload`: Value
  - `idempotency_key`: string
  - `sender`: Option<string>
  - `envelope_version`: i64 (default 1)
- **Retrieval Surface:** `200 OK`, JSON `CoordinationMessageDto`.
- **Durable Store:** SQLite operational store (`coordination_messages`, `coordination_events`).
- **Idempotency & Receipts:**
  - Scoped to `(sender, idempotency_key)` in SQLite.
  - Replay returns original message and re-authorizes wing.
- **Crash Recovery:** Atomic SQLite transaction commits message and `message_sent` event.
- **Provenance Status:** Sender namespaced under `{token_id}:{sender}`.

#### 27. `GET /v1/coordination/messages/{id}`
- **Operation Gate:** `coordination_read`.
- **Wing Authorization:** Category B (Lookup message -> lookup task -> verify wing). `404 Not Found` if unauthorized or missing.
- **Demo Role Eligibility:** `readonly`, `write`, `admin`.
- **Request Surface:** `GET /v1/coordination/messages/{id}`, path parameter `id`.
- **Retrieval Surface:** `200 OK`, JSON `CoordinationMessageDto`.
- **Durable Store:** SQLite operational store (`coordination_messages`).
- **Idempotency & Receipts:** Naturally idempotent read.
- **Crash Recovery:** Read-only.
- **Provenance Status:** Reports sender and recipient strings.

#### 28. `POST /v1/coordination/messages/{id}/ack`
- **Operation Gate:** `coordination_write`.
- **Wing Authorization:** Category B (Lookup message -> lookup task -> verify wing).
- **Demo Role Eligibility:** `write`, `admin` (denied to `readonly`).
- **Request Surface:** `POST /v1/coordination/messages/{id}/ack`, JSON `AckMessageRequest` (`actor: Option<string>`).
- **Retrieval Surface:** `200 OK`, JSON `CoordinationMessageDto` with `acknowledged_at` and `acknowledged_by`.
- **Durable Store:** SQLite operational store (`coordination_messages`, `coordination_events`).
- **Idempotency & Receipts:** Storage enforces that resolved actor matches recipient. Idempotent if already acknowledged.
- **Crash Recovery:** Atomic SQLite update.
- **Provenance Status:** `acknowledged_by` namespaced under token.

#### 29. `GET /v1/coordination/inbox`
- **Operation Gate:** `coordination_read`.
- **Wing Authorization:** Category C (Aggregate).
  - Mandatory query param `recipient`.
  - Optional `wing`: if specified wing is invisible or diary, returns empty page (does not 403).
  - When `wing` omitted: SQL query filters by `CoordinationVisibility` to visible wings only.
- **Demo Role Eligibility:** `readonly`, `write`, `admin`.
- **Request Surface:** `GET /v1/coordination/inbox`, query parameters `InboxQuery` (`recipient`, `wing`, `cursor`, `limit`, `unacknowledged_only`).
- **Retrieval Surface:** `200 OK`, JSON `InboxPageResponse` (`messages: Vec<CoordinationMessageDto>`, `next_cursor`).
- **Durable Store:** SQLite operational store (`coordination_messages`).
- **Idempotency & Receipts:** Naturally idempotent read.
- **Crash Recovery:** Sequential cursor-paginated read.
- **Provenance Status:** Returns message envelopes with sender/recipient.

---

### Group 8: Coordination Artifacts, Results, and Audit Events

#### 30. `POST /v1/coordination/artifacts`
- **Operation Gate:** `coordination_write`.
- **Wing Authorization:** Category B (Lookup task to determine wing). Verifies `CoordinationWrite` on task wing.
- **Demo Role Eligibility:** `write`, `admin` (denied to `readonly`).
- **Request Surface:** `POST /v1/coordination/artifacts`, JSON `NewArtifactRequest`:
  - `task_id`: string
  - `role`: string
  - `media_type`: string
  - `content`: string
  - `idempotency_key`: string
  - `created_by`: Option<string>
- **Retrieval Surface:** `200 OK`, JSON `CoordinationArtifactDto` (`artifact_id`, `content_hash`, `created_at`, etc.).
- **Durable Store:** SQLite operational store (`coordination_artifacts`, `coordination_events`).
- **Idempotency & Receipts:**
  - `(created_by, idempotency_key)` uniqueness in SQLite.
  - Replay returns existing artifact; re-authorizes wing.
- **Crash Recovery:** Atomic SQLite commit.
- **Provenance Status:** `created_by` namespaced under token; content addressed via BLAKE3 hash.

#### 31. `GET /v1/coordination/artifacts/{id}`
- **Operation Gate:** `coordination_read`.
- **Wing Authorization:** Category B (Lookup artifact -> lookup task -> verify wing). `404 Not Found` if unauthorized or missing.
- **Demo Role Eligibility:** `readonly`, `write`, `admin`.
- **Request Surface:** `GET /v1/coordination/artifacts/{id}`, path parameter `id`.
- **Retrieval Surface:** `200 OK`, JSON `CoordinationArtifactDto`.
- **Durable Store:** SQLite operational store (`coordination_artifacts`).
- **Idempotency & Receipts:** Naturally idempotent read.
- **Crash Recovery:** Read-only.
- **Provenance Status:** Immutable artifact content and content hash.

#### 32. `POST /v1/coordination/results`
- **Operation Gate:** `coordination_write`.
- **Wing Authorization:** Category B (Lookup task to determine wing). Verifies `CoordinationWrite` on task wing.
- **Demo Role Eligibility:** `write`, `admin` (denied to `readonly`).
- **Request Surface:** `POST /v1/coordination/results`, JSON `NewTaskResultRequest`:
  - `task_id`: string
  - `payload`: Value
  - `idempotency_key`: string
  - `created_by`: Option<string>
- **Retrieval Surface:** `200 OK`, JSON `CoordinationTaskResultDto` (`result_id`, `task_id`, `created_by`, `payload`, `created_at`).
- **Durable Store:** SQLite operational store (`coordination_task_results`, `coordination_events`).
- **Idempotency & Receipts:**
  - `(created_by, idempotency_key)` uniqueness in SQLite.
  - Replay returns existing result; re-authorizes wing.
- **Crash Recovery:** Atomic SQLite commit.
- **Provenance Status:** Creator namespaced under token.

#### 33. `GET /v1/coordination/results/{id}`
- **Operation Gate:** `coordination_read`.
- **Wing Authorization:** Category B (Lookup result -> lookup task -> verify wing). `404 Not Found` if unauthorized or missing.
- **Demo Role Eligibility:** `readonly`, `write`, `admin`.
- **Request Surface:** `GET /v1/coordination/results/{id}`, path parameter `id`.
- **Retrieval Surface:** `200 OK`, JSON `CoordinationTaskResultDto`.
- **Durable Store:** SQLite operational store (`coordination_task_results`).
- **Idempotency & Receipts:** Naturally idempotent read.
- **Crash Recovery:** Read-only.
- **Provenance Status:** Result payload with creator identity.

#### 34. `GET /v1/coordination/events`
- **Operation Gate:** `coordination_read`.
- **Wing Authorization:** Category C (Aggregate). Filtered by `CoordinationReadScope` inside SQLite query (`scope.visibility()`). Diary and invisible wings excluded.
- **Demo Role Eligibility:** `readonly`, `write`, `admin`.
- **Request Surface:** `GET /v1/coordination/events`, query parameters `CoordinationEventsQuery`:
  - `cursor`: Option<string> (opaque sequence cursor)
  - `task_id`: Option<string>
  - `wing`: Option<string>
  - `limit`: Option<usize> (default 50, max 200)
- **Retrieval Surface:** `200 OK`, JSON `CoordinationEventsResponse`:
  - `events`: array of `CoordinationEventDto` (`sequence`, `event_id`, `entity_type`, `entity_id`, `task_id`, `wing`, `event_type`, `actor`, `from_state`, `to_state`, `revision`, `details`, `occurred_at`)
  - `next_cursor`: Option<string>
- **Durable Store:** SQLite operational store (`coordination_events`).
- **Idempotency & Receipts:** Naturally idempotent read.
- **Crash Recovery:** Monotonically increasing sequence log.
- **Provenance Status:**
  - *Available now:* `CoordinationEventDto::actor` records namespaced acting identity.
  - *Deferred to storage slice:* Attaching verified human `owner_id` to event records.

---

## 5. Provenance Implementation Contract for Downstream Slices

### 5.1 The Transition from Composite Strings to Structured Owner Envelope

Current engine versions represent caller identity by formatting a composite string:
```
{token_identity}:{claimed_agent}
```
While this foundation prevents unauthenticated impersonation across tokens, a composite string cannot distinguish an authenticated Google account from an arbitrary service token, nor does it retain immutable account identifiers across email renames.

Under the Demo Hub design:
1. **Authenticated Owner Record:** The server associates each active token entry with an optional, validated, provider-neutral owner metadata record:
   ```json
   {
     "owner": {
       "id": "usr_01J8Y...",
       "issuer": "https://accounts.google.com",
       "subject": "104928190283019283019",
       "email_at_write": "tester@example.com"
     }
   }
   ```
2. **Never Trust Owner from Request Body:** The client LLM or harness is never permitted to establish, override, or suggest authenticated ownership through `owner` fields. Existing production federation REST DTOs omit client-writable `owner` fields entirely; under their current serde compatibility behavior, an extra `owner` field is ignored rather than used to establish ownership. Where a mutation handler or ingest path explicitly opts into checking an untyped or extended payload, the `reject_payload_owner_claim` helper rejects a supplied owner claim with `invalid_provenance`. In both cases, ownership comes only from server-validated authentication context.
3. **Legacy Preservation:** Standard static tokens without owner metadata continue to function identically to legacy installations. Ownership is marked explicitly as unknown (`None`), never fabricated.
4. **Stable Owner Identity Across Rotation:** `owner.id` is the immutable internal human-owner identifier. Rotating a token, changing its secret or display name, or refreshing `email_at_write` does not create a new owner. Loading a token file rejects different owner IDs for the same (issuer, subject) across entries, including disabled entries; malformed hot reloads disable all tokens until corrected. The `(issuer, subject)` binding identifies the provider account; `email_at_write` is an audit snapshot and is never the stable identity key.
5. **Explicit Legacy and Unknown Ownership:** A token without owner metadata remains ownerless and resolves to the explicit `Unknown`/legacy representation. The server never infers an owner from a caller label, source author, token name, or email. Unknown values remain distinguishable from authenticated owners on the wire and in storage.
6. **Owner-Scoped Idempotency and Receipts:** The downstream storage slice must update receipt and idempotency indices so deduplication keys are scoped to `(owner_id, operation_id)` or `(owner_id, created_by, idempotency_key)`. Unknown/legacy operations use the legacy scope and must not collide with authenticated-owner keys. A replay or recovery may return only the receipt and resource associated with that same owner scope; it must not adopt a later submitter as the creator.

### 5.2 Shared Engine Provenance Value Types (`agentpalace-core::provenance`)

Implemented in `crates/agentpalace-core/src/provenance.rs`, the engine provides provider-neutral domain types with bounded validation and explicit wire semantics:

| Type | Bounds & Character Rules | Wire Representation / Notes |
|---|---|---|
| `OwnerId` | 1–128 bytes; ASCII alphanumeric, `_`, `-`, `.`; rejects reserved sentinels (`legacy`, `unknown`, `none`, `null`) | Transparent string (e.g. `"usr_01J8Y..."`). Immutable across rotation. Guaranteed collision-free with legacy scopes. |
| `Issuer` | 1–256 bytes; printable ASCII (no whitespace or control chars); does not enforce URI syntax or reject sentinels | Transparent string (e.g. `"https://accounts.google.com"`). |
| `Subject` | 1–256 bytes; printable ASCII (no whitespace or control chars) | Transparent string (e.g. `"104928190283019283019"`). Provider account identifier. |
| `SubjectBinding` | Holds `(Issuer, Subject)` | Structured JSON: `{ "issuer": "...", "subject": "..." }`. Binds provider issuer and subject. |
| `EmailAtWrite` | 3–254 bytes; basic bounded check with one `@` surrounded by non-empty local-part and domain; no ASCII whitespace or control chars. This is not full RFC 5321 validation. | Transparent string (e.g. `"tester@example.com"`). Advisory audit trace, non-authoritative. |
| `OwnerMetadata` | Validated bundle of `(OwnerId, Issuer, Subject, EmailAtWrite)` | Structured JSON object. Validates internal consistency. `OwnerId` is stable across credential rotation; `EmailAtWrite` is an audit snapshot, not an identity key. |
| `AuthenticatedOwner` | Direct representation of authenticated owner | Structured JSON: `{ "id": "...", "issuer": "...", "subject": "...", "email_at_write": "..." }`. Optional `"status": "authenticated"` wire tag supported with fail-closed validation. |
| `LegacyUnknownOwner` | Unit struct sentinel representing absence of owner metadata | In-memory type marker; does not serialize as tagged JSON objects (defaults to null/unit). |
| `OwnerIdentity` | Enum: `Unknown` \| `Authenticated(AuthenticatedOwner)` (legacy wire inputs normalize to `Unknown`) | Serializes `Unknown` as `{ "status": "unknown" }`, `Authenticated` as bare authenticated object. Deserializes `null`, `"unknown"`, `"legacy"`, `{ "status": "unknown" }`, `{ "status": "legacy" }`, bare authenticated, or `{ "status": "authenticated", ... }`. Fail-closed validation on unrecognized status or unauthenticated claims. |
| `AgentName` | 1–128 bytes; ASCII alphanumeric, `_`, `-`, `.`, `/`, `:` | Transparent string (e.g. `"codex"`, `"agy"`). |
| `AgentAssurance` | Enum: `CallerAsserted` | Wire string `"caller_asserted"`. |
| `AgentAttribution` | `agent_name` + `assurance` | Wire JSON: `{ "agent_name": "codex", "assurance": "caller_asserted" }`. |
| `SourceAuthor` | 1–256 bytes; non-empty, trimmed, no ASCII control chars | Transparent string (e.g. `"Alice <alice@example.com>"`). Separate from submitting owner. |
| `SourceReference` | 1–2048 bytes; non-empty, trimmed, no ASCII control chars | Transparent string (e.g. `"crates/agentpalace-core/src/lib.rs"`). Max 128 references per envelope. |
| `StorageOrigin` | Enum: `Local(LocalOrigin)` \| `Federated(FederatedOrigin)` | Tagged wire JSON: `{ "kind": "local", "origin_id": "..." }` or `{ "kind": "federated", "origin_id": "...", "original_record_id": "..." }`. Sealed variant data (`LocalOrigin`, `FederatedOrigin`) with private fields; validated constructors (`local`, `federated`, `local_default`) and read-only accessors (`origin_id`, `original_record_id`, `is_local`, `is_federated`, `as_local`, `as_federated`). |
| `RecordingTime` | Wrapped UTC `OffsetDateTime`, max 64 chars RFC 3339, strictly bounded to RFC 3339 representable UTC range (year `0000..=9999`) | Formatted RFC 3339 UTC string (e.g. `"2026-09-17T11:04:27Z"`). Construction enforces UTC normalization and RFC 3339 range; formatting and serialization explicitly propagate errors without silent Unix-epoch fallback. |
| `OwnerScopedKey` | Holds `(Option<OwnerId>, raw_key)` (raw key max 128 chars, non-empty, trimmed) | Scoped storage key `"{owner_id}:{raw_key}"` or `"legacy:{raw_key}"`. Sealed components with private fields; validated constructors (`new`, `from_str`, `with_owner_id`) and read-only accessors (`owner_id`, `raw_key`, `composite_key`, `is_authenticated`, `is_legacy`). Unambiguous and collision-free due to reserved sentinel owner IDs. Fail-closed Visitor deserialization rejects unknown or misspelled fields. |
| `ProvenanceEnvelope` | Full top-level metadata envelope | Unites owner, actor, recorded_at, origin, operation_id (`Option<OwnerScopedKey>`), source_author, and source_refs (max 128). Enforces owner-scoping alignment, sealed constructor invocation, and boundary validation on both serialization and deserialization. |

#### Invariants Enforced by Construction

1. **Server-Assigned Provenance & Unauthenticated Owner Rejection Helper Contract:** Authenticated owner provenance is established exclusively by the server from token configuration (`OwnerMetadata` on `TokenEntry`) and carried into `AuthIdentity` / `AuthenticatedOwnerContext`. Existing production federation REST routes do not expose client-writable owner fields on request DTOs (`AddDrawerRequest`, `NewTaskRequest`, etc.); extra JSON fields such as `owner` are currently ignored for legacy compatibility and cannot establish ownership. Caller-asserted agent parameters (`added_by`, `sender`, etc.) likewise cannot override or manufacture ownership. For mutation handlers and future storage-slice ingest processing untyped or extended payloads, the `reject_payload_owner_claim` helper contract provides an explicit check to reject caller-asserted owner fields with `ProvenanceError::UnauthenticatedOwnerClaim`, mapping to HTTP 400 Bad Request (`invalid_provenance`). Durable owner-scoped persistence and receipts remain deferred to issue #161; this issue implements the validated foundation and context propagation.
2. **Validating Deserialization (Unbypassable):** All domain value types (`OwnerId`, `Issuer`, `Subject`, `EmailAtWrite`, `AgentName`, `SourceAuthor`, `SourceReference`, `StorageOrigin`, `OwnerScopedKey`, `ProvenanceEnvelope`) implement validating Serde deserialization. Malformed, whitespace-only, or oversized wire inputs cannot bypass domain constructors.
3. **Owner-Scoped Operation Identity:** `ProvenanceEnvelope::operation_id` uses the validated `OwnerScopedKey` type. The builder `with_operation_id` normalizes non-empty raw keys and automatically binds them to the envelope's owner. Deserialization validates that any explicit `operation_id.owner_id` strictly matches the envelope's `owner`.
4. **First-Class Unknown Representation:** Legacy installations without owner metadata explicitly serialize as `{ "status": "unknown" }` or deserialize from `null` without fabricating identities. Deserialization uses provider-neutral Serde visitors/helpers without runtime dependencies on format-specific libraries in core domain logic.
5. **Boundary Separation:** Evidence status (claim truth) and execution authority (roles/permissions) remain outside these types, preserving issue #157 separation.
6. **Collision-Resistant Owner Scoping:** Sentinel identifiers (`legacy`, `unknown`, `none`, `null`) are strictly reserved and rejected by `validate_owner_id`. This guarantees that `OwnerScopedKey::composite_key()` never produces colliding keys between authenticated owners and legacy/unknown scopes.
7. **Strict Recording Time Boundaries:** `RecordingTime` enforces that only RFC 3339-representable UTC timestamps (calendar years `0000..=9999`) can be constructed. Construction via `from_offset_date_time` or `from_rfc3339` rejects out-of-range timestamps and non-representable offset shifts. Serialization and formatting propagate errors explicitly, preventing silent fallback to the Unix epoch (1970-01-01).
8. **Sealed Provenance Value Types & Persistence Boundary Validation:** `StorageOrigin` variant data and `OwnerScopedKey` components are sealed behind private fields, preventing unchecked external construction. All deserialization and envelope-building paths must use validated constructors. Fail-closed Serde parsing (`deny_unknown_fields`) with presence-aware status validation rejects unknown or misspelled fields, explicit null status values, and unauthenticated/contradictory claims across all provenance DTOs and wire helpers (`AuthenticatedOwner`, `OwnerIdentity`, `OwnerScopedKey`, `StorageOrigin`, `SubjectBinding`, `AgentAttribution`, `ProvenanceEnvelope`). Persistence boundaries enforce unbypassable validation (`validate(&self)` checked upon envelope serialization and deserialization).
9. **Private Server Token Entry Owner Metadata & Request Context Propagation:** Private server token-file entries (`server_tokens.json`) support optional provider-neutral `OwnerMetadata` containing the immutable internal owner ID, issuer, subject, and email-at-write. Initial load and hot reload enforce fail-closed parsing (`deny_unknown_fields` at both token entry and owner metadata levels) and validate owner fields through core domain types. Tokens omitting `owner` or providing explicit `null` retain unchanged legacy static-token behavior, resolving to `OwnerIdentity::Unknown`. Authenticated tokens carry validated owner metadata into `AuthIdentity` with focused public accessors (`name()`, `is_unrestricted()`, `owner()`, `owner_identity()`, `owner_id()`, `has_owner()`, `issuer()`, `subject()`, `email_at_write()`, `subject_binding()`, `owner_scoped_key()`) while keeping the `TokenScopeEntry` type module-private and keeping `AuthIdentity::new` and `AuthIdentity::scopes` crate-private (`pub(crate)`), eliminating `private_interfaces` diagnostics. The authentication middleware inserts the coherent `AuthenticatedOwnerContext` and underlying `AuthIdentity` directly into request extensions. Handlers extract `AuthenticatedOwnerContext` via its Axum `FromRequestParts` extractor, which retrieves the coherent middleware-inserted context or derives all fields exclusively from `AuthIdentity` (`from_identity`), strictly ignoring uncoordinated or contradictory standalone extensions and preventing cross-contamination between different owner identities. Caller-asserted agent parameters (`added_by`, `created_by`, `sender`, `actor`, `worker`) remain strictly namespaced against the display name (`{identity}:{claimed}`) and cannot alter, override, or manufacture authenticated ownership. To ensure callers cannot manufacture or override authenticated ownership in writable payloads, the `reject_payload_owner_claim` helper contract enables mutation handlers to reject caller-supplied owner claims, mapping `ProvenanceError::UnauthenticatedOwnerClaim` to HTTP 400 Bad Request (`invalid_provenance`). Production federation request DTOs strictly adhere to this separation by omitting client-writable authenticated owner fields, deferring durable storage attribution to the storage slice.

---

## 6. Document Revision and Verification History

- **2026-09-18:** Version 1.1.15 corrects the Issue #161 reconciliation matrix against the audited schemas: KG uses `knowledge_graph_facts`, results use `coordination_results`, and drawer deletion removes the LanceDB row while recovery uses `mutation_receipts` and `change_log`; proposed #161 additions are identified separately from current stores.
- **2026-09-18:** Version 1.1.14 adds the Issue #161 reconciliation matrix, pairing every approved remote mutation with its retrieval/search surfaces, actual store, owner/history boundary, receipt/recovery invariant, and explicit legacy behavior. It preserves the exclusions for diaries, MCP-only operations, and coordination delegation/telemetry, and does not claim the deferred durable storage slice is implemented.
- **2026-09-18:** Version 1.1.13 corrects the earlier explicit-registration-only count to include 17 implicit HEAD operations (51 method/path pairs), aligns search/content/KG limits and defaults with server constants, and validates consistent owner IDs for subject bindings across token entries. Earlier dated audit counts remain historical evidence.
- **2026-09-17:** Version 1.1.12 reconfirmed all 34 production method/path registrations against the route table, including POST search, writes, KG invalidation, deletion, both ingest routes, and every coordination read/write/claim operation. Added the privilege/store/receipt-recovery count ledger and an explicit provenance retrieval crosswalk. Reconfirmed that local diaries, MCP-only operations, and test routes are excluded, unlisted routes remain fail-closed, and durable human-owner attribution remains deferred to the storage slice.
- **2026-09-17:** Version 1.1.11 pre-publication static verification for Issue #160. Reviewed the complete retained diff against `origin/main` for production-path coverage, test coverage, documentation consistency, dependency changes, provenance claims, formatting artifacts, and merge-conflict markers. Confirmed the router inventory still covers all 34 production method/path registrations and that no Cargo manifest or lockfile changes were introduced. `git diff --check` and targeted source/document searches passed. Compilation, Rust tests, `rustfmt`, and Clippy were not run because Rust commands are disabled by VM policy; GitHub CI remains the required authority for those checks. This evidence does not claim durable attribution is complete; that remains deferred to the storage slice, and issue #157 remains open.
- **2026-09-17:** Version 1.1.10 updated for Issue #160. Reconciled provenance terminology and visibility with the implementation: the `TokenScopeEntry` type is module-private, while `AuthIdentity::new` and `AuthIdentity::scopes` are crate-private. Clarified immutable creator versus later submitters/modifiers, source attribution versus authenticated ownership, explicit legacy/unknown ownership, stable owner identity across credential rotation, and owner-scoped receipt/recovery behavior. Preserved implementation-accurate wire representations, validation limits, the complete 34-route inventory, and the statement that durable attribution remains deferred to the storage slice.
- **2026-09-17:** Version 1.1.9 updated for Issue #160. Audited the 34 production method/path registrations in `build_router`, explicitly excluded test-only routes, `/mcp`, local-only diaries, and MCP-only operations, and documented that every numbered route retains privilege, durable store, idempotency/receipt behavior, recovery invariant, and provenance retrieval status. Unlisted method/path pairs remain outside the demo allowlist and fail closed.
- **2026-09-17:** Version 1.1.8 updated for Issue #160. Reconciled published contract and implementation:
  - Ensured `AuthenticatedOwnerContext::from_request_parts` extracts the coherent middleware-inserted `AuthenticatedOwnerContext` or derives all fields exclusively from `AuthIdentity`, preventing mismatched request extensions from cross-contaminating owner identities.
  - Added regression test suite (`mismatched_extensions_cannot_cross_contaminate_owner_context`) verifying mutual consistency across multi-owner contradictory extensions and legacy static tokens.
  - Kept the internal `TokenScopeEntry` structure module-private and restricted `AuthIdentity::new` and `AuthIdentity::scopes` to crate-private (`pub(crate)`), resolving the `private_interfaces` compiler diagnostic while preserving public owner accessors.
  - Retained all 34 supported remote REST routes, permissions, durable stores, receipts/idempotency invariants, crash/recovery rules, and provenance retrieval paths, preserving the strict allowlist and exclusions for local-only diaries and MCP-only operations without claiming durable storage attribution before the storage slice lands.
- **2026-09-17:** Version 1.1.7 updated for Issue #160. Completed authenticated ownership context propagation across `agentpalace-server`: consolidated public core imports, provided focused accessors on `AuthIdentity` (`scopes`, `issuer`, `subject`, `email_at_write`, `subject_binding`, `owner_scoped_key`), introduced first-class `AuthenticatedOwnerContext` extractor with `Deref<Target = AuthIdentity>` and `FromRequestParts` implementations, mapped `ProvenanceError` to `ServerError::Provenance` (HTTP 400 `invalid_provenance`), verified that caller-asserted agent attribution cannot compromise or manufacture server-established `OwnerIdentity`, narrowed documentation and test claims to the `reject_payload_owner_claim` helper contract, verified tamper-resistance across both production endpoints and helper contract validation, and restored implementation-accurate bounds and wire representations in Section 5.2 domain types table (`Issuer` 256-byte ASCII graphic, `Subject` 256-byte ASCII graphic, `EmailAtWrite` 254-byte basic bounded syntax check rather than full RFC 5321 validation, `SubjectBinding` `{ "issuer", "subject" }` JSON object, `LegacyUnknownOwner` in-memory sentinel marker, and `OwnerIdentity` binary enum with legacy wire normalization to `Unknown`).
- **2026-09-17:** Version 1.1.6 updated for Issue #160. Extended private server token-file entries (`TokenEntry`) with optional provider-neutral `OwnerMetadata` containing the immutable internal owner ID, issuer, subject, and email-at-write. Enforced fail-closed validation on initial load and hot reload across both entry and owner metadata boundaries, rejecting unknown or malformed fields. Preserved unchanged behavior for ordinary static tokens (omitted or null `owner` resolves to `OwnerIdentity::Unknown`). Widened `AuthIdentity` and `auth_middleware` to propagate authenticated owner context into request extensions. Added exhaustive unit and reload test coverage.
- **2026-09-17:** Version 1.1.5 updated for Issue #160. Hardened `OwnerIdentity`, `AuthenticatedOwner`, and `OwnerScopedKey` deserialization to fail-closed against unknown and misspelled fields using direct Serde Visitors and `deny_unknown_fields` wire helpers. Implemented presence-aware status validation to distinguish absent status (bare authenticated representation) from explicit `null` status (rejected fail-closed as malformed across `AuthenticatedOwner`, `OwnerMetadata`, and `OwnerIdentity`). Preserved all documented compatible wire formats (null, legacy, unknown, bare authenticated, and explicitly authenticated) while rejecting incomplete, contradictory, spoofed, or malformed identities.
- **2026-09-17:** Version 1.1.4 updated for Issue #160. Sealed `StorageOrigin` variant data (`LocalOrigin`, `FederatedOrigin`) and `OwnerScopedKey` components behind private fields with read-only accessors; enforced validated constructors across all deserialization and envelope-building paths; added fail-closed parsing against unknown/misspelled fields; and instituted persistence-facing boundary validation on `ProvenanceEnvelope` serialization and deserialization.
- **2026-09-17:** Version 1.1.3 updated for Issue #160. Hardened `RecordingTime` construction and serialization: enforced invariant that only RFC 3339-representable UTC values (year `0000..=9999`) can be constructed, eliminated silent Unix-epoch fallback in favor of explicit error propagation, and added boundary test coverage.
- **2026-09-17:** Version 1.1.2 updated for Issue #160. Hardened `OwnerIdentity` deserialization to fail-closed against unknown status values and contradictory object shapes; reserved sentinel owner IDs (`legacy`, `unknown`, `none`, `null`) to guarantee collision-free `OwnerScopedKey::composite_key()` storage indexing; removed `serde_json` from non-test crate dependencies; added exhaustive negative and collision unit tests.
- **2026-09-17:** Version 1.1.1 updated for Issue #160. Added validating Serde deserialization across all domain types, enforced owner-scoped operation ID contracts on `ProvenanceEnvelope`, added negative wire-format test coverage, and eliminated library runtime dependencies on `serde_json`.
- **2026-09-17:** Version 1.1.0 updated for Issue #160. Added §5.2 defining shared engine provenance value types in `crates/agentpalace-core/src/provenance.rs`.
- **2026-09-17:** Version 1.0.0 published for Issue #160. Verified against `crates/agentpalace-server/src/lib.rs` (34 method/path pairs), `crates/agentpalace-federation/src/lib.rs` (wire DTOs), and `docs/Demo-Hub-Design.md`.
