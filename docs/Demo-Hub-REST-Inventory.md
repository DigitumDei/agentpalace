# Demo Hub: Canonical Remote REST Inventory and Implementation Contract

**Document Version:** 1.0.0  
**Release Series:** 0.2.0 (`release/version.toml`)  
**Federation API Version:** 1 (`agentpalace_federation::FEDERATION_API_VERSION`)  
**Status:** Approved Implementation Contract for AgentPalace #160 (parent issue #159)  
**Date:** 2026-09-17  
**Authoritative Sources:** `crates/agentpalace-server/src/lib.rs`, `crates/agentpalace-federation/src/lib.rs`, `docs/Demo-Hub-Design.md`

---

## 1. Executive Summary and Scope Boundaries

This document defines the canonical inventory of all remote REST operations exposed by `agentpalace-server`. It forms the authoritative implementation contract for the Demo Hub (AgentPalace #159 / #160) and subsequent implementation slices.

### 1.1 Strict Allowlist and Fail-Closed Policy

The remote REST routes enumerated in this document constitute the **complete, closed allowlist** of remote operations supported by the AgentPalace server.
- **Fail-closed rule:** Any HTTP method, path, or operation not explicitly listed in this inventory is **not demo-enabled** and must be rejected with `404 Not Found` or `403 Forbidden`.
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

In accordance with `docs/Demo-Hub-Design.md` and issue #157, the Demo Hub enforces strict separation between five distinct provenance dimensions:
1. **Authenticated Human Owner:** The verified account holder identity established at authentication time (`owner.id`, `issuer`, `subject`, `email_at_write`). This is derived exclusively from server-validated credential context and **never** accepted from writable request payload fields.
2. **Caller-Asserted Agent:** The agent or harness identity claimed in request payloads (`added_by`, `created_by`, `sender`, `worker`, `actor`). When this claim differs from the authenticated identity, the server namespaces the claim as `{identity}:{claimed}`.
3. **Original Source Author & References:** File paths, repository commits, and external citations associated with ingested content.
4. **Execution Authority & Ceilings:** The effective role (`readonly`, `write`, `admin`) restricting which operations a caller may execute.
5. **Evidence & Truth Status:** Provenance records attribution only; it does not attest that a claim is true, nor does it grant permission for an autonomous agent to execute instructions embedded in a stored memory.

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

## 3. Master Inventory Summary Table (34 Routes)

The table below catalogs every current method/path pair registered in `build_router` (`crates/agentpalace-server/src/lib.rs`):

| # | Method | Path | Token Operation | Auth Category | Demo Roles | Durable Store(s) | Idempotency / Receipt Key | Provenance Status |
|---|---|---|---|---|---|---|---|---|
| 1 | `GET` | `/v1/health` | None | Public | All (public) | In-memory | Naturally idempotent | N/A (unauthenticated) |
| 2 | `GET` | `/v1/info` | None (auth only) | D (Server-wide) | `readonly`, `write`, `admin` | In-memory / Config | Naturally idempotent | Available now |
| 3 | `POST` | `/v1/drawers/search` | `read` | A/C (Hybrid) | `readonly`, `write`, `admin` | LanceDB + Storage | Naturally idempotent | Gap: `added_by` omitted |
| 4 | `POST` | `/v1/drawers/check_duplicate` | `read` | C (Aggregate) | `readonly`, `write`, `admin` | LanceDB | Naturally idempotent | Available now |
| 5 | `POST` | `/v1/drawers` | `write` | A (Body wing) | `write`, `admin` | LanceDB + SQLite | `operation_id` (receipt) | Available now / storage deferred |
| 6 | `GET` | `/v1/drawers` | `read` | A/C (Hybrid) | `readonly`, `write`, `admin` | LanceDB / Storage | Naturally idempotent | Available now (`added_by`) |
| 7 | `GET` | `/v1/drawers/{id}` | `read` | B (Lookup 404) | `readonly`, `write`, `admin` | LanceDB / Storage | Naturally idempotent | Available now (`added_by`) |
| 8 | `DELETE` | `/v1/drawers/{id}` | `delete` | B (Lookup 404) | `admin` | LanceDB + SQLite | `operation_id` (receipt) | Tombstone deferred |
| 9 | `POST` | `/v1/kg/query` | `read` | D (Server-wide) | `readonly`, `write`, `admin` | SQLite (`kg_facts`) | Naturally idempotent | No owner envelope |
| 10 | `POST` | `/v1/kg/facts` | `write` | D (Server-wide) | `write`, `admin` | SQLite (`kg_facts`, receipts) | `operation_id` / triple dedupe | Actor in change log only |
| 11 | `POST` | `/v1/kg/facts/invalidate` | `write` | D (Server-wide) | `write`, `admin` | SQLite (`kg_facts`, receipts) | `operation_id` / serial lock | Actor in change log only |
| 12 | `GET` | `/v1/kg/timeline` | `read` | D (Server-wide) | `readonly`, `write`, `admin` | SQLite (`kg_facts`) | Naturally idempotent | No owner envelope |
| 13 | `GET` | `/v1/kg/stats` | `read` | D (Server-wide) | `readonly`, `write`, `admin` | SQLite (`kg_facts`) | Naturally idempotent | N/A (aggregate stats) |
| 14 | `GET` | `/v1/taxonomy` | `read` | C (Aggregate) | `readonly`, `write`, `admin` | Storage count stream | Naturally idempotent | N/A (structural counts) |
| 15 | `GET` | `/v1/wings` | `read` | C (Aggregate) | `readonly`, `write`, `admin` | Storage count stream | Naturally idempotent | N/A (structural counts) |
| 16 | `GET` | `/v1/rooms` | `read` | C (Aggregate) | `readonly`, `write`, `admin` | Storage count stream | Naturally idempotent | N/A (structural counts) |
| 17 | `GET` | `/v1/changes` | `read` | C (Aggregate) | `readonly`, `write`, `admin` | SQLite (`changes`) | Naturally idempotent | `actor` in event DTO |
| 18 | `POST` | `/v1/ingest/preflight` | `ingest` | A (Body wing) | `write`, `admin` | Filesystem checkouts | Naturally idempotent | Content-free hash check |
| 19 | `POST` | `/v1/ingest/batch` | `ingest` | A (Body wing) | `write`, `admin` | LanceDB + SQLite + Filesystem | `record_id` (source lock) | Available now / storage deferred |
| 20 | `POST` | `/v1/coordination/tasks` | `coordination_write` | A (Body wing) | `write`, `admin` | SQLite (`coordination_tasks`) | `(created_by, idempotency_key)` | Available now / storage deferred |
| 21 | `GET` | `/v1/coordination/tasks` | `coordination_read` | C (Aggregate) | `readonly`, `write`, `admin` | SQLite (`coordination_tasks`) | Naturally idempotent | `created_by`, `owner` |
| 22 | `GET` | `/v1/coordination/tasks/{id}` | `coordination_read` | B (Lookup 404) | `readonly`, `write`, `admin` | SQLite (`coordination_tasks`) | Naturally idempotent | `created_by`, `owner` |
| 23 | `POST` | `/v1/coordination/tasks/{id}/claim` | `coordination_claim` | B (Lookup 404) | `write`, `admin` | SQLite (`coordination_tasks`) | `expected_revision` CAS | Worker namespaced |
| 24 | `POST` | `/v1/coordination/tasks/{id}/renew` | `coordination_claim` | B (Lookup 404) | `write`, `admin` | SQLite (`coordination_tasks`) | `expected_revision` CAS | Worker namespaced |
| 25 | `POST` | `/v1/coordination/tasks/{id}/transition` | `coordination_claim` | B (Lookup 404) | `write`, `admin` | SQLite (`coordination_tasks`) | `expected_revision` CAS | Actor namespaced |
| 26 | `POST` | `/v1/coordination/messages` | `coordination_write` | B (Task wing) | `write`, `admin` | SQLite (`coordination_messages`) | `(sender, idempotency_key)` | Sender namespaced |
| 27 | `GET` | `/v1/coordination/messages/{id}` | `coordination_read` | B (Task wing) | `readonly`, `write`, `admin` | SQLite (`coordination_messages`) | Naturally idempotent | Sender / recipient |
| 28 | `POST` | `/v1/coordination/messages/{id}/ack` | `coordination_write` | B (Task wing) | `write`, `admin` | SQLite (`coordination_messages`) | Recipient match check | Actor namespaced |
| 29 | `GET` | `/v1/coordination/inbox` | `coordination_read` | C (Aggregate) | `readonly`, `write`, `admin` | SQLite (`coordination_messages`) | Naturally idempotent | Sender / recipient |
| 30 | `POST` | `/v1/coordination/artifacts` | `coordination_write` | B (Task wing) | `write`, `admin` | SQLite (`coordination_artifacts`) | `(created_by, idempotency_key)` | Creator namespaced |
| 31 | `GET` | `/v1/coordination/artifacts/{id}` | `coordination_read` | B (Task wing) | `readonly`, `write`, `admin` | SQLite (`coordination_artifacts`) | Naturally idempotent | Content hash + creator |
| 32 | `POST` | `/v1/coordination/results` | `coordination_write` | B (Task wing) | `write`, `admin` | SQLite (`coordination_task_results`) | `(created_by, idempotency_key)` | Creator namespaced |
| 33 | `GET` | `/v1/coordination/results/{id}` | `coordination_read` | B (Task wing) | `readonly`, `write`, `admin` | SQLite (`coordination_task_results`) | Naturally idempotent | Creator namespaced |
| 34 | `GET` | `/v1/coordination/events` | `coordination_read` | C (Aggregate) | `readonly`, `write`, `admin` | SQLite (`coordination_events`) | Naturally idempotent | `actor` in event DTO |

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
  - `query`: string (mandatory, max 8,192 bytes)
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
  - `content`: string (mandatory, max 128 KiB)
  - `threshold`: Option<f32> (default `0.87`)
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
  - `content`: string (max 128 KiB)
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
  - *Deferred to storage slice:* Validated `owner` metadata on token entry; durable persistence of human `owner_id`, `issuer`, `subject`, and `email_at_write`; scoping `operation_id` to `(owner_id, operation_id)`.

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
  - `entity`: string (mandatory, max 512 bytes)
  - `as_of`: Option<string> (RFC 3339 or `YYYY-MM-DD` date)
  - `direction`: Option<string> (`"outgoing"`, `"incoming"`, `"both"`, defaults to `"both"`)
- **Retrieval Surface:** `200 OK`, JSON:
  - `entity`: string (the queried entity name)
  - `as_of`: Option<string> (effective query date, if specified)
  - `facts`: array of `KnowledgeQueryRow` objects:
    - `direction`: string (`"outgoing"` or `"incoming"`)
    - `subject`: string
    - `predicate`: string
    - `object`: string
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
  - `subject`: string
  - `predicate`: string
  - `object`: string
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
  - `subject`: string
  - `predicate`: string
  - `object`: string
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
  - `entity`: Option<string>
  - `limit`: Option<usize> (default 50, clamped to `[1, 200]`)
- **Retrieval Surface:** `200 OK`, JSON:
  - `entity`: string (the queried entity name, or `"all"` if omitted)
  - `timeline`: array of `KnowledgeTimelineRow` objects:
    - `subject`: string
    - `predicate`: string
    - `object`: string
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
2. **Never Accept Owner from Request Body:** The client LLM or harness is never permitted to supply, override, or suggest `owner` fields. Any caller-supplied identity headers or JSON payload fields claiming owner status are ignored or rejected.
3. **Legacy Preservation:** Standard static tokens without owner metadata continue to function identically to legacy installations. Ownership is marked explicitly as unknown (`None`), never fabricated.
4. **Owner-Scoped Idempotency:** The downstream storage slice must update the receipt and idempotency indices so that deduplication keys are scoped to `(owner_id, operation_id)` or `(owner_id, created_by, idempotency_key)`. This guarantees that one user's retried requests cannot collide with or replay another user's operations.

### 5.2 Shared Engine Provenance Value Types (`agentpalace-core::provenance`)

Implemented in `crates/agentpalace-core/src/provenance.rs`, the engine provides provider-neutral domain types with bounded validation and explicit wire semantics:

| Type | Bounds & Character Rules | Wire Representation / Notes |
|---|---|---|
| `OwnerId` | 1–128 chars; ASCII alphanumeric, `_`, `-`, `.`; rejects reserved sentinels (`legacy`, `unknown`, `none`, `null`) | Transparent string (e.g. `"usr_01J8Y..."`). Immutable across rotation. Guaranteed collision-free with legacy scopes. |
| `Issuer` | 1–256 chars; printable ASCII (`33..=126`) | Transparent string (e.g. `"https://accounts.google.com"`). |
| `Subject` | 1–256 chars; printable ASCII (`33..=126`) | Transparent string (e.g. `"104928190283019283019"`). |
| `SubjectBinding` | Holds `(issuer, subject)` | Composite `{ "issuer": "...", "subject": "..." }`. |
| `EmailAtWrite` | 3–254 chars; valid `local@domain` format | Transparent string (e.g. `"tester@example.com"`). Informational/audit only. |
| `AuthenticatedOwner` / `OwnerMetadata` | Validated `(id, issuer, subject, email_at_write)` | Wire JSON: `{ "id": "...", "issuer": "...", "subject": "...", "email_at_write": "..." }`. |
| `LegacyUnknownOwner` | Unit struct sentinel | Explicit unknown representation. |
| `OwnerIdentity` | Enum: `Unknown` \| `Authenticated(AuthenticatedOwner)` | Serializes `Unknown` as `{ "status": "unknown" }` and `Authenticated` as the owner JSON. Fail-closed deserialization: rejects unknown `status` values, rejects contradictory shapes (`status: "unknown"` with authenticated owner fields), and requires all four fields (`id`, `issuer`, `subject`, `email_at_write`) for authenticated owners. Accepts bare owner objects, tagged objects, explicit strings `"unknown"`/`"legacy"`, and `null`. |
| `AgentName` | 1–128 chars; ASCII alphanumeric, `_`, `-`, `.`, `/`, `:` | Transparent string (e.g. `"codex"`, `"agy"`). |
| `AgentAssurance` | Enum: `CallerAsserted` | Wire string `"caller_asserted"`. |
| `AgentAttribution` | `agent_name` + `assurance` | Wire JSON: `{ "agent_name": "codex", "assurance": "caller_asserted" }`. |
| `SourceAuthor` | 1–256 chars; non-empty, trimmed, no ASCII control chars | Transparent string (e.g. `"Alice <alice@example.com>"`). Separate from submitting owner. |
| `SourceReference` | 1–2048 chars; non-empty, trimmed, no ASCII control chars | Transparent string (e.g. `"crates/agentpalace-core/src/lib.rs"`). Max 128 references per envelope. |
| `StorageOrigin` | Enum: `Local { origin_id }` \| `Federated { origin_id, original_record_id }` | Tagged wire JSON: `{ "kind": "local", "origin_id": "..." }` or `{ "kind": "federated", "origin_id": "...", "original_record_id": "..." }`. |
| `RecordingTime` | Wrapped UTC `OffsetDateTime`, max 64 chars RFC 3339 | Formatted RFC 3339 UTC string (e.g. `"2026-09-17T11:04:27Z"`). |
| `OwnerScopedKey` | Holds `(Option<OwnerId>, raw_key)` (raw key max 128 chars, non-empty, trimmed) | Scoped storage key `"{owner_id}:{raw_key}"` or `"legacy:{raw_key}"`. Unambiguous and collision-free due to reserved sentinel owner IDs. Validates non-empty normalization and bounded length on both construction and deserialization. |
| `ProvenanceEnvelope` | Full top-level metadata envelope | Unites owner, actor, recorded_at, origin, operation_id (`Option<OwnerScopedKey>`), source_author, and source_refs (max 128). Enforces owner-scoping alignment and bounded validation on deserialization. |

#### Invariants Enforced by Construction

1. **Server-Assigned Provenance:** `reject_payload_owner_claim` explicitly errors if any writable request payload supplies an `owner` field.
2. **Validating Deserialization (Unbypassable):** All domain value types (`OwnerId`, `Issuer`, `Subject`, `EmailAtWrite`, `AgentName`, `SourceAuthor`, `SourceReference`, `StorageOrigin`, `OwnerScopedKey`, `ProvenanceEnvelope`) implement validating Serde deserialization. Malformed, whitespace-only, or oversized wire inputs cannot bypass domain constructors.
3. **Owner-Scoped Operation Identity:** `ProvenanceEnvelope::operation_id` uses the validated `OwnerScopedKey` type. The builder `with_operation_id` normalizes non-empty raw keys and automatically binds them to the envelope's owner. Deserialization validates that any explicit `operation_id.owner_id` strictly matches the envelope's `owner`.
4. **First-Class Unknown Representation:** Legacy installations without owner metadata explicitly serialize as `{ "status": "unknown" }` or deserialize from `null` without fabricating identities. Deserialization uses provider-neutral Serde visitors/helpers without runtime dependencies on format-specific libraries in core domain logic.
5. **Boundary Separation:** Evidence status (claim truth) and execution authority (roles/permissions) remain outside these types, preserving issue #157 separation.
6. **Collision-Resistant Owner Scoping:** Sentinel identifiers (`legacy`, `unknown`, `none`, `null`) are strictly reserved and rejected by `validate_owner_id`. This guarantees that `OwnerScopedKey::composite_key()` never produces colliding keys between authenticated owners and legacy/unknown scopes.

---

## 6. Document Revision and Verification History

- **2026-09-17:** Version 1.1.2 updated for Issue #160. Hardened `OwnerIdentity` deserialization to fail-closed against unknown status values and contradictory object shapes; reserved sentinel owner IDs (`legacy`, `unknown`, `none`, `null`) to guarantee collision-free `OwnerScopedKey::composite_key()` storage indexing; removed `serde_json` from non-test crate dependencies; added exhaustive negative and collision unit tests.
- **2026-09-17:** Version 1.1.1 updated for Issue #160. Added validating Serde deserialization across all domain types, enforced owner-scoped operation ID contracts on `ProvenanceEnvelope`, added negative wire-format test coverage, and eliminated library runtime dependencies on `serde_json`.
- **2026-09-17:** Version 1.1.0 updated for Issue #160. Added §5.2 defining shared engine provenance value types in `crates/agentpalace-core/src/provenance.rs`.
- **2026-09-17:** Version 1.0.0 published for Issue #160. Verified against `crates/agentpalace-server/src/lib.rs` (34 method/path pairs), `crates/agentpalace-federation/src/lib.rs` (wire DTOs), and `docs/Demo-Hub-Design.md`.
