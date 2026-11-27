# Design: one provenance format for drawer retrieval (#157 phase A)

Status: **draft, waiting on the open questions at the end.**
Issue: [#157](https://github.com/DigitumDei/agentpalace/issues/157), phase A as split in
[the issue comment of 2026-09-25](https://github.com/DigitumDei/agentpalace/issues/157#issuecomment-5838679761):
items 1, 4 and 5. Phase B (derivation references, evidence status, authority, correction
references with #156) is out of scope here.

## Research attribution

Issue #157 was inspired by Deepak Akkil et al., *Emergence World: Adversarial Stress-Testing of
Long-Horizon Multi-Agent Systems*, arXiv:2609.17320v1 (2026), especially sections 5.1.1, 5.1.3
and 5.9 on retained adversarial content, private-memory use and controls at action boundaries
([PDF](https://arxiv.org/pdf/2609.17320), [HTML](https://arxiv.org/html/2609.17320v1)). The paper
motivates tracing where retained information came from. The format below is an AgentPalace
design adapted from that motivation. The authors did not propose or test it, and this document
claims no security benefit for it. Metadata alone does not stop prompt injection.

## Goal

Every drawer that a retrieval path returns carries one `provenance` object with the same field
meanings everywhere: local MCP, CLI, the HTTP server, and combined (local plus remote) results
merged by the MCP client. The object separates:

- **who holds this copy** (the palace that answered),
- **where the content was first filed** (this palace or another one),
- **who filed it**, with authenticated identities kept apart from caller-asserted labels,
- **what the content cites as its source** (file, author, references, dates), and
- **what is not recorded**, stated explicitly rather than left out or guessed.

It also gives #191 a defined value for a synced copy: held locally, content from
`remote:<name>`, and the remote's own envelope kept as it was received.

## What the code does today

Each claim is labelled *traced* (read in the code at `main` 7dd887d, file and line given) or
*inferred*.

| # | Finding | Evidence |
|---|---|---|
| 1 | The types already exist. `PersistedProvenance` is stored with a drawer, and `ProvenanceResponse` is its redacted read form (owner ID and email-at-write; issuer and subject withheld). | traced, `crates/agentpalace-core/src/provenance.rs:2169`, `:2456` |
| 2 | Only HTTP-server writes populate it. Local MCP writes always store `provenance: None`, so every locally filed drawer has none. | traced, `crates/agentpalace-mcp/src/lib.rs:4928`; `crates/agentpalace-server/src/lib.rs:1967` |
| 3 | The search core puts provenance into `SearchResult`, but both local MCP search formatters drop it. Local results have no attribution at all. | traced, `crates/agentpalace-search/src/lib.rs:452`; `crates/agentpalace-mcp/src/lib.rs:3220` (combined), `:3304` (local only) |
| 4 | `added_by`, the only attribution a local drawer has, is not in `SearchResult`, so no search output shows it. The HTTP server sends `added_by: None` on every result. | traced, `crates/agentpalace-core/src/search.rs:163`; `crates/agentpalace-server/src/lib.rs:1738` |
| 5 | The HTTP server stores `added_by` as `"<token name>:<claimed name>"`. That one string mixes the credential-authenticated token identity with a caller assertion. It does not set `creator.agent`. | traced, `crates/agentpalace-server/src/lib.rs:1790`, `:2361` |
| 6 | Every palace calls itself `StorageOrigin::Local { origin_id: "local" }`. A remote result's `storage_origin` arrives at the client as `local`, meaning local to the hub, and the client passes it through unchanged. | traced, `crates/agentpalace-server/src/lib.rs:2361`; `crates/agentpalace-mcp/src/federation.rs:2806` |
| 7 | The meaning of `StorageOrigin` is itself unclear. The enum doc says "where a record was originally created", but `PersistedProvenance.storage_origin` says "where this copy is stored". Those are two different facts, and #191 needs both. | traced, `crates/agentpalace-core/src/provenance.rs:1557`, `:2181` |
| 8 | Two origin spellings. Drawer search annotates `origin` as `local` or the bare remote name (`alpha`), while the change feed and wake-up use `remote:<name>`. `docs/Federation.md` documents both. | traced, `crates/agentpalace-mcp/src/federation.rs:2585`, `:2806`; `docs/Federation.md` lines 46 and 927 |
| 9 | No palace has a stable identifier: neither config nor `/v1/info` carries one. A multi-hop chain cannot name the original palace except by the name each hop gives its remote. | traced, `crates/agentpalace-federation/src/lib.rs:15` |
| 10 | `AgentAssurance` has one variant, `CallerAsserted`. Nothing can say "authenticated" today. | traced, `crates/agentpalace-core/src/provenance.rs:1154` |
| 11 | KG query results already carry `ProvenanceResponse`. Phase A brings drawers into line with them; it leaves the KG unchanged. | traced, `crates/agentpalace-graph/src/lib.rs:509` |
| 12 | Temporal fields from #147 (`filed_at`, `date`, `ingest_mode`, mined-versus-filed labelling) and drawer IDs from #89 have shipped. Phase A reuses them and adds no second copy of either at the top level. | traced, `crates/agentpalace-core/src/search.rs:186-205`; #147 and #89 closed |
| 13 | A failed provenance serialization is silently dropped (`.ok()`), so a corrupt row looks like a legacy row. | traced, `crates/agentpalace-search/src/lib.rs:452` |

## Proposed format

One read-side type in `agentpalace-core`, serialized as `provenance` on every drawer result.
**It is computed at read time** from the stored row plus the reader's point of view. Phase A adds
no storage migration (but see open question 2).

```jsonc
"provenance": {
  "format": 1,

  // Which palace holds the copy that answered, from the reader's point of view.
  // Computed at read time, never stored, never taken from a remote.
  "held_by": "local",                        // or "remote:<name>"

  // Where the content was first filed, from the reader's point of view.
  "content_origin": { "kind": "local" },
  //   or { "kind": "federated", "origin": "remote:<name>", "record_id": "<id there>" }
  //   or { "kind": "unknown" }

  "filed": {
    "at": "2026-11-27T09:15:00Z",            // filing time; for mined rows, the mining time
    "mode": "mcp",                           // ingest_mode: mcp, diary, projects, convos, federation_write, ...
    "owner": { "status": "unknown", "id": null, "email_at_write": null },
    "credential": null,                      // e.g. { "name": "alice", "assurance": "credential_authenticated" }
    "agent": { "name": "claude", "assurance": "caller_asserted" }
  },

  "source": {
    "file": "/full/path/as/stored",          // full path; the top-level source_file stays a basename
    "author": null,
    "refs": [],
    "date": "2026-11-20",                    // authored or event date, if recorded
    "stale": false                           // mined file changed since mining
  },

  "history": [], "deleted_by": null, "invalidated_by": null,   // existing redacted events, unchanged

  // Present only when the record crossed a hop: the provenance object exactly as the holding
  // palace reported it, never rewritten. Bounded depth (proposed 4), then "truncated": true.
  "upstream": null
}
```

### Rules

1. **Always present, nulls explicit.** Every drawer result has `provenance`, legacy rows included.
   Every scalar field is serialized. `null` means *not recorded*, never *none exists*. An empty
   `refs` means no references were recorded, which is not evidence that the content has no
   source. This is item 5.
2. **Never upgrade.** An owner is `authenticated` only when stored provenance says so. Legacy rows
   and rows without stored provenance report `owner.status: "unknown"`. A legacy `added_by` is
   reported verbatim as one `caller_asserted` agent. That includes a hub row's `"alice:claude"`,
   because a claimed name can itself contain `:`. A label is never split after the fact into a
   credential identity. This is item 4.
3. **Credential and agent are separate fields.** `credential` is the identity that the transport
   authenticated: on the HTTP server, the token name, with assurance
   `credential_authenticated`. It identifies the holder of a token, not a human or a model.
   `agent` is what the caller claimed. New HTTP writes store both, structured (see
   "Write-side changes"). Local stdio MCP and the CLI have no credential, so `credential` is
   `null` there.
4. **Reader-relative origins.** When the MCP client merges a remote result, it sets
   `held_by: "remote:<name>"` itself, using the name from its own config. It translates the
   remote's `content_origin` as follows:
   - the remote says `local`: the client reports `{ "kind": "federated", "origin": "remote:<name>", "record_id": <drawer_id> }`;
   - the remote says `federated`: the client keeps `federated` with `origin: "remote:<name>"`,
     meaning "reached us through this remote". The remote's own naming of the earlier hop stays
     visible only in `upstream`;
   - the remote sends no `format: 1` object (an older server): `content_origin` is
     `{ "kind": "federated", "origin": "remote:<name>" }` and `upstream` holds whatever the server
     sent (an old `ProvenanceResponse`, or `null`).

   The remote's object goes into `upstream` byte-for-byte as received. A hop can therefore add
   context but cannot remove the remote's statement of its sources. This satisfies the acceptance
   criterion "a federated hop does not erase that distinction".
5. **#191 synced copy.** A record synced from `remote:<name>` is stored with
   `content_origin: federated(remote:<name>, record_id)` and the remote's envelope kept as
   `upstream`. Read back, it reports `held_by: "local"`, with everything else the same as a live
   remote result. The only visible difference between "I asked the remote" and "I read my synced
   copy" is `held_by`, which is the difference that matters.
6. **A locally filed quotation of an external document** has `held_by: local` and
   `content_origin: local`. The document is named in `source.author` and `source.refs`. Filing
   a quotation makes the filer the filer, not the author. Phase A needs a way to record
   `source.author` and `source.refs` on local writes (open question 3).
7. **Re-mining is not re-verification.** For mined rows, `filed.at` is the mining time and
   `filed.mode` names the miner. The authored date stays in `source.date`. Nothing in the format
   says a claim was checked. Evidence status is phase B, and the format reserves no field for it.
8. **Not authority.** Consumer docs will state that no `provenance` field grants permission,
   including `credential`, `owner.status: authenticated`, similarity and content hashes. The
   format describes where material came from. Whether to act on it is the host's decision.
9. **Errors are not legacy.** A stored provenance value that fails to parse is an error to log,
   and the result reports `"invalid": true` rather than passing as legacy (finding 13).

### Where it is applied in phase A

| Surface | Change |
|---|---|
| MCP `agentpalace_search` (local only and combined) | Emit `provenance`, both paths |
| MCP `agentpalace_check_duplicate` matches | Emit `provenance` |
| HTTP `POST /v1/drawers/search` | Emit `provenance` format 1 with the server's own point of view (`held_by: local`); advertise capability `provenance_v1` |
| MCP client merge (`federation.rs`) | Apply rule 4; old servers handled as in rule 4 |
| CLI `search` | Human output gains `Filed by: <agent> (asserted)` and, when known, `Credential:` and `Owner:` lines; legacy rows print `Owner: unknown`. No JSON output change (the CLI has no `--json` search today) |
| KG results | No change (already carry `ProvenanceResponse`) |
| Change feed, wake-up, diary read, traverse | Out of phase A. The #191 cursor work uses the same `remote:<name>` spelling |

Existing top-level fields (`drawer_id`, `origin`, `source_file`, `filed_at`, `date`,
`ingest_mode`, `stale`) stay as they are for compatibility. The duplication with `provenance` is
deliberate for one release; open question 4 asks whether `origin` changes spelling.

### Write-side changes (small)

- `ProvenanceHistoryEntry` gains an optional `credential: AgentName`, and `AgentAssurance` gains
  `CredentialAuthenticated`. Both are `serde(default)`, so rows written by older binaries still
  load. **Downgrade risk:** the wire types use `deny_unknown_fields`, so an older binary would
  reject a row written by 0.3. That is acceptable for 0.3 and will be named in the release notes.
- HTTP `POST /v1/drawers` stores `creator.credential = <token name>` and
  `creator.agent = <claimed added_by>` (caller asserted). The legacy `added_by` column keeps its
  current `"<token>:<claimed>"` value so nothing that reads it breaks.
- `StorageOrigin` docs are corrected. The stored field means content origin ("first filed"), and
  "held by" is never stored (finding 7).

## Tests (phase A acceptance)

- Legacy row with no stored provenance: `owner.status: unknown`, verbatim asserted agent, nulls
  present; identical on local MCP, HTTP, and through a remote.
- Hub write with a token and a claimed `added_by`: `credential` is authenticated, `agent` is
  asserted, never merged. A legacy hub row with `"alice:claude"` stays one asserted label.
- Copied external content: `source.refs` and `source.author` survive local MCP → HTTP → MCP client
  merge unchanged inside `upstream`, and the outer object reports `federated(remote:<name>)`.
- Old server (no `provenance_v1`): result reports `federated(remote:<name>)`, with the old
  response verbatim in `upstream`.
- Stale mined file: `source.stale: true`, `filed.mode: projects`, `filed.at` is the mining time.
- Corrupt stored provenance: `invalid: true`, not legacy.
- Same record seen locally and through a remote: same field meanings, and only `held_by` and
  `content_origin` differ, as the rules say.

Multiple derivation sources and corrected or retracted records are phase B (item 2, #156).

## Documentation in the implementation PR

- New `docs/Provenance.md`: consumer guide covering the format, how to follow sources and
  upstream, what `null` means, and what stays a host responsibility (authority, prompt-injection
  handling). It carries the research attribution.
- `docs/Federation.md`: the search DTO's `provenance`, capability `provenance_v1`, rule 4, and
  the corrected "Local results do not include it" paragraph.
- `docs/Release-Scope.md`: `agentpalace_search` and `agentpalace_check_duplicate` response notes,
  plus a Breaking Changes entry if open question 4 is answered yes.
- `docs/CLI-Surface.md`: new search output lines.

## Open questions for Dion

1. **Local owner status.** Local stdio MCP and the CLI have no account identity. Should new local
   writes report `owner.status: "unknown"` (honest, but every local drawer looks the same as a
   legacy one), or a new `"local"` status meaning "filed through this palace's own local
   interface; no account identity"? *Recommendation:* `"local"` for rows written by 0.3 onward;
   rows written before stay `"unknown"`.
2. **Store or derive for local writes?** Deriving at read time (this draft) needs no migration.
   Storing `PersistedProvenance` on new local writes makes `"local"` status (question 1) and
   source references durable. *Recommendation:* store it on new local writes (no backfill); derive
   for older rows.
3. **Source fields on `agentpalace_add_drawer`.** Should phase A add optional `source_author`
   and `source_refs` arguments (bounded by the existing `MAX_SOURCE_REFS`), so a quotation of an
   external document can say so? *Recommendation:* yes. Without them, rule 6 cannot be
   exercised from MCP.
4. **`origin` spelling.** Change drawer search's top-level `origin` from the bare remote name to
   `remote:<name>`, matching the change feed and wake-up? It is a breaking change for any caller
   that compares against the bare name. *Recommendation:* yes, in 0.3, with a Breaking Changes
   entry.
5. **Stable palace ID.** Multi-hop chains can only name hops by each hop's local remote name
   (finding 9). Generating a palace UUID at `init` and exposing it on `/v1/info` would fix that.
   *Recommendation:* defer to #191 (0.4), where multi-hop sync makes it necessary; phase A works
   without it.
