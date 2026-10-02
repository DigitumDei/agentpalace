// Snapshot-series retrieval benchmark for search freshness (issue #194).
//
// Builds a synthetic, generic palace in a temp dir: several monitoring-snapshot
// series (one line template, drifting numbers and timestamps, increasing
// `filed_at`), operational notes filed around them, old reference how-tos, and
// filler — at least 256 drawers, so LanceDB's approximate vector index is built
// and exercised. Then reports, under `relevant`, `balanced` and `recent`:
//
//   newest@1 / newest@5  for "latest snapshot for <host>" queries
//   newest@1 / newest@5  for exact source-label queries
//   reference@1          for how-to queries (old durable references must not be buried)
//
// Embeddings are real by default (offline: set AGENTPALACE_EMBED_ALLOW_DOWNLOADS=1 the
// first time to fetch the model). AGENTPALACE_STUB_EMBEDDINGS=1 uses deterministic stub
// vectors, which only checks that the harness runs; its numbers are meaningless.
//
// Usage:
//   cargo run --release --example snapshot_series_bench -p agentpalace-cli
#![allow(clippy::unwrap_used)]
#![allow(missing_docs)]

use std::env;
use std::path::PathBuf;

use agentpalace_core::{
    DrawerId, DrawerRecord, EmbeddingProfile, Freshness, RoomId, SearchQuery, WingId, hash_text,
};
use agentpalace_embeddings::{
    DeterministicStubProvider, EmbeddingProvider, EmbeddingRequest, FastembedProvider,
    FastembedProviderConfig,
};
use agentpalace_search::{FreshnessPolicy, SearchRuntime, SearchRuntimePolicy};
use agentpalace_storage::{DrawerStore, DuplicateStrategy, StorageEngine};
use time::{Duration, OffsetDateTime, macros::datetime};

const HOSTS: [&str; 8] = ["web-01", "web-02", "db-01", "db-02", "cache-01", "queue-01", "edge-01", "batch-01"];
const RUNS_PER_HOST: usize = 12;
const LIMIT: usize = 5;

struct Fixture {
    drawers: Vec<(String, String, String, String, OffsetDateTime)>, // id, room, source, text, filed_at
    newest_snapshot: Vec<(String, String)>,                         // host -> newest id
    how_tos: Vec<(String, String)>,                                 // query, id
}

fn snapshot_text(host: &str, run: usize, at: OffsetDateTime) -> String {
    let load = 20 + (run * 7 + host.len() * 3) % 60;
    let disk = 40 + (run * 3 + host.len()) % 50;
    format!(
        "status snapshot {host} {} cpu {load}% mem {}% disk {disk}% open connections {} errors {}",
        at.date(),
        30 + (run * 5) % 50,
        100 + run * 13,
        run % 4
    )
}

fn build_fixture() -> Fixture {
    let start = datetime!(2026-09-01 00:00:00 UTC);
    let mut drawers = Vec::new();
    let mut newest_snapshot = Vec::new();
    for (h, host) in HOSTS.iter().enumerate() {
        let mut newest = String::new();
        for run in 0..RUNS_PER_HOST {
            let at = start + Duration::hours((run * 20 + h) as i64);
            let id = format!("snap_{host}_{run:02}");
            drawers.push((
                id.clone(),
                "snapshots".to_owned(),
                format!("/var/monitor/{host}.status"),
                snapshot_text(host, run, at),
                at,
            ));
            newest = id;
        }
        newest_snapshot.push((host.to_string(), newest));
        // Operational notes, some filed after the newest snapshot.
        for note in 0..3 {
            let at = start + Duration::hours((RUNS_PER_HOST * 20 + note * 30 + h) as i64);
            drawers.push((
                format!("note_{host}_{note}"),
                "snapshots".to_owned(),
                format!("notes/{host}-{note}.md"),
                format!("operator note for {host}: investigated alert {note}, restarted the agent and watched the snapshot recover"),
                at,
            ));
        }
    }
    let how_tos = [
        ("how do I rotate the TLS certificates on the edge hosts", "Rotate edge TLS certificates: drain the host, replace the bundle, reload the proxy, verify with openssl s_client."),
        ("how to restore the database from a nightly backup", "Database restore runbook: stop writers, restore the nightly backup into a fresh volume, replay WAL, switch the replica."),
        ("steps to scale the queue workers", "Scaling queue workers: raise the worker count in the deployment, watch queue depth and consumer lag, then lower it after the backlog drains."),
        ("how to clear a stuck batch job", "Stuck batch job: find the lock row, confirm the worker is gone, release the lock, requeue the job with its original parameters."),
    ];
    let mut how_to_ids = Vec::new();
    for (i, (query, text)) in how_tos.iter().enumerate() {
        let id = format!("howto_{i}");
        drawers.push((
            id.clone(),
            "runbooks".to_owned(),
            format!("runbooks/howto-{i}.md"),
            (*text).to_owned(),
            start - Duration::days(120 + i as i64),
        ));
        how_to_ids.push(((*query).to_owned(), id));
    }
    // Filler so the palace crosses the 256-row approximate-index threshold.
    let topics = ["budget review", "team offsite", "vendor contract", "office move", "hiring plan", "quarterly goals", "design critique", "release retro"];
    let mut n = 0;
    while drawers.len() < 300 {
        let topic = topics[n % topics.len()];
        drawers.push((
            format!("filler_{n:03}"),
            "general".to_owned(),
            format!("misc/{n:03}.md"),
            format!("meeting notes {n}: {topic} discussion, action items assigned, follow up next week"),
            start + Duration::hours(n as i64),
        ));
        n += 1;
    }
    Fixture { drawers, newest_snapshot, how_tos: how_to_ids }
}

/// Real model or stub vectors, chosen at startup.
enum BenchProvider {
    Real(Box<FastembedProvider>),
    Stub(DeterministicStubProvider),
}

impl EmbeddingProvider for BenchProvider {
    fn profile(&self) -> &'static agentpalace_core::EmbeddingProfileMetadata {
        match self {
            Self::Real(provider) => provider.profile(),
            Self::Stub(provider) => provider.profile(),
        }
    }

    fn startup_validation(
        &self,
    ) -> agentpalace_embeddings::Result<agentpalace_embeddings::StartupValidation> {
        match self {
            Self::Real(provider) => provider.startup_validation(),
            Self::Stub(provider) => provider.startup_validation(),
        }
    }

    fn embed(
        &mut self,
        request: &EmbeddingRequest,
    ) -> agentpalace_embeddings::Result<agentpalace_embeddings::EmbeddingResponse> {
        match self {
            Self::Real(provider) => provider.embed(request),
            Self::Stub(provider) => provider.embed(request),
        }
    }
}

fn provider() -> Result<BenchProvider, Box<dyn std::error::Error>> {
    if agentpalace_core::env_var("AGENTPALACE_STUB_EMBEDDINGS").is_ok_and(|v| v == "1") {
        eprintln!("Using stub embeddings: harness check only, numbers are meaningless.");
        return Ok(BenchProvider::Stub(DeterministicStubProvider::new(EmbeddingProfile::Balanced)));
    }
    let cache_root = env::var_os("AGENTPALACE_EMBED_CACHE")
        .map(PathBuf::from)
        .or_else(|| dirs::cache_dir().map(|d| d.join("agentpalace").join("embeddings")))
        .ok_or("cannot determine cache root; set AGENTPALACE_EMBED_CACHE")?;
    let mut config = FastembedProviderConfig::new(cache_root);
    config.allow_downloads = agentpalace_core::env_var("AGENTPALACE_EMBED_ALLOW_DOWNLOADS")
        .is_ok_and(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"));
    Ok(BenchProvider::Real(Box::new(
        FastembedProvider::new(EmbeddingProfile::Balanced, config).try_initialize()?,
    )))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = build_fixture();
    let mut provider = provider()?;
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let tmp = tempfile::TempDir::new()?;
    let engine = rt.block_on(StorageEngine::open(tmp.path().join("palace"), EmbeddingProfile::Balanced))?;

    let texts: Vec<String> = fixture.drawers.iter().map(|d| d.3.clone()).collect();
    let mut records = Vec::with_capacity(texts.len());
    for (chunk, drawers) in texts.chunks(32).zip(fixture.drawers.chunks(32)) {
        let response = provider.embed(&EmbeddingRequest::new(chunk.to_vec())?)?;
        for ((id, room, source, text, filed_at), embedding) in drawers.iter().zip(response.vectors()) {
            records.push(DrawerRecord {
                id: DrawerId::new(id.as_str())?,
                wing: WingId::new("wing_ops")?,
                room: RoomId::new(room.as_str())?,
                hall: None,
                date: None,
                source_file: source.clone(),
                chunk_index: 0,
                ingest_mode: "mcp".to_owned(),
                extract_mode: None,
                added_by: "bench".to_owned(),
                filed_at: *filed_at,
                importance: None,
                emotional_weight: None,
                weight: None,
                content: text.clone(),
                content_hash: hash_text(text),
                embedding: embedding.clone(),
                locator: None,
                view_metadata: None,
                provenance: None,
            });
        }
    }
    rt.block_on(engine.drawer_store().put_drawers(&records, DuplicateStrategy::Error))?;
    println!("Snapshot-series benchmark: {} drawers, limit {LIMIT}\n", records.len());

    let mut search = SearchRuntime::with_policy(
        provider,
        SearchRuntimePolicy { rerank_enabled: false, freshness: FreshnessPolicy::default() },
    );
    let mut run = |text: String, mode: Freshness| -> Vec<String> {
        let query = SearchQuery {
            text,
            wing: None,
            room: None,
            view: None,
            limit: LIMIT,
            profile: EmbeddingProfile::Balanced,
            freshness: Some(mode),
        };
        rt.block_on(search.search(engine.drawer_store(), &query))
            .unwrap()
            .into_iter()
            .filter_map(|r| r.drawer_id.map(|id| id.as_str().to_owned()))
            .collect()
    };

    println!("{:<10} {:>15} {:>15} {:>15} {:>15} {:>13}", "mode", "natural new@1", "natural new@5", "label new@1", "label new@5", "reference@1");
    for mode in Freshness::ALL {
        let (mut n1, mut n5, mut l1, mut l5, mut r1) = (0, 0, 0, 0, 0);
        for (host, newest) in &fixture.newest_snapshot {
            let natural = run(format!("latest status snapshot for {host}"), mode);
            n1 += usize::from(natural.first() == Some(newest));
            n5 += usize::from(natural.contains(newest));
            let label = run(format!("/var/monitor/{host}.status"), mode);
            l1 += usize::from(label.first() == Some(newest));
            l5 += usize::from(label.contains(newest));
        }
        for (query, id) in &fixture.how_tos {
            r1 += usize::from(run(query.clone(), mode).first() == Some(id));
        }
        let hosts = fixture.newest_snapshot.len();
        let refs = fixture.how_tos.len();
        println!(
            "{:<10} {:>15} {:>15} {:>15} {:>15} {:>13}",
            mode.as_str(),
            format!("{n1}/{hosts}"),
            format!("{n5}/{hosts}"),
            format!("{l1}/{hosts}"),
            format!("{l5}/{hosts}"),
            format!("{r1}/{refs}")
        );
    }
    Ok(())
}
