//! Exercise the public gateway and private, persistent engine together.
//! Google itself is replaced only at the identity-verification boundary.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::Arc,
};

use agentpalace_config::{
    AgentPalaceConfig, FederationRuntimeConfig, LowCpuRuntimeConfig, MaintenanceRuntimeConfig,
    ServerRuntimeConfig,
};
use agentpalace_core::{EmbeddingProfile, Issuer};
use agentpalace_demo_hub::{
    AdmissionPolicy, DenyAllAdmission, Gateway, GatewayConfig, GatewayMode, GoogleOidcConfig,
    NativeClient, VerifiedIdentity,
    access_policy::{AccessEntry, AccessPolicyStore, AccessRole, BootstrapAdmin},
    forwarding::{DemoRole, Forwarder, PrivateTokenProvisioner},
};
use agentpalace_embeddings::DeterministicStubProvider;
use agentpalace_server::{TokenRegistry, build_router};
use axum::http::StatusCode;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::tempdir;
use tokio::net::TcpListener;

fn identity(email: &str, subject: &str) -> VerifiedIdentity {
    VerifiedIdentity {
        email: email.into(),
        subject: subject.into(),
        issuer: "https://accounts.google.com".into(),
    }
}

fn issue_token(gateway: &Gateway, email: &str, subject: &str, resource: &str) -> String {
    let verifier = "compiled-acceptance-verifier";
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let code = gateway
        .authorize_code(
            "agentpalace-native",
            "http://127.0.0.1:43127/callback",
            &challenge,
            resource,
            identity(email, subject),
            true,
            "state",
            "state",
            "nonce",
            "nonce",
        )
        .expect("admitted identity can authorize");
    gateway
        .exchange_code(
            &code,
            "agentpalace-native",
            "http://127.0.0.1:43127/callback",
            verifier,
            resource,
        )
        .expect("exchange one-time code")
        .access_token
}

#[tokio::test]
async fn public_gateway_enforces_current_roles_and_persists_owner_provenance() {
    let temp = tempdir().expect("temporary persistent palace");
    let access = Arc::new(
        AccessPolicyStore::open(
            temp.path().join("access.json"),
            temp.path().join("bindings.json"),
            temp.path().join("audit.jsonl"),
            Some(BootstrapAdmin { email: "admin@gmail.com".into(), mailbox_proven: false }),
        )
        .expect("policy store"),
    );
    let snapshot = access.snapshot().expect("initial policy");
    let mut users = snapshot.users;
    for (email, role) in [
        ("writer-a@gmail.com", AccessRole::Write),
        ("writer-b@gmail.com", AccessRole::Write),
        ("reader@gmail.com", AccessRole::Readonly),
    ] {
        users.insert(email.into(), AccessEntry { role, enabled: true, mailbox_proven: false });
    }
    users.insert(
        "disabled@gmail.com".into(),
        AccessEntry { role: AccessRole::Write, enabled: false, mailbox_proven: false },
    );
    access.replace(snapshot.revision, "fixture", users).expect("admission policy");

    let engine_listener = TcpListener::bind("127.0.0.1:0").await.expect("private engine listener");
    let engine_addr = engine_listener.local_addr().expect("private engine address");
    let gateway_listener = TcpListener::bind("127.0.0.1:0").await.expect("public gateway listener");
    let gateway_addr = gateway_listener.local_addr().expect("public gateway address");
    let gateway_base = format!("http://{gateway_addr}");
    let resource = format!("{gateway_base}/api");
    let token_file = temp.path().join("engine_tokens.json");
    std::fs::write(&token_file, "[]").expect("empty engine token file");
    let provisioner = Arc::new(PrivateTokenProvisioner::new(&token_file).expect("provisioner"));
    let owner_a = access
        .resolve(&identity("writer-a@gmail.com", "subject-a"))
        .expect("policy lookup")
        .expect("admitted A");
    let owner_b = access
        .resolve(&identity("writer-b@gmail.com", "subject-b"))
        .expect("policy lookup")
        .expect("admitted B");
    let reader = access
        .resolve(&identity("reader@gmail.com", "subject-reader"))
        .expect("policy lookup")
        .expect("admitted reader");
    for (owner, role) in [
        (&owner_a.admission, DemoRole::Write),
        (&owner_b.admission, DemoRole::Write),
        (&reader.admission, DemoRole::Readonly),
    ] {
        provisioner.provision(owner, role).expect("private role token");
    }

    let checkout = temp.path().join("checkout");
    std::fs::create_dir_all(checkout.join("src")).expect("fixture checkout");
    let mut checkouts = BTreeMap::new();
    checkouts.insert("wing_ingest".into(), checkout);
    let config = AgentPalaceConfig {
        schema_version: 1,
        collection_name: "agentpalace_drawers".into(),
        palace_path: temp.path().join("palace"),
        embedding_profile: EmbeddingProfile::Balanced,
        low_cpu: LowCpuRuntimeConfig::defaults_for_profile(EmbeddingProfile::Balanced),
        server: ServerRuntimeConfig {
            bind: engine_addr,
            token_file: PathBuf::from(&token_file),
            checkouts,
        },
        federation: FederationRuntimeConfig::default(),
        maintenance: MaintenanceRuntimeConfig {
            enabled: false,
            background_enabled: false,
            ..MaintenanceRuntimeConfig::defaults()
        },
    };
    let engine_tokens = TokenRegistry::load(token_file.clone()).expect("engine tokens");
    let (engine_router, engine_state) = build_router(
        config.clone(),
        DeterministicStubProvider::new(EmbeddingProfile::Balanced),
        engine_tokens,
    )
    .await
    .expect("compiled engine router");
    let engine_task = tokio::spawn(async move {
        axum::serve(engine_listener, engine_router).await.expect("serve private engine");
    });
    let gateway = Gateway::new(
        GatewayConfig {
            issuer: gateway_base.clone(),
            resource: resource.clone(),
            mode: GatewayMode::LoopbackDemo,
            google: GoogleOidcConfig {
                client_id: "fixture-google-client".into(),
                client_secret: "fixture-secret".into(),
                issuer: Issuer::new("https://accounts.google.com").expect("issuer"),
                scopes: BTreeSet::from(["openid".into(), "email".into()]),
            },
            native_client: NativeClient {
                client_id: "agentpalace-native".into(),
                redirect_uri: "http://127.0.0.1:43127/callback".into(),
            },
        },
        Arc::new(DenyAllAdmission) as Arc<dyn AdmissionPolicy>,
    )
    .expect("gateway")
    .with_access_policy_store(access.clone())
    .with_forwarder(Arc::new(
        Forwarder::new(&format!("http://{engine_addr}")).expect("private origin"),
    ))
    .with_token_provisioner(provisioner);
    let token_a = issue_token(&gateway, "writer-a@gmail.com", "subject-a", &resource);
    let token_b = issue_token(&gateway, "writer-b@gmail.com", "subject-b", &resource);
    let token_reader = issue_token(&gateway, "reader@gmail.com", "subject-reader", &resource);
    assert!(
        gateway
            .authorize_code(
                "agentpalace-native",
                "http://127.0.0.1:43127/callback",
                "challenge",
                &resource,
                identity("unlisted@gmail.com", "unlisted"),
                true,
                "state",
                "state",
                "nonce",
                "nonce"
            )
            .is_err()
    );
    assert!(
        gateway
            .authorize_code(
                "agentpalace-native",
                "http://127.0.0.1:43127/callback",
                "challenge",
                &resource,
                identity("disabled@gmail.com", "disabled"),
                true,
                "state",
                "state",
                "nonce",
                "nonce"
            )
            .is_err()
    );
    let gateway_task = tokio::spawn(async move {
        axum::serve(gateway_listener, gateway.router()).await.expect("serve public gateway");
    });
    let client = reqwest::Client::new();

    let add = json!({
        "wing": "wing_acceptance", "room": "room_test",
        "content": "A owns this compiled-gateway drawer", "added_by": "same-agent-name",
        "drawer_id": "drawer_acceptance_a", "operation_id": "acceptance-add-1"
    });
    let create = client
        .post(format!("{gateway_base}/v1/drawers"))
        .bearer_auth(&token_a)
        .json(&add)
        .send()
        .await
        .expect("create drawer");
    assert_eq!(create.status(), StatusCode::OK, "{}", create.text().await.expect("error body"));
    let retry = client
        .post(format!("{gateway_base}/v1/drawers"))
        .bearer_auth(&token_a)
        .json(&add)
        .send()
        .await
        .expect("idempotent retry");
    assert_eq!(retry.status(), StatusCode::OK, "{}", retry.text().await.expect("error body"));

    let read_a = client
        .get(format!("{gateway_base}/v1/drawers/drawer_acceptance_a"))
        .bearer_auth(&token_a)
        .send()
        .await
        .expect("read A drawer");
    assert_eq!(read_a.status(), StatusCode::OK);
    let record_a: Value = read_a.json().await.expect("drawer JSON");
    assert_eq!(record_a["provenance"]["creator"]["id"], owner_a.admission.owner.id.as_str());
    assert_eq!(
        record_a["provenance"]["authenticated_submitter"]["id"],
        owner_a.admission.owner.id.as_str()
    );

    let read_b = client
        .get(format!("{gateway_base}/v1/drawers/drawer_acceptance_a"))
        .bearer_auth(&token_b)
        .send()
        .await
        .expect("other owner's read");
    assert_eq!(read_b.status(), StatusCode::OK, "admitted users share this palace");
    let seen_by_b: Value = read_b.json().await.expect("shared record JSON");
    assert_eq!(seen_by_b["provenance"]["creator"]["id"], owner_a.admission.owner.id.as_str());
    let anonymous = client
        .get(format!("{gateway_base}/v1/drawers/drawer_acceptance_a"))
        .send()
        .await
        .expect("anonymous read");
    assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);
    let spoof = client
        .post(format!("{gateway_base}/v1/drawers"))
        .bearer_auth(&token_b)
        .header("x-owner-id", owner_a.admission.owner.id.as_str())
        .json(&add)
        .send()
        .await
        .expect("forged owner header");
    assert_eq!(spoof.status(), StatusCode::BAD_REQUEST);
    let spoof_body = client
        .post(format!("{gateway_base}/v1/drawers"))
        .bearer_auth(&token_b)
        .json(&json!({"owner_id": owner_a.admission.owner.id.as_str()}))
        .send()
        .await
        .expect("forged owner body");
    assert_eq!(spoof_body.status(), StatusCode::BAD_REQUEST);

    let fact = client.post(format!("{gateway_base}/v1/kg/facts"))
        .bearer_auth(&token_a)
        .json(&json!({"subject":"A","predicate":"works_at","object":"palace","operation_id":"acceptance-fact-1"}))
        .send().await.expect("KG write");
    assert_eq!(fact.status(), StatusCode::OK, "{}", fact.text().await.expect("error body"));
    let query_a = client
        .post(format!("{gateway_base}/v1/kg/query"))
        .bearer_auth(&token_a)
        .json(&json!({"entity":"A"}))
        .send()
        .await
        .expect("KG query");
    assert_eq!(query_a.status(), StatusCode::OK);
    let facts_a: Value = query_a.json().await.expect("KG result");
    assert!(facts_a["count"].as_u64().unwrap_or(0) >= 1);
    let b_fact = client.post(format!("{gateway_base}/v1/kg/facts"))
        .bearer_auth(&token_b)
        .json(&json!({"subject":"B","predicate":"works_at","object":"palace","operation_id":"acceptance-fact-1"}))
        .send().await.expect("B's owner-scoped KG receipt");
    assert_eq!(b_fact.status(), StatusCode::OK, "{}", b_fact.text().await.expect("error body"));
    let query_b = client
        .post(format!("{gateway_base}/v1/kg/query"))
        .bearer_auth(&token_a)
        .json(&json!({"entity":"B"}))
        .send()
        .await
        .expect("other KG query");
    assert_eq!(query_b.status(), StatusCode::OK);
    let facts_b: Value = query_b.json().await.expect("other KG result");
    assert!(
        facts_b["count"].as_u64().unwrap_or(0) >= 1,
        "KG is shared but attribution remains attached"
    );
    assert_eq!(
        facts_b["facts"][0]["provenance"]["creator"]["id"],
        owner_b.admission.owner.id.as_str()
    );
    assert!(!facts_b.to_string().contains("subject-b"), "provider subject is redacted");
    let timeline = client
        .get(format!("{gateway_base}/v1/kg/timeline?entity=B"))
        .bearer_auth(&token_a)
        .send()
        .await
        .expect("KG timeline");
    assert_eq!(timeline.status(), StatusCode::OK);
    let timeline: Value = timeline.json().await.expect("timeline JSON");
    assert_eq!(
        timeline["timeline"][0]["provenance"]["creator"]["id"],
        owner_b.admission.owner.id.as_str()
    );

    let task = client
        .post(format!("{gateway_base}/v1/coordination/tasks"))
        .bearer_auth(&token_a)
        .json(&json!({
            "title":"Acceptance task", "description":"real gateway and engine",
            "wing":"wing_acceptance", "idempotency_key":"acceptance-task-1",
            "created_by":"same-agent-name", "dependencies":[]
        }))
        .send()
        .await
        .expect("coordination task");
    let task_status = task.status();
    let task: Value = task.json().await.expect("task JSON");
    assert_eq!(task_status, StatusCode::OK, "{task}");
    let task_id = task["task_id"].as_str().expect("task ID");
    assert_eq!(task["provenance"]["creator"]["id"], owner_a.admission.owner.id.as_str());
    let message = client
        .post(format!("{gateway_base}/v1/coordination/messages"))
        .bearer_auth(&token_a)
        .json(&json!({
            "task_id": task_id, "recipient": "reviewer", "kind": "status",
            "payload": {"progress": 0.5}, "idempotency_key": "acceptance-message-1",
            "sender": "same-agent-name", "envelope_version": 1
        }))
        .send()
        .await
        .expect("coordination message");
    let message_status = message.status();
    let message: Value = message.json().await.expect("message JSON");
    assert_eq!(message_status, StatusCode::OK, "{message}");
    assert_eq!(message["provenance"]["creator"]["id"], owner_a.admission.owner.id.as_str());
    let artifact = client
        .post(format!("{gateway_base}/v1/coordination/artifacts"))
        .bearer_auth(&token_a)
        .json(&json!({
            "task_id": task_id, "role": "log", "media_type": "text/plain",
            "content": "compiled gateway acceptance", "idempotency_key": "acceptance-artifact-1",
            "created_by": "same-agent-name"
        }))
        .send()
        .await
        .expect("coordination artifact");
    let artifact_status = artifact.status();
    let artifact: Value = artifact.json().await.expect("artifact JSON");
    assert_eq!(artifact_status, StatusCode::OK, "{artifact}");
    assert_eq!(artifact["provenance"]["creator"]["id"], owner_a.admission.owner.id.as_str());
    let result = client
        .post(format!("{gateway_base}/v1/coordination/results"))
        .bearer_auth(&token_a)
        .json(&json!({
            "task_id": task_id, "payload": {"answer": 42},
            "idempotency_key": "acceptance-result-1", "created_by": "same-agent-name"
        }))
        .send()
        .await
        .expect("coordination result");
    let result_status = result.status();
    let result: Value = result.json().await.expect("result JSON");
    assert_eq!(result_status, StatusCode::OK, "{result}");
    assert_eq!(result["provenance"]["creator"]["id"], owner_a.admission.owner.id.as_str());
    let ingest = client
        .post(format!("{gateway_base}/v1/ingest/batch"))
        .bearer_auth(&token_a)
        .json(&json!({
            "wing": "wing_ingest", "repo_id": "github.com/test/acceptance",
            "agent": "same-agent-name", "files": [{
                "relative_path": "src/acceptance.rs",
                "content_hash": "acceptance-content-v1",
                "chunks": [{
                    "chunk_index": 0, "room": "code",
                    "text": "frombulation subsystem quxzort acceptance fixture"
                }]
            }]
        }))
        .send()
        .await
        .expect("ingest through gateway");
    let ingest_status = ingest.status();
    let ingest: Value = ingest.json().await.expect("ingest JSON");
    assert_eq!(ingest_status, StatusCode::OK, "{ingest}");
    assert_eq!(ingest["files"][0]["status"], "ingested");
    let search = client
        .post(format!("{gateway_base}/v1/drawers/search"))
        .bearer_auth(&token_a)
        .json(&json!({
            "query": "frombulation subsystem quxzort",
            "wing": "wing_ingest", "limit": 5
        }))
        .send()
        .await
        .expect("search ingested chunk");
    let search_status = search.status();
    let search: Value = search.json().await.expect("search JSON");
    assert_eq!(search_status, StatusCode::OK, "{search}");
    assert_eq!(
        search["results"][0]["provenance"]["creator"]["id"],
        owner_a.admission.owner.id.as_str()
    );

    let reader_write = client
        .post(format!("{gateway_base}/v1/drawers"))
        .bearer_auth(&token_reader)
        .json(&add)
        .send()
        .await
        .expect("reader mutation");
    assert_eq!(reader_write.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        reader_write.json::<Value>().await.expect("reader refusal body")["error"],
        "insufficient_scope"
    );
    let reader_kg = client
        .post(format!("{gateway_base}/v1/kg/facts"))
        .bearer_auth(&token_reader)
        .json(&json!({"subject":"x","predicate":"p","object":"y"}))
        .send()
        .await
        .expect("reader KG mutation");
    assert_eq!(reader_kg.status(), StatusCode::FORBIDDEN);
    let reader_task = client
        .post(format!("{gateway_base}/v1/coordination/tasks"))
        .bearer_auth(&token_reader)
        .json(&json!({"title":"denied"}))
        .send()
        .await
        .expect("reader coordination mutation");
    assert_eq!(reader_task.status(), StatusCode::FORBIDDEN);
    let reader_ingest = client
        .post(format!("{gateway_base}/v1/ingest/batch"))
        .bearer_auth(&token_reader)
        .json(&json!({}))
        .send()
        .await
        .expect("reader ingest mutation");
    assert_eq!(reader_ingest.status(), StatusCode::FORBIDDEN);
    let writer_delete = client
        .delete(format!("{gateway_base}/v1/drawers/drawer_acceptance_a"))
        .bearer_auth(&token_a)
        .send()
        .await
        .expect("writer hard delete");
    assert_eq!(writer_delete.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        writer_delete.json::<Value>().await.expect("hard-delete refusal body")["error"],
        "insufficient_scope"
    );

    let snapshot = access.snapshot().expect("policy revision");
    let mut users = snapshot.users;
    users.insert(
        "writer-a@gmail.com".into(),
        AccessEntry { role: AccessRole::Readonly, enabled: true, mailbox_proven: false },
    );
    users.insert(
        "writer-b@gmail.com".into(),
        AccessEntry { role: AccessRole::Write, enabled: false, mailbox_proven: false },
    );
    access.replace(snapshot.revision, "demotion", users).expect("live policy change");
    let after_demotion = client
        .post(format!("{gateway_base}/v1/drawers"))
        .bearer_auth(&token_a)
        .json(&add)
        .send()
        .await
        .expect("old grant after demotion");
    assert_eq!(after_demotion.status(), StatusCode::FORBIDDEN);
    let after_disable = client
        .get(format!("{gateway_base}/v1/info"))
        .bearer_auth(&token_b)
        .send()
        .await
        .expect("old grant after disable");
    assert_eq!(after_disable.status(), StatusCode::UNAUTHORIZED);
    assert!(after_disable.headers().contains_key(reqwest::header::WWW_AUTHENTICATE));
    assert_eq!(
        after_disable.json::<Value>().await.expect("disabled grant body")["error"],
        "invalid_token"
    );

    engine_task.abort();
    let _ = engine_task.await;
    drop(engine_state);
    let restarted_listener =
        TcpListener::bind(engine_addr).await.expect("restarted engine listener");
    let restarted_tokens = TokenRegistry::load(token_file).expect("reloaded tokens");
    let (restarted_router, restarted_state) = build_router(
        config,
        DeterministicStubProvider::new(EmbeddingProfile::Balanced),
        restarted_tokens,
    )
    .await
    .expect("reopened persistent engine");
    let restarted_task = tokio::spawn(async move {
        axum::serve(restarted_listener, restarted_router).await.expect("serve restarted engine");
    });
    let persisted = client
        .get(format!("{gateway_base}/v1/drawers/drawer_acceptance_a"))
        .bearer_auth(&token_a)
        .send()
        .await
        .expect("read after restart");
    assert_eq!(
        persisted.status(),
        StatusCode::OK,
        "{}",
        persisted.text().await.expect("error body")
    );
    let persisted = client
        .get(format!("{gateway_base}/v1/drawers/drawer_acceptance_a"))
        .bearer_auth(&token_a)
        .send()
        .await
        .expect("read persisted attribution");
    let record: Value = persisted.json().await.expect("persisted JSON");
    assert_eq!(record["provenance"]["creator"]["id"], owner_a.admission.owner.id.as_str());
    assert_eq!(
        record["provenance"]["authenticated_submitter"]["id"],
        owner_a.admission.owner.id.as_str()
    );
    let task_after_restart = client
        .get(format!("{gateway_base}/v1/coordination/tasks/{task_id}"))
        .bearer_auth(&token_a)
        .send()
        .await
        .expect("task after restart");
    assert_eq!(task_after_restart.status(), StatusCode::OK);
    let task_after_restart: Value = task_after_restart.json().await.expect("persisted task JSON");
    assert_eq!(
        task_after_restart["provenance"]["creator"]["id"],
        owner_a.admission.owner.id.as_str()
    );
    let fact_after_restart = client
        .post(format!("{gateway_base}/v1/kg/query"))
        .bearer_auth(&token_a)
        .json(&json!({"entity":"B"}))
        .send()
        .await
        .expect("KG after restart");
    assert_eq!(fact_after_restart.status(), StatusCode::OK);
    let fact_after_restart: Value = fact_after_restart.json().await.expect("persisted KG JSON");
    assert_eq!(
        fact_after_restart["facts"][0]["provenance"]["creator"]["id"],
        owner_b.admission.owner.id.as_str()
    );
    let search_after_restart = client
        .post(format!("{gateway_base}/v1/drawers/search"))
        .bearer_auth(&token_a)
        .json(&json!({
            "query": "frombulation subsystem quxzort", "wing": "wing_ingest", "limit": 5
        }))
        .send()
        .await
        .expect("ingest search after restart");
    assert_eq!(search_after_restart.status(), StatusCode::OK);
    let search_after_restart: Value =
        search_after_restart.json().await.expect("persisted ingest search");
    assert_eq!(
        search_after_restart["results"][0]["provenance"]["creator"]["id"],
        owner_a.admission.owner.id.as_str()
    );
    restarted_task.abort();
    gateway_task.abort();
    drop(restarted_state);
}
