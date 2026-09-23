//! Exercises the forwarding boundary against the real AgentPalace server.

use std::{collections::BTreeMap, net::SocketAddr, path::PathBuf};

use agentpalace_config::{
    AgentPalaceConfig, FederationRuntimeConfig, LowCpuRuntimeConfig, MaintenanceRuntimeConfig,
    ServerRuntimeConfig,
};
use agentpalace_core::{AuthenticatedOwner, EmbeddingProfile};
use agentpalace_demo_hub::AdmissionIdentity;
use agentpalace_demo_hub::forwarding::{
    AuthorizedOwner, DemoRole, ForwardRequest, Forwarder, PrivateTokenProvisioner,
};
use agentpalace_embeddings::DeterministicStubProvider;
use agentpalace_server::{TokenRegistry, build_router};
use axum::http::{HeaderMap, Method, StatusCode, header};
use serde_json::{Value, json};
use tempfile::tempdir;
use tokio::net::TcpListener;

#[tokio::test]
async fn forwarding_writes_and_reads_back_authenticated_owner_provenance() {
    let temp = tempdir().expect("temporary palace directory");
    let token_file = temp.path().join("engine_tokens.json");
    std::fs::write(&token_file, "[]").expect("empty token file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&token_file, std::fs::Permissions::from_mode(0o600))
            .expect("restrict token file");
    }

    let owner = AuthenticatedOwner::parse(
        "usr_01J8Y_PROVENANCE_OWNER0000001",
        "https://accounts.google.com",
        "subject_provenance_owner",
        "provenance@example.com",
    )
    .expect("valid owner");
    let expected_owner_id = owner.id.as_str().to_owned();
    let admission = AdmissionIdentity::new(owner.id.clone(), owner);
    let provisioned = PrivateTokenProvisioner::new(&token_file)
        .expect("provisioner")
        .provision(&admission, DemoRole::Write)
        .expect("explicitly scoped owner token");

    let engine_listener = TcpListener::bind("127.0.0.1:0").await.expect("engine listener");
    let engine_addr: SocketAddr = engine_listener.local_addr().expect("engine address");
    let config = AgentPalaceConfig {
        schema_version: 1,
        collection_name: "agentpalace_drawers".into(),
        palace_path: temp.path().join("palace"),
        embedding_profile: EmbeddingProfile::Balanced,
        low_cpu: LowCpuRuntimeConfig::defaults_for_profile(EmbeddingProfile::Balanced),
        server: ServerRuntimeConfig {
            bind: engine_addr,
            token_file: PathBuf::from(&token_file),
            checkouts: BTreeMap::new(),
        },
        federation: FederationRuntimeConfig::default(),
        maintenance: MaintenanceRuntimeConfig {
            enabled: false,
            background_enabled: false,
            ..MaintenanceRuntimeConfig::defaults()
        },
    };
    let tokens = TokenRegistry::load(token_file.clone()).expect("load real engine token registry");
    let (engine_router, _engine_state) =
        build_router(config.clone(), DeterministicStubProvider::new(EmbeddingProfile::Balanced), tokens)
            .await
            .expect("build real engine router");
    let engine_task = tokio::spawn(async move {
        axum::serve(engine_listener, engine_router).await.expect("serve engine")
    });

    let forwarder =
        Forwarder::new(&format!("http://{engine_addr}")).expect("configured private engine origin");
    let trusted_owner = AuthorizedOwner {
        owner_id: expected_owner_id.clone(),
        upstream_token: provisioned.token,
        role: DemoRole::Write,
    };
    let create_body = json!({
        "wing": "wing_hub_provenance",
        "room": "room_test",
        "content": "Written through the demo hub forwarder into the real engine.",
        "added_by": "integration-agent",
        "drawer_id": "drawer_hub_provenance_1",
        "operation_id": "hub-provenance-write-1"
    });
    let mut write_headers = HeaderMap::new();
    write_headers.insert(
        header::CONTENT_TYPE,
        "application/json".parse().expect("test operation succeeded"),
    );
    write_headers.insert(
        "x-operation-id",
        "hub-provenance-write-1".parse().expect("test operation succeeded"),
    );
    let write = forwarder
        .forward(
            &trusted_owner,
            ForwardRequest {
                method: Method::POST,
                path_and_query: "/v1/drawers".into(),
                headers: write_headers,
                body: serde_json::to_vec(&create_body).expect("test operation succeeded"),
            },
        )
        .await
        .expect("forward write");
    assert_eq!(write.status, StatusCode::OK, "{}", String::from_utf8_lossy(&write.body));
    let created: Value = serde_json::from_slice(&write.body).expect("write response JSON");
    assert_eq!(
        created["drawer_id"], "drawer_hub_provenance_1",
        "unexpected add response: {created}"
    );

    let read = forwarder
        .forward(
            &trusted_owner,
            ForwardRequest {
                method: Method::GET,
                path_and_query: "/v1/drawers/drawer_hub_provenance_1".into(),
                headers: HeaderMap::new(),
                body: Vec::new(),
            },
        )
        .await
        .expect("forward readback");
    assert_eq!(read.status, StatusCode::OK, "{}", String::from_utf8_lossy(&read.body));
    let record: Value = serde_json::from_slice(&read.body).expect("read response JSON");
    assert_eq!(record["id"], "drawer_hub_provenance_1");
    assert_eq!(record["provenance"]["creator"]["id"], expected_owner_id);
    assert_eq!(record["provenance"]["creator"]["email_at_write"], "provenance@example.com");
    assert_eq!(record["provenance"]["authenticated_submitter"]["id"], expected_owner_id);

    engine_task.abort();
    let _ = engine_task.await;
    drop(_engine_state);

    let restarted_listener = TcpListener::bind(engine_addr).await.expect("restarted engine listener");
    let restarted_tokens = TokenRegistry::load(token_file).expect("reload owner tokens");
    let (restarted_router, _restarted_state) =
        build_router(config, DeterministicStubProvider::new(EmbeddingProfile::Balanced), restarted_tokens)
            .await.expect("reopen persistent palace");
    let restarted_task = tokio::spawn(async move {
        axum::serve(restarted_listener, restarted_router).await.expect("serve restarted engine")
    });
    let restarted_forwarder =
        Forwarder::new(&format!("http://{engine_addr}")).expect("private restarted engine origin");
    let persisted = restarted_forwarder.forward(&trusted_owner, ForwardRequest {
        method: Method::GET,
        path_and_query: "/v1/drawers/drawer_hub_provenance_1".into(),
        headers: HeaderMap::new(),
        body: Vec::new(),
    }).await.expect("read persisted drawer after restart");
    assert_eq!(persisted.status, StatusCode::OK, "{}", String::from_utf8_lossy(&persisted.body));
    let persisted_record: Value = serde_json::from_slice(&persisted.body).expect("persisted record");
    assert_eq!(persisted_record["provenance"]["creator"]["id"], expected_owner_id);
    assert_eq!(persisted_record["provenance"]["authenticated_submitter"]["id"], expected_owner_id);
    assert_eq!(persisted_record["provenance"]["creator"]["email_at_write"], "provenance@example.com");
    restarted_task.abort();
}
