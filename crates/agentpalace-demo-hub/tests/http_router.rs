//! Wire-level regression coverage for the public gateway router.
//!
//! These tests deliberately bind the real router to an ephemeral loopback
//! listener. They are the harness boundary for the RemoteClient/OIDC fixture
//! tests; no handler is reconstructed in a test helper.

use std::{collections::BTreeSet, sync::Arc};

use agentpalace_core::Issuer;
use agentpalace_demo_hub::{DenyAllAdmission, Gateway, GatewayConfig, GatewayMode, GoogleOidcConfig, NativeClient};

fn config() -> GatewayConfig {
    GatewayConfig {
        issuer: "http://127.0.0.1:1".into(),
        resource: "http://127.0.0.1:1/api".into(),
        mode: GatewayMode::LoopbackDemo,
        google: GoogleOidcConfig {
            client_id: "fixture-client".into(),
            client_secret: "fixture-secret".into(),
            issuer: Issuer::new("https://accounts.google.com").expect("fixture issuer"),
            scopes: ["openid", "email"].into_iter().map(str::to_owned).collect::<BTreeSet<_>>(),
        },
        native_client: NativeClient { client_id: "agentpalace-native".into(), redirect_uri: "http://127.0.0.1:49152/callback".into() },
    }
}

async fn start(gateway: Gateway) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.expect("ephemeral listener");
    let address = listener.local_addr().expect("listener address");
    let task = tokio::spawn(async move { axum::serve(listener, gateway.router()).await.expect("router server"); });
    (format!("http://{address}"), task)
}

#[tokio::test]
async fn gateway_router_serves_metadata_and_device_authorization_over_http() {
    let gateway = Gateway::new(config(), Arc::new(DenyAllAdmission)).expect("gateway");
    let (base, task) = start(gateway).await;
    let client = reqwest::Client::new();
    let metadata = client.get(format!("{base}/.well-known/oauth-protected-resource")).send().await.expect("metadata").error_for_status().expect("metadata status").json::<serde_json::Value>().await.expect("metadata json");
    assert_eq!(metadata["resource"], "http://127.0.0.1:1/api");
    let response = client.post(format!("{base}/device")).form(&[("client_id", "agentpalace-native"), ("resource", "http://127.0.0.1:1/api")]).send().await.expect("device");
    assert!(response.status().is_success());
    let body = response.json::<serde_json::Value>().await.expect("device json");
    assert!(body["device_code"].as_str().is_some());
    task.abort();
}
