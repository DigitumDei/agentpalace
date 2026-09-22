//! Wire-level regression coverage for the public gateway router.
//!
//! These tests deliberately bind the real router to an ephemeral loopback
//! listener. They are the harness boundary for the RemoteClient/OIDC fixture
//! tests; no handler is reconstructed in a test helper.

use std::{collections::BTreeSet, sync::Arc};

use agentpalace_core::Issuer;
use agentpalace_demo_hub::{DenyAllAdmission, Gateway, GatewayConfig, GatewayMode, GoogleOidcConfig, NativeClient, GoogleOidcVerifier, GoogleOidcVerifierAdapter, GoogleClaimError};
use axum::{routing::get, Json, Router};
use jsonwebtoken::{encode, EncodingKey, Header};

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

async fn start_dynamic(mut config: GatewayConfig) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.expect("ephemeral listener");
    let base = format!("http://{}", listener.local_addr().expect("listener address"));
    config.issuer = base.clone();
    config.resource = format!("{base}/api");
    let gateway = Gateway::new(config, Arc::new(DenyAllAdmission)).expect("gateway");
    let router = gateway.router().merge(Router::new().route("/v1/info", get(|| async {
        Json(serde_json::json!({"server_version":"fixture","federation_api_version":1,"capabilities":["coordination"]}))
    })));
    let task = tokio::spawn(async move { axum::serve(listener, router).await.expect("router server"); });
    (base, task)
}

fn cookie(response: &reqwest::Response, name: &str) -> String {
    response.headers().get_all(reqwest::header::SET_COOKIE).iter().find_map(|value| value.to_str().ok()?.split(';').next()?.strip_prefix(&format!("{name}=")).map(str::to_owned)).expect("cookie")
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

#[tokio::test]
async fn http_browser_consent_requires_the_origin_browser_cookie() {
    let (base, task) = start_dynamic(config()).await;
    let client = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().expect("client");
    let query = format!("{base}/authorize?client_id=agentpalace-native&redirect_uri=http%3A%2F%2F127.0.0.1%3A49152%2Fcallback&code_challenge=fixture&resource={base}%2Fapi&state=browser-state&nonce=browser-nonce");
    let first = client.get(query).send().await.expect("authorize");
    assert_eq!(first.status(), reqwest::StatusCode::TEMPORARY_REDIRECT);
    let browser_cookie = cookie(&first, "agentpalace_browser");
    let location = first.headers().get(reqwest::header::LOCATION).and_then(|v| v.to_str().ok()).expect("provider redirect");
    let transaction = reqwest::Url::parse(location).expect("redirect url").query_pairs().find(|(key, _)| key == "state").map(|(_, value)| value.into_owned()).expect("transaction");
    let second = client.get(format!("{base}/authorize?client_id=agentpalace-native&redirect_uri=http%3A%2F%2F127.0.0.1%3A49152%2Fcallback&code_challenge=fixture-2&resource={base}%2Fapi&state=browser-state-2&nonce=browser-nonce-2")).send().await.expect("second authorize");
    let second_browser_cookie = cookie(&second, "agentpalace_browser");
    let stolen = client.get(format!("{base}/auth/google/callback?state={transaction}&error=access_denied")).header(reqwest::header::COOKIE, second_browser_cookie).send().await.expect("stolen callback");
    assert_eq!(stolen.status(), reqwest::StatusCode::FORBIDDEN);
    let valid = client.get(format!("{base}/auth/google/callback?state={transaction}&error=access_denied")).header(reqwest::header::COOKIE, browser_cookie).send().await.expect("bound callback");
    assert_eq!(valid.status(), reqwest::StatusCode::TEMPORARY_REDIRECT);
    task.abort();
}

#[tokio::test]
async fn http_device_callback_denial_is_bound_and_persisted_for_polling() {
    let (base, task) = start_dynamic(config()).await;
    let client = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().expect("client");
    let grant = client.post(format!("{base}/device")).form(&[("client_id", "agentpalace-native"), ("resource", format!("{base}/api").as_str())]).send().await.expect("device").json::<serde_json::Value>().await.expect("device json");
    let user_code = grant["user_code"].as_str().expect("user code");
    let verify = client.get(format!("{base}/device/verify?user_code={user_code}")).send().await.expect("verify");
    let device_cookie = cookie(&verify, "agentpalace_device_browser");
    let location = verify.headers().get(reqwest::header::LOCATION).and_then(|v| v.to_str().ok()).expect("provider redirect");
    let state = reqwest::Url::parse(location).expect("redirect url").query_pairs().find(|(key, _)| key == "state").map(|(_, value)| value.into_owned()).expect("state");
    let denied = client.get(format!("{base}/auth/google/device-callback?state={state}&error=access_denied")).header(reqwest::header::COOKIE, device_cookie).send().await.expect("denial callback");
    assert_eq!(denied.status(), reqwest::StatusCode::NO_CONTENT);
    let poll = client.post(format!("{base}/token")).form(&[("grant_type", "urn:ietf:params:oauth:grant-type:device_code"), ("device_code", grant["device_code"].as_str().expect("device code")), ("client_id", "agentpalace-native"), ("resource", format!("{base}/api").as_str())]).send().await.expect("poll");
    assert_eq!(poll.status(), reqwest::StatusCode::FORBIDDEN);
    task.abort();
}

#[tokio::test]
async fn http_device_polling_exposes_pending_and_slow_down_transitions() {
    let (base, task) = start_dynamic(config()).await;
    let client = reqwest::Client::new();
    let grant = client.post(format!("{base}/device")).form(&[("client_id", "agentpalace-native"), ("resource", format!("{base}/api").as_str())]).send().await.expect("device").json::<serde_json::Value>().await.expect("device json");
    let form = [("grant_type", "urn:ietf:params:oauth:grant-type:device_code"), ("device_code", grant["device_code"].as_str().expect("device code")), ("client_id", "agentpalace-native"), ("resource", format!("{base}/api").as_str())];
    assert_eq!(client.post(format!("{base}/token")).form(&form).send().await.expect("pending").status(), reqwest::StatusCode::BAD_REQUEST);
    assert_eq!(client.post(format!("{base}/token")).form(&form).send().await.expect("slow down").status(), reqwest::StatusCode::BAD_REQUEST);
    task.abort();
}

#[tokio::test]
async fn mock_oidc_jwks_server_rejects_bad_signature_fixture() {
    let token = encode(&Header::default(), &serde_json::json!({
        "iss": "https://accounts.google.com", "aud": "fixture-client", "sub": "subject",
        "email": "owner@example.test", "email_verified": true, "exp": 4_000_000_000_u64,
        "nonce": "nonce"
    }), &EncodingKey::from_secret(b"not-an-rsa-key")).expect("signed fixture");
    let token_body = serde_json::json!({"id_token": token});
    let redirects = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.expect("OIDC listener");
    let address = listener.local_addr().expect("OIDC address");
    let token_body_for_server = token_body.clone();
    let redirects_for_server = Arc::clone(&redirects);
    let router = Router::new()
        .route("/token", axum::routing::post(move |axum::extract::Form(form): axum::extract::Form<std::collections::HashMap<String, String>>| { let body = token_body_for_server.clone(); let redirects = Arc::clone(&redirects_for_server); async move { redirects.lock().expect("redirect capture").push(form.get("redirect_uri").cloned().unwrap_or_default()); Json(body) } }))
        .route("/jwks", get(|| async { Json(serde_json::json!({"keys": []})) }));
    let task = tokio::spawn(async move { axum::serve(listener, router).await.expect("OIDC server"); });
    let adapter = GoogleOidcVerifierAdapter::new_with_endpoints(config().google, "http://127.0.0.1:49152/callback", format!("http://{address}/token"), format!("http://{address}/jwks")).expect("adapter");
    assert_eq!(adapter.exchange_and_verify("fixture-code", "nonce", "http://127.0.0.1:49152/callback"), Err(GoogleClaimError::Signature));
    assert_eq!(adapter.exchange_and_verify("fixture-code", "nonce", "http://127.0.0.1:49152/device-callback"), Err(GoogleClaimError::Signature));
    assert_eq!(*redirects.lock().expect("redirect assertions"), vec!["http://127.0.0.1:49152/callback", "http://127.0.0.1:49152/device-callback"]);
    task.abort();
}
