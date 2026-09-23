//! HTTP integration for live membership administration and non-escalating grants.
use std::{collections::{BTreeMap, BTreeSet}, fs::OpenOptions, io::Write, sync::Arc, time::{SystemTime, UNIX_EPOCH}};

use agentpalace_core::Issuer;
use agentpalace_demo_hub::{
    access_policy::{AccessEntry, AccessPolicyStore, AccessRole, BootstrapAdmin},
    AdmissionPolicy, DenyAllAdmission, Gateway, GatewayConfig, GatewayMode, GoogleIdClaims,
    GoogleOidcConfig, GoogleOidcVerifier, GoogleClaimError, NativeClient, VerifiedIdentity,
};
use axum::{extract::State, http::{StatusCode, header}, response::IntoResponse};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::redirect::Policy;
use fs4::FileExt;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;

const GOOGLE_CLIENT: &str = "fixture-google-client";
const EMAIL: &str = "admin@gmail.com";

#[derive(Clone)]
struct FixtureVerifier;

#[async_trait::async_trait]
impl GoogleOidcVerifier for FixtureVerifier {
    async fn exchange_and_verify(
        &self,
        _code: &str,
        expected_nonce: &str,
        _redirect_uri: &str,
    ) -> Result<GoogleIdClaims, GoogleClaimError> {
        Ok(GoogleIdClaims {
            iss: "https://accounts.google.com".into(),
            aud: GOOGLE_CLIENT.into(),
            sub: "immutable-admin-subject".into(),
            email: EMAIL.into(),
            email_verified: true,
            exp: now() + 600,
            nonce: expected_nonce.into(),
            additional: BTreeMap::new(),
        })
    }
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |duration| duration.as_secs())
}

async fn start_gateway() -> (String, reqwest::Client, tempfile::TempDir, Gateway, std::path::PathBuf) {
    let temp = tempfile::tempdir().expect("tempdir");
    let access_path = temp.path().join("access.json");
    let access = Arc::new(AccessPolicyStore::open(
        access_path.clone(),
        temp.path().join("bindings.json"),
        temp.path().join("audit.jsonl"),
        Some(BootstrapAdmin { email: EMAIL.into(), mailbox_proven: false }),
    ).expect("policy"));
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind");
    let address = listener.local_addr().expect("address");
    let base = format!("http://127.0.0.1:{}", address.port());
    let config = GatewayConfig {
        issuer: base.clone(),
        resource: format!("{base}/api"),
        mode: GatewayMode::LoopbackDemo,
        google: GoogleOidcConfig {
            client_id: GOOGLE_CLIENT.into(),
            client_secret: "fixture-secret".into(),
            issuer: Issuer::new("https://accounts.google.com").expect("issuer"),
            scopes: BTreeSet::from(["openid".into(), "email".into()]),
        },
        native_client: NativeClient {
            client_id: "agentpalace-native".into(),
            redirect_uri: "http://127.0.0.1:43127/callback".into(),
        },
    };
    let gateway = Gateway::new(config, Arc::new(DenyAllAdmission) as Arc<dyn AdmissionPolicy>)
        .expect("gateway")
        .with_access_policy_store(access)
        .with_google_verifier(Arc::new(FixtureVerifier));
    let test_gateway = gateway.clone();
    tokio::spawn(async move { axum::serve(listener, gateway.router()).await.expect("server"); });
    let client = reqwest::Client::builder().redirect(Policy::none()).build().expect("client");
    (base, client, temp, test_gateway, access_path)
}

fn query(url: &str, name: &str) -> String {
    reqwest::Url::parse(url).expect("url").query_pairs().find(|(key, _)| key == name)
        .expect("query value").1.into_owned()
}

fn hidden(html: &str, name: &str) -> String {
    let marker = format!("name=\"{name}\" value=\"");
    html.split(&marker).nth(1).and_then(|value| value.split('\"').next()).expect("hidden value").to_owned()
}

fn response_cookie(response: &reqwest::Response, name: &str) -> Option<String> {
    response.headers().get_all(header::SET_COOKIE).iter().filter_map(|value| value.to_str().ok())
        .find_map(|cookie| cookie.strip_prefix(&format!("{name}=")).and_then(|value| value.split(';').next()).map(str::to_owned))
}

async fn admin_browser(base: &str, client: &reqwest::Client) -> (String, String) {
    let response = client.get(format!("{base}/authorize"))
        .query(&[
            ("client_id", "agentpalace-native"),
            ("redirect_uri", "http://127.0.0.1:43127/callback"),
            ("code_challenge", "fixture-challenge"),
            ("resource", &format!("{base}/api")),
            ("state", "native-state"),
            ("nonce", "fixture-nonce"),
        ]).send().await.expect("authorize");
    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    let google = response.headers().get(header::LOCATION).expect("integration test setup").to_str().expect("integration test setup").to_owned();
    let browser = response_cookie(&response, "agentpalace_browser").expect("browser cookie");
    let transaction = query(&google, "state");

    let callback = client.get(format!("{base}/auth/google/callback"))
        .query(&[("state", transaction.as_str()), ("code", "fixture-code")])
        .header(header::COOKIE, format!("agentpalace_browser={browser}"))
        .send().await.expect("Google callback");
    assert_eq!(callback.status(), StatusCode::OK);
    let form = callback.text().await.expect("consent page");
    let csrf = hidden(&form, "csrf_token");
    let transaction = hidden(&form, "transaction");
    let consent = client.post(format!("{base}/auth/google/consent"))
        .header(header::COOKIE, format!("agentpalace_browser={browser}"))
        .form(&[("transaction", transaction.as_str()), ("csrf_token", csrf.as_str()), ("consent", "true")])
        .send().await.expect("consent");
    assert_eq!(consent.status(), StatusCode::TEMPORARY_REDIRECT);
    let session = response_cookie(&consent, "agentpalace_session").expect("session cookie");
    let csrf_cookie = response_cookie(&consent, "agentpalace_csrf").expect("csrf cookie");
    (format!("agentpalace_session={session}; agentpalace_csrf={csrf_cookie}"), csrf_cookie)
}

fn pkce(verifier: &str) -> String { URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())) }

fn verified(email: &str, subject: &str) -> VerifiedIdentity {
    VerifiedIdentity { email: email.into(), subject: subject.into(), issuer: "https://accounts.google.com".into() }
}

#[tokio::test]
async fn admin_api_requires_recent_google_session_csrf_and_current_etag() {
    let (base, client, _temp, _gateway, _access_path) = start_gateway().await;
    let (cookies, csrf) = admin_browser(&base, &client).await;

    let get = client.get(format!("{base}/hub/v1/access")).header(header::COOKIE, &cookies).send().await.expect("integration test setup");
    assert_eq!(get.status(), StatusCode::OK);
    let etag = get.headers().get(header::ETAG).expect("integration test setup").to_str().expect("integration test setup").to_owned();
    let body: Value = get.json().await.expect("integration test setup");
    assert_eq!(body["users"][EMAIL]["role"], "admin");
    assert_eq!(body["csrf_token"], csrf);
    assert_eq!(etag, "\"1\"");

    let writer_url = format!("{base}/hub/v1/access/writer%40gmail.com");
    let put = client.put(&writer_url).header(header::COOKIE, &cookies)
        .header("x-csrf-token", &csrf).header(header::IF_MATCH, &etag)
        .json(&AccessEntry { role: AccessRole::Write, enabled: true, mailbox_proven: false })
        .send().await.expect("integration test setup");
    assert_eq!(put.status(), StatusCode::OK);
    let new_etag = put.headers().get(header::ETAG).expect("integration test setup").to_str().expect("integration test setup").to_owned();
    assert_eq!(new_etag, "\"2\"");

    let stale = client.delete(&writer_url).header(header::COOKIE, &cookies)
        .header("x-csrf-token", &csrf).header(header::IF_MATCH, &etag).send().await.expect("integration test setup");
    assert_eq!(stale.status(), StatusCode::PRECONDITION_FAILED);
    let no_csrf_put = client.put(&writer_url).header(header::COOKIE, &cookies)
        .header(header::IF_MATCH, &new_etag)
        .json(&AccessEntry { role: AccessRole::Readonly, enabled: true, mailbox_proven: false })
        .send().await.expect("integration test setup");
    assert_eq!(no_csrf_put.status(), StatusCode::FORBIDDEN);
    let no_csrf = client.delete(&writer_url).header(header::COOKIE, &cookies)
        .header(header::IF_MATCH, &new_etag).send().await.expect("integration test setup");
    assert_eq!(no_csrf.status(), StatusCode::FORBIDDEN);

    let delete = client.delete(&writer_url).header(header::COOKIE, &cookies)
        .header("x-csrf-token", &csrf).header(header::IF_MATCH, &new_etag).send().await.expect("integration test setup");
    assert_eq!(delete.status(), StatusCode::OK);
    let second_admin = client.put(format!("{base}/hub/v1/access/second%40gmail.com"))
        .header(header::COOKIE, &cookies).header("x-csrf-token", &csrf)
        .header(header::IF_MATCH, "\"3\"")
        .json(&AccessEntry { role: AccessRole::Admin, enabled: true, mailbox_proven: false })
        .send().await.expect("integration test setup");
    assert_eq!(second_admin.status(), StatusCode::OK);
    let demote = client.put(format!("{base}/hub/v1/access/admin%40gmail.com"))
        .header(header::COOKIE, &cookies).header("x-csrf-token", &csrf)
        .header(header::IF_MATCH, "\"4\"")
        .json(&AccessEntry { role: AccessRole::Readonly, enabled: true, mailbox_proven: false })
        .send().await.expect("integration test setup");
    assert_eq!(demote.status(), StatusCode::OK);
    let stale_session = client.get(format!("{base}/hub/v1/access"))
        .header(header::COOKIE, &cookies).send().await.expect("integration test setup");
    assert_eq!(stale_session.status(), StatusCode::FORBIDDEN);
}

async fn put_role(
    base: &str,
    client: &reqwest::Client,
    cookies: &str,
    csrf: &str,
    email: &str,
    etag: &str,
    role: AccessRole,
) -> reqwest::Response {
    client.put(format!("{base}/hub/v1/access/{}", email.replace('@', "%40")))
        .header(header::COOKIE, cookies)
        .header("x-csrf-token", csrf)
        .header(header::IF_MATCH, etag)
        .json(&AccessEntry { role, enabled: true, mailbox_proven: false })
        .send().await.expect("integration test setup")
}

fn issue_token(gateway: &Gateway, email: &str, subject: &str, resource: &str) -> String {
    let verifier = "integration-pkce-verifier";
    let code = gateway.authorize_code(
        "agentpalace-native", "http://127.0.0.1:43127/callback", &pkce(verifier), resource,
        verified(email, subject), true, "state", "state", "nonce", "nonce",
    ).expect("authorize code");
    gateway.exchange_code(&code, "agentpalace-native", "http://127.0.0.1:43127/callback", verifier, resource)
        .expect("exchange code").access_token
}

#[tokio::test]
async fn existing_grants_observe_demotion_revocation_promotion_ceiling_and_manual_edits() {
    let (base, client, _temp, gateway, access_path) = start_gateway().await;
    let (cookies, csrf) = admin_browser(&base, &client).await;
    let get = client.get(format!("{base}/hub/v1/access")).header(header::COOKIE, &cookies).send().await.expect("integration test setup");
    let mut etag = get.headers().get(header::ETAG).expect("integration test setup").to_str().expect("integration test setup").to_owned();

    assert_eq!(put_role(&base, &client, &cookies, &csrf, "writer@gmail.com", &etag, AccessRole::Write).await.status(), StatusCode::OK);
    etag = "\"2\"".into();
    assert_eq!(put_role(&base, &client, &cookies, &csrf, "reader@gmail.com", &etag, AccessRole::Readonly).await.status(), StatusCode::OK);
    etag = "\"3\"".into();

    let resource = format!("{base}/api");
    let writer_token = issue_token(&gateway, "writer@gmail.com", "writer-subject", &resource);
    let reader_token = issue_token(&gateway, "reader@gmail.com", "reader-subject", &resource);

    assert_eq!(put_role(&base, &client, &cookies, &csrf, "writer@gmail.com", &etag, AccessRole::Readonly).await.status(), StatusCode::OK);
    assert_eq!(gateway.authorize_rest_role(&writer_token, &resource).expect("integration test setup").1, AccessRole::Readonly);
    etag = "\"4\"".into();
    assert_eq!(put_role(&base, &client, &cookies, &csrf, "reader@gmail.com", &etag, AccessRole::Write).await.status(), StatusCode::OK);
    assert_eq!(gateway.authorize_rest_role(&reader_token, &resource).expect("integration test setup").1, AccessRole::Readonly);

    // Simulate the documented operator edit while holding the same lock as API writers.
    let lock_path = access_path.with_extension("json.lock");
    let lock = OpenOptions::new().create(true).truncate(false).read(true).write(true).open(lock_path).expect("integration test setup");
    lock.lock_exclusive().expect("integration test setup");
    let mut policy: Value = serde_json::from_slice(&std::fs::read(&access_path).expect("integration test setup")).expect("integration test setup");
    let before = policy["users"].clone();
    let mut after = before.clone();
    after["writer@gmail.com"]["role"] = json!("write");
    let revision = policy["revision"].as_u64().expect("integration test setup") + 1;
    policy["revision"] = json!(revision);
    policy["users"] = after.clone();
    policy["audit"].as_array_mut().expect("integration test setup").push(json!({
        "actor": "operator:integration-test",
        "occurred_at": now().to_string(),
        "action": "operator_file_edit",
        "before": before,
        "after": after,
    }));
    let mut temp_file = tempfile::NamedTempFile::new_in(access_path.parent().expect("integration test setup")).expect("integration test setup");
    temp_file.write_all(&serde_json::to_vec_pretty(&policy).expect("integration test setup")).expect("integration test setup");
    temp_file.as_file().sync_all().expect("integration test setup");
    temp_file.persist(&access_path).expect("integration test setup");
    FileExt::unlock(&lock).expect("integration test setup");
    assert_eq!(gateway.authorize_rest_role(&reader_token, &resource).expect("integration test setup").1, AccessRole::Readonly);
    assert_eq!(gateway.authorize_rest_role(&writer_token, &resource).expect("integration test setup").1, AccessRole::Write);

    etag = format!("\"{revision}\"");
    let removed = client.delete(format!("{base}/hub/v1/access/writer%40gmail.com"))
        .header(header::COOKIE, &cookies).header("x-csrf-token", &csrf)
        .header(header::IF_MATCH, &etag).send().await.expect("integration test setup");
    assert_eq!(removed.status(), StatusCode::OK);
    assert!(gateway.authorize_rest_role(&writer_token, &resource).is_err());
}

async fn record_upstream(State(log): axum::extract::State<Arc<std::sync::Mutex<Vec<String>>>>, headers: axum::http::HeaderMap) -> axum::response::Response {
    let bearer = headers.get(header::AUTHORIZATION).and_then(|value| value.to_str().ok()).unwrap_or_default().to_owned();
    log.lock().expect("integration test setup").push(bearer.clone());
    (StatusCode::OK, axum::Json(json!({"authorization": bearer, "owner": headers.get("x-owner").and_then(|v| v.to_str().ok())}))).into_response()
}

#[tokio::test]
async fn public_gateway_forwarding_is_closed_authenticated_and_owner_scoped() {
    let temp = tempfile::tempdir().expect("integration test setup");
    let access = Arc::new(AccessPolicyStore::open(
        temp.path().join("access.json"), temp.path().join("bindings.json"), temp.path().join("audit.jsonl"),
        Some(BootstrapAdmin { email: EMAIL.into(), mailbox_proven: false }),
    ).expect("integration test setup"));
    let snapshot = access.snapshot().expect("integration test setup");
    let mut users = snapshot.users;
    users.insert("reader@gmail.com".into(), AccessEntry { role: AccessRole::Readonly, enabled: true, mailbox_proven: false });
    users.insert("writer@gmail.com".into(), AccessEntry { role: AccessRole::Write, enabled: true, mailbox_proven: false });
    access.replace(snapshot.revision, "test-setup", users).expect("integration test setup");

    let upstream_listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("integration test setup");
    let upstream_base = format!("http://127.0.0.1:{}", upstream_listener.local_addr().expect("integration test setup").port());
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let upstream = axum::Router::new()
        .route("/v1/info", axum::routing::get(record_upstream))
        .route("/v1/drawers", axum::routing::post(record_upstream))
        .with_state(seen.clone());
    tokio::spawn(async move { axum::serve(upstream_listener, upstream).await.expect("integration test setup"); });

    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("integration test setup");
    let base = format!("http://127.0.0.1:{}", listener.local_addr().expect("integration test setup").port());
    let resource = format!("{base}/api");
    let config = GatewayConfig {
        issuer: base.clone(), resource: resource.clone(), mode: GatewayMode::LoopbackDemo,
        google: GoogleOidcConfig {
            client_id: GOOGLE_CLIENT.into(), client_secret: "fixture-secret".into(),
            issuer: Issuer::new("https://accounts.google.com").expect("integration test setup"),
            scopes: BTreeSet::from(["openid".into(), "email".into()]),
        },
        native_client: NativeClient { client_id: "agentpalace-native".into(), redirect_uri: "http://127.0.0.1:43127/callback".into() },
    };
    let forwarder = Arc::new(agentpalace_demo_hub::forwarding::Forwarder::new(&upstream_base).expect("integration test setup"));
    let provisioner = Arc::new(agentpalace_demo_hub::forwarding::PrivateTokenProvisioner::new(temp.path().join("engine-tokens.json")).expect("integration test setup"));
    let gateway = Gateway::new(config, Arc::new(DenyAllAdmission) as Arc<dyn AdmissionPolicy>).expect("integration test setup")
        .with_access_policy_store(access.clone()).with_forwarder(forwarder).with_token_provisioner(provisioner);
    let verifier = "reader-hub-grant-verifier";
    let code = gateway.authorize_code(
        "agentpalace-native", "http://127.0.0.1:43127/callback", &pkce(verifier), &resource,
        verified("reader@gmail.com", "reader-subject"), true, "state", "state", "nonce", "nonce",
    ).expect("integration test setup");
    let token = gateway.exchange_code(&code, "agentpalace-native", "http://127.0.0.1:43127/callback", verifier, &resource).expect("integration test setup").access_token;
    let writer_token = issue_token(&gateway, "writer@gmail.com", "writer-subject", &resource);
    let admin = access.resolve(&verified(EMAIL, "immutable-admin-subject"))
        .expect("resolve bootstrap admin")
        .expect("enabled bootstrap admin");
    gateway.create_admin_session("hard-delete-admin-session", admin.admission, "valid-session-csrf")
        .expect("create recent admin session");
    tokio::spawn(async move { axum::serve(listener, gateway.router()).await.expect("integration test setup"); });
    let client = reqwest::Client::builder().redirect(Policy::none()).build().expect("integration test setup");

    let health = client.get(format!("{base}/v1/health")).send().await.expect("integration test setup");
    assert_eq!(health.status(), StatusCode::OK);
    let head_health = client.head(format!("{base}/v1/health")).send().await.expect("integration test setup");
    assert_eq!(head_health.status(), StatusCode::OK);
    assert_eq!(client.get(format!("{base}/mcp")).send().await.expect("integration test setup").status(), StatusCode::NOT_FOUND);
    assert_eq!(client.get(format!("{base}/v1/unknown")).send().await.expect("integration test setup").status(), StatusCode::NOT_FOUND);

    let read = client.get(format!("{base}/v1/info")).bearer_auth(&token).send().await.expect("integration test setup");
    assert_eq!(read.status(), StatusCode::OK);
    let body: Value = read.json().await.expect("integration test setup");
    let private_bearer = body["authorization"].as_str().expect("integration test setup");
    assert!(private_bearer.starts_with("Bearer "));
    assert_ne!(private_bearer, format!("Bearer {token}"));
    assert_eq!(seen.lock().expect("integration test setup").len(), 1);

    let spoof_header = client.get(format!("{base}/v1/info")).bearer_auth(&token).header("x-owner-id", "victim").send().await.expect("integration test setup");
    assert_eq!(spoof_header.status(), StatusCode::BAD_REQUEST);
    let spoof_body = client.post(format!("{base}/v1/drawers")).bearer_auth(&writer_token).json(&json!({"owner_id":"victim"})).send().await.expect("integration test setup");
    assert_eq!(spoof_body.status(), StatusCode::BAD_REQUEST);
    let no_csrf_hard_delete = client.delete(format!("{base}/v1/drawers/test-id"))
        .header(header::COOKIE, "agentpalace_session=hard-delete-admin-session")
        .send().await.expect("integration test setup");
    assert_eq!(no_csrf_hard_delete.status(), StatusCode::FORBIDDEN);
    assert_eq!(seen.lock().expect("integration test setup").len(), 1, "missing-CSRF hard delete never reaches the private engine");
    let readonly_mutation = client.post(format!("{base}/v1/drawers")).bearer_auth(&token).json(&json!({"text":"not written"})).send().await.expect("integration test setup");
    assert_eq!(readonly_mutation.status(), StatusCode::FORBIDDEN);
    assert_eq!(seen.lock().expect("integration test setup").len(), 1, "denied requests never reach the private engine");
}


#[tokio::test]
async fn health_is_public_without_an_attached_access_store() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind listener");
    let base = format!("http://127.0.0.1:{}", listener.local_addr().expect("listener address").port());
    let config = GatewayConfig {
        issuer: base.clone(),
        resource: format!("{base}/api"),
        mode: GatewayMode::LoopbackDemo,
        google: GoogleOidcConfig {
            client_id: GOOGLE_CLIENT.into(),
            client_secret: "fixture-secret".into(),
            issuer: Issuer::new("https://accounts.google.com").expect("Google issuer"),
            scopes: BTreeSet::from(["openid".into(), "email".into()]),
        },
        native_client: NativeClient {
            client_id: "agentpalace-native".into(),
            redirect_uri: "http://127.0.0.1:43127/callback".into(),
        },
    };
    let gateway = Gateway::new(config, Arc::new(DenyAllAdmission) as Arc<dyn AdmissionPolicy>)
        .expect("gateway without policy store");
    tokio::spawn(async move { axum::serve(listener, gateway.router()).await.expect("serve gateway"); });
    let client = reqwest::Client::new();

    let get = client.get(format!("{base}/v1/health")).send().await.expect("GET health");
    assert_eq!(get.status(), StatusCode::OK);
    assert_eq!(get.json::<Value>().await.expect("health JSON"), json!({"status": "ok"}));
    let head = client.head(format!("{base}/v1/health")).send().await.expect("HEAD health");
    assert_eq!(head.status(), StatusCode::OK);
}
