//! Interactive authorization for OAuth federation remotes exposed through MCP.
//! A desktop host opens the system browser and returns its public authorization URL as a
//! fallback. A headless host, or one whose browser cannot be opened, uses device authorization.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use agentpalace_remote::{LoginInteraction, OAuthLoginMode, RemoteClient, SystemLoginInteraction};
use serde_json::{Value, json};
use tokio::sync::{Mutex, oneshot};
use tokio::task::JoinHandle;

#[derive(Clone)]
enum AuthPrompt {
    Browser { authorization_url: String },
    Device { verification_uri: String, user_code: String },
}

struct PromptInteraction {
    sender: StdMutex<Option<oneshot::Sender<AuthPrompt>>>,
    browser_opener: Arc<dyn LoginInteraction>,
    browser_open_failed: AtomicBool,
}

impl std::fmt::Debug for PromptInteraction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PromptInteraction")
    }
}

impl LoginInteraction for PromptInteraction {
    fn open_browser(&self, url: &str) -> Result<(), String> {
        if let Err(error) = self.browser_opener.open_browser(url) {
            self.browser_open_failed.store(true, Ordering::SeqCst);
            return Err(error);
        }
        if let Some(sender) = self.sender.lock().expect("prompt lock poisoned").take() {
            let _ = sender.send(AuthPrompt::Browser { authorization_url: url.to_owned() });
        }
        Ok(())
    }

    fn show_device_code(&self, verification_uri: &str, user_code: &str) {
        if let Some(sender) = self.sender.lock().expect("prompt lock poisoned").take() {
            let _ = sender.send(AuthPrompt::Device {
                verification_uri: verification_uri.to_owned(),
                user_code: user_code.to_owned(),
            });
        }
    }
}

struct AuthFlow {
    prompt: AuthPrompt,
    task: JoinHandle<agentpalace_remote::Result<()>>,
}

/// A cancelled MCP request must not leave an untracked login polling in the background.
struct AbortOnDrop(Option<tokio::task::AbortHandle>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            handle.abort();
        }
    }
}

/// One in-flight login per named remote. Later calls inspect the same flow rather than
/// opening more browser tabs or issuing more device codes.
pub struct RemoteAuth {
    clients: BTreeMap<String, Arc<RemoteClient>>,
    flows: Mutex<BTreeMap<String, AuthFlow>>,
    start_gates: BTreeMap<String, Mutex<()>>,
    browser_opener: Arc<dyn LoginInteraction>,
}

impl std::fmt::Debug for RemoteAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteAuth").field("remotes", &self.clients.keys()).finish()
    }
}

impl RemoteAuth {
    pub fn new(clients: BTreeMap<String, Arc<RemoteClient>>) -> Self {
        Self::with_browser_opener(clients, Arc::new(SystemLoginInteraction))
    }

    fn with_browser_opener(
        clients: BTreeMap<String, Arc<RemoteClient>>,
        browser_opener: Arc<dyn LoginInteraction>,
    ) -> Self {
        let start_gates = clients.keys().map(|name| (name.clone(), Mutex::new(()))).collect();
        Self {
            clients,
            flows: Mutex::new(BTreeMap::new()),
            start_gates,
            browser_opener,
        }
    }

    pub async fn start(&self, name: &str) -> Result<Value, String> {
        let client = self
            .clients
            .get(name)
            .ok_or_else(|| format!("remote `{name}` is not configured for OAuth"))?
            .clone();
        let gate = self.start_gates.get(name).ok_or_else(|| format!("remote `{name}` has no sign-in gate"))?;
        let _guard = gate.lock().await;
        if let Some(prompt) = self.flows.lock().await.get(name).map(|flow| flow.prompt.clone()) {
            return Ok(prompt_value(name, &prompt));
        }
        let challenge = match client.login_challenge().await {
            Err(error) => return Ok(crate::federation::structured_remote_failure(
                name,
                "remote_auth_start",
                &error,
            )),
            Ok(None) => return Ok(json!({ "remote": name, "status": "authenticated" })),
            Ok(Some(url)) => url,
        };
        let (sender, receiver) = oneshot::channel();
        let interaction = Arc::new(PromptInteraction {
            sender: StdMutex::new(Some(sender)),
            browser_opener: Arc::clone(&self.browser_opener),
            browser_open_failed: AtomicBool::new(false),
        });
        let task = tokio::spawn(async move {
            let first = client
                .login_from_challenge_with_interaction(&challenge, None, Some(interaction.clone()))
                .await;
            if first.is_err() && interaction.browser_open_failed.load(Ordering::SeqCst) {
                client
                    .login_from_challenge_with_interaction(
                        &challenge,
                        Some(OAuthLoginMode::Device),
                        Some(interaction),
                    )
                    .await
            } else {
                first
            }
        });
        let mut abort_on_drop = AbortOnDrop(Some(task.abort_handle()));
        let prompt = match tokio::time::timeout(Duration::from_secs(30), receiver).await {
            Ok(Ok(prompt)) => prompt,
            _ => {
                if task.is_finished() {
                    let result = match task.await {
                        Ok(result) => result,
                        Err(_) => {
                            return Ok(local_auth_failure(
                                name,
                                "remote_auth_start",
                                "remote login task stopped",
                            ));
                        }
                    };
                    return Ok(match result {
                        Ok(()) => local_auth_failure(
                            name,
                            "remote_auth_start",
                            "remote login ended without a device prompt",
                        ),
                        Err(error) => crate::federation::structured_remote_failure(
                            name,
                            "remote_auth_start",
                            &error,
                        ),
                    });
                }
                task.abort();
                return Ok(local_auth_failure(
                    name,
                    "remote_auth_start",
                    "remote did not provide a device prompt within 30 seconds",
                ));
            }
        };
        let response = prompt_value(name, &prompt);
        self.flows.lock().await.insert(name.to_owned(), AuthFlow { prompt, task });
        abort_on_drop.0 = None;
        Ok(response)
    }

    pub async fn status(&self, name: &str) -> Result<Value, String> {
        if !self.clients.contains_key(name) {
            return Err(format!("remote `{name}` is not configured for OAuth"));
        }
        let mut flows = self.flows.lock().await;
        let Some(flow) = flows.get(name) else {
            drop(flows);
            return self.probe_status(name).await;
        };
        if !flow.task.is_finished() {
            return Ok(json!({ "remote": name, "status": "pending" }));
        }
        let flow = flows.remove(name).expect("completed flow exists");
        drop(flows);
        match flow.task.await {
            Ok(Ok(())) => self.probe_status(name).await,
            Ok(Err(error)) => Ok(auth_status_failure(name, &error)),
            Err(_) => Ok(local_auth_failure(
                name,
                "remote_auth_status",
                "remote login task stopped",
            )),
        }
    }

    async fn probe_status(&self, name: &str) -> Result<Value, String> {
        let client = &self.clients[name];
        match client.login_challenge().await {
            Ok(None) => Ok(json!({ "remote": name, "status": "authenticated" })),
            Ok(Some(_)) => Ok(json!({ "remote": name, "status": "not_authenticated" })),
            Err(error) => Ok(auth_status_failure(name, &error)),
        }
    }
}

fn local_auth_failure(name: &str, kind: &str, message: &str) -> Value {
    json!({
        "success": false,
        "outcome": "failed",
        "remote": name,
        "kind": kind,
        "status": "failed",
        "classification": "invalid_response",
        "error": message,
    })
}

fn auth_status_failure(name: &str, error: &agentpalace_remote::RemoteError) -> Value {
    let mut value = crate::federation::structured_remote_failure(
        name,
        "remote_auth_status",
        error,
    );
    value["status"] = json!("failed");
    if matches!(
        error,
        agentpalace_remote::RemoteError::AuthenticationRequired { .. }
            | agentpalace_remote::RemoteError::Unauthorized { .. }
            | agentpalace_remote::RemoteError::RemoteRejected { .. }
    ) {
        value["next"] = json!(format!(
            "Run `agentpalace auth logout --remote {name}` to clear the refused grant, then start sign-in again."
        ));
    }
    value
}

fn prompt_value(name: &str, prompt: &AuthPrompt) -> Value {
    match prompt {
        AuthPrompt::Browser { authorization_url } => json!({
            "remote": name,
            "status": "pending",
            "mode": "browser",
            "authorization_url": authorization_url,
            "next": "Approve in the opened browser. If no tab appeared, open authorization_url manually. Then call agentpalace_remote_auth_status."
        }),
        AuthPrompt::Device { verification_uri, user_code } => json!({
            "remote": name,
            "status": "pending",
            "mode": "device",
            "verification_uri": verification_uri,
            "user_code": user_code,
            "next": "Open verification_uri, enter user_code, then call agentpalace_remote_auth_status."
        }),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use agentpalace_remote::{
        InMemoryTokenStore, LoginInteraction, OAuthConfig, OAuthLoginMode, RemoteClient,
        RemoteEndpoint,
    };
    use axum::extract::State;
    use axum::http::{HeaderMap, StatusCode, header};
    use axum::response::{IntoResponse, Response};
    use axum::routing::{get, post};
    use serde_json::json;

    use super::RemoteAuth;

    #[derive(Clone)]
    struct Issuer {
        base: String,
        device_calls: Arc<AtomicUsize>,
    }

    impl Issuer {
        async fn info(State(this): State<Self>, headers: HeaderMap) -> Response {
            if headers.get(header::AUTHORIZATION).is_some_and(|value| value == "Bearer access") {
                return axum::Json(json!({"federation_api_version":1,"capabilities":["drawers"]}))
                    .into_response();
            }
            let challenge = format!(
                "Bearer resource_metadata=\"{}/.well-known/oauth-protected-resource\"",
                this.base,
            );
            (StatusCode::UNAUTHORIZED, [(header::WWW_AUTHENTICATE, challenge)], "login required")
                .into_response()
        }

        async fn protected(State(this): State<Self>) -> impl IntoResponse {
            axum::Json(json!({
                "resource": format!("{}/", this.base),
                "authorization_servers": [this.base]
            }))
        }

        async fn metadata(State(this): State<Self>) -> impl IntoResponse {
            axum::Json(json!({
                "issuer": this.base,
                "authorization_endpoint": format!("{}/authorize", this.base),
                "token_endpoint": format!("{}/token", this.base),
                "device_authorization_endpoint": format!("{}/device", this.base)
            }))
        }

        async fn device(State(this): State<Self>) -> impl IntoResponse {
            this.device_calls.fetch_add(1, Ordering::SeqCst);
            axum::Json(json!({
                "device_code": "private-device-code",
                "user_code": "PUBLIC-123",
                "verification_uri": format!("{}/verify", this.base),
                "interval": 1,
                "expires_in": 30
            }))
        }

        async fn token() -> impl IntoResponse {
            axum::Json(json!({"access_token":"access","token_type":"Bearer","expires_in":300}))
        }
    }

    #[derive(Debug, Default)]
    struct ScriptedBrowserOpener {
        opens: AtomicUsize,
        preconnect: bool,
    }

    impl LoginInteraction for ScriptedBrowserOpener {
        fn open_browser(&self, url: &str) -> Result<(), String> {
            self.opens.fetch_add(1, Ordering::SeqCst);
            let authorization_url = reqwest::Url::parse(url).map_err(|error| error.to_string())?;
            let parameter = |key| {
                authorization_url
                    .query_pairs()
                    .find(|(name, _)| name == key)
                    .map(|(_, value)| value.into_owned())
                    .ok_or_else(|| format!("missing {key}"))
            };
            let redirect = parameter("redirect_uri")?;
            let state = parameter("state")?;
            let mut callback = reqwest::Url::parse(&redirect).map_err(|error| error.to_string())?;
            callback.query_pairs_mut().append_pair("code", "approved").append_pair("state", &state);
            if self.preconnect {
                let address = format!(
                    "127.0.0.1:{}",
                    callback.port_or_known_default().ok_or("missing callback port")?
                );
                let idle =
                    std::net::TcpStream::connect(address).map_err(|error| error.to_string())?;
                tokio::spawn(async move {
                    let _idle = idle;
                    tokio::time::sleep(Duration::from_secs(30)).await;
                });
            }
            tokio::spawn(async move {
                let _ = reqwest::Client::new().get(callback).send().await;
            });
            Ok(())
        }

        fn show_device_code(&self, _verification_uri: &str, _user_code: &str) {
            panic!("browser test should not request a device code");
        }
    }

    #[derive(Debug, Default)]
    struct UnavailableBrowserOpener {
        opens: AtomicUsize,
    }

    impl LoginInteraction for UnavailableBrowserOpener {
        fn open_browser(&self, _url: &str) -> Result<(), String> {
            self.opens.fetch_add(1, Ordering::SeqCst);
            Err("no desktop browser".to_owned())
        }

        fn show_device_code(&self, _verification_uri: &str, _user_code: &str) {}
    }

    async fn browser_test_remote() -> (Issuer, Arc<RemoteClient>, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let issuer = Issuer { base: base.clone(), device_calls: Arc::new(AtomicUsize::new(0)) };
        let app = axum::Router::new()
            .route("/v1/info", get(Issuer::info))
            .route("/.well-known/oauth-protected-resource", get(Issuer::protected))
            .route("/.well-known/oauth-authorization-server", get(Issuer::metadata))
            .route("/device", post(Issuer::device))
            .route("/token", post(Issuer::token))
            .with_state(issuer.clone());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = Arc::new(
            RemoteClient::new(RemoteEndpoint {
                name: "demo".to_owned(),
                base_url: base,
                token: None,
                oauth: Some(OAuthConfig {
                    client_id: "public-client".to_owned(),
                    account: None,
                    allow_in_memory: true,
                    allow_loopback_demo: true,
                    login_mode: OAuthLoginMode::Browser,
                    token_store: Some(Arc::new(InMemoryTokenStore::default())),
                    interaction: None,
                    login_timeout_seconds: 30,
                }),
                timeout: Duration::from_secs(5),
            })
            .unwrap(),
        );
        (issuer, client, server)
    }

    async fn wait_for_login(auth: &RemoteAuth) -> serde_json::Value {
        for _ in 0..50 {
            let status = auth.status("demo").await.unwrap();
            if status["status"] != "pending" {
                return status;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("login did not finish");
    }

    #[tokio::test]
    async fn slow_remote_sign_in_does_not_block_another_remote() {
        let (_issuer, fast_client, fast_server) = browser_test_remote().await;
        let slow_started = Arc::new(tokio::sync::Notify::new());
        let release_slow = Arc::new(tokio::sync::Notify::new());
        let app = axum::Router::new().route(
            "/v1/info",
            get({
                let slow_started = Arc::clone(&slow_started);
                let release_slow = Arc::clone(&release_slow);
                move || {
                    let slow_started = Arc::clone(&slow_started);
                    let release_slow = Arc::clone(&release_slow);
                    async move {
                        slow_started.notify_one();
                        release_slow.notified().await;
                        StatusCode::UNAUTHORIZED
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let slow_base = format!("http://{}", listener.local_addr().unwrap());
        let slow_server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let slow_client = Arc::new(
            RemoteClient::new(RemoteEndpoint {
                name: "slow".to_owned(),
                base_url: slow_base,
                token: None,
                oauth: Some(OAuthConfig {
                    client_id: "public-client".to_owned(),
                    account: None,
                    allow_in_memory: true,
                    allow_loopback_demo: true,
                    login_mode: OAuthLoginMode::Browser,
                    token_store: Some(Arc::new(InMemoryTokenStore::default())),
                    interaction: None,
                    login_timeout_seconds: 30,
                }),
                timeout: Duration::from_secs(5),
            })
            .unwrap(),
        );
        let auth = Arc::new(RemoteAuth::with_browser_opener(
            [("slow".to_owned(), slow_client), ("demo".to_owned(), fast_client)].into(),
            Arc::new(ScriptedBrowserOpener::default()),
        ));
        let slow_task = {
            let auth = Arc::clone(&auth);
            tokio::spawn(async move { auth.start("slow").await })
        };
        tokio::time::timeout(Duration::from_secs(2), slow_started.notified())
            .await
            .expect("slow remote should enter its challenge request");
        let fast = tokio::time::timeout(Duration::from_secs(2), auth.start("demo")).await;
        release_slow.notify_one();
        let _ = slow_task.await.expect("slow start task");
        assert_eq!(
            fast.expect("other remote should not wait for slow remote").unwrap()["mode"],
            "browser"
        );
        fast_server.abort();
        slow_server.abort();
    }

    #[tokio::test]
    async fn mcp_browser_sign_in_opens_once_and_completes_callback() {
        let (issuer, client, server) = browser_test_remote().await;
        let opener = Arc::new(ScriptedBrowserOpener::default());
        let auth = RemoteAuth::with_browser_opener(
            [(String::from("demo"), client.clone())].into(),
            opener.clone(),
        );
        let prompt = auth.start("demo").await.unwrap();
        assert_eq!(prompt["mode"], "browser");
        assert_eq!(prompt["status"], "pending");
        assert!(
            prompt["authorization_url"]
                .as_str()
                .unwrap()
                .starts_with(&format!("{}/authorize?", issuer.base))
        );
        assert_eq!(auth.start("demo").await.unwrap(), prompt);
        assert_eq!(opener.opens.load(Ordering::SeqCst), 1);
        assert_eq!(issuer.device_calls.load(Ordering::SeqCst), 0);
        assert_eq!(wait_for_login(&auth).await["status"], "authenticated");
        assert!(client.login_challenge().await.unwrap().is_none());
        server.abort();
    }

    #[tokio::test]
    async fn mcp_browser_callback_overtakes_idle_preconnection() {
        let (_issuer, client, server) = browser_test_remote().await;
        let opener =
            Arc::new(ScriptedBrowserOpener { opens: AtomicUsize::new(0), preconnect: true });
        let auth = RemoteAuth::with_browser_opener(
            [(String::from("demo"), client.clone())].into(),
            opener.clone(),
        );
        let prompt = auth.start("demo").await.unwrap();
        assert_eq!(prompt["mode"], "browser");
        assert_eq!(wait_for_login(&auth).await["status"], "authenticated");
        assert_eq!(opener.opens.load(Ordering::SeqCst), 1);
        assert!(client.login_challenge().await.unwrap().is_none());
        server.abort();
    }

    #[tokio::test]
    async fn mcp_browser_launch_failure_falls_back_to_device_code() {
        let (issuer, client, server) = browser_test_remote().await;
        let opener = Arc::new(UnavailableBrowserOpener::default());
        let auth = RemoteAuth::with_browser_opener(
            [(String::from("demo"), client.clone())].into(),
            opener.clone(),
        );
        let prompt = auth.start("demo").await.unwrap();
        assert_eq!(prompt["mode"], "device");
        assert_eq!(prompt["verification_uri"], format!("{}/verify", issuer.base));
        assert_eq!(prompt["user_code"], "PUBLIC-123");
        assert_eq!(opener.opens.load(Ordering::SeqCst), 1);
        assert_eq!(issuer.device_calls.load(Ordering::SeqCst), 1);
        assert_eq!(wait_for_login(&auth).await["status"], "authenticated");
        assert!(client.login_challenge().await.unwrap().is_none());
        server.abort();
    }

    #[tokio::test]
    async fn mcp_device_sign_in_returns_public_prompt_once_and_saves_grant() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let issuer = Issuer { base: base.clone(), device_calls: Arc::new(AtomicUsize::new(0)) };
        let app = axum::Router::new()
            .route("/v1/info", get(Issuer::info))
            .route("/.well-known/oauth-protected-resource", get(Issuer::protected))
            .route("/.well-known/oauth-authorization-server", get(Issuer::metadata))
            .route("/device", post(Issuer::device))
            .route("/token", post(Issuer::token))
            .with_state(issuer.clone());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = Arc::new(
            RemoteClient::new(RemoteEndpoint {
                name: "demo".to_owned(),
                base_url: base.clone(),
                token: None,
                oauth: Some(OAuthConfig {
                    client_id: "public-client".to_owned(),
                    account: None,
                    allow_in_memory: true,
                    allow_loopback_demo: true,
                    login_mode: OAuthLoginMode::Device,
                    token_store: Some(Arc::new(InMemoryTokenStore::default())),
                    interaction: None,
                    login_timeout_seconds: 30,
                }),
                timeout: Duration::from_secs(5),
            })
            .unwrap(),
        );
        let auth = RemoteAuth::new([(String::from("demo"), client.clone())].into());
        let prompt = auth.start("demo").await.unwrap();
        assert_eq!(prompt["status"], "pending");
        assert_eq!(prompt["user_code"], "PUBLIC-123");
        assert_eq!(prompt["verification_uri"], format!("{base}/verify"));
        assert!(!prompt.to_string().contains("private-device-code"));
        assert_eq!(auth.start("demo").await.unwrap(), prompt);
        assert_eq!(issuer.device_calls.load(Ordering::SeqCst), 1);

        let mut final_status = json!({});
        for _ in 0..20 {
            final_status = auth.status("demo").await.unwrap();
            if final_status["status"] != "pending" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(final_status["status"], "authenticated", "{final_status}");
        assert!(client.login_challenge().await.unwrap().is_none());
        assert_eq!(auth.start("demo").await.unwrap()["status"], "authenticated");
        assert_eq!(issuer.device_calls.load(Ordering::SeqCst), 1);
        server.abort();
    }

    #[tokio::test]
    async fn mcp_auth_start_returns_a_structured_failure_instead_of_a_tool_error() {
        let client = Arc::new(
            RemoteClient::new(RemoteEndpoint {
                name: "demo".to_owned(),
                base_url: "http://127.0.0.1:1".to_owned(),
                token: None,
                oauth: Some(OAuthConfig {
                    client_id: "public-client".to_owned(),
                    account: None,
                    allow_in_memory: true,
                    allow_loopback_demo: true,
                    login_mode: OAuthLoginMode::Device,
                    token_store: Some(Arc::new(InMemoryTokenStore::default())),
                    interaction: None,
                    login_timeout_seconds: 1,
                }),
                timeout: Duration::from_millis(100),
            })
            .unwrap(),
        );
        let auth = RemoteAuth::new([("demo".to_owned(), client)].into());

        let result = auth.start("demo").await.expect("failure should be returned as data");
        assert_eq!(result["success"], false);
        assert_eq!(result["outcome"], "failed");
        assert_eq!(result["classification"], "unreachable");
        assert_eq!(result["kind"], "remote_auth_start");
    }

    #[tokio::test]
    async fn mcp_auth_status_reports_a_refused_grant_and_sign_out_guidance() {
        let app = axum::Router::new().route(
            "/v1/info",
            get(|| async {
                (
                    StatusCode::FORBIDDEN,
                    axum::Json(json!({"error": "access_denied"})),
                )
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = Arc::new(
            RemoteClient::new(RemoteEndpoint {
                name: "demo".to_owned(),
                base_url: base,
                token: None,
                oauth: Some(OAuthConfig {
                    client_id: "public-client".to_owned(),
                    account: None,
                    allow_in_memory: true,
                    allow_loopback_demo: true,
                    login_mode: OAuthLoginMode::Device,
                    token_store: Some(Arc::new(InMemoryTokenStore::default())),
                    interaction: None,
                    login_timeout_seconds: 1,
                }),
                timeout: Duration::from_secs(1),
            })
            .unwrap(),
        );
        let auth = RemoteAuth::new([("demo".to_owned(), client)].into());

        let result = auth.status("demo").await.expect("refusal should be returned as data");
        assert_eq!(result["status"], "failed");
        assert_eq!(result["classification"], "rejected");
        assert_eq!(result["http_status"], 403);
        assert!(result["next"].as_str().unwrap().contains("auth logout --remote demo"));
        server.abort();
    }
}
