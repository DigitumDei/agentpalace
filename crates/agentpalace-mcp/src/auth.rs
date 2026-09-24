//! Interactive device authorization for OAuth federation remotes exposed through MCP.
//! The MCP server can run without a visible desktop, so login returns a public verification
//! URI and user code to the caller while the private device code stays in the remote client.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use agentpalace_remote::{LoginInteraction, OAuthLoginMode, RemoteClient};
use serde_json::{Value, json};
use tokio::sync::{Mutex, oneshot};
use tokio::task::JoinHandle;

#[derive(Clone)]
struct DevicePrompt {
    verification_uri: String,
    user_code: String,
}

struct PromptInteraction {
    sender: StdMutex<Option<oneshot::Sender<DevicePrompt>>>,
}

impl std::fmt::Debug for PromptInteraction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PromptInteraction")
    }
}

impl LoginInteraction for PromptInteraction {
    fn open_browser(&self, _url: &str) -> Result<(), String> {
        Err("MCP authorization requires the device flow".to_owned())
    }

    fn show_device_code(&self, verification_uri: &str, user_code: &str) {
        if let Some(sender) = self.sender.lock().expect("prompt lock poisoned").take() {
            let _ = sender.send(DevicePrompt {
                verification_uri: verification_uri.to_owned(),
                user_code: user_code.to_owned(),
            });
        }
    }
}

struct AuthFlow {
    prompt: DevicePrompt,
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

/// One in-flight login per named remote. The first MCP auth request starts RFC 8628; later
/// calls inspect the same flow rather than issuing more device codes.
pub struct RemoteAuth {
    clients: BTreeMap<String, Arc<RemoteClient>>,
    flows: Mutex<BTreeMap<String, AuthFlow>>,
    start_gate: Mutex<()>,
}

impl std::fmt::Debug for RemoteAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteAuth").field("remotes", &self.clients.keys()).finish()
    }
}

impl RemoteAuth {
    pub fn new(clients: BTreeMap<String, Arc<RemoteClient>>) -> Self {
        Self { clients, flows: Mutex::new(BTreeMap::new()), start_gate: Mutex::new(()) }
    }

    pub async fn start(&self, name: &str) -> Result<Value, String> {
        let _guard = self.start_gate.lock().await;
        let client = self
            .clients
            .get(name)
            .ok_or_else(|| format!("remote `{name}` is not configured for OAuth"))?
            .clone();
        if let Some(prompt) = self.flows.lock().await.get(name).map(|flow| flow.prompt.clone()) {
            return Ok(prompt_value(name, &prompt));
        }
        let challenge = match client.login_challenge().await.map_err(|error| error.to_string())? {
            Some(url) => url,
            None => return Ok(json!({ "remote": name, "status": "authenticated" })),
        };
        let (sender, receiver) = oneshot::channel();
        let interaction = Arc::new(PromptInteraction { sender: StdMutex::new(Some(sender)) });
        let task = tokio::spawn(async move {
            client
                .login_from_challenge_with_interaction(
                    &challenge,
                    Some(OAuthLoginMode::Device),
                    Some(interaction),
                )
                .await
        });
        let mut abort_on_drop = AbortOnDrop(Some(task.abort_handle()));
        let prompt = match tokio::time::timeout(Duration::from_secs(30), receiver).await {
            Ok(Ok(prompt)) => prompt,
            _ => {
                if task.is_finished() {
                    let result = task.await.map_err(|_| "remote login task stopped".to_owned())?;
                    return Err(result.err().map_or_else(
                        || "remote login ended without a device prompt".to_owned(),
                        |error| error.to_string(),
                    ));
                }
                task.abort();
                return Err("remote did not provide a device prompt within 30 seconds".to_owned());
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
            Ok(Err(error)) => {
                Ok(json!({ "remote": name, "status": "failed", "error": error.to_string() }))
            }
            Err(_) => {
                Ok(json!({ "remote": name, "status": "failed", "error": "login task stopped" }))
            }
        }
    }

    async fn probe_status(&self, name: &str) -> Result<Value, String> {
        let client = &self.clients[name];
        match client.login_challenge().await {
            Ok(None) => Ok(json!({ "remote": name, "status": "authenticated" })),
            Ok(Some(_)) => Ok(json!({ "remote": name, "status": "not_authenticated" })),
            Err(error) => Err(error.to_string()),
        }
    }
}

fn prompt_value(name: &str, prompt: &DevicePrompt) -> Value {
    json!({
        "remote": name,
        "status": "pending",
        "verification_uri": prompt.verification_uri,
        "user_code": prompt.user_code,
        "next": "Open verification_uri, enter user_code, then call agentpalace_remote_auth_status."
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use agentpalace_remote::{
        InMemoryTokenStore, OAuthConfig, OAuthLoginMode, RemoteClient, RemoteEndpoint,
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
}
