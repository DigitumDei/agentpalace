//! Provider-neutral OAuth discovery and native-client primitives.
//!
//! This module deliberately contains no provider names or provider-specific assumptions. It
//! handles the metadata and PKCE/state invariants that are common to standards-compliant
//! protected resources. Token persistence is injected through [`TokenStore`]; the default
//! in-memory store is explicit and is never serialized or logged.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use agentpalace_config::OAuthLoginMode;

/// Public client configuration for an OAuth native application.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthConfig {
    /// Registered public client identifier.
    pub client_id: String,
    /// Optional account label used to isolate multiple grants.
    #[serde(default)]
    pub account: Option<String>,
    /// Explicitly permit volatile in-memory credentials instead of an OS credential store.
    #[serde(default)]
    pub allow_in_memory: bool,
    /// Explicitly allow the exact configured loopback origin for standards-compliant test issuers.
    #[serde(default)]
    pub allow_loopback_demo: bool,
    /// Login transport selected for interactive authorization.
    #[serde(default)]
    pub login_mode: OAuthLoginMode,
    /// Optional host-provided secure credential backend. This is intentionally skipped by
    /// serde: credential implementations and secrets never belong in config files.
    #[serde(skip)]
    pub token_store: Option<SharedTokenStore>,
    /// Optional absolute login timeout (defaults to five minutes).
    #[serde(default = "default_login_timeout_seconds")]
    pub login_timeout_seconds: u64,
}

fn default_login_timeout_seconds() -> u64 { 300 }

/// RFC 9728 protected-resource metadata.
#[derive(Debug, Clone, Deserialize)]
pub struct ProtectedResourceMetadata {
    pub resource: String,
    #[serde(default)]
    pub authorization_servers: Vec<String>,
}

/// RFC 8414 authorization-server metadata.
#[derive(Debug, Clone, Deserialize)]
pub struct AuthorizationServerMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    #[serde(default)]
    pub revocation_endpoint: Option<String>,
    #[serde(default)]
    pub device_authorization_endpoint: Option<String>,
}

#[derive(Deserialize)]
struct DeviceAuthorizationResponse {
    device_code: String,
    user_code: String,
    #[serde(alias = "verification_url")]
    verification_uri: String,
    #[serde(default)]
    #[serde(rename = "verification_uri_complete")]
    _verification_uri_complete: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    interval: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct OAuthErrorResponse {
    error: String,
}

/// Extract the resource-metadata URL from a Bearer challenge without treating arbitrary
/// authentication parameters as URLs. The value is returned opaque and is validated only by
/// the discovery caller.
pub(crate) fn resource_metadata_from_challenge(value: &str) -> Option<String> {
    let lower = value.to_ascii_lowercase();
    let start = lower.find("resource_metadata=")? + "resource_metadata=".len();
    let rest = value.get(start..)?.trim_start();
    if let Some(quoted) = rest.strip_prefix('"') {
        return quoted.split_once('"').map(|(url, _)| url.to_owned());
    }
    rest.split([',', ' ']).next().filter(|url| !url.is_empty()).map(str::to_owned)
}

/// Access and rotating refresh credentials. This type intentionally has no `Display` impl.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthSession {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub expires_at: Option<u64>,
    pub resource: String,
    pub issuer: String,
    pub client_id: String,
    #[serde(default)]
    pub account: Option<String>,
}

/// Storage boundary for credentials. Implementations must scope records by all session identity
/// fields and must not use ordinary config files for secret material.
#[async_trait::async_trait]
pub trait TokenStore: Send + Sync + std::fmt::Debug {
    async fn load(&self, resource: &str, issuer: &str, client_id: &str, account: Option<&str>) -> Option<OAuthSession>;
    async fn save(&self, session: OAuthSession) -> Result<(), String>;
    async fn clear(&self, resource: &str, issuer: &str, client_id: &str, account: Option<&str>);
}

/// Explicit volatile credential storage for offline/test use.
#[derive(Debug, Default)]
pub struct InMemoryTokenStore(Mutex<Option<OAuthSession>>);

/// A store used when the host has no configured OS credential backend. It makes the failure
/// explicit instead of silently persisting tokens in a config file or process arguments.
#[derive(Debug, Default)]
pub struct UnavailableTokenStore;

/// A local persistent store for CLI/native clients. The file is created with owner-only
/// permissions where the platform supports them and is never included in config or output.
/// Applications with a stronger OS credential facility should inject that facility instead.
#[derive(Debug)]
pub struct FileTokenStore {
    path: PathBuf,
    lock: Mutex<()>,
}

impl FileTokenStore {
    /// Create a store at `path`, creating its parent directory on first save.
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self { path: path.as_ref().to_path_buf(), lock: Mutex::new(()) }
    }

    async fn read_all(&self) -> Vec<OAuthSession> {
        let _guard = self.lock.lock().await;
        let Ok(bytes) = std::fs::read(&self.path) else { return Vec::new() };
        serde_json::from_slice(&bytes).unwrap_or_default()
    }
}

#[async_trait::async_trait]
impl TokenStore for UnavailableTokenStore {
    async fn load(&self, _resource: &str, _issuer: &str, _client_id: &str, _account: Option<&str>) -> Option<OAuthSession> { None }
    async fn save(&self, _session: OAuthSession) -> Result<(), String> {
        Err("secure OS credential storage is unavailable; enable explicit in-memory mode".to_owned())
    }
    async fn clear(&self, _resource: &str, _issuer: &str, _client_id: &str, _account: Option<&str>) {}
}

#[async_trait::async_trait]
impl TokenStore for InMemoryTokenStore {
    async fn load(&self, resource: &str, issuer: &str, client_id: &str, account: Option<&str>) -> Option<OAuthSession> {
        let value = self.0.lock().await.clone()?;
        (value.resource == resource && value.issuer == issuer && value.client_id == client_id && value.account.as_deref() == account).then_some(value)
    }
    async fn save(&self, session: OAuthSession) -> Result<(), String> {
        *self.0.lock().await = Some(session);
        Ok(())
    }
    async fn clear(&self, resource: &str, issuer: &str, client_id: &str, account: Option<&str>) {
        let mut guard = self.0.lock().await;
        if guard.as_ref().is_some_and(|s| s.resource == resource && s.issuer == issuer && s.client_id == client_id && s.account.as_deref() == account) {
            *guard = None;
        }
    }
}

#[async_trait::async_trait]
impl TokenStore for FileTokenStore {
    async fn load(&self, resource: &str, issuer: &str, client_id: &str, account: Option<&str>) -> Option<OAuthSession> {
        self.read_all().await.into_iter().find(|session| session.resource == resource && session.issuer == issuer && session.client_id == client_id && session.account.as_deref() == account)
    }

    async fn save(&self, session: OAuthSession) -> Result<(), String> {
        let _guard = self.lock.lock().await;
        let mut sessions: Vec<OAuthSession> = std::fs::read(&self.path).ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok()).unwrap_or_default();
        sessions.retain(|current| !(current.resource == session.resource && current.issuer == session.issuer && current.client_id == session.client_id && current.account.as_deref() == session.account.as_deref()));
        sessions.push(session);
        let body = serde_json::to_vec(&sessions).map_err(|_| "OAuth credential store could not be encoded".to_owned())?;
        if let Some(parent) = self.path.parent() { std::fs::create_dir_all(parent).map_err(|_| "OAuth credential store directory could not be created".to_owned())?; }
        let temporary = self.path.with_extension("tmp");
        std::fs::write(&temporary, body).map_err(|_| "OAuth credential store could not be written".to_owned())?;
        #[cfg(unix)]
        std::fs::set_permissions(&temporary, std::os::unix::fs::PermissionsExt::from_mode(0o600)).map_err(|_| "OAuth credential store permissions could not be set".to_owned())?;
        std::fs::rename(&temporary, &self.path).map_err(|_| "OAuth credential store could not be committed".to_owned())
    }

    async fn clear(&self, resource: &str, issuer: &str, client_id: &str, account: Option<&str>) {
        let _guard = self.lock.lock().await;
        let Ok(bytes) = std::fs::read(&self.path) else { return };
        let mut sessions: Vec<OAuthSession> = serde_json::from_slice(&bytes).unwrap_or_default();
        sessions.retain(|session| !(session.resource == resource && session.issuer == issuer && session.client_id == client_id && session.account.as_deref() == account));
        if let Ok(body) = serde_json::to_vec(&sessions) { let _ = std::fs::write(&self.path, body); }
    }
}

/// Generate an RFC 7636 verifier and its S256 challenge.
pub fn new_pkce_pair() -> (String, String) {
    let mut bytes = [0_u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    let verifier = URL_SAFE_NO_PAD.encode(bytes);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    (verifier, challenge)
}

/// Generate unpredictable state for the authorization response.
pub fn new_state() -> String {
    let mut bytes = [0_u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Validate that a discovered URL is HTTPS, or is on the exact configured loopback origin.
pub fn validate_oauth_url(raw: &str, configured_origin: &reqwest::Url, allow_loopback_demo: bool) -> Result<reqwest::Url, String> {
    let url = reqwest::Url::parse(raw).map_err(|_| "OAuth metadata contains an invalid URL".to_owned())?;
    if url.scheme() == "https" { return Ok(url); }
    if allow_loopback_demo && url.scheme() == "http" && url.origin() == configured_origin.origin()
        && url.host_str().is_some_and(|h| h == "localhost" || h == "127.0.0.1" || h == "[::1]") {
        return Ok(url);
    }
    Err("OAuth metadata must use HTTPS (only the exact opted-in loopback origin may use HTTP)".to_owned())
}

/// Validate discovery relationships before accepting any endpoint or credential.
pub fn validate_metadata(resource: &ProtectedResourceMetadata, server: &AuthorizationServerMetadata, configured_resource: &reqwest::Url, configured_origin: &reqwest::Url, allow_loopback_demo: bool) -> Result<(), String> {
    let advertised = reqwest::Url::parse(&resource.resource).map_err(|_| "invalid protected resource URL".to_owned())?;
    if advertised != *configured_resource { return Err("protected-resource metadata does not identify the configured remote".to_owned()); }
    let issuer = validate_oauth_url(&server.issuer, configured_origin, allow_loopback_demo)?;
    if !resource.authorization_servers.iter().any(|candidate| candidate.trim_end_matches('/') == server.issuer.trim_end_matches('/')) {
        return Err("authorization-server issuer is not advertised by the protected resource".to_owned());
    }
    let authorization_endpoint = reqwest::Url::parse(&server.authorization_endpoint).map_err(|_| "invalid authorization endpoint".to_owned())?;
    let token_endpoint = reqwest::Url::parse(&server.token_endpoint).map_err(|_| "invalid token endpoint".to_owned())?;
    if issuer.origin() != authorization_endpoint.origin() || issuer.origin() != token_endpoint.origin() {
        return Err("authorization endpoint is unrelated to the discovered issuer".to_owned());
    }
    let _ = validate_oauth_url(&server.authorization_endpoint, configured_origin, allow_loopback_demo)?;
    let _ = validate_oauth_url(&server.token_endpoint, configured_origin, allow_loopback_demo)?;
    if let Some(endpoint) = &server.revocation_endpoint { let _ = validate_oauth_url(endpoint, configured_origin, allow_loopback_demo)?; }
    if let Some(endpoint) = &server.device_authorization_endpoint {
        let device_endpoint = reqwest::Url::parse(endpoint).map_err(|_| "invalid device authorization endpoint".to_owned())?;
        if issuer.origin() != device_endpoint.origin() {
            return Err("device authorization endpoint is unrelated to the discovered issuer".to_owned());
        }
        let _ = validate_oauth_url(endpoint, configured_origin, allow_loopback_demo)?;
    }
    Ok(())
}

/// Check an authorization callback without ever accepting a mismatched or replayed state.
pub fn validate_callback_state(expected: &str, returned: &str) -> Result<(), String> {
    if expected.is_empty() || returned.is_empty() || expected != returned { return Err("OAuth callback state mismatch".to_owned()); }
    Ok(())
}

/// Shared session slot used by a client to single-flight token updates.
pub type SharedTokenStore = Arc<dyn TokenStore>;

/// Return a unix timestamp, useful for bounded expiry checks without exposing credentials.
pub fn now_seconds() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs()) }

/// Default bounded interactive timeout.
pub fn login_timeout(config: &OAuthConfig) -> Duration { Duration::from_secs(config.login_timeout_seconds.clamp(1, 900)) }

/// Resolve automatic login selection after the caller determines whether the
/// browser/callback path is usable.
pub fn select_login_mode(configured: OAuthLoginMode, browser_usable: bool) -> OAuthLoginMode {
    match configured {
        OAuthLoginMode::Auto if browser_usable => OAuthLoginMode::Browser,
        OAuthLoginMode::Auto => OAuthLoginMode::Device,
        mode => mode,
    }
}

/// Return whether this process has the prerequisites for the native browser flow.
///
/// This is deliberately a local capability check: it does not contact the hub and it does not
/// launch a browser. Device mode is therefore selected before any browser side effect when the
/// client is headless (or no platform opener is available).
pub fn browser_callback_usable() -> bool {
    if std::net::TcpListener::bind(("127.0.0.1", 0)).is_err() {
        return false;
    }
    #[cfg(target_os = "windows")]
    { return true; }
    #[cfg(target_os = "macos")]
    { return command_in_path("open"); }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        std::env::var_os("BROWSER").is_some_and(|value| !value.is_empty()) || command_in_path("xdg-open")
    }
}

#[cfg(unix)]
fn command_in_path(command: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else { return false };
    std::env::split_paths(&path).any(|dir| dir.join(command).is_file())
}

/// Fetch and validate protected-resource and authorization-server metadata. Redirects are not
/// followed, so a malicious metadata endpoint cannot silently move discovery to another origin.
pub async fn discover_metadata(
    http: &reqwest::Client,
    metadata_url: &str,
    configured_resource: &reqwest::Url,
    configured_origin: &reqwest::Url,
    allow_loopback_demo: bool,
) -> Result<(ProtectedResourceMetadata, AuthorizationServerMetadata), String> {
    let metadata_url = validate_oauth_url(metadata_url, configured_origin, allow_loopback_demo)?;
    let protected = http.get(metadata_url).send().await.map_err(|_| "protected-resource metadata is unreachable".to_owned())?
        .error_for_status().map_err(|_| "protected-resource metadata was rejected".to_owned())?
        .json::<ProtectedResourceMetadata>().await.map_err(|_| "protected-resource metadata is malformed".to_owned())?;
    let issuer = protected.authorization_servers.first().ok_or_else(|| "protected-resource metadata advertises no authorization server".to_owned())?;
    let issuer_url = validate_oauth_url(issuer, configured_origin, allow_loopback_demo)?;
    let server_url = well_known_url(&issuer_url)?;
    let server = http.get(server_url).send().await.map_err(|_| "authorization-server metadata is unreachable".to_owned())?
        .error_for_status().map_err(|_| "authorization-server metadata was rejected".to_owned())?
        .json::<AuthorizationServerMetadata>().await.map_err(|_| "authorization-server metadata is malformed".to_owned())?;
    validate_metadata(&protected, &server, configured_resource, configured_origin, allow_loopback_demo)?;
    Ok((protected, server))
}

/// Build the native-client authorization request. Only public protocol parameters are placed in
/// the URL; access and refresh credentials never are.
pub fn authorization_url(
    metadata: &AuthorizationServerMetadata,
    config: &OAuthConfig,
    redirect_uri: &str,
    state: &str,
    challenge: &str,
    resource: &str,
    allow_loopback_demo: bool,
) -> Result<reqwest::Url, String> {
    let resource_url = reqwest::Url::parse(resource).map_err(|_| "invalid resource URL".to_owned())?;
    let mut url = validate_oauth_url(&metadata.authorization_endpoint, &resource_url, allow_loopback_demo)?;
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &config.client_id)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("code_challenge", challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("state", state)
        .append_pair("resource", resource);
    Ok(url)
}

/// Run one bounded native browser login. Callers decide whether this function is appropriate;
/// unattended/background requests must return [`RemoteError::AuthenticationRequired`] instead.
pub async fn browser_login(
    http: &reqwest::Client,
    metadata: &AuthorizationServerMetadata,
    config: &OAuthConfig,
    resource: &str,
) -> Result<OAuthSession, String> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.map_err(|_| "cannot bind the loopback OAuth callback".to_owned())?;
    let port = listener.local_addr().map_err(|_| "cannot determine loopback callback port".to_owned())?.port();
    let redirect_uri = format!("http://127.0.0.1:{port}/callback");
    let (verifier, challenge) = new_pkce_pair();
    let state = new_state();
    let url = authorization_url(metadata, config, &redirect_uri, &state, &challenge, resource, config.allow_loopback_demo)?;
    open_browser(url.as_str())?;
    let result = tokio::time::timeout(login_timeout(config), async {
        let (mut socket, _) = listener.accept().await.map_err(|_| "OAuth callback was not accepted".to_owned())?;
        let mut bytes = vec![0_u8; 8192];
        let count = tokio::io::AsyncReadExt::read(&mut socket, &mut bytes).await.map_err(|_| "OAuth callback could not be read".to_owned())?;
        let request = std::str::from_utf8(&bytes[..count]).map_err(|_| "OAuth callback was not valid HTTP".to_owned())?;
        let target = request.lines().next().and_then(|line| line.split_whitespace().nth(1)).ok_or_else(|| "OAuth callback request was malformed".to_owned())?;
        let callback = reqwest::Url::parse(&format!("http://127.0.0.1{target}")).map_err(|_| "OAuth callback URL was malformed".to_owned())?;
        if callback.path() != "/callback" || callback.host_str() != Some("127.0.0.1") { return Err("OAuth callback was outside the constrained loopback path".to_owned()); }
        let returned_state = callback.query_pairs().find(|(key, _)| key == "state").map(|(_, value)| value.into_owned()).unwrap_or_default();
        validate_callback_state(&state, &returned_state)?;
        let code = callback.query_pairs().find(|(key, _)| key == "code").map(|(_, value)| value.into_owned()).ok_or_else(|| "OAuth consent did not return an authorization code".to_owned())?;
        let body = http.post(&metadata.token_endpoint).form(&[
            ("grant_type", "authorization_code"), ("client_id", config.client_id.as_str()),
            ("code", code.as_str()), ("redirect_uri", redirect_uri.as_str()),
            ("code_verifier", verifier.as_str()), ("resource", resource),
        ]).send().await.map_err(|_| "OAuth token exchange was unreachable".to_owned())?
            .error_for_status().map_err(|_| "OAuth token exchange was rejected".to_owned())?
            .json::<TokenResponse>().await.map_err(|_| "OAuth token response was malformed".to_owned())?;
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 24\r\nContent-Type: text/plain\r\n\r\nLogin complete; you may close this window.";
        let _ = tokio::io::AsyncWriteExt::write_all(&mut socket, response).await;
        Ok::<_, String>(OAuthSession { access_token: body.access_token, refresh_token: body.refresh_token, expires_at: body.expires_in.map(|seconds| now_seconds().saturating_add(seconds)), resource: resource.to_owned(), issuer: metadata.issuer.clone(), client_id: config.client_id.clone(), account: config.account.clone() })
    }).await.map_err(|_| "OAuth login timed out".to_owned())??;
    Ok(result)
}

/// Run RFC 8628 device authorization without exposing the private device code.
pub async fn device_login(
    http: &reqwest::Client,
    metadata: &AuthorizationServerMetadata,
    config: &OAuthConfig,
    resource: &str,
) -> Result<OAuthSession, String> {
    let endpoint = metadata.device_authorization_endpoint.as_deref()
        .ok_or_else(|| "the authorization server does not advertise device authorization".to_owned())?;
    let endpoint = validate_oauth_url(endpoint, &reqwest::Url::parse(resource).map_err(|_| "invalid resource URL".to_owned())?, config.allow_loopback_demo)?;
    let response = http.post(endpoint).form(&[
        ("client_id", config.client_id.as_str()), ("resource", resource),
    ]).send().await.map_err(|_| "device authorization endpoint is unreachable".to_owned())?;
    let status = response.status();
    let bytes = response.bytes().await.map_err(|_| "device authorization response could not be read".to_owned())?;
    if !status.is_success() {
        let error = serde_json::from_slice::<OAuthErrorResponse>(&bytes).map(|body| body.error).unwrap_or_else(|_| "device authorization was rejected".to_owned());
        return Err(format!("device authorization failed: {error}"));
    }
    let grant: DeviceAuthorizationResponse = serde_json::from_slice(&bytes).map_err(|_| "device authorization response was malformed".to_owned())?;
    // These are the only values suitable for a user-facing device prompt. The device_code is
    // intentionally never formatted, logged, or returned by this function.
    eprintln!("Open {} and enter code {}.", grant.verification_uri, grant.user_code);
    let deadline = tokio::time::Instant::now() + login_timeout(config).min(Duration::from_secs(grant.expires_in.unwrap_or(900)));
    let mut interval = Duration::from_secs(grant.interval.unwrap_or(5).clamp(1, 60));
    loop {
        tokio::time::sleep(interval).await;
        if tokio::time::Instant::now() >= deadline { return Err("device authorization expired".to_owned()); }
        let response = http.post(&metadata.token_endpoint).form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("device_code", grant.device_code.as_str()), ("client_id", config.client_id.as_str()),
            ("resource", resource),
        ]).send().await;
        let response = match response {
            Ok(response) => response,
            Err(_) => {
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                interval = (interval * 2).min(Duration::from_secs(8)).min(remaining);
                continue;
            }
        };
        let status = response.status();
        let bytes = response.bytes().await.map_err(|_| "device token response could not be read".to_owned())?;
        if status.is_success() {
            let body: TokenResponse = serde_json::from_slice(&bytes).map_err(|_| "device token response was malformed".to_owned())?;
            return Ok(OAuthSession { access_token: body.access_token, refresh_token: body.refresh_token, expires_at: body.expires_in.map(|seconds| now_seconds().saturating_add(seconds)), resource: resource.to_owned(), issuer: metadata.issuer.clone(), client_id: config.client_id.clone(), account: config.account.clone() });
        }
        let error = serde_json::from_slice::<OAuthErrorResponse>(&bytes).map(|body| body.error).unwrap_or_default();
        match error.as_str() {
            "authorization_pending" => {}
            "slow_down" => interval = (interval + Duration::from_secs(5)).min(Duration::from_secs(60)),
            "expired_token" => return Err("device authorization expired".to_owned()),
            "access_denied" | "authorization_denied" => return Err("device authorization was denied".to_owned()),
            "invalid_grant" | "invalid_request" => return Err("device authorization code was rejected or already used".to_owned()),
            _ if status.is_client_error() => return Err("device authorization was rejected".to_owned()),
            _ => {
                interval = (interval * 2).min(Duration::from_secs(8));
            }
        }
    }
}

/// RFC 8414 §3.1 discovery URL. For a path-based issuer, the well-known
/// component is inserted immediately after the authority and the issuer path
/// follows it (for example `/tenant` becomes `/.well-known/oauth-authorization-server/tenant`).
pub fn well_known_url(issuer: &reqwest::Url) -> Result<reqwest::Url, String> {
    let mut url = issuer.clone();
    let path = issuer.path().trim_matches('/');
    let suffix = if path.is_empty() {
        "/.well-known/oauth-authorization-server".to_owned()
    } else {
        format!("/.well-known/oauth-authorization-server/{path}")
    };
    url.set_path(&suffix);
    Ok(url)
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)] refresh_token: Option<String>,
    #[serde(default)] expires_in: Option<u64>,
}

fn open_browser(url: &str) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    let command = ("cmd", vec!["/C", "start", "", url]);
    #[cfg(target_os = "macos")]
    let command = ("open", vec![url]);
    #[cfg(all(unix, not(target_os = "macos")))]
    let command = ("xdg-open", vec![url]);
    std::process::Command::new(command.0).args(command.1).spawn().map(|_| ()).map_err(|_| "cannot open the system browser; use an explicit headless login mode".to_owned())
}

/// Exchange a rotating refresh token once. The caller replaces the stored session with the
/// returned session; a failed exchange must clear the old refresh token rather than retrying it.
pub async fn refresh(
    http: &reqwest::Client,
    metadata: &AuthorizationServerMetadata,
    session: &OAuthSession,
) -> Result<OAuthSession, String> {
    let refresh_token = session.refresh_token.as_deref().ok_or_else(|| "OAuth session has no refresh token".to_owned())?;
    let body = http.post(&metadata.token_endpoint).form(&[
        ("grant_type", "refresh_token"), ("refresh_token", refresh_token),
        ("client_id", session.client_id.as_str()), ("resource", session.resource.as_str()),
    ]).send().await.map_err(|_| "OAuth refresh was unreachable".to_owned())?
        .error_for_status().map_err(|_| "OAuth refresh was rejected; reauthorization is required".to_owned())?
        .json::<TokenResponse>().await.map_err(|_| "OAuth refresh response was malformed".to_owned())?;
    Ok(OAuthSession { access_token: body.access_token, refresh_token: body.refresh_token.or_else(|| Some(refresh_token.to_owned())), expires_at: body.expires_in.map(|seconds| now_seconds().saturating_add(seconds)), ..session.clone() })
}

/// Revoke a grant where the issuer advertises RFC 7009 revocation.
pub async fn revoke(http: &reqwest::Client, metadata: &AuthorizationServerMetadata, session: &OAuthSession) -> Result<(), String> {
    let endpoint = metadata.revocation_endpoint.as_deref().ok_or_else(|| "the authorization server does not advertise revocation".to_owned())?;
    http.post(endpoint).form(&[("token", session.refresh_token.as_deref().unwrap_or(&session.access_token)), ("client_id", session.client_id.as_str())]).send().await
        .map_err(|_| "OAuth revocation was unreachable".to_owned())?.error_for_status().map(|_| ()).map_err(|_| "OAuth revocation was rejected".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, body::Body, extract::State, http::{StatusCode, Uri}, response::Response, routing::post};
    use std::collections::VecDeque;
    use std::sync::Arc;
    #[test]
    fn pkce_is_s256_and_state_is_unpredictable() {
        let (verifier, challenge) = new_pkce_pair();
        assert_eq!(challenge, URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())));
        assert_ne!(new_state(), new_state());
    }
    #[test]
    fn callback_state_rejects_replay_or_mismatch() {
        assert!(validate_callback_state("a", "a").is_ok());
        assert!(validate_callback_state("a", "b").is_err());
        assert!(validate_callback_state("a", "").is_err());
    }

    #[test]
    fn well_known_url_preserves_path_based_issuer() {
        let issuer = reqwest::Url::parse("https://issuer.example/tenant1").expect("test URL");
        assert_eq!(
            well_known_url(&issuer).expect("well-known URL").as_str(),
            "https://issuer.example/.well-known/oauth-authorization-server/tenant1"
        );
    }

    #[test]
    fn automatic_login_mode_only_selects_device_when_browser_is_unusable() {
        assert_eq!(select_login_mode(OAuthLoginMode::Auto, true), OAuthLoginMode::Browser);
        assert_eq!(select_login_mode(OAuthLoginMode::Auto, false), OAuthLoginMode::Device);
        assert_eq!(select_login_mode(OAuthLoginMode::Device, true), OAuthLoginMode::Device);
        assert_eq!(select_login_mode(OAuthLoginMode::Browser, false), OAuthLoginMode::Browser);
    }

    #[test]
    fn browser_capability_check_does_not_launch_a_process() {
        let _ = browser_callback_usable();
    }
    #[test]
    fn metadata_rejects_resource_and_endpoint_mismatch() {
        let resource = reqwest::Url::parse("https://hub.example").expect("test URL");
        let origin = resource.clone();
        let protected = ProtectedResourceMetadata { resource: "https://other.example".to_owned(), authorization_servers: vec!["https://issuer.example".to_owned()] };
        let server = AuthorizationServerMetadata { issuer: "https://issuer.example".to_owned(), authorization_endpoint: "https://issuer.example/authorize".to_owned(), token_endpoint: "https://issuer.example/token".to_owned(), revocation_endpoint: None, device_authorization_endpoint: None };
        assert!(validate_metadata(&protected, &server, &resource, &origin, false).is_err());
    }

    #[test]
    fn device_endpoint_is_checked_like_other_oauth_endpoints() {
        let resource = reqwest::Url::parse("https://hub.example").expect("test URL");
        let protected = ProtectedResourceMetadata { resource: resource.to_string(), authorization_servers: vec!["https://issuer.example".to_owned()] };
        let server = AuthorizationServerMetadata {
            issuer: "https://issuer.example".to_owned(),
            authorization_endpoint: "https://issuer.example/authorize".to_owned(),
            token_endpoint: "https://issuer.example/token".to_owned(),
            revocation_endpoint: None,
            device_authorization_endpoint: Some("http://issuer.example/device".to_owned()),
        };
        assert!(validate_metadata(&protected, &server, &resource, &resource, false).is_err());
    }

    #[test]
    fn device_endpoint_must_share_issuer_origin() {
        let resource = reqwest::Url::parse("https://hub.example").expect("test URL");
        let protected = ProtectedResourceMetadata { resource: resource.to_string(), authorization_servers: vec!["https://issuer.example".to_owned()] };
        let server = AuthorizationServerMetadata {
            issuer: "https://issuer.example".to_owned(),
            authorization_endpoint: "https://issuer.example/authorize".to_owned(),
            token_endpoint: "https://issuer.example/token".to_owned(),
            revocation_endpoint: None,
            device_authorization_endpoint: Some("https://unrelated.example/device".to_owned()),
        };
        assert!(validate_metadata(&protected, &server, &resource, &resource, false).is_err());
    }
    #[test]
    fn non_loopback_http_is_rejected() {
        let origin = reqwest::Url::parse("https://hub.example").expect("test URL");
        assert!(validate_oauth_url("http://issuer.example/token", &origin, true).is_err());
    }
    #[test]
    fn well_known_preserves_path_based_issuer() {
        let issuer = reqwest::Url::parse("https://issuer.example/tenant-a").expect("test URL");
        assert_eq!(well_known_url(&issuer).expect("well-known URL").as_str(), "https://issuer.example/.well-known/oauth-authorization-server/tenant-a");
    }
    #[test]
    fn loopback_demo_requires_explicit_opt_in() {
        let origin = reqwest::Url::parse("http://127.0.0.1:8765").expect("test URL");
        assert!(validate_oauth_url("http://127.0.0.1:8765/token", &origin, true).is_ok());
        assert!(validate_oauth_url("http://127.0.0.1:8766/token", &origin, true).is_err());
        assert!(validate_oauth_url("http://127.0.0.1:8765/token", &origin, false).is_err());
    }
    #[tokio::test]
    async fn volatile_store_is_scoped_and_unavailable_store_is_explicit() {
        let store = InMemoryTokenStore::default();
        let session = OAuthSession { access_token: "access".to_owned(), refresh_token: None, expires_at: None, resource: "https://resource".to_owned(), issuer: "https://issuer".to_owned(), client_id: "client".to_owned(), account: None };
        store.save(session.clone()).await.expect("volatile store");
        assert!(store.load("https://resource", "https://issuer", "client", None).await.is_some());
        assert!(store.load("https://other", "https://issuer", "client", None).await.is_none());
        assert!(UnavailableTokenStore.save(session).await.is_err());
    }

    #[tokio::test]
    async fn file_store_survives_client_process_boundaries_and_clears() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("oauth_tokens.json");
        let session = OAuthSession { access_token: "access".to_owned(), refresh_token: Some("refresh".to_owned()), expires_at: None, resource: "https://resource".to_owned(), issuer: "https://issuer".to_owned(), client_id: "client".to_owned(), account: None };
        FileTokenStore::new(&path).save(session.clone()).await.expect("file store");
        let other = OAuthSession { issuer: "https://other-issuer".to_owned(), access_token: "other-access".to_owned(), ..session.clone() };
        FileTokenStore::new(&path).save(other).await.expect("second issuer");
        assert_eq!(FileTokenStore::new(&path).load("https://resource", "https://issuer", "client", None).await.map(|s| s.access_token), Some("access".to_owned()));
        FileTokenStore::new(&path).clear("https://resource", "https://issuer", "client", None).await;
        assert!(FileTokenStore::new(&path).load("https://resource", "https://issuer", "client", None).await.is_none());
        assert_eq!(FileTokenStore::new(&path).load("https://resource", "https://other-issuer", "client", None).await.map(|s| s.access_token), Some("other-access".to_owned()));
    }

    async fn device_server(responses: Vec<(StatusCode, &'static str)>) -> (String, Arc<Mutex<VecDeque<(StatusCode, &'static str)>>>, tokio::task::JoinHandle<()>) {
        let state = Arc::new(Mutex::new(responses.into_iter().collect::<VecDeque<_>>()));
        let app = Router::new().route("/device", post(mock_device)).route("/token", post(mock_device)).with_state(state.clone());
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.expect("mock listener");
        let address = listener.local_addr().expect("mock address");
        let task = tokio::spawn(async move { axum::serve(listener, app).await.expect("mock server"); });
        (format!("http://{address}"), state, task)
    }

    async fn mock_device(State(state): State<Arc<Mutex<VecDeque<(StatusCode, &'static str)>>>>, _uri: Uri) -> Response<Body> {
        let body = state.lock().await.pop_front().unwrap_or((StatusCode::INTERNAL_SERVER_ERROR, "{}"));
        Response::builder().status(body.0).header("content-type", "application/json").body(Body::from(body.1)).expect("mock response")
    }

    fn device_metadata(origin: &str) -> AuthorizationServerMetadata {
        AuthorizationServerMetadata { issuer: origin.to_owned(), authorization_endpoint: format!("{origin}/authorize"), token_endpoint: format!("{origin}/token"), revocation_endpoint: None, device_authorization_endpoint: Some(format!("{origin}/device")) }
    }

    fn device_config(timeout: u64) -> OAuthConfig {
        OAuthConfig { client_id: "client".to_owned(), account: None, allow_in_memory: true, allow_loopback_demo: true, login_mode: OAuthLoginMode::Device, token_store: None, login_timeout_seconds: timeout }
    }

    #[tokio::test]
    async fn device_login_polls_pending_then_succeeds_without_returning_device_code() {
        let (origin, _state, task) = device_server(vec![
            (StatusCode::OK, r#"{"device_code":"private-device-code","user_code":"ABCD-EFGH","verification_uri":"https://issuer.example/verify","expires_in":30,"interval":1}"#),
            (StatusCode::BAD_REQUEST, r#"{"error":"authorization_pending"}"#),
            (StatusCode::OK, r#"{"access_token":"access-token","refresh_token":"refresh-token","expires_in":60}"#),
        ]).await;
        let result = device_login(&reqwest::Client::new(), &device_metadata(&origin), &device_config(5), &origin).await.expect("device login");
        assert_eq!(result.access_token, "access-token");
        assert_eq!(result.refresh_token.as_deref(), Some("refresh-token"));
        assert!(!format!("{result:?}").contains("private-device-code"));
        task.abort();
    }

    #[tokio::test]
    async fn device_login_reports_denial_and_reused_code() {
        for error in ["access_denied", "invalid_grant"] {
            let (origin, _state, task) = device_server(vec![
                (StatusCode::OK, r#"{"device_code":"private","user_code":"ABCD","verification_uri":"https://issuer.example/verify","expires_in":30,"interval":1}"#),
                (StatusCode::BAD_REQUEST, if error == "access_denied" { r#"{"error":"access_denied"}"# } else { r#"{"error":"invalid_grant"}"# }),
            ]).await;
            let result = device_login(&reqwest::Client::new(), &device_metadata(&origin), &device_config(5), &origin).await;
            let message = result.expect_err("device login should fail").to_string();
            assert!(!message.contains("private"));
            assert!(message.contains(if error == "access_denied" { "denied" } else { "rejected" }));
            task.abort();
        }
    }

    #[tokio::test]
    async fn device_login_bounds_slow_down_and_expiry() {
        let (origin, state, task) = device_server(vec![
            (StatusCode::OK, r#"{"device_code":"private","user_code":"ABCD","verification_uri":"https://issuer.example/verify","expires_in":30,"interval":1}"#),
            (StatusCode::BAD_REQUEST, r#"{"error":"slow_down"}"#),
        ]).await;
        let result = device_login(&reqwest::Client::new(), &device_metadata(&origin), &device_config(1), &origin).await;
        assert!(result.expect_err("short device timeout").contains("expired"));
        assert_eq!(state.lock().await.len(), 1);
        task.abort();
    }

    #[tokio::test]
    async fn device_login_rejects_issuers_without_device_support() {
        let metadata = AuthorizationServerMetadata { issuer: "https://issuer.example".to_owned(), authorization_endpoint: "https://issuer.example/authorize".to_owned(), token_endpoint: "https://issuer.example/token".to_owned(), revocation_endpoint: None, device_authorization_endpoint: None };
        let error = device_login(&reqwest::Client::new(), &metadata, &device_config(1), "https://issuer.example").await.expect_err("unsupported device flow");
        assert!(error.contains("does not advertise device authorization"));
    }

    #[tokio::test]
    async fn device_login_bounds_transient_network_retry() {
        let (origin, _state, task) = device_server(vec![
            (StatusCode::OK, r#"{"device_code":"private","user_code":"ABCD","verification_uri":"https://issuer.example/verify","expires_in":30,"interval":1}"#),
        ]).await;
        let mut metadata = device_metadata(&origin);
        metadata.token_endpoint = "http://127.0.0.1:1/token".to_owned();
        let error = device_login(&reqwest::Client::new(), &metadata, &device_config(3), &origin).await.expect_err("network retry should expire");
        assert!(error.contains("expired"));
        task.abort();
    }
}
