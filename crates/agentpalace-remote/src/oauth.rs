//! Provider-neutral OAuth discovery and native-client primitives.
//!
//! This module deliberately contains no provider names or provider-specific assumptions. It
//! handles the metadata and PKCE/state invariants that are common to standards-compliant
//! protected resources. Token persistence is injected through [`TokenStore`]; the default
//! in-memory store is explicit and is never serialized or logged.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use agentpalace_config::OAuthLoginMode;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

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
    /// Optional host-provided user interaction (browser launch and device-code prompt).
    /// `None` uses [`SystemLoginInteraction`].
    #[serde(skip)]
    pub interaction: Option<Arc<dyn LoginInteraction>>,
    /// Optional absolute login timeout (defaults to five minutes).
    #[serde(default = "default_login_timeout_seconds")]
    pub login_timeout_seconds: u64,
}

fn default_login_timeout_seconds() -> u64 {
    300
}

/// The user-facing side effects of an interactive login. Hosts inject an implementation to
/// present the prompt in their own UI; tests inject one that drives a scripted browser.
pub trait LoginInteraction: Send + Sync + std::fmt::Debug {
    /// Present the authorization URL to the user (normally by launching the system browser).
    fn open_browser(&self, url: &str) -> Result<(), String>;
    /// Present the RFC 8628 verification URI and user code. The private device code is never
    /// passed to this method.
    fn show_device_code(&self, verification_uri: &str, user_code: &str);
}

/// Default interaction: launches the platform browser and prints the device prompt to stderr.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemLoginInteraction;

impl LoginInteraction for SystemLoginInteraction {
    fn open_browser(&self, url: &str) -> Result<(), String> {
        open_browser(url)
    }

    fn show_device_code(&self, verification_uri: &str, user_code: &str) {
        eprintln!("Open {verification_uri} and enter code {user_code}.");
    }
}

fn interaction(config: &OAuthConfig) -> Arc<dyn LoginInteraction> {
    config.interaction.clone().unwrap_or_else(|| Arc::new(SystemLoginInteraction))
}

/// RFC 9728 protected-resource metadata.
#[derive(Debug, Clone, Deserialize)]
pub struct ProtectedResourceMetadata {
    /// Protected resource identifier.
    pub resource: String,
    /// Issuers trusted to mint credentials for the resource.
    #[serde(default)]
    pub authorization_servers: Vec<String>,
}

/// RFC 8414 authorization-server metadata.
#[derive(Debug, Clone, Deserialize)]
pub struct AuthorizationServerMetadata {
    /// Authorization-server issuer identifier.
    pub issuer: String,
    /// Authorization endpoint used by the browser flow.
    pub authorization_endpoint: String,
    /// Token endpoint.
    pub token_endpoint: String,
    /// Optional RFC 7009 revocation endpoint.
    #[serde(default)]
    pub revocation_endpoint: Option<String>,
    /// Optional RFC 8628 device authorization endpoint.
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
#[derive(Clone, Serialize, Deserialize)]
pub struct OAuthSession {
    /// Bearer access token.
    pub access_token: String,
    /// Rotating refresh token, when issued.
    #[serde(default)]
    pub refresh_token: Option<String>,
    /// Access-token expiry as Unix seconds, when the issuer reported one.
    #[serde(default)]
    pub expires_at: Option<u64>,
    /// Exact resource identifier the grant is bound to (as advertised by the resource).
    pub resource: String,
    /// Issuer that minted the grant.
    pub issuer: String,
    /// Public client identifier.
    pub client_id: String,
    /// Optional account partition.
    #[serde(default)]
    pub account: Option<String>,
}

impl std::fmt::Debug for OAuthSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Token material is never formatted, even in debug output.
        formatter
            .debug_struct("OAuthSession")
            .field("resource", &self.resource)
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id)
            .field("account", &self.account)
            .field("expires_at", &self.expires_at)
            .field("has_refresh_token", &self.refresh_token.is_some())
            .finish_non_exhaustive()
    }
}

/// Canonical credential-store key for a resource identifier.
///
/// Resource identity is exact: `https://hub.example/api` and `https://hub.example/api/` are
/// different resources and never share a credential. The only normalization applied is the
/// RFC 3986 syntax normalization performed by URL parsing (scheme/host case, default port, and
/// the empty root path), so `https://hub.example` and `https://hub.example/` name the same
/// record. This is independent of the slash-terminated REST transport base used by
/// `RemoteClient`.
pub fn resource_key(raw: &str) -> String {
    reqwest::Url::parse(raw).map_or_else(|_| raw.to_owned(), |url| url.to_string())
}

fn same_identity(
    session: &OAuthSession,
    resource: &str,
    issuer: &str,
    client_id: &str,
    account: Option<&str>,
) -> bool {
    resource_key(&session.resource) == resource_key(resource)
        && session.issuer == issuer
        && session.client_id == client_id
        && session.account.as_deref() == account
}

/// Why a credential-store operation failed. Absence of a credential is never an error: loads
/// return `Ok(None)` and clears return [`ClearOutcome::Absent`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenStoreErrorKind {
    /// No usable secure backend exists on this host (no keychain/secret service, or the
    /// explicit "unavailable" store).
    Unavailable,
    /// A stored record exists but could not be decoded.
    Corrupt,
    /// The backend was present but the operation failed (I/O, permission, platform error).
    Backend,
}

impl std::fmt::Display for TokenStoreErrorKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "unavailable",
            Self::Corrupt => "corrupt",
            Self::Backend => "backend failure",
        })
    }
}

/// A credential-store failure. Messages never contain credential material.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("credential store {kind}: {message}")]
pub struct TokenStoreError {
    /// Failure classification.
    pub kind: TokenStoreErrorKind,
    /// Safe description of the failure.
    pub message: String,
}

impl TokenStoreError {
    /// No usable backend.
    pub fn unavailable(message: impl Into<String>) -> Self {
        Self { kind: TokenStoreErrorKind::Unavailable, message: message.into() }
    }

    /// A stored record could not be decoded.
    pub fn corrupt(message: impl Into<String>) -> Self {
        Self { kind: TokenStoreErrorKind::Corrupt, message: message.into() }
    }

    /// The backend failed.
    pub fn backend(message: impl Into<String>) -> Self {
        Self { kind: TokenStoreErrorKind::Backend, message: message.into() }
    }
}

/// Result of clearing one credential record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClearOutcome {
    /// A matching record existed and was deleted.
    Removed,
    /// No matching record existed.
    Absent,
}

/// Storage boundary for credentials. Implementations must scope records by all session identity
/// fields (via [`resource_key`] for the resource), must not use ordinary config files for secret
/// material, and must report absence distinctly from failure.
#[async_trait::async_trait]
pub trait TokenStore: Send + Sync + std::fmt::Debug {
    /// Load the record for the identity tuple. `Ok(None)` means no record exists.
    async fn load(
        &self,
        resource: &str,
        issuer: &str,
        client_id: &str,
        account: Option<&str>,
    ) -> Result<Option<OAuthSession>, TokenStoreError>;
    /// Replace the record for the session's identity tuple.
    async fn save(&self, session: OAuthSession) -> Result<(), TokenStoreError>;
    /// Delete the record for the identity tuple.
    async fn clear(
        &self,
        resource: &str,
        issuer: &str,
        client_id: &str,
        account: Option<&str>,
    ) -> Result<ClearOutcome, TokenStoreError>;
}

/// Explicit volatile credential storage for offline/test use.
#[derive(Debug, Default)]
pub struct InMemoryTokenStore(Mutex<Vec<OAuthSession>>);

/// A store used when the host has no configured OS credential backend. Every operation fails
/// with [`TokenStoreErrorKind::Unavailable`] instead of silently persisting tokens in a config
/// file or reporting a misleading "no credential".
#[derive(Debug, Default)]
pub struct UnavailableTokenStore;

/// Credential store backed by the platform keychain (Keychain, Credential
/// Manager, or Secret Service). Keychain errors are surfaced; no file fallback
/// is attempted.
#[derive(Debug, Clone)]
pub struct KeyringTokenStore {
    service: String,
}

impl KeyringTokenStore {
    /// Create a store whose records live under `service` in the platform keychain.
    pub fn new(service: impl Into<String>) -> Self {
        Self { service: service.into() }
    }

    fn entry(
        &self,
        resource: &str,
        issuer: &str,
        client_id: &str,
        account: Option<&str>,
    ) -> Result<keyring::Entry, TokenStoreError> {
        let key = format!(
            "{}\n{}\n{}\n{}",
            resource_key(resource),
            issuer,
            client_id,
            account.unwrap_or_default()
        );
        let digest = Sha256::digest(key.as_bytes());
        keyring::Entry::new(&self.service, &URL_SAFE_NO_PAD.encode(digest)).map_err(keyring_error)
    }
}

fn keyring_error(error: keyring::Error) -> TokenStoreError {
    match error {
        keyring::Error::PlatformFailure(_) | keyring::Error::NoStorageAccess(_) => {
            TokenStoreError::unavailable("platform secure credential storage is unavailable")
        }
        keyring::Error::BadEncoding(_) | keyring::Error::Ambiguous(_) => {
            TokenStoreError::corrupt("platform secure credential record is unreadable")
        }
        _ => TokenStoreError::backend("platform secure credential operation failed"),
    }
}

fn join_error(_: tokio::task::JoinError) -> TokenStoreError {
    TokenStoreError::backend("secure credential operation was interrupted")
}

#[async_trait::async_trait]
impl TokenStore for KeyringTokenStore {
    async fn load(
        &self,
        resource: &str,
        issuer: &str,
        client_id: &str,
        account: Option<&str>,
    ) -> Result<Option<OAuthSession>, TokenStoreError> {
        let entry = self.entry(resource, issuer, client_id, account)?;
        tokio::task::spawn_blocking(move || match entry.get_password() {
            Ok(value) => serde_json::from_str(&value)
                .map(Some)
                .map_err(|_| TokenStoreError::corrupt("secure credential record was malformed")),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => Err(keyring_error(error)),
        })
        .await
        .map_err(join_error)?
    }

    async fn save(&self, session: OAuthSession) -> Result<(), TokenStoreError> {
        let entry = self.entry(
            &session.resource,
            &session.issuer,
            &session.client_id,
            session.account.as_deref(),
        )?;
        let value = serde_json::to_string(&session)
            .map_err(|_| TokenStoreError::backend("secure credential could not be encoded"))?;
        tokio::task::spawn_blocking(move || entry.set_password(&value).map_err(keyring_error))
            .await
            .map_err(join_error)?
    }

    async fn clear(
        &self,
        resource: &str,
        issuer: &str,
        client_id: &str,
        account: Option<&str>,
    ) -> Result<ClearOutcome, TokenStoreError> {
        let entry = self.entry(resource, issuer, client_id, account)?;
        tokio::task::spawn_blocking(move || match entry.delete_credential() {
            Ok(()) => Ok(ClearOutcome::Removed),
            Err(keyring::Error::NoEntry) => Ok(ClearOutcome::Absent),
            Err(error) => Err(keyring_error(error)),
        })
        .await
        .map_err(join_error)?
    }
}

/// A local persistent store for embedding applications that manage their own protected
/// directory. The file is written with owner-only permissions where the platform supports them
/// and is never included in config or output. The CLI and MCP server do not use this store;
/// they use [`KeyringTokenStore`].
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

    /// Read every record. A missing file is an empty store; an unreadable or malformed file is
    /// an error, never silently treated as empty (which would let a save destroy other records).
    fn read_all(&self) -> Result<Vec<OAuthSession>, TokenStoreError> {
        let bytes = match std::fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(_) => {
                return Err(TokenStoreError::backend("OAuth credential store could not be read"));
            }
        };
        serde_json::from_slice(&bytes)
            .map_err(|_| TokenStoreError::corrupt("OAuth credential store was malformed"))
    }

    fn write_all(&self, sessions: &[OAuthSession]) -> Result<(), TokenStoreError> {
        let body = serde_json::to_vec(sessions)
            .map_err(|_| TokenStoreError::backend("OAuth credential store could not be encoded"))?;
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(|_| {
                TokenStoreError::backend("OAuth credential store directory could not be created")
            })?;
        }
        let temporary = self.path.with_extension("tmp");
        std::fs::write(&temporary, body)
            .map_err(|_| TokenStoreError::backend("OAuth credential store could not be written"))?;
        #[cfg(unix)]
        std::fs::set_permissions(&temporary, std::os::unix::fs::PermissionsExt::from_mode(0o600))
            .map_err(|_| {
            TokenStoreError::backend("OAuth credential store permissions could not be set")
        })?;
        std::fs::rename(&temporary, &self.path)
            .map_err(|_| TokenStoreError::backend("OAuth credential store could not be committed"))
    }
}

#[async_trait::async_trait]
impl TokenStore for UnavailableTokenStore {
    async fn load(
        &self,
        _resource: &str,
        _issuer: &str,
        _client_id: &str,
        _account: Option<&str>,
    ) -> Result<Option<OAuthSession>, TokenStoreError> {
        Err(unavailable_store())
    }

    async fn save(&self, _session: OAuthSession) -> Result<(), TokenStoreError> {
        Err(unavailable_store())
    }

    async fn clear(
        &self,
        _resource: &str,
        _issuer: &str,
        _client_id: &str,
        _account: Option<&str>,
    ) -> Result<ClearOutcome, TokenStoreError> {
        Err(unavailable_store())
    }
}

fn unavailable_store() -> TokenStoreError {
    TokenStoreError::unavailable(
        "no secure OS credential storage is available; set oauth.allow_in_memory for volatile credentials",
    )
}

#[async_trait::async_trait]
impl TokenStore for InMemoryTokenStore {
    async fn load(
        &self,
        resource: &str,
        issuer: &str,
        client_id: &str,
        account: Option<&str>,
    ) -> Result<Option<OAuthSession>, TokenStoreError> {
        Ok(self
            .0
            .lock()
            .await
            .iter()
            .find(|value| same_identity(value, resource, issuer, client_id, account))
            .cloned())
    }

    async fn save(&self, session: OAuthSession) -> Result<(), TokenStoreError> {
        let mut sessions = self.0.lock().await;
        sessions.retain(|value| {
            !same_identity(
                value,
                &session.resource,
                &session.issuer,
                &session.client_id,
                session.account.as_deref(),
            )
        });
        sessions.push(session);
        Ok(())
    }

    async fn clear(
        &self,
        resource: &str,
        issuer: &str,
        client_id: &str,
        account: Option<&str>,
    ) -> Result<ClearOutcome, TokenStoreError> {
        let mut sessions = self.0.lock().await;
        let before = sessions.len();
        sessions.retain(|value| !same_identity(value, resource, issuer, client_id, account));
        Ok(if sessions.len() == before { ClearOutcome::Absent } else { ClearOutcome::Removed })
    }
}

#[async_trait::async_trait]
impl TokenStore for FileTokenStore {
    async fn load(
        &self,
        resource: &str,
        issuer: &str,
        client_id: &str,
        account: Option<&str>,
    ) -> Result<Option<OAuthSession>, TokenStoreError> {
        let _guard = self.lock.lock().await;
        Ok(self
            .read_all()?
            .into_iter()
            .find(|session| same_identity(session, resource, issuer, client_id, account)))
    }

    async fn save(&self, session: OAuthSession) -> Result<(), TokenStoreError> {
        let _guard = self.lock.lock().await;
        let mut sessions = self.read_all()?;
        sessions.retain(|current| {
            !same_identity(
                current,
                &session.resource,
                &session.issuer,
                &session.client_id,
                session.account.as_deref(),
            )
        });
        sessions.push(session);
        self.write_all(&sessions)
    }

    async fn clear(
        &self,
        resource: &str,
        issuer: &str,
        client_id: &str,
        account: Option<&str>,
    ) -> Result<ClearOutcome, TokenStoreError> {
        let _guard = self.lock.lock().await;
        let mut sessions = self.read_all()?;
        let before = sessions.len();
        sessions.retain(|session| !same_identity(session, resource, issuer, client_id, account));
        if sessions.len() == before {
            return Ok(ClearOutcome::Absent);
        }
        self.write_all(&sessions)?;
        Ok(ClearOutcome::Removed)
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
pub fn validate_oauth_url(
    raw: &str,
    configured_origin: &reqwest::Url,
    allow_loopback_demo: bool,
) -> Result<reqwest::Url, String> {
    let url = reqwest::Url::parse(raw)
        .map_err(|_| "OAuth metadata contains an invalid URL".to_owned())?;
    if url.scheme() == "https" {
        return Ok(url);
    }
    if allow_loopback_demo
        && url.scheme() == "http"
        && url.origin() == configured_origin.origin()
        && url.host_str().is_some_and(|h| h == "localhost" || h == "127.0.0.1" || h == "[::1]")
    {
        return Ok(url);
    }
    Err("OAuth metadata must use HTTPS (only the exact opted-in loopback origin may use HTTP)"
        .to_owned())
}

/// Validate discovery relationships before accepting any endpoint or credential.
pub fn validate_metadata(
    resource: &ProtectedResourceMetadata,
    server: &AuthorizationServerMetadata,
    configured_resource: &reqwest::Url,
    configured_origin: &reqwest::Url,
    allow_loopback_demo: bool,
) -> Result<(), String> {
    let advertised = reqwest::Url::parse(&resource.resource)
        .map_err(|_| "invalid protected resource URL".to_owned())?;
    if advertised != *configured_resource {
        return Err(
            "protected-resource metadata does not identify the configured remote".to_owned()
        );
    }
    let issuer = validate_oauth_url(&server.issuer, configured_origin, allow_loopback_demo)?;
    if !resource
        .authorization_servers
        .iter()
        .any(|candidate| candidate.trim_end_matches('/') == server.issuer.trim_end_matches('/'))
    {
        return Err(
            "authorization-server issuer is not advertised by the protected resource".to_owned()
        );
    }
    let authorization_endpoint = reqwest::Url::parse(&server.authorization_endpoint)
        .map_err(|_| "invalid authorization endpoint".to_owned())?;
    let token_endpoint = reqwest::Url::parse(&server.token_endpoint)
        .map_err(|_| "invalid token endpoint".to_owned())?;
    if issuer.origin() != authorization_endpoint.origin()
        || issuer.origin() != token_endpoint.origin()
    {
        return Err("authorization endpoint is unrelated to the discovered issuer".to_owned());
    }
    validate_oauth_url(&server.authorization_endpoint, configured_origin, allow_loopback_demo)?;
    validate_oauth_url(&server.token_endpoint, configured_origin, allow_loopback_demo)?;
    if let Some(endpoint) = &server.revocation_endpoint {
        let revocation_endpoint =
            reqwest::Url::parse(endpoint).map_err(|_| "invalid revocation endpoint".to_owned())?;
        if issuer.origin() != revocation_endpoint.origin() {
            return Err("revocation endpoint is unrelated to the discovered issuer".to_owned());
        }
        validate_oauth_url(endpoint, configured_origin, allow_loopback_demo)?;
    }
    if let Some(endpoint) = &server.device_authorization_endpoint {
        let device_endpoint = reqwest::Url::parse(endpoint)
            .map_err(|_| "invalid device authorization endpoint".to_owned())?;
        if issuer.origin() != device_endpoint.origin() {
            return Err(
                "device authorization endpoint is unrelated to the discovered issuer".to_owned()
            );
        }
        validate_oauth_url(endpoint, configured_origin, allow_loopback_demo)?;
    }
    Ok(())
}

/// Check an authorization callback without ever accepting a mismatched or replayed state.
pub fn validate_callback_state(expected: &str, returned: &str) -> Result<(), String> {
    if expected.is_empty() || returned.is_empty() || expected != returned {
        return Err("OAuth callback state mismatch".to_owned());
    }
    Ok(())
}

/// Shared credential backend.
pub type SharedTokenStore = Arc<dyn TokenStore>;

/// Return a unix timestamp, useful for bounded expiry checks without exposing credentials.
pub fn now_seconds() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// Default bounded interactive timeout.
pub fn login_timeout(config: &OAuthConfig) -> Duration {
    Duration::from_secs(config.login_timeout_seconds.clamp(1, 900))
}

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
    {
        true
    }
    #[cfg(target_os = "macos")]
    {
        command_in_path("open")
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        std::env::var_os("BROWSER").is_some_and(|value| !value.is_empty())
            || (std::env::var_os("DISPLAY").is_some()
                || std::env::var_os("WAYLAND_DISPLAY").is_some())
                && command_in_path("xdg-open")
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
    let protected = http
        .get(metadata_url)
        .send()
        .await
        .map_err(|_| "protected-resource metadata is unreachable".to_owned())?
        .error_for_status()
        .map_err(|_| "protected-resource metadata was rejected".to_owned())?
        .json::<ProtectedResourceMetadata>()
        .await
        .map_err(|_| "protected-resource metadata is malformed".to_owned())?;
    let issuer = protected.authorization_servers.first().ok_or_else(|| {
        "protected-resource metadata advertises no authorization server".to_owned()
    })?;
    let server =
        fetch_authorization_server_metadata(http, issuer, configured_origin, allow_loopback_demo)
            .await?;
    validate_metadata(
        &protected,
        &server,
        configured_resource,
        configured_origin,
        allow_loopback_demo,
    )?;
    Ok((protected, server))
}

/// Fetch RFC 8414 metadata for a known issuer and require the document to name that exact
/// issuer (RFC 8414 §3.3), so one issuer's metadata can never be substituted for another's.
pub async fn fetch_authorization_server_metadata(
    http: &reqwest::Client,
    issuer: &str,
    configured_origin: &reqwest::Url,
    allow_loopback_demo: bool,
) -> Result<AuthorizationServerMetadata, String> {
    let issuer_url = validate_oauth_url(issuer, configured_origin, allow_loopback_demo)?;
    let server = http
        .get(well_known_url(&issuer_url)?)
        .send()
        .await
        .map_err(|_| "authorization-server metadata is unreachable".to_owned())?
        .error_for_status()
        .map_err(|_| "authorization-server metadata was rejected".to_owned())?
        .json::<AuthorizationServerMetadata>()
        .await
        .map_err(|_| "authorization-server metadata is malformed".to_owned())?;
    if server.issuer.trim_end_matches('/') != issuer.trim_end_matches('/') {
        return Err("authorization-server metadata names a different issuer".to_owned());
    }
    Ok(server)
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
    let resource_url =
        reqwest::Url::parse(resource).map_err(|_| "invalid resource URL".to_owned())?;
    let mut url =
        validate_oauth_url(&metadata.authorization_endpoint, &resource_url, allow_loopback_demo)?;
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

async fn write_callback_page(socket: &mut tokio::net::TcpStream, status: &str, body: &str) {
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = tokio::io::AsyncWriteExt::write_all(socket, response.as_bytes()).await;
    let _ = tokio::io::AsyncWriteExt::shutdown(socket).await;
}

/// Read one HTTP request line from a loopback connection and return its target path+query.
/// Connections that close without a request (browser pre-connects) yield `None`.
async fn read_request_target(socket: &mut tokio::net::TcpStream) -> Option<String> {
    let mut bytes = Vec::with_capacity(1024);
    let mut chunk = [0_u8; 1024];
    while !bytes.windows(2).any(|window| window == b"\r\n") && bytes.len() < 8192 {
        let count = tokio::io::AsyncReadExt::read(socket, &mut chunk).await.ok()?;
        if count == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..count]);
    }
    let text = std::str::from_utf8(&bytes).ok()?;
    let line = text.lines().next()?;
    let mut parts = line.split_whitespace();
    (parts.next()? == "GET").then_some(())?;
    parts.next().map(str::to_owned)
}

/// Run one bounded native browser login. Callers decide whether this function is appropriate;
/// unattended/background requests must return `RemoteError::AuthenticationRequired` instead.
///
/// The loopback listener binds an ephemeral port per attempt (RFC 8252 §7.3). Requests for other
/// paths and empty pre-connections are answered with 404 and ignored; the first `/callback`
/// request is authoritative and its `state` must match before any other parameter is read.
pub async fn browser_login(
    http: &reqwest::Client,
    metadata: &AuthorizationServerMetadata,
    config: &OAuthConfig,
    resource: &str,
) -> Result<OAuthSession, String> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .map_err(|_| "cannot bind the loopback OAuth callback".to_owned())?;
    let port = listener
        .local_addr()
        .map_err(|_| "cannot determine loopback callback port".to_owned())?
        .port();
    let redirect_uri = format!("http://127.0.0.1:{port}/callback");
    let (verifier, challenge) = new_pkce_pair();
    let state = new_state();
    let url = authorization_url(
        metadata,
        config,
        &redirect_uri,
        &state,
        &challenge,
        resource,
        config.allow_loopback_demo,
    )?;
    interaction(config).open_browser(url.as_str())?;
    tokio::time::timeout(login_timeout(config), async {
        let (mut socket, callback) = loop {
            let (mut socket, _) = listener
                .accept()
                .await
                .map_err(|_| "OAuth callback was not accepted".to_owned())?;
            let Some(target) = read_request_target(&mut socket).await else { continue };
            let Ok(callback) = reqwest::Url::parse(&format!("http://127.0.0.1:{port}{target}"))
            else {
                write_callback_page(&mut socket, "400 Bad Request", "Malformed callback.").await;
                continue;
            };
            if callback.path() != "/callback" {
                write_callback_page(&mut socket, "404 Not Found", "Not found.").await;
                continue;
            }
            break (socket, callback);
        };
        let parameter = |name: &str| {
            callback.query_pairs().find(|(key, _)| key == name).map(|(_, value)| value.into_owned())
        };
        if let Err(error) = validate_callback_state(&state, &parameter("state").unwrap_or_default())
        {
            write_callback_page(
                &mut socket,
                "400 Bad Request",
                "Login failed: the response did not match this login attempt.",
            )
            .await;
            return Err(error);
        }
        if let Some(error) = parameter("error") {
            write_callback_page(
                &mut socket,
                "200 OK",
                "Login was not completed; you may close this window.",
            )
            .await;
            return Err(if error == "access_denied" {
                "OAuth authorization was denied".to_owned()
            } else {
                "OAuth authorization failed at the issuer".to_owned()
            });
        }
        let Some(code) = parameter("code") else {
            write_callback_page(
                &mut socket,
                "400 Bad Request",
                "Login failed: no authorization code was returned.",
            )
            .await;
            return Err("OAuth consent did not return an authorization code".to_owned());
        };
        let exchange = http
            .post(&metadata.token_endpoint)
            .form(&[
                ("grant_type", "authorization_code"),
                ("client_id", config.client_id.as_str()),
                ("code", code.as_str()),
                ("redirect_uri", redirect_uri.as_str()),
                ("code_verifier", verifier.as_str()),
                ("resource", resource),
            ])
            .send()
            .await;
        let body = match token_response(exchange, "OAuth token exchange").await {
            Ok(body) => body,
            Err(failure) => {
                write_callback_page(
                    &mut socket,
                    "200 OK",
                    "Login failed; return to the terminal for details.",
                )
                .await;
                return Err(failure.message().to_owned());
            }
        };
        write_callback_page(&mut socket, "200 OK", "Login complete; you may close this window.")
            .await;
        Ok(session_from(body, resource, metadata, config))
    })
    .await
    .map_err(|_| "OAuth login timed out".to_owned())?
}

fn session_from(
    body: TokenResponse,
    resource: &str,
    metadata: &AuthorizationServerMetadata,
    config: &OAuthConfig,
) -> OAuthSession {
    OAuthSession {
        access_token: body.access_token,
        refresh_token: body.refresh_token,
        expires_at: body.expires_in.map(|seconds| now_seconds().saturating_add(seconds)),
        resource: resource.to_owned(),
        issuer: metadata.issuer.clone(),
        client_id: config.client_id.clone(),
        account: config.account.clone(),
    }
}

/// Run RFC 8628 device authorization without exposing the private device code.
pub async fn device_login(
    http: &reqwest::Client,
    metadata: &AuthorizationServerMetadata,
    config: &OAuthConfig,
    resource: &str,
) -> Result<OAuthSession, String> {
    let endpoint = metadata.device_authorization_endpoint.as_deref().ok_or_else(|| {
        "the authorization server does not advertise device authorization".to_owned()
    })?;
    let endpoint = validate_oauth_url(
        endpoint,
        &reqwest::Url::parse(resource).map_err(|_| "invalid resource URL".to_owned())?,
        config.allow_loopback_demo,
    )?;
    let response = http
        .post(endpoint)
        .form(&[("client_id", config.client_id.as_str()), ("resource", resource)])
        .send()
        .await
        .map_err(|_| "device authorization endpoint is unreachable".to_owned())?;
    let status = response.status();
    let bytes = response
        .bytes()
        .await
        .map_err(|_| "device authorization response could not be read".to_owned())?;
    if !status.is_success() {
        let error = serde_json::from_slice::<OAuthErrorResponse>(&bytes)
            .map(|body| body.error)
            .unwrap_or_else(|_| "device authorization was rejected".to_owned());
        return Err(format!("device authorization failed: {error}"));
    }
    let grant: DeviceAuthorizationResponse = serde_json::from_slice(&bytes)
        .map_err(|_| "device authorization response was malformed".to_owned())?;
    // These are the only values suitable for a user-facing device prompt. The device_code is
    // intentionally never formatted, logged, or returned by this function.
    interaction(config).show_device_code(&grant.verification_uri, &grant.user_code);
    let deadline = tokio::time::Instant::now()
        + login_timeout(config).min(Duration::from_secs(grant.expires_in.unwrap_or(900)));
    let mut interval = Duration::from_secs(grant.interval.unwrap_or(5).max(1));
    let mut network_backoff = interval;
    loop {
        tokio::time::sleep(interval).await;
        if tokio::time::Instant::now() >= deadline {
            return Err("device authorization expired".to_owned());
        }
        let response = http
            .post(&metadata.token_endpoint)
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("device_code", grant.device_code.as_str()),
                ("client_id", config.client_id.as_str()),
                ("resource", resource),
            ])
            .send()
            .await;
        let response = match response {
            Ok(response) => response,
            Err(_) => {
                network_backoff = network_backoff.saturating_mul(2);
                interval = interval.max(network_backoff);
                continue;
            }
        };
        let status = response.status();
        let bytes = response
            .bytes()
            .await
            .map_err(|_| "device token response could not be read".to_owned())?;
        if status.is_success() {
            let body: TokenResponse = serde_json::from_slice(&bytes)
                .map_err(|_| "device token response was malformed".to_owned())?;
            return Ok(session_from(body, resource, metadata, config));
        }
        let error = serde_json::from_slice::<OAuthErrorResponse>(&bytes)
            .map(|body| body.error)
            .unwrap_or_default();
        match error.as_str() {
            "authorization_pending" => {}
            "slow_down" => {
                interval = interval.saturating_add(Duration::from_secs(5));
                network_backoff = network_backoff.max(interval);
            }
            "expired_token" => return Err("device authorization expired".to_owned()),
            "access_denied" | "authorization_denied" => {
                return Err("device authorization was denied".to_owned());
            }
            "invalid_grant" | "invalid_request" => {
                return Err("device authorization code was rejected or already used".to_owned());
            }
            _ if status.is_client_error() => {
                return Err("device authorization was rejected".to_owned());
            }
            _ => {
                network_backoff = network_backoff.saturating_mul(2);
                interval = interval.max(network_backoff);
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
    url.set_query(None);
    Ok(url)
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
}

/// Why a token-endpoint exchange failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenEndpointFailure {
    /// The issuer answered with an authoritative OAuth rejection (for example `invalid_grant`):
    /// the credential used is dead and must not be retried.
    Rejected(String),
    /// The issuer could not be reached or answered with a transient error; the credential may
    /// still be valid.
    Transient(String),
}

impl TokenEndpointFailure {
    /// Safe description with no credential material.
    pub fn message(&self) -> &str {
        match self {
            Self::Rejected(message) | Self::Transient(message) => message,
        }
    }
}

async fn token_response(
    response: Result<reqwest::Response, reqwest::Error>,
    operation: &str,
) -> Result<TokenResponse, TokenEndpointFailure> {
    let response = response
        .map_err(|_| TokenEndpointFailure::Transient(format!("{operation} was unreachable")))?;
    let status = response.status();
    let bytes = response.bytes().await.map_err(|_| {
        TokenEndpointFailure::Transient(format!("{operation} response could not be read"))
    })?;
    if status.is_success() {
        return serde_json::from_slice(&bytes).map_err(|_| {
            TokenEndpointFailure::Transient(format!("{operation} response was malformed"))
        });
    }
    if status.is_client_error() && status != reqwest::StatusCode::TOO_MANY_REQUESTS {
        let error = serde_json::from_slice::<OAuthErrorResponse>(&bytes)
            .map(|body| body.error)
            .unwrap_or_else(|_| "rejected".to_owned());
        return Err(TokenEndpointFailure::Rejected(format!(
            "{operation} was rejected ({error}); reauthorization is required"
        )));
    }
    Err(TokenEndpointFailure::Transient(format!(
        "{operation} failed with HTTP {}",
        status.as_u16()
    )))
}

fn open_browser(url: &str) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    let command = ("rundll32", vec!["url.dll,FileProtocolHandler", url]);
    #[cfg(target_os = "macos")]
    let command = ("open", vec![url]);
    #[cfg(all(unix, not(target_os = "macos")))]
    let command = ("xdg-open", vec![url]);
    std::process::Command::new(command.0).args(command.1).spawn().map(|_| ()).map_err(|_| {
        "cannot open the system browser; use an explicit headless login mode".to_owned()
    })
}

/// Exchange a rotating refresh token once. The caller replaces the stored session with the
/// returned session. A [`TokenEndpointFailure::Rejected`] result means the refresh token is dead
/// (rotated, reused, revoked, or expired) and the caller must forget it rather than retrying;
/// a [`TokenEndpointFailure::Transient`] result leaves it usable.
pub async fn refresh(
    http: &reqwest::Client,
    metadata: &AuthorizationServerMetadata,
    session: &OAuthSession,
) -> Result<OAuthSession, TokenEndpointFailure> {
    let refresh_token = session.refresh_token.as_deref().ok_or_else(|| {
        TokenEndpointFailure::Rejected("OAuth session has no refresh token".to_owned())
    })?;
    let response = http
        .post(&metadata.token_endpoint)
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", session.client_id.as_str()),
            ("resource", session.resource.as_str()),
        ])
        .send()
        .await;
    let body = token_response(response, "OAuth refresh").await?;
    Ok(OAuthSession {
        access_token: body.access_token,
        refresh_token: body.refresh_token.or_else(|| Some(refresh_token.to_owned())),
        expires_at: body.expires_in.map(|seconds| now_seconds().saturating_add(seconds)),
        ..session.clone()
    })
}

/// Revoke a grant where the issuer advertises RFC 7009 revocation. The refresh token is revoked
/// when present (which revokes the whole grant family at issuers that implement family
/// revocation); otherwise the access token is.
pub async fn revoke(
    http: &reqwest::Client,
    metadata: &AuthorizationServerMetadata,
    session: &OAuthSession,
) -> Result<(), String> {
    let endpoint = metadata
        .revocation_endpoint
        .as_deref()
        .ok_or_else(|| "the authorization server does not advertise revocation".to_owned())?;
    let (token, hint) = match session.refresh_token.as_deref() {
        Some(token) => (token, "refresh_token"),
        None => (session.access_token.as_str(), "access_token"),
    };
    http.post(endpoint)
        .form(&[
            ("token", token),
            ("token_type_hint", hint),
            ("client_id", session.client_id.as_str()),
        ])
        .send()
        .await
        .map_err(|_| "OAuth revocation was unreachable".to_owned())?
        .error_for_status()
        .map(|_| ())
        .map_err(|_| "OAuth revocation was rejected".to_owned())
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Arc;

    use axum::Router;
    use axum::body::Body;
    use axum::extract::State;
    use axum::http::{StatusCode, Uri};
    use axum::response::Response;
    use axum::routing::post;

    use super::*;

    fn session(resource: &str, issuer: &str, access: &str) -> OAuthSession {
        OAuthSession {
            access_token: access.to_owned(),
            refresh_token: Some(format!("{access}-refresh")),
            expires_at: None,
            resource: resource.to_owned(),
            issuer: issuer.to_owned(),
            client_id: "client".to_owned(),
            account: None,
        }
    }

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
    fn session_debug_never_prints_tokens() {
        let value = session("https://resource", "https://issuer", "secret-access");
        let debug = format!("{value:?}");
        assert!(!debug.contains("secret-access"));
        assert!(debug.contains("has_refresh_token: true"));
    }

    #[test]
    fn resource_key_keeps_trailing_slash_paths_distinct() {
        assert_eq!(resource_key("https://hub.example"), resource_key("https://hub.example/"));
        assert_eq!(resource_key("HTTPS://Hub.Example:443/api"), "https://hub.example/api");
        assert_ne!(
            resource_key("https://hub.example/api"),
            resource_key("https://hub.example/api/")
        );
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
    fn metadata_rejects_resource_and_endpoint_mismatch() {
        let resource = reqwest::Url::parse("https://hub.example").expect("test URL");
        let protected = ProtectedResourceMetadata {
            resource: "https://other.example".to_owned(),
            authorization_servers: vec!["https://issuer.example".to_owned()],
        };
        let server = AuthorizationServerMetadata {
            issuer: "https://issuer.example".to_owned(),
            authorization_endpoint: "https://issuer.example/authorize".to_owned(),
            token_endpoint: "https://issuer.example/token".to_owned(),
            revocation_endpoint: None,
            device_authorization_endpoint: None,
        };
        assert!(validate_metadata(&protected, &server, &resource, &resource, false).is_err());
    }

    #[test]
    fn device_and_revocation_endpoints_must_share_issuer_origin_and_scheme_policy() {
        let resource = reqwest::Url::parse("https://hub.example").expect("test URL");
        let protected = ProtectedResourceMetadata {
            resource: resource.to_string(),
            authorization_servers: vec!["https://issuer.example".to_owned()],
        };
        let base = AuthorizationServerMetadata {
            issuer: "https://issuer.example".to_owned(),
            authorization_endpoint: "https://issuer.example/authorize".to_owned(),
            token_endpoint: "https://issuer.example/token".to_owned(),
            revocation_endpoint: None,
            device_authorization_endpoint: None,
        };
        assert!(validate_metadata(&protected, &base, &resource, &resource, false).is_ok());
        for (revocation, device) in [
            (None, Some("http://issuer.example/device")),
            (None, Some("https://unrelated.example/device")),
            (Some("https://unrelated.example/revoke"), None),
        ] {
            let server = AuthorizationServerMetadata {
                revocation_endpoint: revocation.map(str::to_owned),
                device_authorization_endpoint: device.map(str::to_owned),
                ..base.clone()
            };
            assert!(validate_metadata(&protected, &server, &resource, &resource, false).is_err());
        }
    }

    #[test]
    fn loopback_http_requires_explicit_opt_in_and_exact_origin() {
        let origin = reqwest::Url::parse("http://127.0.0.1:8765").expect("test URL");
        assert!(validate_oauth_url("http://127.0.0.1:8765/token", &origin, true).is_ok());
        assert!(validate_oauth_url("http://127.0.0.1:8766/token", &origin, true).is_err());
        assert!(validate_oauth_url("http://127.0.0.1:8765/token", &origin, false).is_err());
        let https = reqwest::Url::parse("https://hub.example").expect("test URL");
        assert!(validate_oauth_url("http://issuer.example/token", &https, true).is_err());
    }

    #[tokio::test]
    async fn in_memory_store_reports_absent_and_removed_distinctly() {
        let store = InMemoryTokenStore::default();
        assert!(matches!(
            store.load("https://resource", "https://issuer", "client", None).await,
            Ok(None)
        ));
        store
            .save(session("https://resource", "https://issuer", "access"))
            .await
            .expect("volatile save");
        let loaded = store
            .load("https://resource", "https://issuer", "client", None)
            .await
            .expect("volatile load");
        assert_eq!(loaded.map(|value| value.access_token), Some("access".to_owned()));
        assert_eq!(
            store
                .load("https://other", "https://issuer", "client", None)
                .await
                .expect("scoped load")
                .map(|_| ()),
            None
        );
        assert_eq!(
            store.clear("https://resource", "https://issuer", "client", None).await,
            Ok(ClearOutcome::Removed)
        );
        assert_eq!(
            store.clear("https://resource", "https://issuer", "client", None).await,
            Ok(ClearOutcome::Absent)
        );
    }

    #[tokio::test]
    async fn unavailable_store_fails_every_operation_as_unavailable() {
        let store = UnavailableTokenStore;
        let load = store
            .load("https://resource", "https://issuer", "client", None)
            .await
            .expect_err("load must not report absence");
        assert_eq!(load.kind, TokenStoreErrorKind::Unavailable);
        let save = store
            .save(session("https://resource", "https://issuer", "access"))
            .await
            .expect_err("save must fail");
        assert_eq!(save.kind, TokenStoreErrorKind::Unavailable);
        let clear = store
            .clear("https://resource", "https://issuer", "client", None)
            .await
            .expect_err("clear must fail");
        assert_eq!(clear.kind, TokenStoreErrorKind::Unavailable);
    }

    #[tokio::test]
    async fn stores_isolate_issuers_and_exact_path_resources() {
        let store = InMemoryTokenStore::default();
        store.save(session("https://resource/api", "https://issuer-a", "a")).await.expect("first");
        store
            .save(session("https://resource/api", "https://issuer-b", "b"))
            .await
            .expect("second issuer");
        store
            .save(session("https://resource/api/", "https://issuer-a", "c"))
            .await
            .expect("slash resource");
        let token = |resource: &'static str, issuer: &'static str| {
            let store = &store;
            async move {
                store
                    .load(resource, issuer, "client", None)
                    .await
                    .expect("load")
                    .map(|value| value.access_token)
            }
        };
        assert_eq!(token("https://resource/api", "https://issuer-a").await.as_deref(), Some("a"));
        assert_eq!(token("https://resource/api", "https://issuer-b").await.as_deref(), Some("b"));
        assert_eq!(token("https://resource/api/", "https://issuer-a").await.as_deref(), Some("c"));
    }

    #[tokio::test]
    async fn file_store_survives_process_boundaries_and_reports_outcomes() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("oauth_tokens.json");
        let first = session("https://resource", "https://issuer", "access");
        FileTokenStore::new(&path).save(first).await.expect("file store");
        FileTokenStore::new(&path)
            .save(session("https://resource", "https://other-issuer", "other"))
            .await
            .expect("second issuer");
        let loaded = FileTokenStore::new(&path)
            .load("https://resource", "https://issuer", "client", None)
            .await
            .expect("load");
        assert_eq!(loaded.map(|value| value.access_token).as_deref(), Some("access"));
        assert_eq!(
            FileTokenStore::new(&path)
                .clear("https://resource", "https://issuer", "client", None)
                .await,
            Ok(ClearOutcome::Removed)
        );
        assert_eq!(
            FileTokenStore::new(&path)
                .clear("https://resource", "https://issuer", "client", None)
                .await,
            Ok(ClearOutcome::Absent)
        );
        let remaining = FileTokenStore::new(&path)
            .load("https://resource", "https://other-issuer", "client", None)
            .await
            .expect("load");
        assert_eq!(remaining.map(|value| value.access_token).as_deref(), Some("other"));
    }

    #[tokio::test]
    async fn file_store_reports_corruption_and_refuses_to_overwrite_it() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("oauth_tokens.json");
        std::fs::write(&path, b"{not json").expect("corrupt fixture");
        let store = FileTokenStore::new(&path);
        assert_eq!(
            store
                .load("https://resource", "https://issuer", "client", None)
                .await
                .expect_err("corrupt")
                .kind,
            TokenStoreErrorKind::Corrupt
        );
        assert_eq!(
            store
                .save(session("https://resource", "https://issuer", "a"))
                .await
                .expect_err("corrupt")
                .kind,
            TokenStoreErrorKind::Corrupt
        );
        assert_eq!(
            store
                .clear("https://resource", "https://issuer", "client", None)
                .await
                .expect_err("corrupt")
                .kind,
            TokenStoreErrorKind::Corrupt
        );
        assert_eq!(
            std::fs::read(&path).expect("fixture"),
            b"{not json",
            "a corrupt store must not be silently replaced"
        );
    }

    #[tokio::test]
    async fn file_store_reports_backend_failure_distinctly() {
        let directory = tempfile::tempdir().expect("temporary directory");
        // A directory where the file should be makes every read fail with a non-NotFound error.
        let store = FileTokenStore::new(directory.path());
        assert_eq!(
            store
                .load("https://resource", "https://issuer", "client", None)
                .await
                .expect_err("backend")
                .kind,
            TokenStoreErrorKind::Backend
        );
    }

    #[derive(Debug, Default)]
    struct RecordingInteraction(std::sync::Mutex<Vec<(String, String)>>);

    impl LoginInteraction for RecordingInteraction {
        fn open_browser(&self, _url: &str) -> Result<(), String> {
            Err("no browser in unit tests".to_owned())
        }

        fn show_device_code(&self, verification_uri: &str, user_code: &str) {
            if let Ok(mut prompts) = self.0.lock() {
                prompts.push((verification_uri.to_owned(), user_code.to_owned()));
            }
        }
    }

    type Script = Arc<Mutex<VecDeque<(StatusCode, &'static str)>>>;

    async fn device_server(
        responses: Vec<(StatusCode, &'static str)>,
    ) -> (String, Script, tokio::task::JoinHandle<()>) {
        let state = Arc::new(Mutex::new(responses.into_iter().collect::<VecDeque<_>>()));
        let app = Router::new()
            .route("/device", post(mock_device))
            .route("/token", post(mock_device))
            .with_state(state.clone());
        let listener =
            tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.expect("mock listener");
        let address = listener.local_addr().expect("mock address");
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("mock server");
        });
        (format!("http://{address}"), state, task)
    }

    async fn mock_device(State(state): State<Script>, _uri: Uri) -> Response<Body> {
        let body =
            state.lock().await.pop_front().unwrap_or((StatusCode::INTERNAL_SERVER_ERROR, "{}"));
        Response::builder()
            .status(body.0)
            .header("content-type", "application/json")
            .body(Body::from(body.1))
            .expect("mock response")
    }

    fn device_metadata(origin: &str) -> AuthorizationServerMetadata {
        AuthorizationServerMetadata {
            issuer: origin.to_owned(),
            authorization_endpoint: format!("{origin}/authorize"),
            token_endpoint: format!("{origin}/token"),
            revocation_endpoint: None,
            device_authorization_endpoint: Some(format!("{origin}/device")),
        }
    }

    fn device_config(timeout: u64, interaction: Arc<RecordingInteraction>) -> OAuthConfig {
        OAuthConfig {
            client_id: "client".to_owned(),
            account: None,
            allow_in_memory: true,
            allow_loopback_demo: true,
            login_mode: OAuthLoginMode::Device,
            token_store: None,
            interaction: Some(interaction),
            login_timeout_seconds: timeout,
        }
    }

    #[tokio::test]
    async fn device_login_polls_pending_then_succeeds_without_exposing_device_code() {
        let (origin, _state, task) = device_server(vec![
            (StatusCode::OK, r#"{"device_code":"private-device-code","user_code":"ABCD-EFGH","verification_uri":"https://issuer.example/verify","expires_in":30,"interval":1}"#),
            (StatusCode::BAD_REQUEST, r#"{"error":"authorization_pending"}"#),
            (StatusCode::OK, r#"{"access_token":"access-token","refresh_token":"refresh-token","expires_in":60}"#),
        ])
        .await;
        let prompts = Arc::new(RecordingInteraction::default());
        let result = device_login(
            &reqwest::Client::new(),
            &device_metadata(&origin),
            &device_config(5, prompts.clone()),
            &origin,
        )
        .await
        .expect("device login");
        assert_eq!(result.access_token, "access-token");
        assert_eq!(result.refresh_token.as_deref(), Some("refresh-token"));
        let shown = prompts.0.lock().expect("prompts").clone();
        assert_eq!(
            shown,
            vec![("https://issuer.example/verify".to_owned(), "ABCD-EFGH".to_owned())]
        );
        assert!(!format!("{shown:?}{result:?}").contains("private-device-code"));
        task.abort();
    }

    #[tokio::test]
    async fn device_login_reports_denial_and_reused_code() {
        for (error, expected) in [
            (r#"{"error":"access_denied"}"#, "denied"),
            (r#"{"error":"invalid_grant"}"#, "rejected"),
        ] {
            let (origin, _state, task) = device_server(vec![
                (StatusCode::OK, r#"{"device_code":"private","user_code":"ABCD","verification_uri":"https://issuer.example/verify","expires_in":30,"interval":1}"#),
                (StatusCode::BAD_REQUEST, error),
            ])
            .await;
            let config = device_config(5, Arc::new(RecordingInteraction::default()));
            let message =
                device_login(&reqwest::Client::new(), &device_metadata(&origin), &config, &origin)
                    .await
                    .expect_err("device login should fail");
            assert!(!message.contains("private"));
            assert!(message.contains(expected), "{message}");
            task.abort();
        }
    }

    #[tokio::test]
    async fn device_login_consumes_slow_down_with_a_longer_interval() {
        let (origin, state, task) = device_server(vec![
            (StatusCode::OK, r#"{"device_code":"private","user_code":"ABCD","verification_uri":"https://issuer.example/verify","expires_in":30,"interval":1}"#),
            (StatusCode::BAD_REQUEST, r#"{"error":"slow_down"}"#),
            (StatusCode::OK, r#"{"access_token":"access","refresh_token":"rotated","expires_in":60}"#),
        ])
        .await;
        let started = tokio::time::Instant::now();
        let config = device_config(15, Arc::new(RecordingInteraction::default()));
        let result =
            device_login(&reqwest::Client::new(), &device_metadata(&origin), &config, &origin)
                .await
                .expect("slow_down should be consumed");
        assert_eq!(result.refresh_token.as_deref(), Some("rotated"));
        assert_eq!(state.lock().await.len(), 0);
        // 1 s initial interval, then 1 + 5 s after slow_down.
        assert!(
            started.elapsed() >= Duration::from_secs(7),
            "slow_down must lengthen the polling interval"
        );
        task.abort();
    }

    #[tokio::test]
    async fn device_login_rejects_issuers_without_device_support() {
        let metadata = AuthorizationServerMetadata {
            issuer: "https://issuer.example".to_owned(),
            authorization_endpoint: "https://issuer.example/authorize".to_owned(),
            token_endpoint: "https://issuer.example/token".to_owned(),
            revocation_endpoint: None,
            device_authorization_endpoint: None,
        };
        let config = device_config(1, Arc::new(RecordingInteraction::default()));
        let error =
            device_login(&reqwest::Client::new(), &metadata, &config, "https://issuer.example")
                .await
                .expect_err("unsupported device flow");
        assert!(error.contains("does not advertise device authorization"));
    }

    #[tokio::test]
    async fn device_login_bounds_transient_network_retry() {
        let (origin, _state, task) = device_server(vec![(
            StatusCode::OK,
            r#"{"device_code":"private","user_code":"ABCD","verification_uri":"https://issuer.example/verify","expires_in":30,"interval":1}"#,
        )])
        .await;
        let mut metadata = device_metadata(&origin);
        metadata.token_endpoint = "http://127.0.0.1:1/token".to_owned();
        let config = device_config(3, Arc::new(RecordingInteraction::default()));
        let error = device_login(&reqwest::Client::new(), &metadata, &config, &origin)
            .await
            .expect_err("network retry should expire");
        assert!(error.contains("expired"));
        task.abort();
    }

    #[tokio::test]
    async fn refresh_distinguishes_rejection_from_transient_failure() {
        let (origin, _state, task) = device_server(vec![
            (StatusCode::BAD_REQUEST, r#"{"error":"invalid_grant"}"#),
            (StatusCode::SERVICE_UNAVAILABLE, "{}"),
        ])
        .await;
        let metadata = device_metadata(&origin);
        let current = session(&origin, &origin, "access");
        assert!(matches!(
            refresh(&reqwest::Client::new(), &metadata, &current).await,
            Err(TokenEndpointFailure::Rejected(_))
        ));
        assert!(matches!(
            refresh(&reqwest::Client::new(), &metadata, &current).await,
            Err(TokenEndpointFailure::Transient(_))
        ));
        let unreachable = AuthorizationServerMetadata {
            token_endpoint: "http://127.0.0.1:1/token".to_owned(),
            ..metadata
        };
        assert!(matches!(
            refresh(&reqwest::Client::new(), &unreachable, &current).await,
            Err(TokenEndpointFailure::Transient(_))
        ));
        task.abort();
    }
}
