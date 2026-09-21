//! Architecture and policy boundary for the AgentPalace demo authorization hub.
//!
//! This crate owns the hub's issuer/resource configuration and the protocol metadata
//! contract. Google is deliberately represented only as an upstream identity provider;
//! the hub must mint credentials for its own resource before a request can reach a palace.
//! The gateway exposes only the documented OAuth metadata and grant endpoints;
//! REST forwarding remains deliberately absent.

use std::{collections::{BTreeMap, BTreeSet}, sync::{atomic::{AtomicU64, Ordering}, Arc, Mutex}, time::{Duration, SystemTime, UNIX_EPOCH}};

use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::{get, post}, Json, Router};
use agentpalace_core::{AuthenticatedOwner, Issuer, OwnerId, SubjectBinding};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The only upstream scopes accepted by the demo gateway.
pub const GOOGLE_SCOPES: [&str; 2] = ["openid", "email"];

static TOKEN_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// The browser identity provider configured behind the hub.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GoogleOidcConfig {
    /// Google OAuth web-client identifier.
    pub client_id: String,
    /// Server-side secret; this type is never serialized by the gateway.
    #[serde(skip_serializing)]
    pub client_secret: String,
    /// Issuer expected in Google ID tokens.
    pub issuer: Issuer,
    /// Exact upstream scopes. No Google API access is needed by the hub.
    pub scopes: BTreeSet<String>,
}

/// A registered public native client. It has no client secret by design.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeClient {
    /// Public client identifier.
    pub client_id: String,
    /// Constrained loopback callback registered for browser authorization.
    pub redirect_uri: String,
}

/// Whether the gateway may use the explicitly documented local HTTP exception.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GatewayMode {
    /// Require HTTPS for issuer, resource, and gateway endpoints.
    Secure,
    /// Permit only the configured localhost origin; this is not a general insecure mode.
    LoopbackDemo,
}

/// Fail-closed gateway configuration shared by handlers and metadata generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayConfig {
    /// Hub authorization-server issuer.
    pub issuer: String,
    /// Audience/resource URL used by hub-issued credentials.
    pub resource: String,
    /// Transport mode.
    pub mode: GatewayMode,
    /// Server-side Google identity-provider settings.
    pub google: GoogleOidcConfig,
    /// Pre-registered native client.
    pub native_client: NativeClient,
}

impl GatewayConfig {
    /// Validate configuration before binding an HTTP listener.
    pub fn validate(&self) -> Result<(), GatewayConfigError> {
        if self.issuer.is_empty() || self.resource.is_empty() {
            return Err(GatewayConfigError::MissingEndpoint);
        }
        for (name, value) in [("issuer", &self.issuer), ("resource", &self.resource)] {
            if !is_allowed_origin(value, self.mode) {
                return Err(GatewayConfigError::InsecureOrigin { name, value: value.clone() });
            }
        }
        if self.google.client_id.trim().is_empty() || self.google.client_secret.is_empty() {
            return Err(GatewayConfigError::MissingGoogleCredential);
        }
        if self.google.issuer.as_str() != "https://accounts.google.com" {
            return Err(GatewayConfigError::UnexpectedGoogleIssuer(self.google.issuer.to_string()));
        }
        if self.google.scopes.iter().any(|scope| !GOOGLE_SCOPES.contains(&scope.as_str()))
            || self.google.scopes.len() != GOOGLE_SCOPES.len()
        {
            return Err(GatewayConfigError::InvalidGoogleScopes);
        }
        if self.native_client.client_id.trim().is_empty()
            || !is_loopback_redirect(&self.native_client.redirect_uri)
        {
            return Err(GatewayConfigError::InvalidNativeRedirect);
        }
        Ok(())
    }

    /// Return the public metadata advertised to protected-resource clients.
    pub fn metadata(&self) -> AuthorizationMetadata {
        AuthorizationMetadata {
            issuer: self.issuer.clone(),
            resource: self.resource.clone(),
            authorization_endpoint: format!("{}/authorize", self.issuer),
            token_endpoint: format!("{}/token", self.issuer),
            revocation_endpoint: format!("{}/revoke", self.issuer),
            device_authorization_endpoint: format!("{}/device", self.issuer),
            registration_endpoint: format!("{}/register", self.issuer),
            grant_types_supported: vec!["authorization_code".into(), "urn:ietf:params:oauth:grant-type:device_code".into(), "refresh_token".into()],
            code_challenge_methods_supported: vec!["S256".into()],
        }
    }
}

/// A verified upstream identity. Construct this only after the Google OIDC
/// verifier has checked signature, issuer, audience, expiry, nonce, state and
/// `email_verified`; a Google token is never accepted by the hub token handler.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedIdentity {
    /// Verified email address.
    pub email: String,
    /// Immutable upstream subject.
    pub subject: String,
    /// Stable upstream issuer.
    pub issuer: String,
}

/// Admission is deliberately a policy boundary. The default denies every user.
pub trait AdmissionPolicy: Send + Sync {
    /// Admit an identity and return its immutable owner record.
    fn admit(&self, identity: &VerifiedIdentity) -> Option<AdmissionIdentity>;
}

/// A policy that cannot accidentally admit an identity while access control is pending.
#[derive(Debug, Default)]
pub struct DenyAllAdmission;

impl AdmissionPolicy for DenyAllAdmission {
    fn admit(&self, _identity: &VerifiedIdentity) -> Option<AdmissionIdentity> { None }
}

#[derive(Debug, Clone)]
struct CodeGrant { client_id: String, redirect_uri: String, challenge: String, resource: String, owner: AdmissionIdentity, expires: u64, used: bool }
#[derive(Debug, Clone)]
struct DeviceGrant { client_id: String, resource: String, user_code: String, owner: Option<AdmissionIdentity>, expires: u64, next_poll: u64, polls: u32 }
#[derive(Debug, Clone)]
struct RefreshGrant { owner: AdmissionIdentity, resource: String, expires: u64, current: String, revoked: bool }

/// In-memory protocol state for the local demo gateway. A production adapter
/// must persist these records atomically; the state machine and its fail-closed
/// policy boundary are kept independent of that storage choice.
#[derive(Clone)]
pub struct Gateway {
    config: Arc<GatewayConfig>,
    policy: Arc<dyn AdmissionPolicy>,
    state: Arc<Mutex<GatewayState>>,
}

#[derive(Default)]
struct GatewayState { codes: BTreeMap<String, CodeGrant>, devices: BTreeMap<String, DeviceGrant>, refresh: BTreeMap<String, RefreshGrant> }

impl Gateway {
    /// Create a gateway after validating its server-side configuration.
    pub fn new(config: GatewayConfig, policy: Arc<dyn AdmissionPolicy>) -> Result<Self, GatewayConfigError> {
        config.validate()?;
        Ok(Self { config: Arc::new(config), policy, state: Arc::new(Mutex::new(GatewayState::default())) })
    }

    /// Build the metadata routes and the protocol endpoints. No REST proxy or `/mcp` route is installed.
    pub fn router(&self) -> Router {
        Router::new()
            .route("/.well-known/oauth-protected-resource", get(protected_metadata))
            .route("/.well-known/oauth-authorization-server", get(authorization_metadata))
            .route("/register", post(register))
            .route("/authorize", get(authorize))
            .route("/token", post(token))
            .route("/revoke", post(revoke))
            .route("/device", post(device))
            .route("/device/verify", post(verify_device))
            .with_state(self.clone())
    }

    /// Issue a one-time authorization code after explicit consent and admission.
    pub fn authorize_code(&self, client_id: &str, redirect_uri: &str, challenge: &str, resource: &str, identity: VerifiedIdentity, consent: bool, state: &str, expected_state: &str, nonce: &str, expected_nonce: &str) -> Result<String, ProtocolError> {
        if !consent { return Err(ProtocolError::AccessDenied); }
        if state.is_empty() || state != expected_state || nonce.is_empty() || nonce != expected_nonce { return Err(ProtocolError::InvalidRequest); }
        if client_id != self.config.native_client.client_id || redirect_uri != self.config.native_client.redirect_uri || resource != self.config.resource || challenge.is_empty() { return Err(ProtocolError::InvalidRequest); }
        let owner = self.policy.admit(&identity).ok_or(ProtocolError::AccessDenied)?;
        let code = secret("code", client_id, challenge);
        self.state.lock().map_err(|_| ProtocolError::ServerError)?.codes.insert(code.clone(), CodeGrant { client_id: client_id.into(), redirect_uri: redirect_uri.into(), challenge: challenge.into(), resource: resource.into(), owner, expires: now()+60, used: false });
        Ok(code)
    }

    /// Exchange a code using the original redirect and S256 challenge binding.
    pub fn exchange_code(&self, code: &str, client_id: &str, redirect_uri: &str, verifier: &str, resource: &str) -> Result<TokenResponse, ProtocolError> {
        let mut state = self.state.lock().map_err(|_| ProtocolError::ServerError)?;
        let owner = {
            let grant = state.codes.get_mut(code).ok_or(ProtocolError::InvalidGrant)?;
            if grant.used || grant.expires < now() || grant.client_id != client_id || grant.redirect_uri != redirect_uri || grant.resource != resource || grant.challenge != pkce(verifier) { return Err(ProtocolError::InvalidGrant); }
            grant.used = true;
            grant.owner.clone()
        };
        Ok(issue(&mut state, owner, resource))
    }

    /// Start an RFC 8628 grant; the private device code never leaves this API.
    pub fn device_authorize(&self, client_id: &str, resource: &str) -> Result<DeviceResponse, ProtocolError> {
        if client_id != self.config.native_client.client_id || resource != self.config.resource { return Err(ProtocolError::InvalidRequest); }
        let device_code = secret("device", client_id, resource);
        let user_code = format!("{}-{}", &device_code[0..4], &device_code[4..8]).to_uppercase();
        self.state.lock().map_err(|_| ProtocolError::ServerError)?.devices.insert(device_code.clone(), DeviceGrant { client_id: client_id.into(), resource: resource.into(), user_code: user_code.clone(), owner: None, expires: now()+600, next_poll: 0, polls: 0 });
        Ok(DeviceResponse { user_code, verification_uri: format!("{}/device/verify", self.config.issuer), expires_in: 600, interval: 5 })
    }

    /// Verify a user code after Google login and explicit consent.
    pub fn verify_device(&self, user_code: &str, identity: VerifiedIdentity, consent: bool) -> Result<(), ProtocolError> {
        if !consent { return Err(ProtocolError::AccessDenied); }
        let mut state = self.state.lock().map_err(|_| ProtocolError::ServerError)?;
        let grant = state.devices.values_mut().find(|grant| grant.user_code == user_code).ok_or(ProtocolError::InvalidGrant)?;
        if grant.expires < now() { return Err(ProtocolError::ExpiredToken); }
        grant.owner = Some(self.policy.admit(&identity).ok_or(ProtocolError::AccessDenied)?);
        Ok(())
    }

    /// Poll a device grant with RFC 8628 expiry and rate-limit semantics.
    pub fn poll_device(&self, device_code: &str) -> Result<TokenResponse, ProtocolError> {
        let mut state = self.state.lock().map_err(|_| ProtocolError::ServerError)?;
        let grant = state.devices.get_mut(device_code).ok_or(ProtocolError::InvalidGrant)?;
        let timestamp = now();
        if grant.expires < timestamp { return Err(ProtocolError::ExpiredToken); }
        grant.polls = grant.polls.saturating_add(1);
        if grant.next_poll >= timestamp { return Err(ProtocolError::SlowDown); }
        grant.next_poll = timestamp + 5;
        let owner = grant.owner.clone().ok_or(ProtocolError::AuthorizationPending)?;
        let resource = grant.resource.clone();
        state.devices.remove(device_code);
        Ok(issue(&mut state, owner, &resource))
    }

    /// Rotate a refresh token, rejecting reuse and revoked/expired grants.
    pub fn refresh(&self, refresh_token: &str) -> Result<TokenResponse, ProtocolError> {
        let mut state = self.state.lock().map_err(|_| ProtocolError::ServerError)?;
        let (owner, resource) = {
            let grant = state.refresh.values_mut().find(|grant| grant.current == refresh_token).ok_or(ProtocolError::InvalidGrant)?;
            if grant.revoked || grant.expires < now() { return Err(ProtocolError::InvalidGrant); }
            grant.revoked = true;
            (grant.owner.clone(), grant.resource.clone())
        };
        let response = issue(&mut state, owner, &resource);
        Ok(response)
    }

    /// Revoke a hub grant; Google tokens are not accepted here.
    pub fn revoke(&self, token: &str) -> Result<(), ProtocolError> {
        let mut state = self.state.lock().map_err(|_| ProtocolError::ServerError)?;
        if let Some(grant) = state.refresh.values_mut().find(|grant| grant.current == token) { grant.revoked = true; return Ok(()); }
        Err(ProtocolError::InvalidGrant)
    }
}

fn now() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO).as_secs() }
fn pkce(verifier: &str) -> String { blake3::hash(verifier.as_bytes()).to_hex().to_string() }
fn secret(kind: &str, a: &str, b: &str) -> String { let sequence = TOKEN_SEQUENCE.fetch_add(1, Ordering::Relaxed); blake3::hash(format!("{kind}:{a}:{b}:{}:{sequence}", now()).as_bytes()).to_hex().to_string() }
fn issue(state: &mut GatewayState, owner: AdmissionIdentity, resource: &str) -> TokenResponse { let access = secret("access", owner.owner.id.as_str(), resource); let refresh = secret("refresh", owner.owner.id.as_str(), &access); state.refresh.insert(refresh.clone(), RefreshGrant { owner, resource: resource.into(), expires: now()+7*24*60*60, current: refresh.clone(), revoked: false }); TokenResponse { access_token: access, refresh_token: refresh, token_type: "Bearer".into(), expires_in: 900, resource: resource.into() } }

/// OAuth token response issued by the hub, never by Google.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse { pub access_token: String, pub refresh_token: String, pub token_type: String, pub expires_in: u64, pub resource: String }
/// RFC 8628 response. The private device code is intentionally not represented.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceResponse { pub user_code: String, pub verification_uri: String, pub expires_in: u64, pub interval: u64 }
/// Protocol failures map to standard OAuth error names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ProtocolError { InvalidRequest, InvalidGrant, AccessDenied, AuthorizationPending, SlowDown, ExpiredToken, ServerError }
impl IntoResponse for ProtocolError { fn into_response(self) -> axum::response::Response { (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": format!("{self:?}").to_lowercase()}))).into_response() } }
#[derive(Debug, Deserialize)] struct RegisterRequest { client_id: String, redirect_uri: String }
#[derive(Debug, Deserialize)] struct AuthorizeRequest { client_id: String, redirect_uri: String, code_challenge: String, resource: String, identity: VerifiedIdentity, consent: bool, state: String, expected_state: String, nonce: String, expected_nonce: String }
#[derive(Debug, Deserialize)] struct TokenRequest { code: String, client_id: String, redirect_uri: String, code_verifier: String, resource: String }
#[derive(Debug, Deserialize)] struct DeviceRequest { client_id: String, resource: String }
#[derive(Debug, Deserialize)] struct VerifyRequest { user_code: String, identity: VerifiedIdentity, consent: bool }
#[derive(Debug, Deserialize)] struct RevokeRequest { token: String }
async fn protected_metadata(State(g): State<Gateway>) -> Json<AuthorizationMetadata> { Json(g.config.metadata()) }
async fn authorization_metadata(State(g): State<Gateway>) -> Json<AuthorizationMetadata> { Json(g.config.metadata()) }
async fn register(State(g): State<Gateway>, Json(r): Json<RegisterRequest>) -> impl IntoResponse { if r.client_id == g.config.native_client.client_id && r.redirect_uri == g.config.native_client.redirect_uri { Json(serde_json::json!({"client_id":r.client_id,"redirect_uris":[r.redirect_uri]})).into_response() } else { ProtocolError::InvalidRequest.into_response() } }
async fn authorize(State(g): State<Gateway>, Json(r): Json<AuthorizeRequest>) -> impl IntoResponse { match g.authorize_code(&r.client_id,&r.redirect_uri,&r.code_challenge,&r.resource,r.identity,r.consent,&r.state,&r.expected_state,&r.nonce,&r.expected_nonce) { Ok(code)=>Json(serde_json::json!({"code":code})).into_response(), Err(e)=>e.into_response() } }
async fn token(State(g): State<Gateway>, Json(r): Json<TokenRequest>) -> impl IntoResponse { match g.exchange_code(&r.code,&r.client_id,&r.redirect_uri,&r.code_verifier,&r.resource) { Ok(v)=>Json(v).into_response(), Err(e)=>e.into_response() } }
async fn device(State(g): State<Gateway>, Json(r): Json<DeviceRequest>) -> impl IntoResponse { match g.device_authorize(&r.client_id,&r.resource) { Ok(v)=>Json(v).into_response(), Err(e)=>e.into_response() } }
async fn verify_device(State(g): State<Gateway>, Json(r): Json<VerifyRequest>) -> impl IntoResponse { match g.verify_device(&r.user_code,r.identity,r.consent) { Ok(())=>StatusCode::NO_CONTENT.into_response(), Err(e)=>e.into_response() } }
async fn revoke(State(g): State<Gateway>, Json(r): Json<RevokeRequest>) -> impl IntoResponse { match g.revoke(&r.token) { Ok(())=>StatusCode::NO_CONTENT.into_response(), Err(e)=>e.into_response() } }

/// Public metadata shared by protected-resource and authorization-server responses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationMetadata {
    /// Authorization-server issuer.
    pub issuer: String,
    /// Resource audience bound to hub-issued credentials.
    pub resource: String,
    /// Authorization endpoint.
    pub authorization_endpoint: String,
    /// Token endpoint.
    pub token_endpoint: String,
    /// Revocation endpoint.
    pub revocation_endpoint: String,
    /// RFC 8628 device endpoint.
    pub device_authorization_endpoint: String,
    /// Native-client registration endpoint.
    pub registration_endpoint: String,
    /// Supported hub grant types.
    pub grant_types_supported: Vec<String>,
    /// Required PKCE method for native authorization.
    pub code_challenge_methods_supported: Vec<String>,
}

/// Provider-neutral admission identity. Email is evidence, never the stable key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionIdentity {
    /// Immutable owner identity used by AgentPalace provenance.
    pub owner: AuthenticatedOwner,
    /// Issuer/subject binding that must remain stable across email changes.
    pub subject_binding: SubjectBinding,
}

impl AdmissionIdentity {
    /// Build an admission identity from already-verified claims and the assigned owner ID.
    pub fn new(owner_id: OwnerId, owner: AuthenticatedOwner) -> Self {
        let subject_binding = owner.subject_binding();
        let owner = AuthenticatedOwner::new(owner_id, owner.issuer.clone(), owner.subject.clone(), owner.email_at_write.clone());
        Self { owner, subject_binding }
    }
}

fn is_allowed_origin(value: &str, mode: GatewayMode) -> bool {
    value.starts_with("https://") || (mode == GatewayMode::LoopbackDemo && is_loopback_origin(value))
}

fn is_loopback_origin(value: &str) -> bool {
    let Some(authority) = value.strip_prefix("http://").and_then(|rest| rest.split('/').next()) else { return false };
    let Some((host, port)) = authority.rsplit_once(':') else { return false };
    (host == "localhost" || host == "127.0.0.1") && valid_port(port) && !authority.contains('@')
}

fn is_loopback_redirect(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("http://") else { return false };
    let Some((authority, path)) = rest.split_once('/') else { return false };
    is_loopback_origin(&format!("http://{authority}")) && path == "callback"
}

fn valid_port(value: &str) -> bool {
    value.parse::<u16>().is_ok_and(|port| port != 0)
}

/// Configuration must be rejected before the gateway can start.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum GatewayConfigError {
    /// Issuer or resource was empty.
    #[error("issuer and resource are required")]
    MissingEndpoint,
    /// An origin violates the secure/explicit-loopback policy.
    #[error("{name} is not an allowed origin: {value}")]
    InsecureOrigin { name: &'static str, value: String },
    /// Google server credentials were not supplied.
    #[error("Google client credentials are required")]
    MissingGoogleCredential,
    /// The upstream issuer is not the supported Google issuer.
    #[error("unexpected Google issuer: {0}")]
    UnexpectedGoogleIssuer(String),
    /// Only openid and email are permitted.
    #[error("Google scopes must be exactly openid and email")]
    InvalidGoogleScopes,
    /// Native clients must be public and loopback-bound.
    #[error("native client redirect must be loopback-bound")]
    InvalidNativeRedirect,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn config(mode: GatewayMode) -> GatewayConfig {
        GatewayConfig {
            issuer: "http://localhost:8080".into(),
            resource: "http://localhost:8080/api".into(),
            mode,
            google: GoogleOidcConfig {
                client_id: "google-client".into(),
                client_secret: "server-only".into(),
                issuer: Issuer::new("https://accounts.google.com").expect("constant issuer"),
                scopes: ["openid", "email"].into_iter().map(str::to_owned).collect(),
            },
            native_client: NativeClient { client_id: "agentpalace-native".into(), redirect_uri: "http://127.0.0.1:49152/callback".into() },
        }
    }

    #[test]
    fn secure_mode_rejects_loopback_http() {
        assert_eq!(config(GatewayMode::Secure).validate(), Err(GatewayConfigError::InsecureOrigin { name: "issuer", value: "http://localhost:8080".into() }));
    }

    #[test]
    fn loopback_mode_accepts_only_google_sign_in_scopes() {
        let mut value = config(GatewayMode::LoopbackDemo);
        assert!(value.validate().is_ok());
        value.google.scopes.insert("profile".into());
        assert_eq!(value.validate(), Err(GatewayConfigError::InvalidGoogleScopes));
    }

    #[test]
    fn metadata_advertises_hub_endpoints_and_pkce() {
        let metadata = config(GatewayMode::LoopbackDemo).metadata();
        assert_eq!(metadata.issuer, "http://localhost:8080");
        assert!(metadata.grant_types_supported.iter().any(|grant| grant == "refresh_token"));
        assert_eq!(metadata.code_challenge_methods_supported, vec!["S256"]);
    }

    #[test]
    fn loopback_validation_rejects_lookalike_hosts() {
        let mut value = config(GatewayMode::LoopbackDemo);
        value.issuer = "http://localhost.evil:8080".into();
        assert!(matches!(value.validate(), Err(GatewayConfigError::InsecureOrigin { .. })));
    }

    struct AllowOne(AdmissionIdentity);
    impl AdmissionPolicy for AllowOne {
        fn admit(&self, identity: &VerifiedIdentity) -> Option<AdmissionIdentity> {
            (identity.email == self.0.owner.email_at_write.as_str()
                && identity.issuer == self.0.owner.issuer.as_str()
                && identity.subject == self.0.owner.subject.as_str()).then(|| self.0.clone())
        }
    }

    fn gateway() -> (Gateway, VerifiedIdentity) {
        let owner = AuthenticatedOwner::parse("owner-1", "https://accounts.google.com", "subject-1", "person@example.com").expect("test owner");
        let identity = VerifiedIdentity { email: "person@example.com".into(), issuer: "https://accounts.google.com".into(), subject: "subject-1".into() };
        let policy = Arc::new(AllowOne(AdmissionIdentity::new(OwnerId::new("owner-1").expect("owner"), owner)));
        (Gateway::new(config(GatewayMode::LoopbackDemo), policy).expect("gateway"), identity)
    }

    #[test]
    fn browser_code_is_consent_and_pkce_bound_and_single_use() {
        let (gateway, identity) = gateway();
        let code = gateway.authorize_code("agentpalace-native", "http://127.0.0.1:49152/callback", &pkce("verifier"), "http://localhost:8080/api", identity.clone(), true, "state", "state", "nonce", "nonce").expect("code");
        assert_eq!(gateway.authorize_code("agentpalace-native", "http://127.0.0.1:49152/callback", "challenge", "http://localhost:8080/api", identity.clone(), true, "wrong", "state", "nonce", "nonce"), Err(ProtocolError::InvalidRequest));
        assert_eq!(gateway.exchange_code(&code, "agentpalace-native", "http://127.0.0.1:49152/callback", "wrong", "http://localhost:8080/api"), Err(ProtocolError::InvalidGrant));
        let token = gateway.exchange_code(&code, "agentpalace-native", "http://127.0.0.1:49152/callback", "verifier", "http://localhost:8080/api").expect("token");
        assert_eq!(gateway.exchange_code(&code, "agentpalace-native", "http://127.0.0.1:49152/callback", "verifier", "http://localhost:8080/api"), Err(ProtocolError::InvalidGrant));
        assert_eq!(gateway.authorize_code("agentpalace-native", "http://127.0.0.1:49152/callback", "challenge", "wrong-resource", identity, true, "state", "state", "nonce", "nonce"), Err(ProtocolError::InvalidRequest));
        assert!(!token.access_token.is_empty());
    }

    #[test]
    fn denied_and_unadmitted_browser_login_fail_closed() {
        let (gateway, identity) = gateway();
        assert_eq!(gateway.authorize_code("agentpalace-native", "http://127.0.0.1:49152/callback", "challenge", "http://localhost:8080/api", identity.clone(), false, "state", "state", "nonce", "nonce"), Err(ProtocolError::AccessDenied));
        let unknown = VerifiedIdentity { email: "other@example.com".into(), ..identity };
        assert_eq!(gateway.authorize_code("agentpalace-native", "http://127.0.0.1:49152/callback", "challenge", "http://localhost:8080/api", unknown, true, "state", "state", "nonce", "nonce"), Err(ProtocolError::AccessDenied));
    }

    #[test]
    fn refresh_rotation_reuse_and_revocation_are_enforced() {
        let (gateway, identity) = gateway();
        let code = gateway.authorize_code("agentpalace-native", "http://127.0.0.1:49152/callback", &pkce("v"), "http://localhost:8080/api", identity, true, "state", "state", "nonce", "nonce").expect("code");
        let first = gateway.exchange_code(&code, "agentpalace-native", "http://127.0.0.1:49152/callback", "v", "http://localhost:8080/api").expect("token");
        let rotated = gateway.refresh(&first.refresh_token).expect("rotation");
        assert_eq!(gateway.refresh(&first.refresh_token), Err(ProtocolError::InvalidGrant));
        gateway.revoke(&rotated.refresh_token).expect("revoke");
        assert_eq!(gateway.refresh(&rotated.refresh_token), Err(ProtocolError::InvalidGrant));
    }

    #[test]
    fn metadata_routes_are_hub_only_and_device_grants_expire_or_rate_limit() {
        let (gateway, _) = gateway();
        let metadata = gateway.config.metadata();
        assert!(metadata.authorization_endpoint.ends_with("/authorize"));
        let _router = gateway.router();
        let device = gateway.device_authorize("agentpalace-native", "http://localhost:8080/api").expect("device");
        assert!(!device.verification_uri.is_empty());
        let code = gateway.state.lock().expect("state").devices.keys().next().cloned().expect("private code");
        assert_eq!(gateway.poll_device(&code), Err(ProtocolError::AuthorizationPending));
        assert_eq!(gateway.poll_device(&code), Err(ProtocolError::SlowDown));
        gateway.state.lock().expect("state").devices.get_mut(&code).expect("grant").expires = now() - 1;
        assert_eq!(gateway.poll_device(&code), Err(ProtocolError::ExpiredToken));
    }
}
