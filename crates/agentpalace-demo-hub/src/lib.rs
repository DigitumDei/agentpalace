//! Architecture and policy boundary for the AgentPalace demo authorization hub.
//!
//! This crate owns the hub's issuer/resource configuration and the protocol metadata
//! contract. Google is deliberately represented only as an upstream identity provider;
//! the hub must mint credentials for its own resource before a request can reach a palace.
//! The gateway exposes documented OAuth metadata and grant endpoints, a closed
//! REST forwarding inventory, and session-protected access administration.

pub mod access_policy;
pub mod forwarding;

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use agentpalace_core::{AuthenticatedOwner, Issuer, OwnerId, SubjectBinding};
use axum::{
    Json, Router,
    body::to_bytes,
    extract::{Form, Path, Query, Request, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post, put},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use access_policy::{AccessEntry, AccessPolicyError, AccessPolicySnapshot, AccessPolicyStore, AccessRole, PolicyDecision};
use forwarding::{AuthorizedOwner, DemoRole, ForwardRequest, Forwarder, PrivateTokenProvisioner};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// The only upstream scopes accepted by the demo gateway.
pub const GOOGLE_SCOPES: [&str; 2] = ["openid", "email"];

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

/// Claims returned by a Google ID token after a maintained OIDC verifier has
/// checked its signature against Google's JWKS.  The gateway never accepts an
/// access token in this position.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoogleIdClaims {
    /// OIDC issuer.
    pub iss: String,
    /// Google OAuth client audience.
    pub aud: String,
    /// Immutable Google subject.
    pub sub: String,
    /// Verified email address.
    pub email: String,
    /// Google assertion's email verification result.
    pub email_verified: bool,
    /// Expiry, as Unix seconds.
    pub exp: u64,
    /// OIDC nonce bound to the browser transaction.
    pub nonce: String,
    /// Additional standard OIDC claims such as `iat`.
    #[serde(flatten)]
    pub additional: BTreeMap<String, serde_json::Value>,
}

/// Boundary for the upstream OIDC implementation. Implementations must validate the ID-token
/// signature against the provider's JWKS before returning claims; the gateway never decodes an
/// unverified JWT.
#[async_trait::async_trait]
pub trait GoogleOidcVerifier: Send + Sync {
    /// Exchange a Google authorization code and verify its ID token for the transaction nonce.
    /// `redirect_uri` is the exact hub callback the code was issued for (browser sign-in and
    /// device verification use different callbacks). The implementation keeps the client secret
    /// and upstream token response server-side.
    async fn exchange_and_verify(
        &self,
        authorization_code: &str,
        expected_nonce: &str,
        redirect_uri: &str,
    ) -> Result<GoogleIdClaims, GoogleClaimError>;
}

/// Google OIDC/JWKS verifier used by the hub. It exchanges the authorization code server-side,
/// verifies the returned ID token's RS256 signature against the provider JWKS, and checks the
/// standard claims before the gateway applies its admission policy.
#[derive(Debug, Clone)]
pub struct GoogleOidcVerifierAdapter {
    config: GoogleOidcConfig,
    token_endpoint: String,
    jwks_endpoint: String,
    http: reqwest::Client,
}

#[derive(Debug, Deserialize)]
struct GoogleTokenResponse {
    id_token: String,
}
#[derive(Debug, Deserialize)]
struct GoogleJwks {
    keys: Vec<GoogleJwk>,
}
#[derive(Debug, Deserialize)]
struct GoogleJwk {
    kid: String,
    kty: String,
    n: String,
    e: String,
    alg: Option<String>,
}

impl GoogleOidcVerifierAdapter {
    /// Construct an adapter for Google's production token and JWKS endpoints.
    pub fn new(config: GoogleOidcConfig) -> Result<Self, String> {
        Self::new_with_endpoints(
            config,
            "https://oauth2.googleapis.com/token",
            "https://www.googleapis.com/oauth2/v3/certs",
        )
    }

    /// Construct an adapter with injectable token and JWKS endpoints for provider fixtures.
    pub fn new_with_endpoints(
        config: GoogleOidcConfig,
        token_endpoint: impl Into<String>,
        jwks_endpoint: impl Into<String>,
    ) -> Result<Self, String> {
        if config.issuer.as_str() != "https://accounts.google.com" {
            return Err("Google issuer must be accounts.google.com".into());
        }
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|_| "Google OIDC client could not be built".to_owned())?;
        Ok(Self {
            config,
            token_endpoint: token_endpoint.into(),
            jwks_endpoint: jwks_endpoint.into(),
            http,
        })
    }
}

fn claim_error(error: &jsonwebtoken::errors::Error) -> GoogleClaimError {
    use jsonwebtoken::errors::ErrorKind;
    match error.kind() {
        ErrorKind::InvalidIssuer => GoogleClaimError::Issuer,
        ErrorKind::InvalidAudience => GoogleClaimError::Audience,
        ErrorKind::ExpiredSignature => GoogleClaimError::Expired,
        ErrorKind::MissingRequiredClaim(claim) if claim == "iss" => GoogleClaimError::Issuer,
        ErrorKind::MissingRequiredClaim(claim) if claim == "aud" => GoogleClaimError::Audience,
        ErrorKind::MissingRequiredClaim(claim) if claim == "exp" => GoogleClaimError::Expired,
        ErrorKind::MissingRequiredClaim(_) | ErrorKind::Json(_) => GoogleClaimError::MissingSubject,
        _ => GoogleClaimError::Signature,
    }
}

#[async_trait::async_trait]
impl GoogleOidcVerifier for GoogleOidcVerifierAdapter {
    async fn exchange_and_verify(
        &self,
        authorization_code: &str,
        expected_nonce: &str,
        redirect_uri: &str,
    ) -> Result<GoogleIdClaims, GoogleClaimError> {
        let token: GoogleTokenResponse = self
            .http
            .post(&self.token_endpoint)
            .form(&[
                ("code", authorization_code),
                ("client_id", self.config.client_id.as_str()),
                ("client_secret", self.config.client_secret.as_str()),
                ("redirect_uri", redirect_uri),
                ("grant_type", "authorization_code"),
            ])
            .send()
            .await
            .map_err(|_| GoogleClaimError::Upstream)?
            .error_for_status()
            .map_err(|_| GoogleClaimError::Upstream)?
            .json()
            .await
            .map_err(|_| GoogleClaimError::Upstream)?;
        let header = decode_header(&token.id_token).map_err(|_| GoogleClaimError::Signature)?;
        // Only RS256 with a key the JWKS names by the token's `kid` is accepted; an HMAC token
        // or a token without `kid` never reaches claim validation.
        if header.alg != Algorithm::RS256 {
            return Err(GoogleClaimError::Signature);
        }
        let kid = header.kid.ok_or(GoogleClaimError::Signature)?;
        let jwks = self
            .http
            .get(&self.jwks_endpoint)
            .send()
            .await
            .map_err(|_| GoogleClaimError::Upstream)?
            .error_for_status()
            .map_err(|_| GoogleClaimError::Upstream)?
            .json::<GoogleJwks>()
            .await
            .map_err(|_| GoogleClaimError::Upstream)?;
        let key = jwks
            .keys
            .into_iter()
            .find(|key| {
                key.kid == kid
                    && key.kty == "RSA"
                    && key.alg.as_deref().is_none_or(|alg| alg == "RS256")
            })
            .ok_or(GoogleClaimError::Signature)?;
        let decoding_key = DecodingKey::from_rsa_components(&key.n, &key.e)
            .map_err(|_| GoogleClaimError::Signature)?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[self.config.issuer.as_str()]);
        validation.set_audience(&[self.config.client_id.as_str()]);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        validation.leeway = 0;
        // Decode into an untyped value first so signature and registered-claim validation run
        // (and report their specific failure) before the typed shape is required.
        let data = decode::<serde_json::Value>(&token.id_token, &decoding_key, &validation)
            .map_err(|error| claim_error(&error))?;
        let claims: GoogleIdClaims =
            serde_json::from_value(data.claims).map_err(|_| GoogleClaimError::MissingSubject)?;
        verify_google_claims(&self.config, &claims, expected_nonce)?;
        Ok(claims)
    }
}

/// Validate the security claims which are independent of a particular
/// admission list. Signature verification is intentionally supplied by the
/// maintained `openidconnect` adapter at the boundary; an unverified decode
/// cannot be converted into this type by the gateway.
pub fn verify_google_claims(
    config: &GoogleOidcConfig,
    claims: &GoogleIdClaims,
    expected_nonce: &str,
) -> Result<VerifiedIdentity, GoogleClaimError> {
    if claims.iss != config.issuer.as_str() {
        return Err(GoogleClaimError::Issuer);
    }
    if claims.aud != config.client_id {
        return Err(GoogleClaimError::Audience);
    }
    if claims.exp <= now() {
        return Err(GoogleClaimError::Expired);
    }
    if !claims.email_verified {
        return Err(GoogleClaimError::EmailUnverified);
    }
    if expected_nonce.is_empty() || claims.nonce != expected_nonce {
        return Err(GoogleClaimError::Nonce);
    }
    if claims.sub.is_empty() || claims.email.trim().is_empty() {
        return Err(GoogleClaimError::MissingSubject);
    }
    Ok(VerifiedIdentity {
        email: claims.email.clone(),
        subject: claims.sub.clone(),
        issuer: claims.iss.clone(),
    })
}

/// Rejection reasons for a Google OIDC assertion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum GoogleClaimError {
    /// Issuer did not match the configured Google issuer.
    #[error("Google issuer mismatch")]
    Issuer,
    /// Audience did not match the configured web client.
    #[error("Google audience mismatch")]
    Audience,
    /// The assertion is expired.
    #[error("Google assertion expired")]
    Expired,
    /// Google did not verify the mailbox.
    #[error("Google email is not verified")]
    EmailUnverified,
    /// Browser transaction nonce did not match.
    #[error("Google nonce mismatch")]
    Nonce,
    /// Required immutable identity claims were absent.
    #[error("Google subject or email is missing")]
    MissingSubject,
    /// The upstream token or JWKS response was not valid.
    #[error("Google upstream assertion could not be verified")]
    Upstream,
    /// The ID-token signature or key was invalid.
    #[error("Google ID-token signature is invalid")]
    Signature,
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

/// Whether hard deletion is available through the demo hub.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HardDeletePolicy {
    /// Disable deletion entirely.
    Disabled,
    /// Proposed demo default: require a fresh admin browser session and CSRF token.
    RecentAdminBrowser,
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
            grant_types_supported: vec![
                "authorization_code".into(),
                "urn:ietf:params:oauth:grant-type:device_code".into(),
                "refresh_token".into(),
            ],
            code_challenge_methods_supported: vec!["S256".into()],
        }
    }

    /// Protected-resource metadata uses the RFC 9728 shape and points at the
    /// hub authorization server rather than pretending to be server metadata.
    pub fn protected_resource_metadata(&self) -> ProtectedResourceMetadata {
        ProtectedResourceMetadata {
            resource: self.resource.clone(),
            authorization_servers: vec![self.issuer.clone()],
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
    fn admit(&self, _identity: &VerifiedIdentity) -> Option<AdmissionIdentity> {
        None
    }
}

#[derive(Debug, Clone)]
struct CodeGrant {
    client_id: String,
    redirect_uri: String,
    challenge: String,
    resource: String,
    owner: AdmissionIdentity,
    role_ceiling: AccessRole,
    expires: u64,
    used: bool,
}
#[derive(Debug, Clone)]
struct BrowserTransaction {
    client_id: String,
    redirect_uri: String,
    challenge: String,
    resource: String,
    state: String,
    nonce: String,
    csrf: String,
    browser_id: String,
    expires: u64,
}
#[derive(Debug, Clone)]
struct DeviceGrant {
    client_id: String,
    resource: String,
    user_code: String,
    owner: Option<AdmissionIdentity>,
    role_ceiling: Option<AccessRole>,
    verify_state: Option<String>,
    verify_nonce: Option<String>,
    verify_csrf: String,
    browser_id: Option<String>,
    expires: u64,
    next_poll: Option<Instant>,
    poll_interval: u64,
    polls: u32,
    verify_attempts: u32,
    denied: bool,
    /// Allocation order, used to evict the oldest decided grant first.
    issued: u64,
}
#[derive(Debug, Clone)]
struct RefreshGrant {
    family: String,
    owner: AdmissionIdentity,
    role_ceiling: AccessRole,
    resource: String,
    expires: u64,
    current: String,
    revoked: bool,
}
#[derive(Debug, Clone)]
struct AccessGrant {
    family: String,
    owner: AdmissionIdentity,
    role_ceiling: AccessRole,
    resource: String,
    expires: u64,
    revoked: bool,
}

/// In-memory protocol state for the local demo gateway. A production adapter
/// must persist these records atomically; the state machine and its fail-closed
/// policy boundary are kept independent of that storage choice.
#[derive(Clone)]
pub struct Gateway {
    config: Arc<GatewayConfig>,
    hard_delete_policy: HardDeletePolicy,
    policy: Arc<dyn AdmissionPolicy>,
    verifier: Option<Arc<dyn GoogleOidcVerifier>>,
    forwarder: Option<Arc<Forwarder>>,
    token_provisioner: Option<Arc<PrivateTokenProvisioner>>,
    access_store: Option<Arc<AccessPolicyStore>>,
    state: Arc<Mutex<GatewayState>>,
    device_timing: DeviceTiming,
}

/// RFC 8628 timing for device grants issued by one gateway.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceTiming {
    /// Minimum seconds between polls (`interval`); each `slow_down` adds five seconds.
    pub interval_seconds: u64,
    /// Seconds until an unapproved grant expires (`expires_in`).
    pub lifetime_seconds: u64,
}

impl Default for DeviceTiming {
    fn default() -> Self {
        Self { interval_seconds: 5, lifetime_seconds: 600 }
    }
}

#[derive(Default)]
struct GatewayState {
    codes: BTreeMap<String, CodeGrant>,
    browser: BTreeMap<String, BrowserTransaction>,
    pending_browser: BTreeMap<String, GoogleIdClaims>,
    pending_device: BTreeMap<String, GoogleIdClaims>,
    devices: BTreeMap<String, DeviceGrant>,
    refresh: BTreeMap<String, RefreshGrant>,
    access: BTreeMap<String, AccessGrant>,
    sessions: BTreeMap<String, BrowserSession>,
    /// Next `DeviceGrant::issued` value.
    device_seq: u64,
    admin_deletes_in_flight: BTreeMap<String, u32>,
}

/// A hub browser session. The CSRF secret is never serialized or returned.
#[derive(Debug, Clone)]
pub struct BrowserSession {
    /// Authenticated owner.
    pub owner: AdmissionIdentity,
    /// Session CSRF value.
    pub csrf: String,
    /// Last successful upstream authentication.
    pub authenticated_at: u64,
    /// Whether this session completed the administrator re-authentication boundary.
    pub admin: bool,
}

/// A deliberately small role ceiling for agents acting through an owner grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentGrantRole {
    /// Read-only access.
    Readonly,
    /// Read and write access.
    Write,
}

impl AgentGrantRole {
    /// Admin-owned agents may never exceed this ceiling.
    pub const fn admin_ceiling(self) -> Self {
        match self {
            Self::Write => Self::Write,
            Self::Readonly => Self::Readonly,
        }
    }
}

fn register_rest_routes(router: Router<Gateway>) -> Router<Gateway> {
    router
        .route("/v1/health", get(forward_rest))
        .route("/v1/info", get(forward_rest))
        .route("/v1/drawers", get(forward_rest).post(forward_rest))
        .route("/v1/drawers/{id}", get(forward_rest).delete(forward_rest))
        .route("/v1/drawers/search", post(forward_rest))
        .route("/v1/drawers/check_duplicate", post(forward_rest))
        .route("/v1/kg/timeline", get(forward_rest))
        .route("/v1/kg/stats", get(forward_rest))
        .route("/v1/kg/query", post(forward_rest))
        .route("/v1/kg/facts", post(forward_rest))
        .route("/v1/kg/facts/invalidate", post(forward_rest))
        .route("/v1/ingest/preflight", post(forward_rest))
        .route("/v1/ingest/batch", post(forward_rest))
        .route("/v1/taxonomy", get(forward_rest))
        .route("/v1/wings", get(forward_rest))
        .route("/v1/rooms", get(forward_rest))
        .route("/v1/changes", get(forward_rest))
        .route("/v1/coordination/tasks", get(forward_rest).post(forward_rest))
        .route("/v1/coordination/tasks/{id}", get(forward_rest))
        .route("/v1/coordination/tasks/{id}/claim", post(forward_rest))
        .route("/v1/coordination/tasks/{id}/renew", post(forward_rest))
        .route("/v1/coordination/tasks/{id}/transition", post(forward_rest))
        .route("/v1/coordination/messages", post(forward_rest))
        .route("/v1/coordination/messages/{id}", get(forward_rest))
        .route("/v1/coordination/messages/{id}/ack", post(forward_rest))
        .route("/v1/coordination/inbox", get(forward_rest))
        .route("/v1/coordination/artifacts", post(forward_rest))
        .route("/v1/coordination/artifacts/{id}", get(forward_rest))
        .route("/v1/coordination/results", post(forward_rest))
        .route("/v1/coordination/results/{id}", get(forward_rest))
        .route("/v1/coordination/events", get(forward_rest))
}

struct AdminDeleteGuard { gateway: Gateway, owner: AdmissionIdentity }

impl Drop for AdminDeleteGuard {
    fn drop(&mut self) {
        self.gateway.end_admin_delete(self.owner.owner.id.as_str());
        let _ = self.gateway.reconcile_owner_tokens(&self.owner.owner.id);
    }
}

impl Gateway {
    /// Create a gateway after validating its server-side configuration.
    pub fn new(
        config: GatewayConfig,
        policy: Arc<dyn AdmissionPolicy>,
    ) -> Result<Self, GatewayConfigError> {
        config.validate()?;
        Ok(Self {
            config: Arc::new(config),
            hard_delete_policy: HardDeletePolicy::RecentAdminBrowser,
            policy,
            verifier: None,
            forwarder: None,
            token_provisioner: None,
            access_store: None,
            state: Arc::new(Mutex::new(GatewayState::default())),
            device_timing: DeviceTiming::default(),
        })
    }

    /// Override the RFC 8628 polling interval and grant lifetime (each at least one second).
    pub fn with_device_timing(mut self, timing: DeviceTiming) -> Self {
        self.device_timing = DeviceTiming {
            interval_seconds: timing.interval_seconds.max(1),
            lifetime_seconds: timing.lifetime_seconds.max(1),
        };
        self
    }

    /// Attach the maintained Google OIDC verifier supplied by the hosting
    /// application. Without one, the callback fails closed.
    pub fn with_google_verifier(mut self, verifier: Arc<dyn GoogleOidcVerifier>) -> Self {
        self.verifier = Some(verifier);
        self
    }

    /// Attach the configured private AgentPalace REST origin.
    pub fn with_forwarder(mut self, forwarder: Arc<Forwarder>) -> Self {
        self.forwarder = Some(forwarder);
        self
    }

    /// Attach the server-side provisioner for owner-scoped palace credentials.
    pub fn with_token_provisioner(mut self, provisioner: Arc<PrivateTokenProvisioner>) -> Self {
        self.token_provisioner = Some(provisioner);
        self
    }

    /// Configure the proposed admin-browser-only hard-delete default.
    pub fn with_hard_delete_policy(mut self, policy: HardDeletePolicy) -> Self {
        self.hard_delete_policy = policy;
        self
    }

    /// Attach the persistent editable access policy used for live admission and role checks.
    pub fn with_access_policy_store(mut self, store: Arc<AccessPolicyStore>) -> Self {
        self.access_store = Some(store);
        self
    }

    fn resolve_identity(&self, identity: &VerifiedIdentity) -> Result<Option<PolicyDecision>, ProtocolError> {
        if let Some(store) = &self.access_store {
            return store.resolve(identity).map_err(|_| ProtocolError::ServerError);
        }
        Ok(self.policy.admit(identity).map(|admission| PolicyDecision {
            admission,
            role: AccessRole::Write,
        }))
    }

    fn role_for_owner(&self, owner_id: &agentpalace_core::OwnerId) -> Result<Option<AccessRole>, ProtocolError> {
        match &self.access_store {
            Some(store) => store.role_for_owner(owner_id).map_err(|_| ProtocolError::ServerError),
            None => Ok(Some(AccessRole::Write)),
        }
    }

    fn effective_role(&self, owner: &AdmissionIdentity, ceiling: AccessRole) -> Result<AccessRole, ProtocolError> {
        let current = self.role_for_owner(&owner.owner.id)?.ok_or(ProtocolError::AccessDenied)?;
        let rank = |role| match role { AccessRole::Readonly => 0, AccessRole::Write => 1, AccessRole::Admin => 2 };
        let role = if rank(current) < rank(ceiling) { current } else { ceiling };
        // OAuth grants are not administrative browser sessions. Hard deletion remains
        // available only to a recently authenticated administrator browser request.
        Ok(if role == AccessRole::Admin { AccessRole::Write } else { role })
    }

    fn begin_admin_delete(&self, owner_id: &str) -> Result<(), ProtocolError> {
        let mut state = self.state.lock().map_err(|_| ProtocolError::ServerError)?;
        let count = state.admin_deletes_in_flight.entry(owner_id.into()).or_default();
        *count = count.saturating_add(1);
        Ok(())
    }

    fn end_admin_delete(&self, owner_id: &str) {
        if let Ok(mut state) = self.state.lock() {
            if let Some(count) = state.admin_deletes_in_flight.get_mut(owner_id) {
                *count = count.saturating_sub(1);
                if *count == 0 { state.admin_deletes_in_flight.remove(owner_id); }
            }
        }
    }

    fn reconcile_email_tokens(&self, email: &str) -> Result<(), ProtocolError> {
        let Some(store) = &self.access_store else { return Err(ProtocolError::ServerError) };
        let owner_id = store.owner_id_for_email(email).map_err(|_| ProtocolError::ServerError)?;
        if let Some(owner_id) = owner_id { self.reconcile_owner_tokens(&owner_id)?; }
        Ok(())
    }

    fn reconcile_owner_tokens(&self, owner_id: &agentpalace_core::OwnerId) -> Result<(), ProtocolError> {
        let (Some(store), Some(provisioner)) = (&self.access_store, &self.token_provisioner) else { return Ok(()) };
        let Some(current_role) = store.role_for_owner(owner_id).map_err(|_| ProtocolError::ServerError)? else {
            provisioner.revoke(owner_id.as_str()).map_err(|_| ProtocolError::ServerError)?;
            return Ok(());
        };
        let owner = {
            let state = self.state.lock().map_err(|_| ProtocolError::ServerError)?;
            state.access.values().map(|grant| &grant.owner)
                .chain(state.refresh.values().map(|grant| &grant.owner))
                .chain(state.codes.values().map(|grant| &grant.owner))
                .chain(state.devices.values().filter_map(|grant| grant.owner.as_ref()))
                .chain(state.sessions.values().map(|session| &session.owner))
                .find(|owner| &owner.owner.id == owner_id).cloned()
        };
        let Some(owner) = owner else {
            provisioner.revoke(owner_id.as_str()).map_err(|_| ProtocolError::ServerError)?;
            return Ok(());
        };
        let active_roles = self.active_token_roles(owner_id, current_role)?;
        provisioner.reconcile_roles(&owner, &active_roles).map_err(|_| ProtocolError::ServerError)?;
        Ok(())
    }

    fn active_token_roles(&self, owner_id: &agentpalace_core::OwnerId, current: AccessRole) -> Result<Vec<DemoRole>, ProtocolError> {
        let state = self.state.lock().map_err(|_| ProtocolError::ServerError)?;
        let mut roles = Vec::new();
        let mut add = |ceiling: AccessRole| {
            let rank = |role| match role { AccessRole::Readonly => 0, AccessRole::Write => 1, AccessRole::Admin => 2 };
            let role = if rank(current) < rank(ceiling) { current } else { ceiling };
            let role = if role == AccessRole::Admin { AccessRole::Write } else { role };
            let role = match role { AccessRole::Readonly => DemoRole::Readonly, AccessRole::Write => DemoRole::Write, AccessRole::Admin => DemoRole::Write };
            if !roles.contains(&role) { roles.push(role); }
        };
        for grant in state.access.values().filter(|grant| grant.owner.owner.id == *owner_id && !grant.revoked && grant.expires >= now()) { add(grant.role_ceiling); }
        for grant in state.refresh.values().filter(|grant| grant.owner.owner.id == *owner_id && !grant.revoked && grant.expires >= now()) { add(grant.role_ceiling); }
        for grant in state.codes.values().filter(|grant| grant.owner.owner.id == *owner_id && !grant.used && grant.expires >= now()) { add(grant.role_ceiling); }
        for grant in state.devices.values().filter(|grant| grant.owner.as_ref().is_some_and(|owner| owner.owner.id == *owner_id) && !grant.denied && grant.expires >= now()) {
            if let Some(ceiling) = grant.role_ceiling { add(ceiling); }
        }
        if state.admin_deletes_in_flight.get(owner_id.as_str()).copied().unwrap_or(0) > 0 { roles.push(DemoRole::Admin); }
        Ok(roles)
    }

    /// Build documented metadata, OAuth, access administration, and explicit REST routes.
    pub fn router(&self) -> Router {
        register_rest_routes(Router::new()
            .route("/", get(home_page))
            .route("/hub/connections", get(connections_page))
            .route("/.well-known/oauth-protected-resource", get(protected_metadata))
            .route("/.well-known/oauth-authorization-server", get(authorization_metadata))
            .route("/register", post(register))
            .route("/authorize", get(authorize))
            .route("/auth/google/callback", get(google_callback))
            .route("/auth/google/device-callback", get(google_device_callback))
            .route("/auth/google/consent", post(google_consent))
            .route("/auth/google/device-consent", post(google_device_consent))
            .route("/session", get(session))
            .route("/connections", get(connections))
            .route("/connections/revoke", post(revoke_connection))
            .route("/token", post(token))
            .route("/revoke", post(revoke))
            .route("/device", post(device))
            .route("/device/verify", get(begin_device_verify).post(verify_device))
            .route("/hub/v1/access", get(get_access))
            .route("/hub/v1/access/{email}", put(put_access).delete(delete_access)))
            .with_state(self.clone())
    }

    /// Issue a one-time authorization code after explicit consent and admission.
    pub fn authorize_code(
        &self,
        client_id: &str,
        redirect_uri: &str,
        challenge: &str,
        resource: &str,
        identity: VerifiedIdentity,
        consent: bool,
        state: &str,
        expected_state: &str,
        nonce: &str,
        expected_nonce: &str,
    ) -> Result<String, ProtocolError> {
        if !consent {
            return Err(ProtocolError::AccessDenied);
        }
        if state.is_empty()
            || state != expected_state
            || nonce.is_empty()
            || nonce != expected_nonce
        {
            return Err(ProtocolError::InvalidRequest);
        }
        if client_id != self.config.native_client.client_id
            || !valid_native_redirect(redirect_uri)
            || resource != self.config.resource
            || challenge.is_empty()
        {
            return Err(ProtocolError::InvalidRequest);
        }
        let decision = self.resolve_identity(&identity)?.ok_or(ProtocolError::AccessDenied)?;
        let ceiling = decision.role;
        let owner = decision.admission;
        let code = secret("code", client_id, challenge);
        let mut state = self.state.lock().map_err(|_| ProtocolError::ServerError)?;
        prune_expired(&mut state, now());
        state.codes.insert(
            code.clone(),
            CodeGrant {
                client_id: client_id.into(),
                redirect_uri: redirect_uri.into(),
                challenge: challenge.into(),
                resource: resource.into(),
                owner,
                role_ceiling: ceiling,
                expires: now() + 60,
                used: false,
            },
        );
        Ok(code)
    }

    /// Start a browser authorization transaction. State and nonce are retained
    /// by the hub and cannot be supplied back as a second, trusted value.
    pub fn begin_browser_authorization(
        &self,
        client_id: &str,
        redirect_uri: &str,
        challenge: &str,
        resource: &str,
        state: &str,
        nonce: &str,
    ) -> Result<String, ProtocolError> {
        if client_id != self.config.native_client.client_id
            || !valid_native_redirect(redirect_uri)
            || resource != self.config.resource
            || challenge.is_empty()
            || state.is_empty()
            || nonce.is_empty()
        {
            return Err(ProtocolError::InvalidRequest);
        }
        let transaction = secret("browser", client_id, state);
        let csrf = secret("browser-csrf", &transaction, state);
        let mut gateway_state = self.state.lock().map_err(|_| ProtocolError::ServerError)?;
        prune_expired(&mut gateway_state, now());
        // `/authorize` is reachable without signing in, so outstanding transactions are
        // hard-bounded; making room evicts the transaction closest to expiry (its browser can
        // simply start again).
        while gateway_state.browser.len() >= MAX_BROWSER_TRANSACTIONS {
            let oldest = gateway_state
                .browser
                .iter()
                .min_by_key(|(_, transaction)| transaction.expires)
                .map(|(key, _)| key.clone());
            let Some(oldest) = oldest else { break };
            gateway_state.browser.remove(&oldest);
            gateway_state.pending_browser.remove(&oldest);
        }
        gateway_state.browser.insert(
            transaction.clone(),
            BrowserTransaction {
                client_id: client_id.into(),
                redirect_uri: redirect_uri.into(),
                challenge: challenge.into(),
                resource: resource.into(),
                state: state.into(),
                nonce: nonce.into(),
                csrf,
                browser_id: secret("browser-id", &transaction, state),
                expires: now() + 300,
            },
        );
        Ok(transaction)
    }

    /// Finish a browser transaction after the upstream OIDC verifier and
    /// explicit consent have succeeded.
    pub fn complete_browser_authorization(
        &self,
        transaction: &str,
        returned_state: &str,
        claims: &GoogleIdClaims,
        consent: bool,
    ) -> Result<String, ProtocolError> {
        let transaction_data = self
            .state
            .lock()
            .map_err(|_| ProtocolError::ServerError)?
            .browser
            .remove(transaction)
            .ok_or(ProtocolError::InvalidGrant)?;
        if transaction_data.expires < now() || returned_state != transaction_data.state {
            return Err(ProtocolError::InvalidRequest);
        }
        let identity = verify_google_claims(&self.config.google, claims, &transaction_data.nonce)
            .map_err(|_| ProtocolError::AccessDenied)?;
        self.authorize_code(
            &transaction_data.client_id,
            &transaction_data.redirect_uri,
            &transaction_data.challenge,
            &transaction_data.resource,
            identity,
            consent,
            returned_state,
            &transaction_data.state,
            &claims.nonce,
            &transaction_data.nonce,
        )
    }

    /// Exchange a code using the original redirect and S256 challenge binding.
    pub fn exchange_code(
        &self,
        code: &str,
        client_id: &str,
        redirect_uri: &str,
        verifier: &str,
        resource: &str,
    ) -> Result<TokenResponse, ProtocolError> {
        let mut state = self.state.lock().map_err(|_| ProtocolError::ServerError)?;
        let (owner, role_ceiling) = {
            let grant = state.codes.get_mut(code).ok_or(ProtocolError::InvalidGrant)?;
            if grant.used
                || grant.expires < now()
                || grant.client_id != client_id
                || grant.redirect_uri != redirect_uri
                || grant.resource != resource
                || grant.challenge != pkce(verifier)
            {
                return Err(ProtocolError::InvalidGrant);
            }
            grant.used = true;
            (grant.owner.clone(), grant.role_ceiling)
        };
        self.effective_role(&owner, role_ceiling)?;
        Ok(issue(&mut state, owner, role_ceiling, resource))
    }

    /// Start an RFC 8628 grant; the private device code is returned only to
    /// the requesting client and is not a user-facing verification value.
    pub fn device_authorize(
        &self,
        client_id: &str,
        resource: &str,
    ) -> Result<DeviceResponse, ProtocolError> {
        if client_id != self.config.native_client.client_id || resource != self.config.resource {
            return Err(ProtocolError::InvalidRequest);
        }
        let device_code = secret("device", client_id, resource);
        let mut state = self.state.lock().map_err(|_| ProtocolError::ServerError)?;
        let timestamp = now();
        // Records are kept briefly past expiry so a late poll still reads `expired_token`,
        // then dropped: no device record outlives its lifetime by more than the grace period.
        prune_expired(&mut state, timestamp);
        // Only grants still awaiting a decision count toward the pending cap; denied or
        // approved grants must not lock other users out of device login until they expire.
        if state
            .devices
            .values()
            .filter(|grant| {
                grant.client_id == client_id
                    && grant.expires >= timestamp
                    && !grant.denied
                    && grant.owner.is_none()
            })
            .count()
            >= MAX_PENDING_DEVICE_GRANTS
        {
            return Err(ProtocolError::SlowDown);
        }
        // Independently, the number of stored records per client is hard-bounded whatever their
        // state, so repeated anonymous denials cannot grow memory. Making room evicts the oldest
        // denied or expired record: its outcome is terminal, and its client either already read
        // it or now reads `invalid_grant`, which is also terminal. Undecided and approved grants
        // are never evicted; if only those remain, allocation is refused.
        while state.devices.values().filter(|grant| grant.client_id == client_id).count()
            >= MAX_STORED_DEVICE_GRANTS
        {
            let victim = state
                .devices
                .iter()
                .filter(|(_, grant)| {
                    grant.client_id == client_id && (grant.denied || grant.expires < timestamp)
                })
                .min_by_key(|(_, grant)| grant.issued)
                .map(|(code, _)| code.clone());
            match victim {
                Some(code) => remove_device_grant(&mut state, &code),
                None => return Err(ProtocolError::SlowDown),
            }
        }
        let issued = state.device_seq;
        state.device_seq = state.device_seq.saturating_add(1);
        // The user code is independent of the private device code, uses an unambiguous
        // consonant alphabet, and is unique among live grants.
        let user_code = loop {
            let candidate = new_user_code();
            if !state.devices.values().any(|grant| grant.user_code == candidate) {
                break candidate;
            }
        };
        let DeviceTiming { interval_seconds, lifetime_seconds } = self.device_timing;
        state.devices.insert(
            device_code.clone(),
            DeviceGrant {
                client_id: client_id.into(),
                resource: resource.into(),
                user_code: user_code.clone(),
                owner: None,
                role_ceiling: None,
                verify_state: None,
                verify_nonce: None,
                verify_csrf: secret("device-csrf", &device_code, &user_code),
                browser_id: None,
                expires: now() + lifetime_seconds,
                next_poll: None,
                poll_interval: interval_seconds,
                polls: 0,
                verify_attempts: 0,
                denied: false,
                issued,
            },
        );
        let mut verification_uri =
            reqwest::Url::parse(&format!("{}/device/verify", self.config.issuer))
                .map_err(|_| ProtocolError::ServerError)?;
        verification_uri.query_pairs_mut().append_pair("user_code", &user_code);
        Ok(DeviceResponse {
            device_code,
            user_code,
            verification_uri: verification_uri.to_string(),
            expires_in: lifetime_seconds,
            interval: interval_seconds,
        })
    }

    /// Verify a user code after Google login and explicit consent.
    pub fn verify_device(
        &self,
        user_code: &str,
        identity: VerifiedIdentity,
        consent: bool,
    ) -> Result<AdmissionIdentity, ProtocolError> {
        if !consent {
            return Err(ProtocolError::AccessDenied);
        }
        let mut state = self.state.lock().map_err(|_| ProtocolError::ServerError)?;
        let grant = state
            .devices
            .values_mut()
            .find(|grant| grant.user_code == user_code)
            .ok_or(ProtocolError::InvalidGrant)?;
        if grant.expires < now() {
            return Err(ProtocolError::ExpiredToken);
        }
        grant.verify_attempts = grant.verify_attempts.saturating_add(1);
        if grant.verify_attempts > 5 {
            return Err(ProtocolError::SlowDown);
        }
        match self.resolve_identity(&identity)? {
            Some(decision) => {
                let owner = decision.admission;
                grant.owner = Some(owner.clone());
                grant.role_ceiling = Some(decision.role);
                Ok(owner)
            }
            None => {
                // The polling client learns of the refusal instead of waiting for expiry.
                grant.denied = true;
                Err(ProtocolError::AccessDenied)
            }
        }
    }

    /// Bind a device verification page to server-held state and nonce before
    /// redirecting the browser to Google.
    pub fn begin_device_verification(
        &self,
        user_code: &str,
    ) -> Result<(String, String), ProtocolError> {
        let state_value = secret("device-state", user_code, &self.config.issuer);
        let nonce = secret("device-nonce", user_code, &self.config.issuer);
        let mut state = self.state.lock().map_err(|_| ProtocolError::ServerError)?;
        let grant = state
            .devices
            .values_mut()
            .find(|grant| grant.user_code == user_code)
            .ok_or(ProtocolError::InvalidGrant)?;
        if grant.expires < now() {
            return Err(ProtocolError::ExpiredToken);
        }
        // Restarting verification supersedes the previous attempt: claims parked under the
        // replaced state can never be consumed again, so they are dropped now rather than
        // accumulating for the life of the grant.
        let replaced = grant.verify_state.replace(state_value.clone());
        grant.verify_nonce = Some(nonce.clone());
        grant.browser_id = Some(secret("device-browser-id", user_code, &state_value));
        if let Some(replaced) = replaced {
            state.pending_device.remove(&replaced);
        }
        Ok((state_value, nonce))
    }

    /// Complete device verification using the server-side Google OIDC adapter.
    pub fn complete_device_verification(
        &self,
        user_code: &str,
        returned_state: &str,
        claims: &GoogleIdClaims,
        consent: bool,
    ) -> Result<AdmissionIdentity, ProtocolError> {
        let (expected_state, expected_nonce) = {
            let state = self.state.lock().map_err(|_| ProtocolError::ServerError)?;
            let grant = state
                .devices
                .values()
                .find(|grant| grant.user_code == user_code)
                .ok_or(ProtocolError::InvalidGrant)?;
            (
                grant.verify_state.clone().ok_or(ProtocolError::InvalidRequest)?,
                grant.verify_nonce.clone().ok_or(ProtocolError::InvalidRequest)?,
            )
        };
        if returned_state != expected_state {
            return Err(ProtocolError::InvalidRequest);
        }
        let identity = match verify_google_claims(&self.config.google, claims, &expected_nonce) {
            Ok(identity) => identity,
            Err(error) => return Err(self.fail_device_verification(user_code, error)),
        };
        self.verify_device(user_code, identity, consent)
    }

    /// Classify an upstream verification failure for a device grant. A terminal failure (bad
    /// signature, issuer, audience, expiry, nonce, unverified email, missing subject) denies the
    /// grant so the polling client's next poll returns `access_denied` instead of
    /// `authorization_pending` until expiry. An unreachable or failed upstream exchange
    /// (`GoogleClaimError::Upstream`) leaves the grant pending and is reported as retryable.
    pub fn fail_device_verification(
        &self,
        user_code: &str,
        error: GoogleClaimError,
    ) -> ProtocolError {
        if error == GoogleClaimError::Upstream {
            return ProtocolError::TemporarilyUnavailable;
        }
        match self.deny_device(user_code) {
            Ok(()) => ProtocolError::AccessDenied,
            Err(error) => error,
        }
    }

    /// Deny a pending device grant from the browser verification surface.
    pub fn deny_device(&self, user_code: &str) -> Result<(), ProtocolError> {
        let mut state = self.state.lock().map_err(|_| ProtocolError::ServerError)?;
        let grant = state
            .devices
            .values_mut()
            .find(|grant| grant.user_code == user_code)
            .ok_or(ProtocolError::InvalidGrant)?;
        if grant.expires < now() {
            return Err(ProtocolError::ExpiredToken);
        }
        grant.denied = true;
        Ok(())
    }

    /// Poll a device grant with RFC 8628 expiry and rate-limit semantics.
    pub fn poll_device(&self, device_code: &str) -> Result<TokenResponse, ProtocolError> {
        let mut state = self.state.lock().map_err(|_| ProtocolError::ServerError)?;
        let grant = state.devices.get_mut(device_code).ok_or(ProtocolError::InvalidGrant)?;
        let timestamp = now();
        if grant.expires < timestamp {
            return Err(ProtocolError::ExpiredToken);
        }
        if grant.denied {
            return Err(ProtocolError::AccessDenied);
        }
        grant.polls = grant.polls.saturating_add(1);
        let poll_time = Instant::now();
        if grant.next_poll.is_some_and(|next_poll| poll_time < next_poll) {
            grant.poll_interval = grant.poll_interval.saturating_add(5);
            grant.next_poll = Some(poll_time + Duration::from_secs(grant.poll_interval));
            return Err(ProtocolError::SlowDown);
        }
        grant.next_poll = Some(poll_time + Duration::from_secs(grant.poll_interval));
        let owner = grant.owner.clone().ok_or(ProtocolError::AuthorizationPending)?;
        let role_ceiling = grant.role_ceiling.ok_or(ProtocolError::AccessDenied)?;
        let resource = grant.resource.clone();
        self.effective_role(&owner, role_ceiling)?;
        state.devices.remove(device_code);
        Ok(issue(&mut state, owner, role_ceiling, &resource))
    }

    /// Poll a device grant while enforcing its public-client binding.
    pub fn poll_device_for_client(
        &self,
        device_code: &str,
        client_id: &str,
        resource: &str,
    ) -> Result<TokenResponse, ProtocolError> {
        let state = self.state.lock().map_err(|_| ProtocolError::ServerError)?;
        let grant = state.devices.get(device_code).ok_or(ProtocolError::InvalidGrant)?;
        if grant.client_id != client_id || grant.resource != resource {
            return Err(ProtocolError::InvalidGrant);
        }
        drop(state);
        self.poll_device(device_code)
    }

    /// Rotate a refresh token, rejecting reuse and revoked/expired grants.
    pub fn refresh(&self, refresh_token: &str) -> Result<TokenResponse, ProtocolError> {
        let (family, owner, role_ceiling, resource, expires, reused) = {
            let mut state = self.state.lock().map_err(|_| ProtocolError::ServerError)?;
            let family = state.refresh.get(refresh_token).map(|grant| grant.family.clone())
                .ok_or(ProtocolError::InvalidGrant)?;
            let (revoked, owner, role_ceiling, resource, expires) = {
                let grant = state.refresh.get_mut(refresh_token).ok_or(ProtocolError::InvalidGrant)?;
                let was_revoked = grant.revoked;
                if !was_revoked {
                    if grant.expires < now() { return Err(ProtocolError::InvalidGrant); }
                    grant.revoked = true;
                }
                (was_revoked, grant.owner.clone(), grant.role_ceiling, grant.resource.clone(), grant.expires)
            };
            if revoked { revoke_family(&mut state, &family); }
            (family, owner, role_ceiling, resource, expires, revoked)
        };
        if reused {
            self.reconcile_owner_tokens(&owner.owner.id)?;
            return Err(ProtocolError::InvalidGrant);
        }
        if let Err(error) = self.effective_role(&owner, role_ceiling) {
            let mut state = self.state.lock().map_err(|_| ProtocolError::ServerError)?;
            revoke_family(&mut state, &family);
            drop(state);
            self.reconcile_owner_tokens(&owner.owner.id)?;
            return Err(error);
        }
        let mut state = self.state.lock().map_err(|_| ProtocolError::ServerError)?;
        let response = issue_with_family(&mut state, family, owner, role_ceiling, &resource, expires);
        Ok(response)
    }

    /// Revoke a hub grant; Google tokens are not accepted here.
    pub fn revoke(&self, token: &str) -> Result<(), ProtocolError> {
        let owner_id = {
            let mut state = self.state.lock().map_err(|_| ProtocolError::ServerError)?;
            if let Some(family) = state.refresh.get(token).map(|grant| grant.family.clone()) {
                let owner_id = state.refresh.get(token).map(|grant| grant.owner.owner.id.clone());
                revoke_family(&mut state, &family);
                owner_id
            } else if let Some(family) = state.access.get(token).map(|grant| grant.family.clone()) {
                let owner_id = state.access.get(token).map(|grant| grant.owner.owner.id.clone());
                revoke_family(&mut state, &family);
                owner_id
            } else { None }
        };
        if let Some(owner_id) = owner_id { self.reconcile_owner_tokens(&owner_id)?; }
        Ok(())
    }

    /// Validate a hub access token for the configured resource. Google tokens
    /// are not present in this store and therefore cannot authenticate REST.
    pub fn authorize_rest(
        &self,
        access_token: &str,
        resource: &str,
    ) -> Result<AdmissionIdentity, ProtocolError> {
        self.authorize_rest_role(access_token, resource).map(|(owner, _)| owner)
    }

    /// Validate the bearer and its live role against the role ceiling captured at issuance.
    pub fn authorize_rest_role(
        &self,
        access_token: &str,
        resource: &str,
    ) -> Result<(AdmissionIdentity, AccessRole), ProtocolError> {
        let grant = {
            let state = self.state.lock().map_err(|_| ProtocolError::ServerError)?;
            state.access.get(access_token).cloned().ok_or(ProtocolError::InvalidGrant)?
        };
        if grant.revoked || grant.expires < now() || grant.resource != resource {
            return Err(ProtocolError::InvalidGrant);
        }
        let role = self.effective_role(&grant.owner, grant.role_ceiling)?;
        self.reconcile_owner_tokens(&grant.owner.owner.id)?;
        Ok((grant.owner, role))
    }

    /// Create a browser session after a successful Google transaction.
    pub fn create_session(
        &self,
        session_id: &str,
        owner: AdmissionIdentity,
        csrf: &str,
    ) -> Result<(), ProtocolError> {
        if session_id.is_empty() || csrf.is_empty() {
            return Err(ProtocolError::InvalidRequest);
        }
        let mut state = self.state.lock().map_err(|_| ProtocolError::ServerError)?;
        prune_expired(&mut state, now());
        state.sessions.insert(
            session_id.into(),
            BrowserSession { owner, csrf: csrf.into(), authenticated_at: now(), admin: false },
        );
        Ok(())
    }

    /// Create a session which has explicitly completed the recent administrator auth step.
    pub fn create_admin_session(
        &self,
        session_id: &str,
        owner: AdmissionIdentity,
        csrf: &str,
    ) -> Result<(), ProtocolError> {
        if session_id.is_empty() || csrf.is_empty() {
            return Err(ProtocolError::InvalidRequest);
        }
        let mut state = self.state.lock().map_err(|_| ProtocolError::ServerError)?;
        prune_expired(&mut state, now());
        state.sessions.insert(
            session_id.into(),
            BrowserSession { owner, csrf: csrf.into(), authenticated_at: now(), admin: true },
        );
        Ok(())
    }

    /// Revoke only grants belonging to the authenticated session owner.
    pub fn revoke_own_grant(
        &self,
        session_id: &str,
        csrf: &str,
        token: &str,
    ) -> Result<(), ProtocolError> {
        let mut state = self.state.lock().map_err(|_| ProtocolError::ServerError)?;
        let session = live_session(&state, session_id)?;
        if self.role_for_owner(&session.owner.owner.id)?.is_none() { return Err(ProtocolError::AccessDenied); }
        if session.csrf != csrf {
            return Err(ProtocolError::InvalidRequest);
        }
        let owner = session.owner.owner.id.clone();
        let family = state
            .refresh
            .values()
            .find(|grant| grant.current == token && grant.owner.owner.id == owner)
            .map(|grant| grant.family.clone())
            .or_else(|| {
                state
                    .access
                    .get(token)
                    .filter(|grant| grant.owner.owner.id == owner)
                    .map(|grant| grant.family.clone())
            })
            .ok_or(ProtocolError::InvalidGrant)?;
        revoke_family(&mut state, &family);
        drop(state);
        self.reconcile_owner_tokens(&owner)?;
        Ok(())
    }

    /// Require a recently authenticated admin session before administrative work.
    pub fn require_recent_auth(
        &self,
        session_id: &str,
        max_age: Duration,
    ) -> Result<AdmissionIdentity, ProtocolError> {
        let state = self.state.lock().map_err(|_| ProtocolError::ServerError)?;
        let session = live_session(&state, session_id)?;
        if !session.admin || now().saturating_sub(session.authenticated_at) > max_age.as_secs() {
            return Err(ProtocolError::AccessDenied);
        }
        Ok(session.owner.clone())
    }

    /// List only the authenticated owner's active grant resources.
    pub fn own_connections(&self, session_id: &str) -> Result<Vec<String>, ProtocolError> {
        let state = self.state.lock().map_err(|_| ProtocolError::ServerError)?;
        let session = live_session(&state, session_id)?;
        if self.role_for_owner(&session.owner.owner.id)?.is_none() { return Err(ProtocolError::AccessDenied); }
        Ok(state
            .refresh
            .values()
            .filter(|grant| !grant.revoked && grant.owner.owner.id == session.owner.owner.id)
            .map(|grant| grant.resource.clone())
            .collect())
    }

    /// Return owner-scoped revocation handles for the browser connection page.
    pub fn own_connection_handles(
        &self,
        session_id: &str,
    ) -> Result<Vec<serde_json::Value>, ProtocolError> {
        let state = self.state.lock().map_err(|_| ProtocolError::ServerError)?;
        let session = live_session(&state, session_id)?;
        if self.role_for_owner(&session.owner.owner.id)?.is_none() { return Err(ProtocolError::AccessDenied); }
        Ok(state
            .refresh
            .values()
            .filter(|grant| !grant.revoked && grant.owner.owner.id == session.owner.owner.id)
            .map(|grant| serde_json::json!({"resource": grant.resource, "token": grant.current}))
            .collect())
    }
}

/// Undecided device grants allowed per client at once.
const MAX_PENDING_DEVICE_GRANTS: usize = 5;
/// Hard bound on stored device records per client, in any state.
const MAX_STORED_DEVICE_GRANTS: usize = 32;
/// How long an expired device record is kept so a late poll still reads `expired_token`.
const DEVICE_RECORD_GRACE_SECONDS: u64 = 60;

/// Hard bound on outstanding browser authorization transactions.
const MAX_BROWSER_TRANSACTIONS: usize = 1024;
/// Browser sessions end this long after sign-in.
const SESSION_LIFETIME_SECONDS: u64 = 8 * 60 * 60;

/// Look up a browser session that has not outlived `SESSION_LIFETIME_SECONDS`.
fn live_session<'a>(
    state: &'a GatewayState,
    session_id: &str,
) -> Result<&'a BrowserSession, ProtocolError> {
    state
        .sessions
        .get(session_id)
        .filter(|session| {
            now().saturating_sub(session.authenticated_at) <= SESSION_LIFETIME_SECONDS
        })
        .ok_or(ProtocolError::AccessDenied)
}

/// Drop every record that can no longer be used, so gateway memory is bounded by live grants
/// rather than by history. Called at every allocation point. Used authorization codes are kept
/// until expiry (for replay rejection), rotated refresh tokens until their grant expires (for
/// reuse detection), and device records for a short grace period (so late polls read
/// `expired_token`).
fn prune_expired(state: &mut GatewayState, timestamp: u64) {
    let stale_transactions: Vec<String> = state
        .browser
        .iter()
        .filter(|(_, t)| t.expires < timestamp)
        .map(|(k, _)| k.clone())
        .collect();
    for transaction in stale_transactions {
        state.browser.remove(&transaction);
        state.pending_browser.remove(&transaction);
    }
    state.codes.retain(|_, grant| grant.expires >= timestamp);
    state.access.retain(|_, grant| grant.expires >= timestamp);
    state.refresh.retain(|_, grant| grant.expires >= timestamp);
    state.sessions.retain(|_, session| {
        timestamp.saturating_sub(session.authenticated_at) <= SESSION_LIFETIME_SECONDS
    });
    let stale_devices: Vec<String> = state
        .devices
        .iter()
        .filter(|(_, grant)| grant.expires.saturating_add(DEVICE_RECORD_GRACE_SECONDS) < timestamp)
        .map(|(code, _)| code.clone())
        .collect();
    for code in stale_devices {
        remove_device_grant(state, &code);
    }
}

/// Remove a device record together with any upstream claims parked for its verification.
fn remove_device_grant(state: &mut GatewayState, device_code: &str) {
    if let Some(grant) = state.devices.remove(device_code)
        && let Some(verify_state) = grant.verify_state
    {
        state.pending_device.remove(&verify_state);
    }
}
fn new_user_code() -> String {
    const ALPHABET: &[u8] = b"BCDFGHJKLMNPQRSTVWXZ";
    let mut bytes = [0_u8; 8];
    rand::rng().fill_bytes(&mut bytes);
    let letters: String = bytes
        .iter()
        .map(|byte| char::from(ALPHABET[usize::from(*byte) % ALPHABET.len()]))
        .collect();
    format!("{}-{}", &letters[..4], &letters[4..])
}
fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO).as_secs()
}
fn pkce(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}
fn secret(_kind: &str, _a: &str, _b: &str) -> String {
    let mut bytes = [0_u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}
fn revoke_family(state: &mut GatewayState, family: &str) {
    for grant in state.refresh.values_mut().filter(|grant| grant.family == family) {
        grant.revoked = true;
    }
    for access in state.access.values_mut().filter(|access| access.family == family) {
        access.revoked = true;
    }
}
fn issue(state: &mut GatewayState, owner: AdmissionIdentity, role_ceiling: AccessRole, resource: &str) -> TokenResponse {
    prune_expired(state, now());
    issue_with_family(
        state,
        secret("family", owner.owner.id.as_str(), resource),
        owner,
        role_ceiling,
        resource,
        now() + 7 * 24 * 60 * 60,
    )
}
fn issue_with_family(
    state: &mut GatewayState,
    family: String,
    owner: AdmissionIdentity,
    role_ceiling: AccessRole,
    resource: &str,
    grant_expiry: u64,
) -> TokenResponse {
    let access = secret("access", owner.owner.id.as_str(), resource);
    let refresh = secret("refresh", owner.owner.id.as_str(), &access);
    state.access.insert(
        access.clone(),
        AccessGrant {
            family: family.clone(),
            owner: owner.clone(),
            role_ceiling,
            resource: resource.into(),
            expires: now() + 900,
            revoked: false,
        },
    );
    state.refresh.insert(
        refresh.clone(),
        RefreshGrant {
            family,
            owner,
            role_ceiling,
            resource: resource.into(),
            expires: grant_expiry,
            current: refresh.clone(),
            revoked: false,
        },
    );
    TokenResponse {
        access_token: access,
        refresh_token: refresh,
        token_type: "Bearer".into(),
        expires_in: 900,
        resource: resource.into(),
    }
}

/// OAuth token response issued by the hub, never by Google.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenResponse {
    /// Hub access token, bound to `resource`.
    pub access_token: String,
    /// Rotating hub refresh token; reuse of a superseded one revokes its whole family.
    pub refresh_token: String,
    /// Always `Bearer`.
    pub token_type: String,
    /// Access-token lifetime in seconds.
    pub expires_in: u64,
    /// The resource the grant is bound to.
    pub resource: String,
}
/// RFC 8628 response. The device code is returned to the requesting client
/// over the token endpoint response; clients must keep it out of user-facing
/// output and logs.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceResponse {
    /// Private client-only polling credential.
    pub device_code: String,
    /// User-facing verification code.
    pub user_code: String,
    /// Hub verification page, with the user code pre-filled.
    pub verification_uri: String,
    /// Seconds until the grant expires.
    pub expires_in: u64,
    /// Minimum seconds between token polls.
    pub interval: u64,
}
/// Protocol failures map to standard OAuth error names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ProtocolError {
    /// `invalid_request`: malformed, mismatched, or unbound request.
    InvalidRequest,
    /// `invalid_grant`: unknown, expired, consumed, or revoked code or token.
    InvalidGrant,
    /// `access_denied`: the user or the admission policy refused.
    AccessDenied,
    /// `authorization_pending`: the device grant is not yet approved.
    AuthorizationPending,
    /// `slow_down`: the client polled faster than the interval.
    SlowDown,
    /// `expired_token`: the device grant expired.
    ExpiredToken,
    /// `server_error`: internal failure.
    ServerError,
    /// `temporarily_unavailable`: the upstream identity provider could not be reached or did
    /// not complete the exchange; retrying may succeed. Answered with HTTP 503.
    TemporarilyUnavailable,
}
impl ProtocolError {
    fn code(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidGrant => "invalid_grant",
            Self::AccessDenied => "access_denied",
            Self::AuthorizationPending => "authorization_pending",
            Self::SlowDown => "slow_down",
            Self::ExpiredToken => "expired_token",
            Self::ServerError => "server_error",
            Self::TemporarilyUnavailable => "temporarily_unavailable",
        }
    }
}
impl IntoResponse for ProtocolError {
    fn into_response(self) -> axum::response::Response {
        let status = match self {
            Self::TemporarilyUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            _ => StatusCode::BAD_REQUEST,
        };
        (status, Json(serde_json::json!({"error": self.code()}))).into_response()
    }
}
#[derive(Debug, Deserialize)]
struct RegisterRequest {
    client_id: String,
    redirect_uri: String,
}
#[derive(Debug, Deserialize)]
struct AuthorizeQuery {
    client_id: String,
    redirect_uri: String,
    code_challenge: String,
    resource: String,
    state: String,
    #[serde(default)]
    nonce: Option<String>,
}
#[derive(Debug, Deserialize)]
struct GoogleCallbackQuery {
    #[serde(rename = "state", alias = "transaction")]
    transaction: String,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    error: Option<String>,
}
#[derive(Debug, Deserialize)]
struct GoogleDeviceCallbackQuery {
    state: String,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    error: Option<String>,
}
#[derive(Debug, Deserialize)]
struct TokenRequest {
    grant_type: String,
    code: Option<String>,
    device_code: Option<String>,
    refresh_token: Option<String>,
    client_id: String,
    redirect_uri: Option<String>,
    code_verifier: Option<String>,
    resource: String,
}
#[derive(Debug, Deserialize)]
struct DeviceRequest {
    client_id: String,
    resource: String,
}
#[derive(Debug, Deserialize)]
struct DeviceVerifyStartQuery {
    user_code: Option<String>,
}
#[derive(Debug, Deserialize)]
struct VerifyRequest {
    user_code: String,
    state: String,
    code: String,
    consent: bool,
    csrf_token: String,
}
#[derive(Debug, Deserialize)]
struct RevokeRequest {
    token: String,
    #[serde(default)]
    csrf_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ConsentRequest {
    transaction: String,
    csrf_token: String,
    #[serde(default)]
    consent: bool,
}
#[derive(Debug, Deserialize)]
struct DeviceConsentRequest {
    user_code: String,
    state: String,
    csrf_token: String,
    #[serde(default)]
    consent: bool,
}
async fn protected_metadata(State(g): State<Gateway>) -> Json<ProtectedResourceMetadata> {
    Json(g.config.protected_resource_metadata())
}
fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers.get(header::COOKIE).and_then(|value| value.to_str().ok()).and_then(|cookies| {
        cookies
            .split(';')
            .find_map(|part| part.trim().strip_prefix(&format!("{name}=")).map(str::to_owned))
    })
}
enum AdminCsrf {
    Required(Option<String>),
    ReadOnly,
}

fn admin_actor(
    g: &Gateway,
    headers: &HeaderMap,
    csrf: AdminCsrf,
) -> Result<(String, AdmissionIdentity, String), ProtocolError> {
    let session_id = cookie_value(headers, "agentpalace_session").ok_or(ProtocolError::AccessDenied)?;
    let owner = g.require_recent_auth(&session_id, Duration::from_secs(300))?;
    let current_role = g.role_for_owner(&owner.owner.id)?.ok_or(ProtocolError::AccessDenied)?;
    if current_role != AccessRole::Admin {
        return Err(ProtocolError::AccessDenied);
    }
    let session_csrf = g.state.lock().map_err(|_| ProtocolError::ServerError)?
        .sessions.get(&session_id).map(|session| session.csrf.clone())
        .ok_or(ProtocolError::AccessDenied)?;
    match csrf {
        AdminCsrf::Required(Some(value)) if value == session_csrf => {}
        AdminCsrf::Required(_) => return Err(ProtocolError::InvalidRequest),
        AdminCsrf::ReadOnly => {}
    }
    Ok((session_id, owner, session_csrf))
}

fn response_for_admin_error(error: ProtocolError) -> Response {
    match error {
        ProtocolError::AccessDenied | ProtocolError::InvalidRequest => StatusCode::FORBIDDEN.into_response(),
        other => other.into_response(),
    }
}

fn response_for_policy_error(error: AccessPolicyError) -> Response {
    let status = match error {
        AccessPolicyError::RevisionConflict { .. } => StatusCode::PRECONDITION_FAILED,
        AccessPolicyError::LastEnabledAdmin | AccessPolicyError::Invalid(_) => StatusCode::BAD_REQUEST,
        AccessPolicyError::BindingConflict | AccessPolicyError::EmailChanged => StatusCode::CONFLICT,
        AccessPolicyError::Storage(_) => StatusCode::SERVICE_UNAVAILABLE,
    };
    (status, Json(serde_json::json!({"error": "access_policy_update_failed"}))).into_response()
}

fn if_match_revision(headers: &HeaderMap) -> Result<u64, Response> {
    let value = headers.get(header::IF_MATCH).and_then(|value| value.to_str().ok())
        .ok_or_else(|| StatusCode::PRECONDITION_REQUIRED.into_response())?;
    let revision = value.trim().strip_prefix('"').and_then(|v| v.strip_suffix('"')).unwrap_or(value.trim())
        .parse::<u64>().map_err(|_| StatusCode::BAD_REQUEST.into_response())?;
    Ok(revision)
}

async fn forward_rest(State(g): State<Gateway>, request: Request) -> Response {
    // Health is a public hub liveness response and does not contact the private palace.
    if matches!(request.method(), &axum::http::Method::GET | &axum::http::Method::HEAD)
        && request.uri().path() == "/v1/health"
    {
        if request.method() == axum::http::Method::HEAD { return StatusCode::OK.into_response(); }
        return Json(serde_json::json!({"status": "ok"})).into_response();
    }
    if g.access_store.is_none() { return StatusCode::SERVICE_UNAVAILABLE.into_response(); }
    let Some(forwarder) = &g.forwarder else { return StatusCode::SERVICE_UNAVAILABLE.into_response() };
    let Some(provisioner) = &g.token_provisioner else { return StatusCode::SERVICE_UNAVAILABLE.into_response() };
    let method = request.method().clone();
    let uri = request.uri().clone();
    let mut headers = request.headers().clone();
    let (owner, role) = if method == axum::http::Method::DELETE {
        if g.hard_delete_policy == HardDeletePolicy::Disabled { return StatusCode::FORBIDDEN.into_response(); }
        let csrf = headers.get("x-csrf-token").and_then(|value| value.to_str().ok()).map(str::to_owned);
        match admin_actor(&g, &headers, AdminCsrf::Required(csrf)) {
            Ok((_, owner, _)) => (owner, DemoRole::Admin),
            Err(error) => return response_for_admin_error(error),
        }
    } else {
        let Some(token) = headers.get(header::AUTHORIZATION).and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer ")) else {
                return StatusCode::UNAUTHORIZED.into_response();
            };
        match g.authorize_rest_role(token, &g.config.resource) {
            Ok((owner, role)) => (owner, match role {
                AccessRole::Readonly => DemoRole::Readonly,
                AccessRole::Write => DemoRole::Write,
                AccessRole::Admin => DemoRole::Write,
            }),
            Err(error) => return error.into_response(),
        }
    };
    // The hub credential authenticates this hop only; never pass it to the palace.
    headers.remove(header::AUTHORIZATION);
    let path_and_query = uri.path_and_query().map(|value| value.as_str().to_owned()).unwrap_or_else(|| uri.path().to_owned());
    let body_limit = if path_and_query.starts_with("/v1/ingest/preflight") || path_and_query.starts_with("/v1/ingest/batch") {
        16 * 1024 * 1024
    } else {
        8 * 1024 * 1024
    };
    let body = match to_bytes(request.into_body(), body_limit).await {
        Ok(body) => body.to_vec(),
        Err(_) => return StatusCode::PAYLOAD_TOO_LARGE.into_response(),
    };
    let is_delete = method == axum::http::Method::DELETE;
    let _delete_guard = if is_delete {
        if let Err(error) = g.begin_admin_delete(owner.owner.id.as_str()) { return error.into_response(); }
        Some(AdminDeleteGuard { gateway: g.clone(), owner: owner.clone() })
    } else { None };
    if let Err(error) = g.reconcile_owner_tokens(&owner.owner.id) { return error.into_response(); }
    let provisioned = match provisioner.provision(&owner, role) {
        Ok(token) => token,
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    let request = ForwardRequest { method, path_and_query, headers, body };
    let forwarded = forwarder.forward(&AuthorizedOwner {
        owner_id: provisioned.owner_id,
        upstream_token: provisioned.token,
        role: provisioned.role,
    }, request).await;
    if let Err(error) = g.reconcile_owner_tokens(&owner.owner.id) { return error.into_response(); }
    match forwarded {
        Ok(upstream) => {
            let mut response = Response::new(axum::body::Body::from(upstream.body));
            *response.status_mut() = upstream.status;
            *response.headers_mut() = upstream.headers;
            response
        }
        Err(forwarding::ForwardError::Forbidden) => StatusCode::FORBIDDEN.into_response(),
        Err(forwarding::ForwardError::SpoofedIdentity) => StatusCode::BAD_REQUEST.into_response(),
        Err(forwarding::ForwardError::UnsupportedRoute) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => StatusCode::BAD_GATEWAY.into_response(),
    }
}

async fn get_access(State(g): State<Gateway>, headers: HeaderMap) -> Response {
    let (_, owner, csrf) = match admin_actor(&g, &headers, AdminCsrf::ReadOnly) {
        Ok(value) => value,
        Err(error) => return response_for_admin_error(error),
    };
    let Some(store) = &g.access_store else { return StatusCode::SERVICE_UNAVAILABLE.into_response() };
    let snapshot = match store.snapshot() {
        Ok(snapshot) => snapshot,
        Err(error) => return response_for_policy_error(error),
    };
    let mut response = Json(serde_json::json!({
        "revision": snapshot.revision,
        "users": snapshot.users,
        "csrf_token": csrf,
        "actor": owner.owner.id.as_str(),
    })).into_response();
    if let Ok(value) = format!("\"{}\"", snapshot.revision).parse() {
        response.headers_mut().insert(header::ETAG, value);
    }
    response.headers_mut().insert(header::CACHE_CONTROL, "no-store".parse().expect("static header"));
    response
}

async fn put_access(State(g): State<Gateway>, Path(email): Path<String>, headers: HeaderMap, Json(entry): Json<AccessEntry>) -> Response {
    let csrf = headers.get("x-csrf-token").and_then(|value| value.to_str().ok()).map(str::to_owned);
    let (_, owner, _) = match admin_actor(&g, &headers, AdminCsrf::Required(csrf)) {
        Ok(value) => value,
        Err(error) => return response_for_admin_error(error),
    };
    let revision = match if_match_revision(&headers) { Ok(value) => value, Err(response) => return response };
    let Some(store) = &g.access_store else { return StatusCode::SERVICE_UNAVAILABLE.into_response() };
    let mut snapshot = match store.snapshot() {
        Ok(snapshot) => snapshot,
        Err(error) => return response_for_policy_error(error),
    };
    if snapshot.revision != revision {
        return response_for_policy_error(AccessPolicyError::RevisionConflict { expected: revision, actual: snapshot.revision });
    }
    snapshot.users.insert(email.clone(), entry);
    match store.replace(revision, owner.owner.id.as_str(), snapshot.users) {
        Ok(snapshot) => {
            if let Err(error) = g.reconcile_email_tokens(&email) { return error.into_response(); }
            access_snapshot_response(snapshot)
        }
        Err(error) => response_for_policy_error(error),
    }
}

async fn delete_access(State(g): State<Gateway>, Path(email): Path<String>, headers: HeaderMap) -> Response {
    let csrf = headers.get("x-csrf-token").and_then(|value| value.to_str().ok()).map(str::to_owned);
    let (_, owner, _) = match admin_actor(&g, &headers, AdminCsrf::Required(csrf)) {
        Ok(value) => value,
        Err(error) => return response_for_admin_error(error),
    };
    let revision = match if_match_revision(&headers) { Ok(value) => value, Err(response) => return response };
    let Some(store) = &g.access_store else { return StatusCode::SERVICE_UNAVAILABLE.into_response() };
    let mut snapshot = match store.snapshot() {
        Ok(snapshot) => snapshot,
        Err(error) => return response_for_policy_error(error),
    };
    if snapshot.revision != revision {
        return response_for_policy_error(AccessPolicyError::RevisionConflict { expected: revision, actual: snapshot.revision });
    }
    if snapshot.users.remove(&email).is_none() {
        return StatusCode::NOT_FOUND.into_response();
    }
    match store.replace(revision, owner.owner.id.as_str(), snapshot.users) {
        Ok(snapshot) => {
            if let Err(error) = g.reconcile_email_tokens(&email) { return error.into_response(); }
            access_snapshot_response(snapshot)
        }
        Err(error) => response_for_policy_error(error),
    }
}

fn access_snapshot_response(snapshot: AccessPolicySnapshot) -> Response {
    let mut response = Json(serde_json::json!({"revision": snapshot.revision, "users": snapshot.users})).into_response();
    if let Ok(value) = format!("\"{}\"", snapshot.revision).parse() {
        response.headers_mut().insert(header::ETAG, value);
    }
    response.headers_mut().insert(header::CACHE_CONTROL, "no-store".parse().expect("static header"));
    response
}

fn transaction_browser_id(g: &Gateway, transaction: &str) -> Option<String> {
    g.state
        .lock()
        .ok()
        .and_then(|state| state.browser.get(transaction).map(|value| value.browser_id.clone()))
}
async fn authorization_metadata(State(g): State<Gateway>) -> Json<AuthorizationMetadata> {
    Json(g.config.metadata())
}
async fn register(State(g): State<Gateway>, Json(r): Json<RegisterRequest>) -> impl IntoResponse {
    if r.client_id == g.config.native_client.client_id
        && r.redirect_uri == g.config.native_client.redirect_uri
    {
        Json(serde_json::json!({"client_id":r.client_id,"redirect_uris":[r.redirect_uri]}))
            .into_response()
    } else {
        ProtocolError::InvalidRequest.into_response()
    }
}
async fn authorize(State(g): State<Gateway>, Query(r): Query<AuthorizeQuery>) -> impl IntoResponse {
    let nonce = r.nonce.unwrap_or_else(|| secret("nonce", &r.client_id, &r.state));
    match g.begin_browser_authorization(
        &r.client_id,
        &r.redirect_uri,
        &r.code_challenge,
        &r.resource,
        &r.state,
        &nonce,
    ) {
        Ok(transaction) => {
            let mut url = reqwest::Url::parse("https://accounts.google.com/o/oauth2/v2/auth")
                .expect("constant Google endpoint");
            url.query_pairs_mut()
                .append_pair("response_type", "code")
                .append_pair("client_id", &g.config.google.client_id)
                .append_pair("redirect_uri", &format!("{}/auth/google/callback", g.config.issuer))
                .append_pair("scope", &GOOGLE_SCOPES.join(" "))
                .append_pair("state", &transaction)
                .append_pair("nonce", &nonce);
            let browser_id = transaction_browser_id(&g, &transaction).unwrap_or_default();
            let mut response = Redirect::temporary(url.as_str()).into_response();
            if let Ok(value) = format!(
                "agentpalace_browser={browser_id}; HttpOnly; SameSite=Lax; Path=/{}",
                secure_attribute(&g)
            )
            .parse()
            {
                response.headers_mut().append(header::SET_COOKIE, value);
            }
            response
        }
        Err(e) => e.into_response(),
    }
}
async fn google_callback(
    State(g): State<Gateway>,
    headers: HeaderMap,
    Query(r): Query<GoogleCallbackQuery>,
) -> impl IntoResponse {
    if cookie_value(&headers, "agentpalace_browser") != transaction_browser_id(&g, &r.transaction) {
        return ProtocolError::AccessDenied.into_response();
    }
    if let Some(error) = r.error {
        // Only a denial is reported as such; any other upstream error is opaque to the client.
        let code = if error == "access_denied" { "access_denied" } else { "server_error" };
        return end_browser_transaction(&g, &r.transaction, code);
    }
    let Some(code) = r.code else {
        return ProtocolError::InvalidRequest.into_response();
    };
    let Some(verifier) = g.verifier.as_ref() else {
        return ProtocolError::ServerError.into_response();
    };
    let nonce = match g.state.lock().map_err(|_| ProtocolError::ServerError).and_then(|state| {
        state
            .browser
            .get(&r.transaction)
            .map(|t| t.nonce.clone())
            .ok_or(ProtocolError::InvalidGrant)
    }) {
        Ok(value) => value,
        Err(error) => return error.into_response(),
    };
    // An unverifiable upstream assertion ends the transaction and tells the waiting native
    // client, instead of leaving it to time out.
    let claims = match verify_upstream(
        verifier.clone(),
        code,
        nonce,
        format!("{}/auth/google/callback", g.config.issuer),
    )
    .await
    {
        Ok(claims) => claims,
        Err(GoogleClaimError::Upstream) => {
            return end_browser_transaction(&g, &r.transaction, "temporarily_unavailable");
        }
        Err(_) => return end_browser_transaction(&g, &r.transaction, "access_denied"),
    };
    if let Ok(mut state) = g.state.lock() {
        state.pending_browser.insert(r.transaction.clone(), claims);
    }
    let csrf = match g.state.lock().map_err(|_| ProtocolError::ServerError).and_then(|state| {
        state.browser.get(&r.transaction).map(|t| t.csrf.clone()).ok_or(ProtocolError::InvalidGrant)
    }) {
        Ok(csrf) => csrf,
        Err(error) => return error.into_response(),
    };
    (StatusCode::OK, [(header::CONTENT_TYPE, "text/html; charset=utf-8")], format!("<form method=post action=\"/auth/google/consent\"><input type=hidden name=\"transaction\" value=\"{}\"><input type=hidden name=\"csrf_token\" value=\"{}\"><button name=\"consent\" value=\"true\" type=submit>Continue</button><button name=\"consent\" value=\"false\" type=submit>Deny</button></form>", r.transaction, csrf)).into_response()
}
async fn google_consent(
    State(g): State<Gateway>,
    headers: HeaderMap,
    Form(r): Form<ConsentRequest>,
) -> impl IntoResponse {
    if cookie_value(&headers, "agentpalace_browser") != transaction_browser_id(&g, &r.transaction) {
        return ProtocolError::AccessDenied.into_response();
    }
    let (claims, client_state, redirect_uri) =
        match g.state.lock().map_err(|_| ProtocolError::ServerError).and_then(|mut state| {
            let (transaction_csrf, client_state, redirect_uri) = state
                .browser
                .get(&r.transaction)
                .map(|transaction| {
                    (
                        transaction.csrf.clone(),
                        transaction.state.clone(),
                        transaction.redirect_uri.clone(),
                    )
                })
                .ok_or(ProtocolError::InvalidGrant)?;
            if transaction_csrf != r.csrf_token {
                return Err(ProtocolError::InvalidRequest);
            }
            let claims =
                state.pending_browser.remove(&r.transaction).ok_or(ProtocolError::InvalidGrant)?;
            Ok((claims, client_state, redirect_uri))
        }) {
            Ok(values) => values,
            Err(error) => return error.into_response(),
        };
    if !r.consent {
        return end_browser_transaction(&g, &r.transaction, "access_denied");
    }
    match g.complete_browser_authorization(&r.transaction, &client_state, &claims, true) {
        Ok(code) => {
            let mut url = match reqwest::Url::parse(&redirect_uri) {
                Ok(url) => url,
                Err(_) => return ProtocolError::InvalidRequest.into_response(),
            };
            url.query_pairs_mut().append_pair("code", &code).append_pair("state", &client_state);
            let owner =
                match g.state.lock().map_err(|_| ProtocolError::ServerError).and_then(|state| {
                    state
                        .codes
                        .get(&code)
                        .map(|grant| grant.owner.clone())
                        .ok_or(ProtocolError::InvalidGrant)
                }) {
                    Ok(owner) => owner,
                    Err(error) => return error.into_response(),
                };
            let session_id = secret("session", &client_state, &code);
            let csrf = secret("csrf", &session_id, &client_state);
            let is_current_admin = match g.role_for_owner(&owner.owner.id) {
                Ok(Some(AccessRole::Admin)) => true,
                Ok(Some(_)) => false,
                Ok(None) => return ProtocolError::AccessDenied.into_response(),
                Err(error) => return error.into_response(),
            };
            let create = if is_current_admin {
                g.create_admin_session(&session_id, owner, &csrf)
            } else {
                g.create_session(&session_id, owner, &csrf)
            };
            if let Err(error) = create { return error.into_response(); }
            let secure = secure_attribute(&g);
            let mut response = Redirect::temporary(url.as_str()).into_response();
            if let Ok(value) =
                format!("agentpalace_session={session_id}; HttpOnly; SameSite=Lax; Path=/{secure}")
                    .parse()
            {
                response.headers_mut().append(header::SET_COOKIE, value);
            }
            if let Ok(value) =
                format!("agentpalace_csrf={csrf}; SameSite=Lax; Path=/{secure}").parse()
            {
                response.headers_mut().append(header::SET_COOKIE, value);
            }
            response
        }
        // `complete_browser_authorization` already consumed the transaction; a denial (the
        // identity was not admitted) is still delivered to the waiting native client.
        Err(ProtocolError::AccessDenied) => {
            client_error_redirect(&redirect_uri, &client_state, "access_denied")
        }
        Err(error) => error.into_response(),
    }
}
/// Give the Google-verified device browser the same owner-scoped session as browser login.
/// The device cookie, state, and CSRF have already been checked by the calling handler.
fn device_browser_session_response(
    g: &Gateway,
    owner: AdmissionIdentity,
    transaction_state: &str,
    mut response: Response,
) -> Response {
    let session_id = secret("session", transaction_state, &owner.owner.id.to_string());
    let csrf = secret("csrf", &session_id, transaction_state);
    let create = match g.role_for_owner(&owner.owner.id) {
        Ok(Some(AccessRole::Admin)) => g.create_admin_session(&session_id, owner, &csrf),
        Ok(Some(_)) => g.create_session(&session_id, owner, &csrf),
        Ok(None) => Err(ProtocolError::AccessDenied),
        Err(error) => Err(error),
    };
    if let Err(error) = create {
        return error.into_response();
    }
    let secure = secure_attribute(g);
    if let Ok(value) =
        format!("agentpalace_session={session_id}; HttpOnly; SameSite=Lax; Path=/{secure}").parse()
    {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    if let Ok(value) = format!("agentpalace_csrf={csrf}; SameSite=Lax; Path=/{secure}").parse() {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    response
}

/// `; Secure` for every cookie except in the explicit HTTP loopback demo mode.
fn secure_attribute(g: &Gateway) -> &'static str {
    if g.config.mode == GatewayMode::Secure { "; Secure" } else { "" }
}
/// Remove a browser transaction and redirect to its native callback with an OAuth error.
fn end_browser_transaction(
    g: &Gateway,
    transaction: &str,
    error: &str,
) -> axum::response::Response {
    let removed = g.state.lock().ok().and_then(|mut state| {
        state.pending_browser.remove(transaction);
        state.browser.remove(transaction)
    });
    match removed {
        Some(transaction) => {
            client_error_redirect(&transaction.redirect_uri, &transaction.state, error)
        }
        None => ProtocolError::InvalidGrant.into_response(),
    }
}
fn client_error_redirect(
    redirect_uri: &str,
    client_state: &str,
    error: &str,
) -> axum::response::Response {
    let Ok(mut url) = reqwest::Url::parse(redirect_uri) else {
        return ProtocolError::InvalidRequest.into_response();
    };
    url.query_pairs_mut().append_pair("error", error).append_pair("state", client_state);
    Redirect::temporary(url.as_str()).into_response()
}
fn token_result(g: &Gateway, r: TokenRequest) -> Result<TokenResponse, ProtocolError> {
    match r.grant_type.as_str() {
        "authorization_code" => r.code.map_or(Err(ProtocolError::InvalidRequest), |code| {
            g.exchange_code(
                &code,
                &r.client_id,
                r.redirect_uri.as_deref().unwrap_or_default(),
                r.code_verifier.as_deref().unwrap_or_default(),
                &r.resource,
            )
        }),
        "urn:ietf:params:oauth:grant-type:device_code" => {
            r.device_code.map_or(Err(ProtocolError::InvalidRequest), |device_code| {
                g.poll_device_for_client(&device_code, &r.client_id, &r.resource)
            })
        }
        "refresh_token" => {
            if r.client_id != g.config.native_client.client_id || r.resource != g.config.resource {
                Err(ProtocolError::InvalidGrant)
            } else {
                r.refresh_token
                    .map_or(Err(ProtocolError::InvalidRequest), |token| g.refresh(&token))
            }
        }
        _ => Err(ProtocolError::InvalidRequest),
    }
}
async fn token(State(g): State<Gateway>, Form(r): Form<TokenRequest>) -> impl IntoResponse {
    match token_result(&g, r) {
        Ok(v) => Json(v).into_response(),
        Err(e) => e.into_response(),
    }
}
async fn device(State(g): State<Gateway>, Form(r): Form<DeviceRequest>) -> impl IntoResponse {
    match g.device_authorize(&r.client_id, &r.resource) {
        Ok(v) => Json(v).into_response(),
        Err(e) => e.into_response(),
    }
}
async fn begin_device_verify(
    State(g): State<Gateway>,
    Query(r): Query<DeviceVerifyStartQuery>,
) -> impl IntoResponse {
    let Some(user_code) = r.user_code else {
        return (StatusCode::OK, [(header::CONTENT_TYPE, "text/html; charset=utf-8")], "<form method=get><label>Device code <input name=user_code required></label><button type=submit>Continue</button></form>").into_response();
    };
    match g.begin_device_verification(&user_code) {
        Ok((state, nonce)) => {
            let mut url = reqwest::Url::parse("https://accounts.google.com/o/oauth2/v2/auth")
                .expect("constant Google endpoint");
            url.query_pairs_mut()
                .append_pair("response_type", "code")
                .append_pair("client_id", &g.config.google.client_id)
                .append_pair(
                    "redirect_uri",
                    &format!("{}/auth/google/device-callback", g.config.issuer),
                )
                .append_pair("scope", &GOOGLE_SCOPES.join(" "))
                .append_pair("state", &state)
                .append_pair("nonce", &nonce);
            let browser_id = g
                .state
                .lock()
                .ok()
                .and_then(|state| {
                    state
                        .devices
                        .values()
                        .find(|grant| grant.user_code == user_code)
                        .and_then(|grant| grant.browser_id.clone())
                })
                .unwrap_or_default();
            let mut response = Redirect::temporary(url.as_str()).into_response();
            if let Ok(value) = format!(
                "agentpalace_device_browser={browser_id}; HttpOnly; SameSite=Lax; Path=/{}",
                secure_attribute(&g)
            )
            .parse()
            {
                response.headers_mut().append(header::SET_COOKIE, value);
            }
            response
        }
        Err(e) => e.into_response(),
    }
}
async fn google_device_callback(
    State(g): State<Gateway>,
    headers: HeaderMap,
    Query(r): Query<GoogleDeviceCallbackQuery>,
) -> impl IntoResponse {
    if r.error.as_deref() == Some("access_denied") {
        let user_code = g.state.lock().ok().and_then(|state| {
            state
                .devices
                .values()
                .find(|grant| {
                    grant.verify_state.as_deref() == Some(r.state.as_str())
                        && grant.browser_id.as_deref()
                            == cookie_value(&headers, "agentpalace_device_browser").as_deref()
                })
                .map(|grant| grant.user_code.clone())
        });
        return match user_code {
            Some(user_code) => match g.deny_device(&user_code) {
                Ok(()) => StatusCode::NO_CONTENT.into_response(),
                Err(error) => error.into_response(),
            },
            None => ProtocolError::InvalidGrant.into_response(),
        };
    }
    let Some(verifier) = g.verifier.as_ref() else {
        return ProtocolError::ServerError.into_response();
    };
    let user_code = match g.state.lock().map_err(|_| ProtocolError::ServerError).and_then(|state| {
        state
            .devices
            .values()
            .find(|grant| {
                grant.verify_state.as_deref() == Some(r.state.as_str())
                    && grant.browser_id.as_deref()
                        == cookie_value(&headers, "agentpalace_device_browser").as_deref()
            })
            .map(|grant| grant.user_code.clone())
            .ok_or(ProtocolError::InvalidGrant)
    }) {
        Ok(user_code) => user_code,
        Err(error) => return error.into_response(),
    };
    let nonce = match g.state.lock().map_err(|_| ProtocolError::ServerError).and_then(|state| {
        state
            .devices
            .values()
            .find(|grant| grant.user_code == user_code)
            .and_then(|grant| grant.verify_nonce.clone())
            .ok_or(ProtocolError::InvalidGrant)
    }) {
        Ok(nonce) => nonce,
        Err(error) => return error.into_response(),
    };
    let Some(code) = r.code else {
        return ProtocolError::InvalidRequest.into_response();
    };
    let claims = match verify_upstream(
        verifier.clone(),
        code,
        nonce,
        format!("{}/auth/google/device-callback", g.config.issuer),
    )
    .await
    {
        Ok(claims) => claims,
        Err(error) => return g.fail_device_verification(&user_code, error).into_response(),
    };
    if let Ok(mut state) = g.state.lock() {
        state.pending_device.insert(r.state.clone(), claims);
    }
    let csrf = match g.state.lock().map_err(|_| ProtocolError::ServerError).and_then(|state| {
        state
            .devices
            .values()
            .find(|grant| grant.user_code == user_code)
            .map(|grant| grant.verify_csrf.clone())
            .ok_or(ProtocolError::InvalidGrant)
    }) {
        Ok(csrf) => csrf,
        Err(error) => return error.into_response(),
    };
    (StatusCode::OK, [(header::CONTENT_TYPE, "text/html; charset=utf-8")], format!("<form method=post action=\"/auth/google/device-consent\"><input type=hidden name=\"user_code\" value=\"{}\"><input type=hidden name=\"state\" value=\"{}\"><input type=hidden name=\"csrf_token\" value=\"{}\"><button name=\"consent\" value=\"true\" type=submit>Approve</button><button name=\"consent\" value=\"false\" type=submit>Deny</button></form>", user_code, r.state, csrf)).into_response()
}
async fn google_device_consent(
    State(g): State<Gateway>,
    headers: HeaderMap,
    Form(r): Form<DeviceConsentRequest>,
) -> impl IntoResponse {
    let csrf_ok = g.state.lock().map_err(|_| ProtocolError::ServerError).and_then(|state| {
        state
            .devices
            .values()
            .find(|grant| grant.user_code == r.user_code)
            .map(|grant| grant.verify_csrf == r.csrf_token)
            .ok_or(ProtocolError::InvalidGrant)
    });
    let browser_ok = g.state.lock().ok().is_some_and(|state| {
        state.devices.values().any(|grant| {
            grant.user_code == r.user_code
                && grant.verify_state.as_deref() == Some(r.state.as_str())
                && grant.browser_id.as_deref()
                    == cookie_value(&headers, "agentpalace_device_browser").as_deref()
        })
    });
    if !matches!(csrf_ok, Ok(true)) || !browser_ok {
        return ProtocolError::InvalidRequest.into_response();
    }
    let claims =
        match g.state.lock().map_err(|_| ProtocolError::ServerError).and_then(|mut state| {
            state.pending_device.remove(&r.state).ok_or(ProtocolError::InvalidGrant)
        }) {
            Ok(claims) => claims,
            Err(error) => return error.into_response(),
        };
    if !r.consent {
        return match g.deny_device(&r.user_code) {
            Ok(()) => (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
                "Device authorization denied; you may close this window.",
            )
                .into_response(),
            Err(error) => error.into_response(),
        };
    }
    let result = g.complete_device_verification(&r.user_code, &r.state, &claims, true);
    match result {
        Ok(owner) => device_browser_session_response(
            &g,
            owner,
            &r.state,
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
                "Device authorization approved; <a href=\"/hub/connections\">view your connections</a>.",
            )
                .into_response(),
        ),
        Err(error) => error.into_response(),
    }
}
async fn verify_device(
    State(g): State<Gateway>,
    headers: HeaderMap,
    Json(r): Json<VerifyRequest>,
) -> impl IntoResponse {
    let csrf_ok = g.state.lock().map_err(|_| ProtocolError::ServerError).and_then(|state| {
        state
            .devices
            .values()
            .find(|grant| grant.user_code == r.user_code)
            .map(|grant| grant.verify_csrf == r.csrf_token)
            .ok_or(ProtocolError::InvalidGrant)
    });
    let transaction_ok = g.state.lock().ok().is_some_and(|state| {
        state.devices.values().any(|grant| {
            grant.user_code == r.user_code
                && grant.verify_state.as_deref() == Some(r.state.as_str())
                && grant.browser_id.as_deref()
                    == cookie_value(&headers, "agentpalace_device_browser").as_deref()
        })
    });
    if !matches!(csrf_ok, Ok(true)) || !transaction_ok {
        return ProtocolError::InvalidRequest.into_response();
    }
    if !r.consent {
        return match g.deny_device(&r.user_code) {
            Ok(()) => StatusCode::NO_CONTENT.into_response(),
            Err(error) => error.into_response(),
        };
    }
    let Some(verifier) = g.verifier.as_ref() else {
        return ProtocolError::ServerError.into_response();
    };
    let nonce = match g.state.lock().map_err(|_| ProtocolError::ServerError).and_then(|state| {
        state
            .devices
            .values()
            .find(|grant| grant.user_code == r.user_code)
            .and_then(|grant| grant.verify_nonce.clone())
            .ok_or(ProtocolError::InvalidGrant)
    }) {
        Ok(nonce) => nonce,
        Err(error) => return error.into_response(),
    };
    let claims = match verify_upstream(
        verifier.clone(),
        r.code,
        nonce,
        format!("{}/auth/google/device-callback", g.config.issuer),
    )
    .await
    {
        Ok(claims) => claims,
        Err(error) => return g.fail_device_verification(&r.user_code, error).into_response(),
    };
    match g.complete_device_verification(&r.user_code, &r.state, &claims, r.consent) {
        Ok(owner) => device_browser_session_response(
            &g,
            owner,
            &r.state,
            StatusCode::NO_CONTENT.into_response(),
        ),
        Err(e) => e.into_response(),
    }
}
async fn revoke(State(g): State<Gateway>, Form(r): Form<RevokeRequest>) -> impl IntoResponse {
    match g.revoke(&r.token) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => e.into_response(),
    }
}

async fn verify_upstream(
    verifier: Arc<dyn GoogleOidcVerifier>,
    code: String,
    nonce: String,
    redirect_uri: String,
) -> Result<GoogleIdClaims, GoogleClaimError> {
    verifier.exchange_and_verify(&code, &nonce, &redirect_uri).await
}

fn html_escape(value: &str) -> String {
    value.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
        .replace('"', "&quot;").replace("'", "&#39;")
}

async fn home_page() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        "<!doctype html><html lang=en><meta charset=utf-8><title>AgentPalace demo hub</title><h1>AgentPalace demo hub</h1><p>Local test hub. Connect your AgentPalace client to http://localhost:8080 and sign in through its browser authorization flow.</p><p>Using a headless client? <a href=\"/device/verify\">Verify a device code</a>.</p><p><a href=\"/hub/connections\">Your connections</a></p></html>")
}

async fn connections_page(State(g): State<Gateway>, headers: HeaderMap) -> Response {
    let Some(session_id) = cookie_value(&headers, "agentpalace_session") else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let handles = match g.own_connection_handles(&session_id) {
        Ok(handles) => handles,
        Err(error) => return error.into_response(),
    };
    let csrf = match g.state.lock().map_err(|_| ProtocolError::ServerError)
        .and_then(|state| live_session(&state, &session_id).map(|session| session.csrf.clone()))
    {
        Ok(csrf) => csrf,
        Err(error) => return error.into_response(),
    };
    let mut page = String::from("<!doctype html><html lang=en><meta charset=utf-8><title>Your connections</title><h1>Your connections</h1>");
    if handles.is_empty() {
        page.push_str("<p>No active connections.</p>");
    }
    for handle in handles {
        let Some(resource) = handle.get("resource").and_then(serde_json::Value::as_str) else { continue };
        let Some(token) = handle.get("token").and_then(serde_json::Value::as_str) else { continue };
        page.push_str(&format!("<form method=post action=\"/connections/revoke\"><span>{}</span><input type=hidden name=\"token\" value=\"{}\"><input type=hidden name=\"csrf_token\" value=\"{}\"><button type=submit>Revoke</button></form>",
            html_escape(resource), html_escape(token), html_escape(&csrf)));
    }
    page.push_str("<p><a href=\"/\">Home</a></p></html>");
    let mut response = ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], page).into_response();
    response.headers_mut().insert(header::CACHE_CONTROL, "no-store".parse().expect("static header"));
    response
}

async fn session(State(g): State<Gateway>, headers: HeaderMap) -> impl IntoResponse {
    let Some(cookie) = headers.get(header::COOKIE).and_then(|v| v.to_str().ok()) else {
        return ProtocolError::AccessDenied.into_response();
    };
    let Some(session_id) =
        cookie.split(';').find_map(|part| part.trim().strip_prefix("agentpalace_session="))
    else {
        return ProtocolError::AccessDenied.into_response();
    };
    match g
        .state
        .lock()
        .map_err(|_| ProtocolError::ServerError)
        .and_then(|state| live_session(&state, session_id).cloned())
    {
        Ok(session) => Json(
            serde_json::json!({"owner": session.owner.owner.id.as_str(), "admin": session.admin}),
        )
        .into_response(),
        Err(e) => e.into_response(),
    }
}

async fn connections(State(g): State<Gateway>, headers: HeaderMap) -> impl IntoResponse {
    let Some(cookie) = headers.get(header::COOKIE).and_then(|v| v.to_str().ok()) else {
        return ProtocolError::AccessDenied.into_response();
    };
    let Some(session_id) =
        cookie.split(';').find_map(|part| part.trim().strip_prefix("agentpalace_session="))
    else {
        return ProtocolError::AccessDenied.into_response();
    };
    match g.own_connection_handles(session_id) {
        Ok(handles) => Json(handles).into_response(),
        Err(error) => error.into_response(),
    }
}

async fn revoke_connection(
    State(g): State<Gateway>,
    headers: HeaderMap,
    Form(r): Form<RevokeRequest>,
) -> impl IntoResponse {
    let Some(cookie) = headers.get(header::COOKIE).and_then(|v| v.to_str().ok()) else {
        return ProtocolError::AccessDenied.into_response();
    };
    let Some(session_id) =
        cookie.split(';').find_map(|part| part.trim().strip_prefix("agentpalace_session="))
    else {
        return ProtocolError::AccessDenied.into_response();
    };
    let csrf = headers
        .get("x-csrf-token")
        .and_then(|v| v.to_str().ok())
        .or(r.csrf_token.as_deref())
        .unwrap_or_default();
    match g.revoke_own_grant(session_id, csrf, &r.token) {
        Ok(()) => {
            if headers.get(header::ACCEPT).and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.contains("text/html"))
            {
                Redirect::to("/hub/connections").into_response()
            } else {
                StatusCode::NO_CONTENT.into_response()
            }
        },
        Err(e) => e.into_response(),
    }
}

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

/// RFC 9728 protected-resource metadata. It intentionally has no token
/// endpoint and does not advertise a REST forwarding surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectedResourceMetadata {
    /// Exact audience/resource URL accepted by the palace boundary.
    pub resource: String,
    /// Authorization-server issuer URLs trusted for this resource.
    pub authorization_servers: Vec<String>,
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
        let owner = AuthenticatedOwner::new(
            owner_id,
            owner.issuer.clone(),
            owner.subject.clone(),
            owner.email_at_write.clone(),
        );
        Self { owner, subject_binding }
    }
}

fn is_allowed_origin(value: &str, mode: GatewayMode) -> bool {
    value.starts_with("https://")
        || (mode == GatewayMode::LoopbackDemo && is_loopback_origin(value))
}

fn is_loopback_origin(value: &str) -> bool {
    let Some(authority) = value.strip_prefix("http://").and_then(|rest| rest.split('/').next())
    else {
        return false;
    };
    let Some((host, port)) = authority.rsplit_once(':') else { return false };
    (host == "localhost" || host == "127.0.0.1") && valid_port(port) && !authority.contains('@')
}

fn is_loopback_redirect(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("http://") else { return false };
    let Some((authority, path)) = rest.split_once('/') else { return false };
    is_loopback_origin(&format!("http://{authority}")) && path == "callback"
}

fn valid_native_redirect(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("http://") else { return false };
    let Some((authority, path)) = rest.split_once('/') else { return false };
    let Some((host, port)) = authority.rsplit_once(':') else { return false };
    (host == "localhost" || host == "127.0.0.1")
        && valid_port(port)
        && path == "callback"
        && !authority.contains('@')
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
    InsecureOrigin {
        /// Which setting was rejected.
        name: &'static str,
        /// The rejected value.
        value: String,
    },
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
            native_client: NativeClient {
                client_id: "agentpalace-native".into(),
                redirect_uri: "http://127.0.0.1:49152/callback".into(),
            },
        }
    }

    #[test]
    fn secure_mode_rejects_loopback_http() {
        assert_eq!(
            config(GatewayMode::Secure).validate(),
            Err(GatewayConfigError::InsecureOrigin {
                name: "issuer",
                value: "http://localhost:8080".into()
            })
        );
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
        let resource = config(GatewayMode::LoopbackDemo).protected_resource_metadata();
        assert_eq!(resource.authorization_servers, vec!["http://localhost:8080"]);
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
                && identity.subject == self.0.owner.subject.as_str())
            .then(|| self.0.clone())
        }
    }

    fn gateway() -> (Gateway, VerifiedIdentity) {
        let owner = AuthenticatedOwner::parse(
            "owner-1",
            "https://accounts.google.com",
            "subject-1",
            "person@example.com",
        )
        .expect("test owner");
        let identity = VerifiedIdentity {
            email: "person@example.com".into(),
            issuer: "https://accounts.google.com".into(),
            subject: "subject-1".into(),
        };
        let policy = Arc::new(AllowOne(AdmissionIdentity::new(
            OwnerId::new("owner-1").expect("owner"),
            owner,
        )));
        (Gateway::new(config(GatewayMode::LoopbackDemo), policy).expect("gateway"), identity)
    }

    #[test]
    fn browser_code_is_consent_and_pkce_bound_and_single_use() {
        let (gateway, identity) = gateway();
        let code = gateway
            .authorize_code(
                "agentpalace-native",
                "http://127.0.0.1:49152/callback",
                &pkce("verifier"),
                "http://localhost:8080/api",
                identity.clone(),
                true,
                "state",
                "state",
                "nonce",
                "nonce",
            )
            .expect("code");
        assert_eq!(
            gateway.authorize_code(
                "agentpalace-native",
                "http://127.0.0.1:49152/callback",
                "challenge",
                "http://localhost:8080/api",
                identity.clone(),
                true,
                "wrong",
                "state",
                "nonce",
                "nonce"
            ),
            Err(ProtocolError::InvalidRequest)
        );
        assert_eq!(
            gateway.exchange_code(
                &code,
                "agentpalace-native",
                "http://127.0.0.1:49152/callback",
                "wrong",
                "http://localhost:8080/api"
            ),
            Err(ProtocolError::InvalidGrant)
        );
        let token = gateway
            .exchange_code(
                &code,
                "agentpalace-native",
                "http://127.0.0.1:49152/callback",
                "verifier",
                "http://localhost:8080/api",
            )
            .expect("token");
        assert_eq!(
            gateway.exchange_code(
                &code,
                "agentpalace-native",
                "http://127.0.0.1:49152/callback",
                "verifier",
                "http://localhost:8080/api"
            ),
            Err(ProtocolError::InvalidGrant)
        );
        assert_eq!(
            gateway.authorize_code(
                "agentpalace-native",
                "http://127.0.0.1:49152/callback",
                "challenge",
                "wrong-resource",
                identity,
                true,
                "state",
                "state",
                "nonce",
                "nonce"
            ),
            Err(ProtocolError::InvalidRequest)
        );
        assert!(!token.access_token.is_empty());
    }

    #[test]
    fn denied_and_unadmitted_browser_login_fail_closed() {
        let (gateway, identity) = gateway();
        assert_eq!(
            gateway.authorize_code(
                "agentpalace-native",
                "http://127.0.0.1:49152/callback",
                "challenge",
                "http://localhost:8080/api",
                identity.clone(),
                false,
                "state",
                "state",
                "nonce",
                "nonce"
            ),
            Err(ProtocolError::AccessDenied)
        );
        let unknown = VerifiedIdentity { email: "other@example.com".into(), ..identity };
        assert_eq!(
            gateway.authorize_code(
                "agentpalace-native",
                "http://127.0.0.1:49152/callback",
                "challenge",
                "http://localhost:8080/api",
                unknown,
                true,
                "state",
                "state",
                "nonce",
                "nonce"
            ),
            Err(ProtocolError::AccessDenied)
        );
    }

    #[test]
    fn refresh_rotation_reuse_and_revocation_are_enforced() {
        let (gateway, identity) = gateway();
        let code = gateway
            .authorize_code(
                "agentpalace-native",
                "http://127.0.0.1:49152/callback",
                &pkce("v"),
                "http://localhost:8080/api",
                identity,
                true,
                "state",
                "state",
                "nonce",
                "nonce",
            )
            .expect("code");
        let first = gateway
            .exchange_code(
                &code,
                "agentpalace-native",
                "http://127.0.0.1:49152/callback",
                "v",
                "http://localhost:8080/api",
            )
            .expect("token");
        let rotated = gateway.refresh(&first.refresh_token).expect("rotation");
        assert_eq!(gateway.refresh(&first.refresh_token), Err(ProtocolError::InvalidGrant));
        assert!(gateway.authorize_rest(&first.access_token, "http://localhost:8080/api").is_err());
        assert!(
            gateway.authorize_rest(&rotated.access_token, "http://localhost:8080/api").is_err()
        );
        gateway.revoke(&rotated.refresh_token).expect("revoke");
        assert_eq!(gateway.refresh(&rotated.refresh_token), Err(ProtocolError::InvalidGrant));
    }

    #[test]
    fn refresh_wire_binding_rejects_wrong_client_or_resource() {
        let (gateway, identity) = gateway();
        let code = gateway
            .authorize_code(
                "agentpalace-native",
                "http://127.0.0.1:49152/callback",
                &pkce("v"),
                "http://localhost:8080/api",
                identity,
                true,
                "state",
                "state",
                "nonce",
                "nonce",
            )
            .expect("code");
        let grant = gateway
            .exchange_code(
                &code,
                "agentpalace-native",
                "http://127.0.0.1:49152/callback",
                "v",
                "http://localhost:8080/api",
            )
            .expect("token");
        let request = |client_id: &str, resource: &str, refresh_token: String| TokenRequest {
            grant_type: "refresh_token".into(),
            code: None,
            device_code: None,
            refresh_token: Some(refresh_token),
            client_id: client_id.into(),
            redirect_uri: None,
            code_verifier: None,
            resource: resource.into(),
        };
        assert_eq!(
            token_result(
                &gateway,
                request("another-client", "http://localhost:8080/api", grant.refresh_token.clone())
            ),
            Err(ProtocolError::InvalidGrant)
        );
        assert_eq!(
            token_result(
                &gateway,
                request(
                    "agentpalace-native",
                    "http://localhost:8080/other",
                    grant.refresh_token.clone()
                )
            ),
            Err(ProtocolError::InvalidGrant)
        );
        assert!(
            token_result(
                &gateway,
                request("agentpalace-native", "http://localhost:8080/api", grant.refresh_token)
            )
            .is_ok()
        );
    }

    #[test]
    fn pkce_uses_rfc7636_s256_known_answer() {
        assert_eq!(
            pkce("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn hub_access_tokens_are_resource_bound_and_google_claims_are_checked() {
        let (gateway, identity) = gateway();
        let code = gateway
            .authorize_code(
                "agentpalace-native",
                "http://127.0.0.1:49152/callback",
                &pkce("v"),
                "http://localhost:8080/api",
                identity.clone(),
                true,
                "state",
                "state",
                "nonce",
                "nonce",
            )
            .expect("code");
        let token = gateway
            .exchange_code(
                &code,
                "agentpalace-native",
                "http://127.0.0.1:49152/callback",
                "v",
                "http://localhost:8080/api",
            )
            .expect("token");
        assert!(gateway.authorize_rest(&token.access_token, "wrong-resource").is_err());
        assert_eq!(
            gateway
                .authorize_rest(&token.access_token, "http://localhost:8080/api")
                .expect("hub token")
                .owner
                .id
                .as_str(),
            "owner-1"
        );
        let mut claims = GoogleIdClaims {
            iss: "https://accounts.google.com".into(),
            aud: "google-client".into(),
            sub: "subject-1".into(),
            email: "person@example.com".into(),
            email_verified: true,
            exp: now() + 60,
            nonce: "nonce".into(),
            additional: BTreeMap::new(),
        };
        assert!(
            verify_google_claims(&config(GatewayMode::LoopbackDemo).google, &claims, "nonce")
                .is_ok()
        );
        claims.email_verified = false;
        assert_eq!(
            verify_google_claims(&config(GatewayMode::LoopbackDemo).google, &claims, "nonce"),
            Err(GoogleClaimError::EmailUnverified)
        );
    }

    #[test]
    fn google_claims_accept_standard_additional_fields() {
        let claims: GoogleIdClaims = serde_json::from_value(serde_json::json!({
            "iss": "https://accounts.google.com", "aud": "google-client", "sub": "subject-1",
            "email": "person@example.com", "email_verified": true, "exp": now() + 60,
            "iat": now(), "nonce": "nonce"
        }))
        .expect("standard OIDC claims");
        assert!(claims.additional.contains_key("iat"));
    }

    #[test]
    fn browser_transaction_owns_state_and_nonce_until_callback() {
        let (gateway, _) = gateway();
        let transaction = gateway
            .begin_browser_authorization(
                "agentpalace-native",
                "http://127.0.0.1:49152/callback",
                &pkce("verifier"),
                "http://localhost:8080/api",
                "client-state",
                "transaction-nonce",
            )
            .expect("transaction");
        let claims = GoogleIdClaims {
            iss: "https://accounts.google.com".into(),
            aud: "google-client".into(),
            sub: "subject-1".into(),
            email: "person@example.com".into(),
            email_verified: true,
            exp: now() + 60,
            nonce: "transaction-nonce".into(),
            additional: BTreeMap::new(),
        };
        assert_eq!(
            gateway.complete_browser_authorization(&transaction, "wrong-state", &claims, true),
            Err(ProtocolError::InvalidRequest)
        );
        assert_eq!(
            gateway.complete_browser_authorization(&transaction, "client-state", &claims, true),
            Err(ProtocolError::InvalidGrant)
        );
    }

    #[test]
    fn browser_session_requires_csrf_and_recent_auth() {
        let (gateway, identity) = gateway();
        let owner = gateway.policy.admit(&identity).expect("admission");
        gateway.create_session("s", owner.clone(), "csrf").expect("session");
        assert_eq!(
            gateway.require_recent_auth("s", Duration::from_secs(60)),
            Err(ProtocolError::AccessDenied)
        );
        gateway.create_admin_session("admin", owner, "admin-csrf").expect("admin session");
        assert_eq!(
            gateway
                .require_recent_auth("admin", Duration::from_secs(60))
                .expect("recent")
                .owner
                .id
                .as_str(),
            "owner-1"
        );
        assert_eq!(
            gateway.revoke_own_grant("s", "wrong", "token"),
            Err(ProtocolError::InvalidRequest)
        );
    }

    #[test]
    fn owner_revoke_accepts_access_handle_and_invalidates_family() {
        let (gateway, identity) = gateway();
        let owner = gateway.policy.admit(&identity).expect("admission");
        gateway.create_session("s", owner, "csrf").expect("session");
        let code = gateway
            .authorize_code(
                "agentpalace-native",
                "http://127.0.0.1:49152/callback",
                &pkce("v"),
                "http://localhost:8080/api",
                identity,
                true,
                "state",
                "state",
                "nonce",
                "nonce",
            )
            .expect("code");
        let token = gateway
            .exchange_code(
                &code,
                "agentpalace-native",
                "http://127.0.0.1:49152/callback",
                "v",
                "http://localhost:8080/api",
            )
            .expect("token");
        gateway.revoke_own_grant("s", "csrf", &token.access_token).expect("owner revoke");
        assert!(gateway.authorize_rest(&token.access_token, "http://localhost:8080/api").is_err());
        assert!(gateway.refresh(&token.refresh_token).is_err());
    }

    #[test]
    fn restarting_device_verification_drops_previously_parked_claims() {
        let (gateway, _) = gateway();
        let grant = gateway
            .device_authorize("agentpalace-native", "http://localhost:8080/api")
            .expect("device");
        let claims = GoogleIdClaims {
            iss: "https://accounts.google.com".into(),
            aud: "google-client".into(),
            sub: "subject-1".into(),
            email: "person@example.com".into(),
            email_verified: true,
            exp: now() + 60,
            nonce: "nonce".into(),
            additional: BTreeMap::new(),
        };
        for _ in 0..50 {
            let (verify_state, _) =
                gateway.begin_device_verification(&grant.user_code).expect("restart");
            // What a verified device callback does before consent.
            gateway
                .state
                .lock()
                .expect("state")
                .pending_device
                .insert(verify_state, claims.clone());
            assert!(
                gateway.state.lock().expect("state").pending_device.len() <= 1,
                "parked claims must not accumulate"
            );
        }
    }

    #[test]
    fn anonymous_browser_transactions_are_bounded_and_expired_records_are_pruned() {
        let (gateway, identity) = gateway();
        for i in 0..(MAX_BROWSER_TRANSACTIONS + 50) {
            gateway
                .begin_browser_authorization(
                    "agentpalace-native",
                    "http://127.0.0.1:49152/callback",
                    "challenge",
                    "http://localhost:8080/api",
                    &format!("state-{i}"),
                    "nonce",
                )
                .expect("authorize is never refused");
        }
        assert!(gateway.state.lock().expect("state").browser.len() <= MAX_BROWSER_TRANSACTIONS);

        let code = gateway
            .authorize_code(
                "agentpalace-native",
                "http://127.0.0.1:49152/callback",
                &pkce("v"),
                "http://localhost:8080/api",
                identity.clone(),
                true,
                "state",
                "state",
                "nonce",
                "nonce",
            )
            .expect("code");
        let token = gateway
            .exchange_code(
                &code,
                "agentpalace-native",
                "http://127.0.0.1:49152/callback",
                "v",
                "http://localhost:8080/api",
            )
            .expect("token");
        let owner = gateway.policy.admit(&identity).expect("admission");
        gateway.create_session("old-session", owner.clone(), "csrf").expect("session");
        {
            let mut state = gateway.state.lock().expect("state");
            for transaction in state.browser.values_mut() {
                transaction.expires = now() - 1;
            }
            state.codes.get_mut(&code).expect("code").expires = now() - 1;
            state.access.get_mut(&token.access_token).expect("access").expires = now() - 1;
            state.refresh.get_mut(&token.refresh_token).expect("refresh").expires = now() - 1;
            state.sessions.get_mut("old-session").expect("session").authenticated_at =
                now() - SESSION_LIFETIME_SECONDS - 1;
        }
        assert_eq!(
            gateway.own_connections("old-session"),
            Err(ProtocolError::AccessDenied),
            "sessions end after their lifetime"
        );
        gateway.create_session("new-session", owner, "csrf").expect("session");
        let state = gateway.state.lock().expect("state");
        assert!(
            state.browser.is_empty()
                && state.codes.is_empty()
                && state.access.is_empty()
                && state.refresh.is_empty()
        );
        assert!(
            !state.sessions.contains_key("old-session")
                && state.sessions.contains_key("new-session")
        );
    }

    #[test]
    fn repeated_denials_stay_within_a_hard_bound_and_never_block_new_grants() {
        let (gateway, _) = gateway();
        let mut last = None;
        for _ in 0..(MAX_STORED_DEVICE_GRANTS * 4) {
            let grant = gateway
                .device_authorize("agentpalace-native", "http://localhost:8080/api")
                .expect("a legitimate client can always start a grant");
            gateway.deny_device(&grant.user_code).expect("deny");
            last = Some(grant);
        }
        assert!(gateway.state.lock().expect("state").devices.len() <= MAX_STORED_DEVICE_GRANTS);
        let last = last.expect("at least one grant");
        assert_eq!(
            gateway.poll_device(&last.device_code),
            Err(ProtocolError::AccessDenied),
            "recent denials stay readable"
        );
        // Undecided grants are never evicted; the pending cap still applies to them.
        let pending: Vec<_> = (0..MAX_PENDING_DEVICE_GRANTS)
            .map(|_| {
                gateway
                    .device_authorize("agentpalace-native", "http://localhost:8080/api")
                    .expect("pending")
            })
            .collect();
        assert!(gateway.state.lock().expect("state").devices.len() <= MAX_STORED_DEVICE_GRANTS);
        for grant in &pending {
            assert_eq!(
                gateway.poll_device(&grant.device_code),
                Err(ProtocolError::AuthorizationPending)
            );
        }
    }

    #[test]
    fn device_records_are_pruned_after_expiry() {
        let (gateway, _) = gateway();
        let grant = gateway
            .device_authorize("agentpalace-native", "http://localhost:8080/api")
            .expect("device");
        gateway.deny_device(&grant.user_code).expect("deny");
        gateway
            .state
            .lock()
            .expect("state")
            .devices
            .get_mut(&grant.device_code)
            .expect("grant")
            .expires = now() - DEVICE_RECORD_GRACE_SECONDS - 1;
        gateway
            .device_authorize("agentpalace-native", "http://localhost:8080/api")
            .expect("device");
        assert!(!gateway.state.lock().expect("state").devices.contains_key(&grant.device_code));
    }

    #[test]
    fn decided_device_grants_do_not_consume_the_pending_cap() {
        let (gateway, _) = gateway();
        let pending: Vec<_> = (0..5)
            .map(|_| {
                gateway
                    .device_authorize("agentpalace-native", "http://localhost:8080/api")
                    .expect("device")
            })
            .collect();
        assert!(matches!(
            gateway.device_authorize("agentpalace-native", "http://localhost:8080/api"),
            Err(ProtocolError::SlowDown)
        ));
        gateway.deny_device(&pending[0].user_code).expect("deny");
        assert!(
            gateway.device_authorize("agentpalace-native", "http://localhost:8080/api").is_ok()
        );
        assert_eq!(gateway.poll_device(&pending[0].device_code), Err(ProtocolError::AccessDenied));
    }

    #[test]
    fn denied_device_grant_stays_denied_for_polls() {
        let (gateway, _) = gateway();
        let device = gateway
            .device_authorize("agentpalace-native", "http://localhost:8080/api")
            .expect("device");
        gateway.deny_device(&device.user_code).expect("deny");
        assert_eq!(gateway.poll_device(&device.device_code), Err(ProtocolError::AccessDenied));
    }

    #[test]
    fn metadata_routes_are_hub_only_and_device_grants_expire_or_rate_limit() {
        let (gateway, _) = gateway();
        let metadata = gateway.config.metadata();
        assert!(metadata.authorization_endpoint.ends_with("/authorize"));
        let _router = gateway.router();
        let device = gateway
            .device_authorize("agentpalace-native", "http://localhost:8080/api")
            .expect("device");
        assert!(!device.verification_uri.is_empty());
        assert!(device.verification_uri.contains("user_code="));
        let code = gateway
            .state
            .lock()
            .expect("state")
            .devices
            .keys()
            .next()
            .cloned()
            .expect("private code");
        assert_eq!(gateway.poll_device(&code), Err(ProtocolError::AuthorizationPending));
        assert_eq!(gateway.poll_device(&code), Err(ProtocolError::SlowDown));
        gateway.state.lock().expect("state").devices.get_mut(&code).expect("grant").expires =
            now() - 1;
        assert_eq!(gateway.poll_device(&code), Err(ProtocolError::ExpiredToken));
    }
}
