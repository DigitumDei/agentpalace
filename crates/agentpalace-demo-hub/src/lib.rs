//! Architecture and policy boundary for the AgentPalace demo authorization hub.
//!
//! This crate owns the hub's issuer/resource configuration and the protocol metadata
//! contract. Google is deliberately represented only as an upstream identity provider;
//! the hub must mint credentials for its own resource before a request can reach a palace.
//! The gateway exposes only the documented OAuth metadata and grant endpoints;
//! REST forwarding remains deliberately absent.

use std::{collections::{BTreeMap, BTreeSet}, sync::{atomic::{AtomicU64, Ordering}, Arc, Mutex}, time::{Duration, SystemTime, UNIX_EPOCH}};

use axum::{extract::{Query, State}, http::StatusCode, response::IntoResponse, routing::{get, post}, Json, Router};
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

/// Claims returned by a Google ID token after a maintained OIDC verifier has
/// checked its signature against Google's JWKS.  The gateway never accepts an
/// access token in this position.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
}

/// Boundary for a maintained OIDC implementation (for example
/// `openidconnect`). Implementations must validate the Google JWKS signature
/// before returning claims; the gateway never decodes an unverified JWT.
pub trait GoogleOidcVerifier: Send + Sync {
    /// Exchange a Google authorization code and verify its ID token for the transaction nonce.
    /// The implementation keeps the client secret and upstream token response server-side.
    fn exchange_and_verify(&self, authorization_code: &str, expected_nonce: &str) -> Result<GoogleIdClaims, GoogleClaimError>;
}

/// Validate the security claims which are independent of a particular
/// admission list. Signature verification is intentionally supplied by the
/// maintained `openidconnect` adapter at the boundary; an unverified decode
/// cannot be converted into this type by the gateway.
pub fn verify_google_claims(config: &GoogleOidcConfig, claims: &GoogleIdClaims, expected_nonce: &str) -> Result<VerifiedIdentity, GoogleClaimError> {
    if claims.iss != config.issuer.as_str() { return Err(GoogleClaimError::Issuer); }
    if claims.aud != config.client_id { return Err(GoogleClaimError::Audience); }
    if claims.exp <= now() { return Err(GoogleClaimError::Expired); }
    if !claims.email_verified { return Err(GoogleClaimError::EmailUnverified); }
    if expected_nonce.is_empty() || claims.nonce != expected_nonce { return Err(GoogleClaimError::Nonce); }
    if claims.sub.is_empty() || claims.email.trim().is_empty() { return Err(GoogleClaimError::MissingSubject); }
    Ok(VerifiedIdentity { email: claims.email.clone(), subject: claims.sub.clone(), issuer: claims.iss.clone() })
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

    /// Protected-resource metadata uses the RFC 9728 shape and points at the
    /// hub authorization server rather than pretending to be server metadata.
    pub fn protected_resource_metadata(&self) -> ProtectedResourceMetadata {
        ProtectedResourceMetadata { resource: self.resource.clone(), authorization_servers: vec![self.issuer.clone()] }
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
struct BrowserTransaction { client_id: String, redirect_uri: String, challenge: String, resource: String, state: String, nonce: String, expires: u64 }
#[derive(Debug, Clone)]
struct DeviceGrant { client_id: String, resource: String, user_code: String, owner: Option<AdmissionIdentity>, verify_state: Option<String>, verify_nonce: Option<String>, expires: u64, next_poll: u64, polls: u32, verify_attempts: u32, denied: bool }
#[derive(Debug, Clone)]
struct RefreshGrant { family: String, owner: AdmissionIdentity, resource: String, expires: u64, current: String, revoked: bool }
#[derive(Debug, Clone)]
struct AccessGrant { owner: AdmissionIdentity, resource: String, expires: u64, revoked: bool }

/// In-memory protocol state for the local demo gateway. A production adapter
/// must persist these records atomically; the state machine and its fail-closed
/// policy boundary are kept independent of that storage choice.
#[derive(Clone)]
pub struct Gateway {
    config: Arc<GatewayConfig>,
    policy: Arc<dyn AdmissionPolicy>,
    verifier: Option<Arc<dyn GoogleOidcVerifier>>,
    state: Arc<Mutex<GatewayState>>,
}

#[derive(Default)]
struct GatewayState { codes: BTreeMap<String, CodeGrant>, browser: BTreeMap<String, BrowserTransaction>, devices: BTreeMap<String, DeviceGrant>, refresh: BTreeMap<String, RefreshGrant>, access: BTreeMap<String, AccessGrant>, sessions: BTreeMap<String, BrowserSession> }

/// A hub browser session. The CSRF secret is never serialized or returned.
#[derive(Debug, Clone)]
pub struct BrowserSession {
    /// Authenticated owner.
    pub owner: AdmissionIdentity,
    /// Session CSRF value.
    pub csrf: String,
    /// Last successful upstream authentication.
    pub authenticated_at: u64,
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

impl Gateway {
    /// Create a gateway after validating its server-side configuration.
    pub fn new(config: GatewayConfig, policy: Arc<dyn AdmissionPolicy>) -> Result<Self, GatewayConfigError> {
        config.validate()?;
        Ok(Self { config: Arc::new(config), policy, verifier: None, state: Arc::new(Mutex::new(GatewayState::default())) })
    }

    /// Attach the maintained Google OIDC verifier supplied by the hosting
    /// application. Without one, the callback fails closed.
    pub fn with_google_verifier(mut self, verifier: Arc<dyn GoogleOidcVerifier>) -> Self {
        self.verifier = Some(verifier);
        self
    }

    /// Build the metadata routes and the protocol endpoints. No REST proxy or `/mcp` route is installed.
    pub fn router(&self) -> Router {
        Router::new()
            .route("/.well-known/oauth-protected-resource", get(protected_metadata))
            .route("/.well-known/oauth-authorization-server", get(authorization_metadata))
            .route("/register", post(register))
            .route("/authorize", get(authorize))
            .route("/auth/google/callback", get(google_callback))
            .route("/token", post(token))
            .route("/revoke", post(revoke))
            .route("/device", post(device))
            .route("/device/verify", get(begin_device_verify).post(verify_device))
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

    /// Start a browser authorization transaction. State and nonce are retained
    /// by the hub and cannot be supplied back as a second, trusted value.
    pub fn begin_browser_authorization(&self, client_id: &str, redirect_uri: &str, challenge: &str, resource: &str, state: &str, nonce: &str) -> Result<String, ProtocolError> {
        if client_id != self.config.native_client.client_id
            || redirect_uri != self.config.native_client.redirect_uri
            || resource != self.config.resource
            || challenge.is_empty() || state.is_empty() || nonce.is_empty()
        { return Err(ProtocolError::InvalidRequest); }
        let transaction = secret("browser", client_id, state);
        self.state.lock().map_err(|_| ProtocolError::ServerError)?.browser.insert(transaction.clone(), BrowserTransaction { client_id: client_id.into(), redirect_uri: redirect_uri.into(), challenge: challenge.into(), resource: resource.into(), state: state.into(), nonce: nonce.into(), expires: now()+300 });
        Ok(transaction)
    }

    fn browser_nonce(&self, transaction: &str) -> Result<String, ProtocolError> {
        self.state.lock().map_err(|_| ProtocolError::ServerError)?.browser.get(transaction).map(|transaction| transaction.nonce.clone()).ok_or(ProtocolError::InvalidGrant)
    }

    /// Finish a browser transaction after the upstream OIDC verifier and
    /// explicit consent have succeeded.
    pub fn complete_browser_authorization(&self, transaction: &str, returned_state: &str, claims: &GoogleIdClaims, consent: bool) -> Result<String, ProtocolError> {
        let transaction_data = self.state.lock().map_err(|_| ProtocolError::ServerError)?.browser.remove(transaction).ok_or(ProtocolError::InvalidGrant)?;
        if transaction_data.expires < now() || returned_state != transaction_data.state { return Err(ProtocolError::InvalidRequest); }
        let identity = verify_google_claims(&self.config.google, claims, &transaction_data.nonce).map_err(|_| ProtocolError::AccessDenied)?;
        self.authorize_code(&transaction_data.client_id, &transaction_data.redirect_uri, &transaction_data.challenge, &transaction_data.resource, identity, consent, returned_state, &transaction_data.state, &claims.nonce, &transaction_data.nonce)
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

    /// Start an RFC 8628 grant; the private device code is returned only to
    /// the requesting client and is not a user-facing verification value.
    pub fn device_authorize(&self, client_id: &str, resource: &str) -> Result<DeviceResponse, ProtocolError> {
        if client_id != self.config.native_client.client_id || resource != self.config.resource { return Err(ProtocolError::InvalidRequest); }
        let device_code = secret("device", client_id, resource);
        let user_code = format!("{}-{}", &device_code[0..4], &device_code[4..8]).to_uppercase();
        let mut state = self.state.lock().map_err(|_| ProtocolError::ServerError)?;
        if state.devices.values().filter(|grant| grant.client_id == client_id && grant.expires >= now()).count() >= 5 { return Err(ProtocolError::SlowDown); }
        state.devices.insert(device_code.clone(), DeviceGrant { client_id: client_id.into(), resource: resource.into(), user_code: user_code.clone(), owner: None, verify_state: None, verify_nonce: None, expires: now()+600, next_poll: 0, polls: 0, verify_attempts: 0, denied: false });
        Ok(DeviceResponse { device_code, user_code, verification_uri: format!("{}/device/verify", self.config.issuer), expires_in: 600, interval: 5 })
    }

    /// Verify a user code after Google login and explicit consent.
    pub fn verify_device(&self, user_code: &str, identity: VerifiedIdentity, consent: bool) -> Result<(), ProtocolError> {
        if !consent { return Err(ProtocolError::AccessDenied); }
        let mut state = self.state.lock().map_err(|_| ProtocolError::ServerError)?;
        let grant = state.devices.values_mut().find(|grant| grant.user_code == user_code).ok_or(ProtocolError::InvalidGrant)?;
        if grant.expires < now() { return Err(ProtocolError::ExpiredToken); }
        grant.verify_attempts = grant.verify_attempts.saturating_add(1);
        if grant.verify_attempts > 5 { return Err(ProtocolError::SlowDown); }
        grant.owner = Some(self.policy.admit(&identity).ok_or(ProtocolError::AccessDenied)?);
        Ok(())
    }

    /// Bind a device verification page to server-held state and nonce before
    /// redirecting the browser to Google.
    pub fn begin_device_verification(&self, user_code: &str) -> Result<(String, String), ProtocolError> {
        let state_value = secret("device-state", user_code, &self.config.issuer);
        let nonce = secret("device-nonce", user_code, &self.config.issuer);
        let mut state = self.state.lock().map_err(|_| ProtocolError::ServerError)?;
        let grant = state.devices.values_mut().find(|grant| grant.user_code == user_code).ok_or(ProtocolError::InvalidGrant)?;
        if grant.expires < now() { return Err(ProtocolError::ExpiredToken); }
        grant.verify_state = Some(state_value.clone());
        grant.verify_nonce = Some(nonce.clone());
        Ok((state_value, nonce))
    }

    /// Complete device verification using the server-side Google OIDC adapter.
    pub fn complete_device_verification(&self, user_code: &str, returned_state: &str, claims: &GoogleIdClaims, consent: bool) -> Result<(), ProtocolError> {
        let (expected_state, expected_nonce) = {
            let state = self.state.lock().map_err(|_| ProtocolError::ServerError)?;
            let grant = state.devices.values().find(|grant| grant.user_code == user_code).ok_or(ProtocolError::InvalidGrant)?;
            (grant.verify_state.clone().ok_or(ProtocolError::InvalidRequest)?, grant.verify_nonce.clone().ok_or(ProtocolError::InvalidRequest)?)
        };
        if returned_state != expected_state { return Err(ProtocolError::InvalidRequest); }
        let identity = verify_google_claims(&self.config.google, claims, &expected_nonce).map_err(|_| ProtocolError::AccessDenied)?;
        self.verify_device(user_code, identity, consent)
    }

    /// Deny a pending device grant from the browser verification surface.
    pub fn deny_device(&self, user_code: &str) -> Result<(), ProtocolError> {
        let mut state = self.state.lock().map_err(|_| ProtocolError::ServerError)?;
        let grant = state.devices.values_mut().find(|grant| grant.user_code == user_code).ok_or(ProtocolError::InvalidGrant)?;
        if grant.expires < now() { return Err(ProtocolError::ExpiredToken); }
        grant.denied = true;
        Ok(())
    }

    /// Poll a device grant with RFC 8628 expiry and rate-limit semantics.
    pub fn poll_device(&self, device_code: &str) -> Result<TokenResponse, ProtocolError> {
        let mut state = self.state.lock().map_err(|_| ProtocolError::ServerError)?;
        let grant = state.devices.get_mut(device_code).ok_or(ProtocolError::InvalidGrant)?;
        let timestamp = now();
        if grant.expires < timestamp { return Err(ProtocolError::ExpiredToken); }
        if grant.denied { return Err(ProtocolError::AccessDenied); }
        grant.polls = grant.polls.saturating_add(1);
        if grant.next_poll >= timestamp { return Err(ProtocolError::SlowDown); }
        grant.next_poll = timestamp + 5;
        let owner = grant.owner.clone().ok_or(ProtocolError::AuthorizationPending)?;
        let resource = grant.resource.clone();
        state.devices.remove(device_code);
        Ok(issue(&mut state, owner, &resource))
    }

    /// Poll a device grant while enforcing its public-client binding.
    pub fn poll_device_for_client(&self, device_code: &str, client_id: &str, resource: &str) -> Result<TokenResponse, ProtocolError> {
        let state = self.state.lock().map_err(|_| ProtocolError::ServerError)?;
        let grant = state.devices.get(device_code).ok_or(ProtocolError::InvalidGrant)?;
        if grant.client_id != client_id || grant.resource != resource { return Err(ProtocolError::InvalidGrant); }
        drop(state);
        self.poll_device(device_code)
    }

    /// Rotate a refresh token, rejecting reuse and revoked/expired grants.
    pub fn refresh(&self, refresh_token: &str) -> Result<TokenResponse, ProtocolError> {
        let mut state = self.state.lock().map_err(|_| ProtocolError::ServerError)?;
        let (family, owner, resource, expires) = {
            let family = state.refresh.get(refresh_token).map(|grant| grant.family.clone()).ok_or(ProtocolError::InvalidGrant)?;
            let (revoked, owner, resource, expires) = {
                let grant = state.refresh.get_mut(refresh_token).ok_or(ProtocolError::InvalidGrant)?;
                let revoked = grant.revoked;
                if !revoked {
                    if grant.expires < now() { return Err(ProtocolError::InvalidGrant); }
                    grant.revoked = true;
                }
                (revoked, grant.owner.clone(), grant.resource.clone(), grant.expires)
            };
            if revoked {
                for sibling in state.refresh.values_mut().filter(|sibling| sibling.family == family) { sibling.revoked = true; }
                return Err(ProtocolError::InvalidGrant);
            }
            (family, owner, resource, expires)
        };
        let response = issue_with_family(&mut state, family, owner, &resource, expires);
        Ok(response)
    }

    /// Revoke a hub grant; Google tokens are not accepted here.
    pub fn revoke(&self, token: &str) -> Result<(), ProtocolError> {
        let mut state = self.state.lock().map_err(|_| ProtocolError::ServerError)?;
        if let Some(family) = state.refresh.get(token).map(|grant| grant.family.clone()) {
            for grant in state.refresh.values_mut().filter(|grant| grant.family == family) { grant.revoked = true; }
            return Ok(())
        }
        if let Some(grant) = state.access.get_mut(token) { grant.revoked = true; return Ok(()); }
        Err(ProtocolError::InvalidGrant)
    }

    /// Validate a hub access token for the configured resource. Google tokens
    /// are not present in this store and therefore cannot authenticate REST.
    pub fn authorize_rest(&self, access_token: &str, resource: &str) -> Result<AdmissionIdentity, ProtocolError> {
        let state = self.state.lock().map_err(|_| ProtocolError::ServerError)?;
        let grant = state.access.get(access_token).ok_or(ProtocolError::InvalidGrant)?;
        if grant.revoked || grant.expires < now() || grant.resource != resource { return Err(ProtocolError::InvalidGrant); }
        Ok(grant.owner.clone())
    }

    /// Create a browser session after a successful Google transaction.
    pub fn create_session(&self, session_id: &str, owner: AdmissionIdentity, csrf: &str) -> Result<(), ProtocolError> {
        if session_id.is_empty() || csrf.is_empty() { return Err(ProtocolError::InvalidRequest); }
        self.state.lock().map_err(|_| ProtocolError::ServerError)?.sessions.insert(session_id.into(), BrowserSession { owner, csrf: csrf.into(), authenticated_at: now() });
        Ok(())
    }

    /// Revoke only grants belonging to the authenticated session owner.
    pub fn revoke_own_grant(&self, session_id: &str, csrf: &str, token: &str) -> Result<(), ProtocolError> {
        let mut state = self.state.lock().map_err(|_| ProtocolError::ServerError)?;
        let session = state.sessions.get(session_id).ok_or(ProtocolError::AccessDenied)?;
        if session.csrf != csrf { return Err(ProtocolError::InvalidRequest); }
        let owner = session.owner.owner.id.clone();
        let grant = state.refresh.values_mut().find(|grant| grant.current == token && grant.owner.owner.id == owner).ok_or(ProtocolError::InvalidGrant)?;
        grant.revoked = true;
        Ok(())
    }

    /// Require a recently authenticated admin session before administrative work.
    pub fn require_recent_auth(&self, session_id: &str, max_age: Duration) -> Result<AdmissionIdentity, ProtocolError> {
        let state = self.state.lock().map_err(|_| ProtocolError::ServerError)?;
        let session = state.sessions.get(session_id).ok_or(ProtocolError::AccessDenied)?;
        if now().saturating_sub(session.authenticated_at) > max_age.as_secs() { return Err(ProtocolError::AccessDenied); }
        Ok(session.owner.clone())
    }

    /// List only the authenticated owner's active grant resources.
    pub fn own_connections(&self, session_id: &str) -> Result<Vec<String>, ProtocolError> {
        let state = self.state.lock().map_err(|_| ProtocolError::ServerError)?;
        let session = state.sessions.get(session_id).ok_or(ProtocolError::AccessDenied)?;
        Ok(state.refresh.values().filter(|grant| !grant.revoked && grant.owner.owner.id == session.owner.owner.id).map(|grant| grant.resource.clone()).collect())
    }
}

fn now() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO).as_secs() }
fn pkce(verifier: &str) -> String { blake3::hash(verifier.as_bytes()).to_hex().to_string() }
fn secret(kind: &str, a: &str, b: &str) -> String { let sequence = TOKEN_SEQUENCE.fetch_add(1, Ordering::Relaxed); blake3::hash(format!("{kind}:{a}:{b}:{}:{sequence}", now()).as_bytes()).to_hex().to_string() }
fn issue(state: &mut GatewayState, owner: AdmissionIdentity, resource: &str) -> TokenResponse { issue_with_family(state, secret("family", owner.owner.id.as_str(), resource), owner, resource, now()+7*24*60*60) }
fn issue_with_family(state: &mut GatewayState, family: String, owner: AdmissionIdentity, resource: &str, grant_expiry: u64) -> TokenResponse { let access = secret("access", owner.owner.id.as_str(), resource); let refresh = secret("refresh", owner.owner.id.as_str(), &access); state.access.insert(access.clone(), AccessGrant { owner: owner.clone(), resource: resource.into(), expires: now()+900, revoked: false }); state.refresh.insert(refresh.clone(), RefreshGrant { family, owner, resource: resource.into(), expires: grant_expiry, current: refresh.clone(), revoked: false }); TokenResponse { access_token: access, refresh_token: refresh, token_type: "Bearer".into(), expires_in: 900, resource: resource.into() } }

/// OAuth token response issued by the hub, never by Google.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse { pub access_token: String, pub refresh_token: String, pub token_type: String, pub expires_in: u64, pub resource: String }
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
    pub verification_uri: String,
    pub expires_in: u64,
    pub interval: u64,
}
/// Protocol failures map to standard OAuth error names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ProtocolError { InvalidRequest, InvalidGrant, AccessDenied, AuthorizationPending, SlowDown, ExpiredToken, ServerError }
impl ProtocolError { fn code(self) -> &'static str { match self { Self::InvalidRequest => "invalid_request", Self::InvalidGrant => "invalid_grant", Self::AccessDenied => "access_denied", Self::AuthorizationPending => "authorization_pending", Self::SlowDown => "slow_down", Self::ExpiredToken => "expired_token", Self::ServerError => "server_error" } } }
impl IntoResponse for ProtocolError { fn into_response(self) -> axum::response::Response { (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": self.code()}))).into_response() } }
#[derive(Debug, Deserialize)] struct RegisterRequest { client_id: String, redirect_uri: String }
#[derive(Debug, Deserialize)] struct AuthorizeQuery { client_id: String, redirect_uri: String, code_challenge: String, resource: String, state: String, nonce: String }
#[derive(Debug, Deserialize)] struct GoogleCallbackQuery { transaction: String, state: String, code: String, consent: bool }
#[derive(Debug, Deserialize)] struct TokenRequest { code: Option<String>, device_code: Option<String>, client_id: String, redirect_uri: Option<String>, code_verifier: Option<String>, resource: String }
#[derive(Debug, Deserialize)] struct DeviceRequest { client_id: String, resource: String }
#[derive(Debug, Deserialize)] struct DeviceVerifyStartQuery { user_code: String }
#[derive(Debug, Deserialize)] struct VerifyRequest { user_code: String, state: String, code: String, consent: bool }
#[derive(Debug, Deserialize)] struct RevokeRequest { token: String }
async fn protected_metadata(State(g): State<Gateway>) -> Json<ProtectedResourceMetadata> { Json(g.config.protected_resource_metadata()) }
async fn authorization_metadata(State(g): State<Gateway>) -> Json<AuthorizationMetadata> { Json(g.config.metadata()) }
async fn register(State(g): State<Gateway>, Json(r): Json<RegisterRequest>) -> impl IntoResponse { if r.client_id == g.config.native_client.client_id && r.redirect_uri == g.config.native_client.redirect_uri { Json(serde_json::json!({"client_id":r.client_id,"redirect_uris":[r.redirect_uri]})).into_response() } else { ProtocolError::InvalidRequest.into_response() } }
async fn authorize(State(g): State<Gateway>, Query(r): Query<AuthorizeQuery>) -> impl IntoResponse { match g.begin_browser_authorization(&r.client_id,&r.redirect_uri,&r.code_challenge,&r.resource,&r.state,&r.nonce) { Ok(transaction)=>Json(serde_json::json!({"transaction":transaction,"provider":"google","scopes":GOOGLE_SCOPES})).into_response(), Err(e)=>e.into_response() } }
async fn google_callback(State(g): State<Gateway>, Query(r): Query<GoogleCallbackQuery>) -> impl IntoResponse {
    let Some(verifier) = g.verifier.as_ref() else { return ProtocolError::ServerError.into_response(); };
    let nonce = match g.browser_nonce(&r.transaction) { Ok(nonce) => nonce, Err(error) => return error.into_response() };
    let claims = match verifier.exchange_and_verify(&r.code, &nonce) { Ok(claims) => claims, Err(_) => return ProtocolError::AccessDenied.into_response() };
    match g.complete_browser_authorization(&r.transaction, &r.state, &claims, r.consent) { Ok(code)=>Json(serde_json::json!({"code":code,"state":r.state})).into_response(), Err(e)=>e.into_response() }
}
async fn token(State(g): State<Gateway>, Json(r): Json<TokenRequest>) -> impl IntoResponse { let result = match (r.code, r.device_code) { (Some(code), None) => g.exchange_code(&code, &r.client_id, r.redirect_uri.as_deref().unwrap_or_default(), r.code_verifier.as_deref().unwrap_or_default(), &r.resource), (None, Some(device_code)) => g.poll_device_for_client(&device_code, &r.client_id, &r.resource), _ => Err(ProtocolError::InvalidRequest) }; match result { Ok(v)=>Json(v).into_response(), Err(e)=>e.into_response() } }
async fn device(State(g): State<Gateway>, Json(r): Json<DeviceRequest>) -> impl IntoResponse { match g.device_authorize(&r.client_id,&r.resource) { Ok(v)=>Json(v).into_response(), Err(e)=>e.into_response() } }
async fn begin_device_verify(State(g): State<Gateway>, Query(r): Query<DeviceVerifyStartQuery>) -> impl IntoResponse { match g.begin_device_verification(&r.user_code) { Ok((state, _nonce))=>Json(serde_json::json!({"state":state,"provider":"google","scopes":GOOGLE_SCOPES})).into_response(), Err(e)=>e.into_response() } }
async fn verify_device(State(g): State<Gateway>, Json(r): Json<VerifyRequest>) -> impl IntoResponse {
    let Some(verifier) = g.verifier.as_ref() else { return ProtocolError::ServerError.into_response(); };
    let nonce = match g.state.lock().map_err(|_| ProtocolError::ServerError).and_then(|state| state.devices.values().find(|grant| grant.user_code == r.user_code).and_then(|grant| grant.verify_nonce.clone()).ok_or(ProtocolError::InvalidGrant)) { Ok(nonce) => nonce, Err(error) => return error.into_response() };
    let claims = match verifier.exchange_and_verify(&r.code, &nonce) { Ok(claims) => claims, Err(_) => return ProtocolError::AccessDenied.into_response() };
    match g.complete_device_verification(&r.user_code,&r.state,&claims,r.consent) { Ok(())=>StatusCode::NO_CONTENT.into_response(), Err(e)=>e.into_response() }
}
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
    fn hub_access_tokens_are_resource_bound_and_google_claims_are_checked() {
        let (gateway, identity) = gateway();
        let code = gateway.authorize_code("agentpalace-native", "http://127.0.0.1:49152/callback", &pkce("v"), "http://localhost:8080/api", identity.clone(), true, "state", "state", "nonce", "nonce").expect("code");
        let token = gateway.exchange_code(&code, "agentpalace-native", "http://127.0.0.1:49152/callback", "v", "http://localhost:8080/api").expect("token");
        assert!(gateway.authorize_rest(&token.access_token, "wrong-resource").is_err());
        assert_eq!(gateway.authorize_rest(&token.access_token, "http://localhost:8080/api").expect("hub token").owner.owner.id, "owner-1");
        let mut claims = GoogleIdClaims { iss: "https://accounts.google.com".into(), aud: "google-client".into(), sub: "subject-1".into(), email: "person@example.com".into(), email_verified: true, exp: now() + 60, nonce: "nonce".into() };
        assert!(verify_google_claims(&config(GatewayMode::LoopbackDemo).google, &claims, "nonce").is_ok());
        claims.email_verified = false;
        assert_eq!(verify_google_claims(&config(GatewayMode::LoopbackDemo).google, &claims, "nonce"), Err(GoogleClaimError::EmailUnverified));
    }

    #[test]
    fn browser_transaction_owns_state_and_nonce_until_callback() {
        let (gateway, _) = gateway();
        let transaction = gateway.begin_browser_authorization("agentpalace-native", "http://127.0.0.1:49152/callback", &pkce("verifier"), "http://localhost:8080/api", "client-state", "transaction-nonce").expect("transaction");
        let claims = GoogleIdClaims { iss: "https://accounts.google.com".into(), aud: "google-client".into(), sub: "subject-1".into(), email: "person@example.com".into(), email_verified: true, exp: now() + 60, nonce: "transaction-nonce".into() };
        assert_eq!(gateway.complete_browser_authorization(&transaction, "wrong-state", &claims, true), Err(ProtocolError::InvalidRequest));
        assert_eq!(gateway.complete_browser_authorization(&transaction, "client-state", &claims, true), Err(ProtocolError::InvalidGrant));
    }

    #[test]
    fn browser_session_requires_csrf_and_recent_auth() {
        let (gateway, identity) = gateway();
        let owner = gateway.policy.admit(&identity).expect("admission");
        gateway.create_session("s", owner, "csrf").expect("session");
        assert_eq!(gateway.require_recent_auth("s", Duration::from_secs(60)).expect("recent").owner.owner.id, "owner-1");
        assert_eq!(gateway.revoke_own_grant("s", "wrong", "token"), Err(ProtocolError::InvalidRequest));
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
