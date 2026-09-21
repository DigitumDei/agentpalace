//! Architecture and policy boundary for the AgentPalace demo authorization hub.
//!
//! This crate owns the hub's issuer/resource configuration and the protocol metadata
//! contract. Google is deliberately represented only as an upstream identity provider;
//! the hub must mint credentials for its own resource before a request can reach a palace.
//! HTTP handlers, persistence, and claim verification are layered on this boundary by the
//! later gateway slices.

use std::collections::BTreeSet;

use agentpalace_core::{AuthenticatedOwner, Issuer, OwnerId, SubjectBinding};
use serde::{Deserialize, Serialize};
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
}
