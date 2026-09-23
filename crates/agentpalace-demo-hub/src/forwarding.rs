//! Deny-by-default forwarding from the authenticated demo hub to its private
//! AgentPalace REST origin.
//!
//! The caller must construct [`AuthorizedOwner`] only after authenticating the
//! hub credential and resolving the owner's current role and private upstream
//! token. Incoming request data is never used to select an owner or token.

use std::{
    fs::{self, OpenOptions},
    io::Write,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
};

use crate::AdmissionIdentity;
use axum::http::{HeaderMap, HeaderName, Method, StatusCode, header};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use fs4::FileExt;
use rand::RngCore;
use reqwest::redirect::Policy;
#[cfg(unix)]
use std::fs::File;

/// Effective role attached to the currently authenticated owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DemoRole {
    /// Read operations and coordination reads.
    Readonly,
    /// Reads and writes, including ingest and coordination writes/claims.
    Write,
    /// All supported operations, including drawer deletion.
    Admin,
}

/// Trusted auth result. Construct this from gateway-owned state, never from
/// request headers or JSON. `upstream_token` is a private server token whose
/// scopes are bounded to this owner and the effective role ceiling.
#[derive(Clone)]
pub struct AuthorizedOwner {
    /// Stable owner ID from the authenticated hub grant.
    pub owner_id: String,
    /// Private, provisioned upstream bearer credential for this role ceiling.
    pub upstream_token: String,
    /// Effective role after applying current policy and grant ceiling.
    pub role: DemoRole,
}

/// The method, origin-relative path/query, and original request data.
#[derive(Debug, Clone)]
pub struct ForwardRequest {
    /// Exact HTTP method to send upstream.
    pub method: Method,
    /// Origin-relative path and optional query string.
    pub path_and_query: String,
    /// Caller headers; only representation and receipt headers are forwarded.
    pub headers: HeaderMap,
    /// Original request body bytes.
    pub body: Vec<u8>,
}

/// Upstream response with hop-by-hop and credential headers removed.
#[derive(Debug, Clone)]
pub struct ForwardResponse {
    /// Status returned by the configured engine.
    pub status: StatusCode,
    /// Response headers with hop-by-hop and credential headers removed.
    pub headers: HeaderMap,
    /// Response body bytes from the engine.
    pub body: Vec<u8>,
}
/// Errors that are safe for the gateway to map to a fail-closed HTTP response.
#[derive(Debug, thiserror::Error)]
pub enum ForwardError {
    #[error("invalid private AgentPalace origin")]
    /// Configured engine origin is not an accepted private origin.
    InvalidOrigin,
    #[error("unsupported method or path")]
    /// Request method/path is absent from the closed REST inventory.
    UnsupportedRoute,
    #[error("role does not permit this operation")]
    /// Owner role does not permit the route operation.
    Forbidden,
    #[error("request attempts to supply authenticated owner identity")]
    /// Request supplied an owner/authentication header or payload claim.
    SpoofedIdentity,
    #[error("authenticated owner context is incomplete")]
    /// Trusted owner context is incomplete or invalid.
    InvalidOwner,
    #[error("invalid token-file path")]
    /// Token provisioner path is empty.
    InvalidTokenFilePath,
    #[error("token-file update lock is poisoned")]
    /// In-process token-file lock is poisoned.
    TokenFileLock,
    #[error("token-file read or write failed")]
    /// Token-file filesystem operation failed.
    TokenFileIo(#[source] std::io::Error),
    #[error("token file is not a JSON array of entries")]
    /// Existing token file is malformed JSON or not an array.
    TokenFileJson(#[source] serde_json::Error),
    #[error("token entries could not be serialized")]
    /// Token entries could not be serialized.
    TokenFileEncode(#[source] serde_json::Error),
    #[error("owner has multiple provisioned tokens")]
    /// Multiple entries already match the same owner and ceiling.
    DuplicateOwnerTokens,
    #[error("matching owner token entry is malformed")]
    /// Matching owner entry is missing a token secret.
    TokenFileMalformed,
    #[error("upstream request failed")]
    /// Configured engine request failed.
    Upstream(#[from] reqwest::Error),
}

/// A fixed-origin client. Redirects are disabled so the private credential can
/// never be replayed to a different origin.
#[derive(Debug, Clone)]
pub struct Forwarder {
    origin: reqwest::Url,
    client: reqwest::Client,
}

impl Forwarder {
    /// Create a forwarder for a configured private origin such as
    /// `http://127.0.0.1:8080`. Public hosts are rejected; a configured single-label service host is accepted for private container networks.
    pub fn new(configured_origin: &str) -> Result<Self, ForwardError> {
        let origin =
            reqwest::Url::parse(configured_origin).map_err(|_| ForwardError::InvalidOrigin)?;
        if !is_private_origin(&origin)
            || origin.path() != "/"
            || origin.query().is_some()
            || origin.fragment().is_some()
        {
            return Err(ForwardError::InvalidOrigin);
        }
        let client = reqwest::Client::builder().redirect(Policy::none()).build()?;
        Ok(Self { origin, client })
    }

    /// Validate policy, then forward once to the configured origin. A retry is
    /// left to the caller so receipt/idempotency keys and CAS revisions retain
    /// their original semantics.
    pub async fn forward(
        &self,
        owner: &AuthorizedOwner,
        request: ForwardRequest,
    ) -> Result<ForwardResponse, ForwardError> {
        if owner.owner_id.trim().is_empty() || owner.upstream_token.trim().is_empty() {
            return Err(ForwardError::InvalidOwner);
        }
        let operation = route_operation(&request.method, &request.path_and_query)
            .ok_or(ForwardError::UnsupportedRoute)?;
        if !owner.role.permits(operation) {
            return Err(ForwardError::Forbidden);
        }
        reject_identity_headers(&request.headers)?;
        reject_payload_owner_claims(&request.body)?;

        let url = self
            .origin
            .join(request.path_and_query.trim_start_matches('/'))
            .map_err(|_| ForwardError::UnsupportedRoute)?;
        let mut upstream =
            self.client.request(request.method, url).bearer_auth(&owner.upstream_token);
        // Preserve only representation negotiation and idempotency/receipt
        // headers. All identity and routing headers are created by this module.
        for name in [
            header::ACCEPT,
            header::CONTENT_TYPE,
            HeaderName::from_static("idempotency-key"),
            HeaderName::from_static("x-operation-id"),
        ] {
            if let Some(value) = request.headers.get(&name) {
                upstream = upstream.header(name, value);
            }
        }
        if !request.body.is_empty() {
            upstream = upstream.body(request.body);
        }
        let response = upstream.send().await?;
        let status = response.status();
        let mut headers = HeaderMap::new();
        for (name, value) in response.headers() {
            if !is_hop_by_hop(name)
                && name != header::SET_COOKIE
                && name != header::WWW_AUTHENTICATE
            {
                headers.append(name.clone(), value.clone());
            }
        }
        let body = response.bytes().await?.to_vec();
        Ok(ForwardResponse { status, headers, body })
    }
}

#[derive(Clone, Copy)]
enum Operation {
    Read,
    Write,
    Delete,
    Ingest,
    CoordinationRead,
    CoordinationWrite,
    CoordinationClaim,
}

impl DemoRole {
    fn permits(self, op: Operation) -> bool {
        match self {
            Self::Readonly => matches!(op, Operation::Read | Operation::CoordinationRead),
            Self::Write => !matches!(op, Operation::Delete),
            Self::Admin => true,
        }
    }
}

fn route_operation(method: &Method, path_query: &str) -> Option<Operation> {
    let path = path_query.split('?').next()?;
    let lower = path_query.to_ascii_lowercase();
    if path_query.contains('#')
        || path_query.contains('\\')
        || lower.contains("%2f")
        || lower.contains("%5c")
        || lower.contains("%2e")
    {
        return None;
    }
    if path_query.starts_with("//")
        || path.contains('#')
        || path.split('/').any(|s| s == "." || s == "..")
    {
        return None;
    }
    let segments: Vec<_> = path.split('/').collect();
    if matches!(method, &Method::GET | &Method::HEAD) {
        if matches!(path, "/v1/health") {
            return Some(Operation::Read);
        }
        if matches!(
            path,
            "/v1/info"
                | "/v1/drawers"
                | "/v1/kg/timeline"
                | "/v1/kg/stats"
                | "/v1/taxonomy"
                | "/v1/wings"
                | "/v1/rooms"
                | "/v1/changes"
        ) {
            return Some(Operation::Read);
        }
        if matches!(
            path,
            "/v1/coordination/tasks" | "/v1/coordination/inbox" | "/v1/coordination/events"
        ) {
            return Some(Operation::CoordinationRead);
        }
        if matches!(path, "/v1/drawers/search" | "/v1/drawers/check_duplicate" | "/v1/kg/query") {
            return None;
        }
        if (segments.len() == 4 && segments[1..3] == ["v1", "drawers"] && !segments[3].is_empty())
            || (segments.len() == 5
                && segments[1..3] == ["v1", "coordination"]
                && matches!(segments[3], "tasks" | "messages" | "artifacts" | "results")
                && !segments[4].is_empty())
        {
            return Some(if path.starts_with("/v1/coordination/") {
                Operation::CoordinationRead
            } else {
                Operation::Read
            });
        }
    }
    if *method == Method::POST {
        if matches!(path, "/v1/drawers/search" | "/v1/drawers/check_duplicate" | "/v1/kg/query") {
            return Some(Operation::Read);
        }
        if matches!(path, "/v1/drawers" | "/v1/kg/facts" | "/v1/kg/facts/invalidate") {
            return Some(Operation::Write);
        }
        if matches!(path, "/v1/ingest/preflight" | "/v1/ingest/batch") {
            return Some(Operation::Ingest);
        }
        if path == "/v1/coordination/tasks"
            || matches!(
                path,
                "/v1/coordination/messages"
                    | "/v1/coordination/artifacts"
                    | "/v1/coordination/results"
            )
        {
            return Some(Operation::CoordinationWrite);
        }
        if segments.len() == 6
            && segments[1..3] == ["v1", "coordination"]
            && segments[3] == "tasks"
            && !segments[4].is_empty()
            && matches!(segments[5], "claim" | "renew" | "transition")
        {
            return Some(Operation::CoordinationClaim);
        }
        if segments.len() == 6
            && segments[1..3] == ["v1", "coordination"]
            && segments[3] == "messages"
            && !segments[4].is_empty()
            && segments[5] == "ack"
        {
            return Some(Operation::CoordinationWrite);
        }
    }
    if *method == Method::DELETE
        && segments.len() == 4
        && segments[1..3] == ["v1", "drawers"]
        && !segments[3].is_empty()
    {
        return Some(Operation::Delete);
    }
    None
}

fn is_private_origin(url: &reqwest::Url) -> bool {
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return false;
    }
    match url.host_str() {
        Some(host) if host.eq_ignore_ascii_case("localhost") => true,
        // A single-label DNS name is a configured private service name (e.g. `palace`) in a container network.
        Some(host)
            if !host.contains('.')
                && !host.is_empty()
                && host.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') =>
        {
            true
        }
        Some(host) => host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(host)
            .parse::<IpAddr>()
            .map(private_ip)
            .unwrap_or(false),
        None => false,
    }
}
fn private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unique_local(),
    }
}

fn reject_identity_headers(headers: &HeaderMap) -> Result<(), ForwardError> {
    for name in headers.keys() {
        let lower = name.as_str().to_ascii_lowercase();
        if lower == "authorization"
            || lower == "x-owner"
            || lower.starts_with("x-owner-")
            || lower.starts_with("x-agentpalace-owner")
            || lower.starts_with("x-authenticated-owner")
            || lower == "x-identity"
            || lower.starts_with("x-authenticated-")
        {
            return Err(ForwardError::SpoofedIdentity);
        }
    }
    Ok(())
}

fn reject_payload_owner_claims(body: &[u8]) -> Result<(), ForwardError> {
    if body.is_empty() {
        return Ok(());
    }
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else { return Ok(()) };
    fn walk(v: &serde_json::Value) -> bool {
        match v {
            serde_json::Value::Object(map) => map.iter().any(|(key, value)| {
                let key = key.to_ascii_lowercase();
                matches!(
                    key.as_str(),
                    "owner"
                        | "owner_id"
                        | "ownerid"
                        | "authenticated_owner"
                        | "authenticatedowner"
                        | "owner_metadata"
                ) || walk(value)
            }),
            serde_json::Value::Array(items) => items.iter().any(walk),
            _ => false,
        }
    }
    if walk(&value) { Err(ForwardError::SpoofedIdentity) } else { Ok(()) }
}

fn is_hop_by_hop(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn m(s: &str) -> Method {
        Method::from_bytes(s.as_bytes()).expect("test operation succeeded")
    }

    #[test]
    fn inventory_all_51_method_path_pairs_map_to_operation() {
        let routes = [
            ("GET", "/v1/health", "read"),
            ("HEAD", "/v1/health", "read"),
            ("GET", "/v1/info", "read"),
            ("HEAD", "/v1/info", "read"),
            ("POST", "/v1/drawers/search", "read"),
            ("POST", "/v1/drawers/check_duplicate", "read"),
            ("POST", "/v1/drawers", "write"),
            ("GET", "/v1/drawers", "read"),
            ("HEAD", "/v1/drawers", "read"),
            ("GET", "/v1/drawers/d-1", "read"),
            ("HEAD", "/v1/drawers/d-1", "read"),
            ("DELETE", "/v1/drawers/d-1", "delete"),
            ("POST", "/v1/kg/query", "read"),
            ("POST", "/v1/kg/facts", "write"),
            ("POST", "/v1/kg/facts/invalidate", "write"),
            ("GET", "/v1/kg/timeline", "read"),
            ("HEAD", "/v1/kg/timeline", "read"),
            ("GET", "/v1/kg/stats", "read"),
            ("HEAD", "/v1/kg/stats", "read"),
            ("GET", "/v1/taxonomy", "read"),
            ("HEAD", "/v1/taxonomy", "read"),
            ("GET", "/v1/wings", "read"),
            ("HEAD", "/v1/wings", "read"),
            ("GET", "/v1/rooms", "read"),
            ("HEAD", "/v1/rooms", "read"),
            ("GET", "/v1/changes", "read"),
            ("HEAD", "/v1/changes", "read"),
            ("POST", "/v1/ingest/preflight", "ingest"),
            ("POST", "/v1/ingest/batch", "ingest"),
            ("POST", "/v1/coordination/tasks", "coordination_write"),
            ("GET", "/v1/coordination/tasks", "coordination_read"),
            ("HEAD", "/v1/coordination/tasks", "coordination_read"),
            ("GET", "/v1/coordination/tasks/t-1", "coordination_read"),
            ("HEAD", "/v1/coordination/tasks/t-1", "coordination_read"),
            ("POST", "/v1/coordination/tasks/t-1/claim", "coordination_claim"),
            ("POST", "/v1/coordination/tasks/t-1/renew", "coordination_claim"),
            ("POST", "/v1/coordination/tasks/t-1/transition", "coordination_claim"),
            ("POST", "/v1/coordination/messages", "coordination_write"),
            ("GET", "/v1/coordination/messages/m-1", "coordination_read"),
            ("HEAD", "/v1/coordination/messages/m-1", "coordination_read"),
            ("POST", "/v1/coordination/messages/m-1/ack", "coordination_write"),
            ("GET", "/v1/coordination/inbox", "coordination_read"),
            ("HEAD", "/v1/coordination/inbox", "coordination_read"),
            ("POST", "/v1/coordination/artifacts", "coordination_write"),
            ("GET", "/v1/coordination/artifacts/a-1", "coordination_read"),
            ("HEAD", "/v1/coordination/artifacts/a-1", "coordination_read"),
            ("POST", "/v1/coordination/results", "coordination_write"),
            ("GET", "/v1/coordination/results/r-1", "coordination_read"),
            ("HEAD", "/v1/coordination/results/r-1", "coordination_read"),
            ("GET", "/v1/coordination/events", "coordination_read"),
            ("HEAD", "/v1/coordination/events", "coordination_read"),
        ];
        assert_eq!(routes.len(), 51);
        for (method, path, op) in routes {
            let operation = route_operation(&m(method), path)
                .unwrap_or_else(|| panic!("missing {method} {path}"));
            let actual = match operation {
                Operation::Read => "read",
                Operation::Write => "write",
                Operation::Delete => "delete",
                Operation::Ingest => "ingest",
                Operation::CoordinationRead => "coordination_read",
                Operation::CoordinationWrite => "coordination_write",
                Operation::CoordinationClaim => "coordination_claim",
            };
            assert_eq!(actual, op, "{method} {path}");
        }
    }

    #[test]
    fn role_policy_is_explicit_and_deny_by_default() {
        let ops = [
            Operation::Read,
            Operation::Write,
            Operation::Delete,
            Operation::Ingest,
            Operation::CoordinationRead,
            Operation::CoordinationWrite,
            Operation::CoordinationClaim,
        ];
        let expected = [
            [true, false, false, false, true, false, false],
            [true, true, false, true, true, true, true],
            [true, true, true, true, true, true, true],
        ];
        for (role, matrix) in
            [DemoRole::Readonly, DemoRole::Write, DemoRole::Admin].into_iter().zip(expected)
        {
            for (op, allowed) in ops.into_iter().zip(matrix) {
                assert_eq!(role.permits(op), allowed);
            }
        }
        for (method, path) in [
            ("PUT", "/v1/drawers"),
            ("POST", "/mcp"),
            ("POST", "/v1/coordination/tasks/abc/unknown"),
            ("POST", "/v1/drawers/abc"),
            ("GET", "/v1/kg/query"),
            ("GET", "/v1/drawers/abc/extra"),
        ] {
            assert!(
                route_operation(&m(method), path).is_none(),
                "unexpectedly allowed {method} {path}"
            );
        }
    }

    #[test]
    fn only_private_origins_are_accepted() {
        for valid in [
            "http://127.0.0.1:8080",
            "http://10.1.2.3:8080",
            "http://localhost:8080",
            "http://palace:8080",
            "https://[::1]:8443",
        ] {
            assert!(Forwarder::new(valid).is_ok(), "{valid}");
        }
        for invalid in [
            "https://example.com",
            "http://8.8.8.8:8080",
            "http://169.254.169.254:8080",
            "http://[fe80::1]:8080",
            "http://localhost:8080/base",
            "http://user@127.0.0.1:8080",
        ] {
            assert!(
                matches!(Forwarder::new(invalid), Err(ForwardError::InvalidOrigin)),
                "{invalid}"
            );
        }
    }

    #[test]
    fn spoofed_identity_headers_and_owner_payloads_are_rejected() {
        let mut headers = HeaderMap::new();
        headers.insert("x-owner-id", HeaderValue::from_static("victim"));
        assert!(matches!(reject_identity_headers(&headers), Err(ForwardError::SpoofedIdentity)));
        headers.clear();
        headers.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer attacker"));
        assert!(matches!(reject_identity_headers(&headers), Err(ForwardError::SpoofedIdentity)));
        for body in [
            br#"{"owner":{"id":"victim"}}"#.as_slice(),
            br#"{"owner_id":"victim"}"#.as_slice(),
            br#"{"items":[{"authenticated_owner":{"id":"victim"}}]}"#.as_slice(),
        ] {
            assert!(matches!(
                reject_payload_owner_claims(body),
                Err(ForwardError::SpoofedIdentity)
            ));
        }
        for body in [
            br#"{"added_by":"agent-x","idempotency_key":"stable"}"#.as_slice(),
            br#"{"operation_id":"receipt-1"}"#.as_slice(),
        ] {
            assert!(reject_payload_owner_claims(body).is_ok());
        }
    }

    #[test]
    fn query_ids_and_coordination_identity_and_receipt_fields_are_preserved_by_policy() {
        let body = br#"{"created_by":"worker-7","idempotency_key":"same-key","expected_revision":4,"actor":"worker-7"}"#;
        assert!(reject_payload_owner_claims(body).is_ok());
        assert_eq!(
            route_operation(&Method::POST, "/v1/coordination/tasks/t-1/claim?lease_seconds=60")
                .map(|op| matches!(op, Operation::CoordinationClaim)),
            Some(true)
        );
        assert_eq!(
            route_operation(&Method::POST, "/v1/coordination/messages/m-1/ack")
                .map(|op| matches!(op, Operation::CoordinationWrite)),
            Some(true)
        );
    }
    #[tokio::test]
    async fn forwards_private_owner_credentials_and_preserves_ingest_and_coordination_retry_fields()
    {
        use axum::{Router, extract::State, routing::post};
        use std::sync::{Arc, Mutex};
        type Captured = Arc<Mutex<Vec<(String, String, Vec<u8>)>>>;
        async fn capture(
            State(rows): State<Captured>,
            headers: HeaderMap,
            body: axum::body::Bytes,
        ) -> StatusCode {
            let auth = headers
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_owned();
            let key = headers
                .get("idempotency-key")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_owned();
            rows.lock().expect("test operation succeeded").push((auth, key, body.to_vec()));
            StatusCode::CREATED
        }
        let rows: Captured = Arc::new(Mutex::new(Vec::new()));
        let app = Router::new()
            .route("/v1/ingest/batch", post(capture))
            .route("/v1/coordination/tasks", post(capture))
            .with_state(rows.clone());
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("test operation succeeded");
        let address = listener.local_addr().expect("test operation succeeded");
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("test operation succeeded");
        });
        let forwarder =
            Forwarder::new(&format!("http://{address}")).expect("test operation succeeded");
        let owner1 = AuthorizedOwner {
            owner_id: "owner-1".into(),
            upstream_token: "private-one".into(),
            role: DemoRole::Write,
        };
        let ingest =
            br#"{"wing":"wing_demo","record_id":"stable-record","files":[{"path":"a.md"}]}"#
                .to_vec();
        for _ in 0..2 {
            let mut headers = HeaderMap::new();
            headers.insert("idempotency-key", HeaderValue::from_static("batch-receipt"));
            let response = forwarder
                .forward(
                    &owner1,
                    ForwardRequest {
                        method: Method::POST,
                        path_and_query: "/v1/ingest/batch".into(),
                        headers,
                        body: ingest.clone(),
                    },
                )
                .await
                .expect("test operation succeeded");
            assert_eq!(response.status, StatusCode::CREATED);
        }
        let owner2 = AuthorizedOwner {
            owner_id: "owner-2".into(),
            upstream_token: "private-two".into(),
            role: DemoRole::Write,
        };
        let coordination =
            br#"{"created_by":"worker-stable","idempotency_key":"task-key","expected_revision":4}"#
                .to_vec();
        let mut headers = HeaderMap::new();
        headers.insert("idempotency-key", HeaderValue::from_static("task-key"));
        let response = forwarder
            .forward(
                &owner2,
                ForwardRequest {
                    method: Method::POST,
                    path_and_query: "/v1/coordination/tasks".into(),
                    headers,
                    body: coordination.clone(),
                },
            )
            .await
            .expect("test operation succeeded");
        assert_eq!(response.status, StatusCode::CREATED);
        let captured = rows.lock().expect("test operation succeeded");
        assert_eq!(captured.len(), 3, "the forwarder must not add hidden retries");
        assert_eq!(
            captured[0],
            ("Bearer private-one".into(), "batch-receipt".into(), ingest.clone())
        );
        assert_eq!(captured[1], captured[0], "caller retry preserves receipt key and body exactly");
        assert_eq!(captured[2], ("Bearer private-two".into(), "task-key".into(), coordination));
        drop(captured);
        server.abort();
    }
}

impl std::fmt::Debug for AuthorizedOwner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthorizedOwner")
            .field("owner_id", &self.owner_id)
            .field("upstream_token", &"[REDACTED]")
            .field("role", &self.role)
            .finish()
    }
}

/// Private server credential returned to gateway-owned grant state. Debug
/// output redacts the bearer secret.
#[derive(Clone)]
pub struct ProvisionedToken {
    /// Stable owner ID bound to this credential.
    pub owner_id: String,
    /// Stable server-side principal name for this owner.
    pub name: String,
    /// Private bearer secret; do not expose it to callers.
    pub token: String,
    /// Explicit role ceiling encoded in the server token scopes.
    pub role: DemoRole,
}
impl std::fmt::Debug for ProvisionedToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProvisionedToken")
            .field("owner_id", &self.owner_id)
            .field("name", &self.name)
            .field("token", &"[REDACTED]")
            .field("role", &self.role)
            .finish()
    }
}

/// Writes a dedicated, private AgentPalace server token file. This file should
/// be mounted only into the palace engine container and watched by its token
/// registry. Each owner has one stable principal name; credential rotation
/// keeps one explicitly scoped entry per effective role ceiling and returns the same secret on repeat calls.
#[derive(Debug, Clone)]
pub struct PrivateTokenProvisioner {
    path: PathBuf,
}

static TOKEN_FILE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

impl PrivateTokenProvisioner {
    /// Create a provisioner for the dedicated private server token file.
    pub fn new(path: impl Into<PathBuf>) -> Result<Self, ForwardError> {
        let path = path.into();
        if path.as_os_str().is_empty() {
            return Err(ForwardError::InvalidTokenFilePath);
        }
        Ok(Self { path })
    }

    /// Provision this owner's private token with explicit role scopes and verified owner metadata. Each role ceiling has a separate stable-name token; repeated calls return the same secret.
    pub fn provision(
        &self,
        identity: &AdmissionIdentity,
        role: DemoRole,
    ) -> Result<ProvisionedToken, ForwardError> {
        self.provision_inner(identity, role, false)
    }

    /// Atomically retain credentials for the owner's currently active effective ceilings and remove stale ceilings after a role or grant change. Existing secrets for still-active roles remain stable.
    pub fn reconcile_roles(
        &self,
        identity: &AdmissionIdentity,
        active_roles: &[DemoRole],
    ) -> Result<Vec<ProvisionedToken>, ForwardError> {
        identity.owner.validate().map_err(|_| ForwardError::InvalidOwner)?;
        let owner_id = identity.owner.id.as_str().to_owned();
        let name = format!("demo-hub-owner-{owner_id}");
        let mut roles = Vec::new();
        for role in active_roles {
            if !roles.contains(role) {
                roles.push(*role);
            }
        }
        let _process_guard = TOKEN_FILE_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .map_err(|_| ForwardError::TokenFileLock)?;
        if let Some(parent) = self.path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent).map_err(ForwardError::TokenFileIo)?;
        }
        let lock = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(sidecar_path(&self.path, ".lock"))
            .map_err(ForwardError::TokenFileIo)?;
        lock.lock_exclusive().map_err(ForwardError::TokenFileIo)?;
        let mut entries = if self.path.exists() {
            serde_json::from_slice::<Vec<serde_json::Value>>(
                &fs::read(&self.path).map_err(ForwardError::TokenFileIo)?,
            )
            .map_err(ForwardError::TokenFileJson)?
        } else {
            Vec::new()
        };
        let owner_json =
            serde_json::to_value(&identity.owner).map_err(ForwardError::TokenFileEncode)?;
        let wanted: Vec<Vec<&str>> = roles.iter().map(|role| operations_for(*role)).collect();
        let mut changed = false;
        entries.retain(|entry| {
            let same_owner =
                entry.get("owner").and_then(|o| o.get("id")).and_then(serde_json::Value::as_str)
                    == Some(&owner_id);
            let allowed = entry_operations(entry)
                .is_some_and(|ops| wanted.iter().any(|expected| ops == *expected));
            if same_owner && !allowed {
                changed = true;
                return false;
            }
            true
        });
        let mut provisioned = Vec::new();
        for (role, operations) in roles.into_iter().zip(wanted) {
            let matching: Vec<usize> = entries
                .iter()
                .enumerate()
                .filter_map(|(index, entry)| {
                    let same_owner = entry
                        .get("owner")
                        .and_then(|o| o.get("id"))
                        .and_then(serde_json::Value::as_str)
                        == Some(&owner_id);
                    (same_owner && entry_operations(entry).is_some_and(|ops| ops == operations))
                        .then_some(index)
                })
                .collect();
            if matching.len() > 1 {
                let _ = FileExt::unlock(&lock);
                return Err(ForwardError::DuplicateOwnerTokens);
            }
            if let Some(index) = matching.first().copied() {
                let token = entries[index]
                    .get("token")
                    .and_then(serde_json::Value::as_str)
                    .ok_or(ForwardError::TokenFileMalformed)?
                    .to_owned();
                if entries[index].get("owner") != Some(&owner_json) {
                    entries[index]["owner"] = owner_json.clone();
                    changed = true;
                }
                provisioned.push(ProvisionedToken {
                    owner_id: owner_id.clone(),
                    name: name.clone(),
                    token,
                    role,
                });
            } else {
                let mut secret = [0u8; 32];
                rand::rng().fill_bytes(&mut secret);
                let token = URL_SAFE_NO_PAD.encode(secret);
                entries.push(serde_json::json!({
                    "token": token,
                    "name": name,
                    "enabled": true,
                    "scopes": [{ "wings": ["*"], "operations": operations }],
                    "owner": owner_json,
                }));
                changed = true;
                provisioned.push(ProvisionedToken {
                    owner_id: owner_id.clone(),
                    name: name.clone(),
                    token,
                    role,
                });
            }
        }
        if changed || !self.path.exists() {
            let bytes =
                serde_json::to_vec_pretty(&entries).map_err(ForwardError::TokenFileEncode)?;
            atomic_replace(&self.path, &bytes)?;
        }
        FileExt::unlock(&lock).map_err(ForwardError::TokenFileIo)?;
        Ok(provisioned)
    }
    /// Explicitly rotate one owner/effective-role credential while retaining its stable principal name.
    pub fn rotate(
        &self,
        identity: &AdmissionIdentity,
        role: DemoRole,
    ) -> Result<ProvisionedToken, ForwardError> {
        self.provision_inner(identity, role, true)
    }

    fn provision_inner(
        &self,
        identity: &AdmissionIdentity,
        role: DemoRole,
        force_rotate: bool,
    ) -> Result<ProvisionedToken, ForwardError> {
        identity.owner.validate().map_err(|_| ForwardError::InvalidOwner)?;
        let owner_id = identity.owner.id.as_str().to_owned();
        let name = format!("demo-hub-owner-{owner_id}");
        let _process_guard = TOKEN_FILE_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .map_err(|_| ForwardError::TokenFileLock)?;
        if let Some(parent) = self.path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent).map_err(ForwardError::TokenFileIo)?;
        }
        let lock_path = sidecar_path(&self.path, ".lock");
        let lock = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(lock_path)
            .map_err(ForwardError::TokenFileIo)?;
        lock.lock_exclusive().map_err(ForwardError::TokenFileIo)?;

        let mut entries = if self.path.exists() {
            let bytes = fs::read(&self.path).map_err(ForwardError::TokenFileIo)?;
            serde_json::from_slice::<Vec<serde_json::Value>>(&bytes)
                .map_err(ForwardError::TokenFileJson)?
        } else {
            Vec::new()
        };
        let operations = match role {
            DemoRole::Readonly => vec!["read", "coordination_read"],
            DemoRole::Write => vec![
                "read",
                "write",
                "ingest",
                "coordination_read",
                "coordination_write",
                "coordination_claim",
            ],
            DemoRole::Admin => vec![
                "read",
                "write",
                "delete",
                "ingest",
                "coordination_read",
                "coordination_write",
                "coordination_claim",
            ],
        };
        let mut matching = Vec::new();
        for (index, entry) in entries.iter().enumerate() {
            let same_owner =
                entry.get("owner").and_then(|o| o.get("id")).and_then(serde_json::Value::as_str)
                    == Some(&owner_id);
            let same_role = entry
                .get("scopes")
                .and_then(serde_json::Value::as_array)
                .and_then(|scopes| scopes.first())
                .and_then(|scope| scope.get("operations"))
                .and_then(serde_json::Value::as_array)
                .is_some_and(|configured| {
                    configured
                        .iter()
                        .filter_map(serde_json::Value::as_str)
                        .eq(operations.iter().copied())
                });
            if same_owner && same_role {
                matching.push(index);
            }
        }
        if matching.len() > 1 {
            let _ = FileExt::unlock(&lock);
            return Err(ForwardError::DuplicateOwnerTokens);
        }
        let mut secret = [0u8; 32];
        let token = if let Some(index) = matching.first().copied() {
            let existing = entries[index]
                .get("token")
                .and_then(serde_json::Value::as_str)
                .ok_or(ForwardError::TokenFileMalformed)?
                .to_owned();
            let old_owner = entries[index].get("owner").cloned().unwrap_or(serde_json::Value::Null);
            let new_owner =
                serde_json::to_value(&identity.owner).map_err(ForwardError::TokenFileEncode)?;
            if !force_rotate {
                if old_owner != new_owner {
                    entries[index]["owner"] = new_owner;
                    let bytes = serde_json::to_vec_pretty(&entries)
                        .map_err(ForwardError::TokenFileEncode)?;
                    atomic_replace(&self.path, &bytes)?;
                }
                let token = existing.clone();
                FileExt::unlock(&lock).map_err(ForwardError::TokenFileIo)?;
                return Ok(ProvisionedToken { owner_id, name, token, role });
            }
            rand::rng().fill_bytes(&mut secret);
            URL_SAFE_NO_PAD.encode(secret)
        } else {
            rand::rng().fill_bytes(&mut secret);
            URL_SAFE_NO_PAD.encode(secret)
        };
        if let Some(index) = matching.first().copied() {
            entries.remove(index);
        }
        let entry = serde_json::json!({
            "token": token,
            "name": name,
            "enabled": true,
            "scopes": [{ "wings": ["*"], "operations": operations }],
            "owner": identity.owner,
        });
        entries.push(entry);
        let bytes = serde_json::to_vec_pretty(&entries).map_err(ForwardError::TokenFileEncode)?;
        atomic_replace(&self.path, &bytes)?;
        FileExt::unlock(&lock).map_err(ForwardError::TokenFileIo)?;
        Ok(ProvisionedToken { owner_id, name, token, role })
    }

    /// Remove all credentials for this owner. The file replacement is atomic,
    /// so the server sees either the previous valid set or the revoked set.
    pub fn revoke(&self, owner_id: &str) -> Result<(), ForwardError> {
        if owner_id.trim().is_empty() {
            return Err(ForwardError::InvalidOwner);
        }
        let name = format!("demo-hub-owner-{owner_id}");
        let _process_guard = TOKEN_FILE_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .map_err(|_| ForwardError::TokenFileLock)?;
        if let Some(parent) = self.path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent).map_err(ForwardError::TokenFileIo)?;
        }
        let lock = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(sidecar_path(&self.path, ".lock"))
            .map_err(ForwardError::TokenFileIo)?;
        lock.lock_exclusive().map_err(ForwardError::TokenFileIo)?;
        let mut entries = if self.path.exists() {
            serde_json::from_slice::<Vec<serde_json::Value>>(
                &fs::read(&self.path).map_err(ForwardError::TokenFileIo)?,
            )
            .map_err(ForwardError::TokenFileJson)?
        } else {
            Vec::new()
        };
        entries.retain(|entry| {
            entry.get("name").and_then(serde_json::Value::as_str) != Some(&name)
                && entry.get("owner").and_then(|o| o.get("id")).and_then(serde_json::Value::as_str)
                    != Some(owner_id)
        });
        let bytes = serde_json::to_vec_pretty(&entries).map_err(ForwardError::TokenFileEncode)?;
        atomic_replace(&self.path, &bytes)?;
        FileExt::unlock(&lock).map_err(ForwardError::TokenFileIo)?;
        Ok(())
    }
}

fn operations_for(role: DemoRole) -> Vec<&'static str> {
    match role {
        DemoRole::Readonly => vec!["read", "coordination_read"],
        DemoRole::Write => vec![
            "read",
            "write",
            "ingest",
            "coordination_read",
            "coordination_write",
            "coordination_claim",
        ],
        DemoRole::Admin => vec![
            "read",
            "write",
            "delete",
            "ingest",
            "coordination_read",
            "coordination_write",
            "coordination_claim",
        ],
    }
}

fn entry_operations(entry: &serde_json::Value) -> Option<Vec<&str>> {
    let scopes = entry.get("scopes")?.as_array()?;
    if scopes.len() != 1 {
        return None;
    }
    scopes[0].get("operations")?.as_array()?.iter().map(serde_json::Value::as_str).collect()
}
fn sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(suffix);
    path.with_file_name(name)
}

fn atomic_replace(path: &Path, bytes: &[u8]) -> Result<(), ForwardError> {
    let parent =
        path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
    let mut file = tempfile::NamedTempFile::new_in(parent).map_err(ForwardError::TokenFileIo)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(ForwardError::TokenFileIo)?;
    }
    file.write_all(bytes).map_err(ForwardError::TokenFileIo)?;
    file.as_file().sync_all().map_err(ForwardError::TokenFileIo)?;
    file.persist(path).map_err(|error| ForwardError::TokenFileIo(error.error))?;
    #[cfg(unix)]
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(ForwardError::TokenFileIo)?;
    Ok(())
}
#[cfg(test)]
mod provisioner_tests {
    use super::*;
    use agentpalace_core::provenance::{
        AuthenticatedOwner, EmailAtWrite, Issuer, OwnerId, Subject,
    };
    use agentpalace_server::TokenRegistry;

    fn identity(owner_id: &str, subject: &str, email: &str) -> AdmissionIdentity {
        let id = OwnerId::new(owner_id).expect("test operation succeeded");
        let owner = AuthenticatedOwner::new(
            id.clone(),
            Issuer::new("https://accounts.google.com").expect("test operation succeeded"),
            Subject::new(subject).expect("test operation succeeded"),
            EmailAtWrite::new(email).expect("test operation succeeded"),
        );
        AdmissionIdentity::new(id, owner)
    }
    fn path() -> PathBuf {
        let mut random = [0u8; 8];
        rand::rng().fill_bytes(&mut random);
        let dir = std::env::temp_dir().join(format!(
            "demo-hub-token-test-{}-{}",
            std::process::id(),
            URL_SAFE_NO_PAD.encode(random)
        ));
        fs::create_dir_all(&dir).expect("test operation succeeded");
        dir.join("engine_tokens.json")
    }

    #[test]
    fn provisioner_is_idempotent_scoped_by_effective_role_and_compatible_with_registry() {
        let path = path();
        fs::write(&path, br#"[{"token":"operator-token","name":"operator","enabled":true}]"#)
            .expect("test operation succeeded");
        let provisioner = PrivateTokenProvisioner::new(&path).expect("test operation succeeded");
        let identity = identity("usr-owner-1", "google-subject-1", "owner@example.com");
        let write =
            provisioner.provision(&identity, DemoRole::Write).expect("test operation succeeded");
        let repeated =
            provisioner.provision(&identity, DemoRole::Write).expect("test operation succeeded");
        assert_eq!(
            write.token, repeated.token,
            "ordinary gateway auth must not rotate the engine credential"
        );
        assert_eq!(write.name, repeated.name);
        let admin =
            provisioner.provision(&identity, DemoRole::Admin).expect("test operation succeeded");
        assert_ne!(
            write.token, admin.token,
            "distinct effective ceilings use distinct private credentials"
        );
        assert_eq!(write.name, admin.name, "coordination principal stays stable across ceilings");

        let registry = TokenRegistry::load(path.clone()).expect("test operation succeeded");
        let write_auth = registry.authenticate(&write.token).expect("write token is active");
        assert!(!write_auth.is_unrestricted());
        assert_eq!(write_auth.name(), "demo-hub-owner-usr-owner-1");
        assert_eq!(write_auth.owner_id().map(|id| id.as_str()), Some("usr-owner-1"));
        assert!(registry.authenticate(&"unused".to_string()).is_none());
        let admin_auth = registry.authenticate(&admin.token).expect("admin token is active");
        assert!(!admin_auth.is_unrestricted());
        assert_eq!(admin_auth.name(), write_auth.name());

        let rotated =
            provisioner.rotate(&identity, DemoRole::Write).expect("test operation succeeded");
        assert_ne!(rotated.token, write.token);
        assert_eq!(rotated.name, write.name);
        let reloaded = TokenRegistry::load(path.clone()).expect("test operation succeeded");
        assert!(
            reloaded.authenticate(&write.token).is_none(),
            "rotated secret is no longer active"
        );
        assert!(reloaded.authenticate(&rotated.token).is_some());
        assert!(
            reloaded.authenticate(&admin.token).is_some(),
            "rotating write ceiling leaves admin grant state independent"
        );

        provisioner.revoke("usr-owner-1").expect("test operation succeeded");
        let revoked = TokenRegistry::load(path.clone()).expect("test operation succeeded");
        assert!(revoked.authenticate(&rotated.token).is_none());
        assert!(revoked.authenticate(&admin.token).is_none());
        assert!(
            revoked.authenticate("operator-token").is_some(),
            "unrelated operator credential is preserved"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).expect("test operation succeeded").permissions().mode() & 0o777,
                0o600
            );
        }
        let _ = fs::remove_dir_all(path.parent().expect("test operation succeeded"));
    }

    #[test]
    fn role_reconciliation_removes_stale_ceilings_and_keeps_active_credentials_stable() {
        let path = path();
        let provisioner = PrivateTokenProvisioner::new(&path).expect("test operation succeeded");
        let identity = identity("usr-owner-1", "subject-1", "owner@example.com");
        let write =
            provisioner.provision(&identity, DemoRole::Write).expect("test operation succeeded");
        let admin =
            provisioner.provision(&identity, DemoRole::Admin).expect("test operation succeeded");
        let readonly = provisioner
            .reconcile_roles(&identity, &[DemoRole::Readonly])
            .expect("test operation succeeded");
        assert_eq!(readonly.len(), 1);
        assert_eq!(readonly[0].role, DemoRole::Readonly);
        let registry = TokenRegistry::load(path.clone()).expect("test operation succeeded");
        assert!(registry.authenticate(&write.token).is_none());
        assert!(registry.authenticate(&admin.token).is_none());
        assert!(registry.authenticate(&readonly[0].token).is_some());
        let stable = provisioner
            .reconcile_roles(&identity, &[DemoRole::Readonly])
            .expect("test operation succeeded");
        assert_eq!(stable[0].token, readonly[0].token);
        let active = provisioner
            .reconcile_roles(&identity, &[DemoRole::Readonly, DemoRole::Write])
            .expect("test operation succeeded");
        assert_eq!(active.len(), 2);
        assert_eq!(
            active
                .iter()
                .find(|entry| entry.role == DemoRole::Readonly)
                .expect("test operation succeeded")
                .token,
            readonly[0].token
        );
        assert!(active.iter().any(|entry| entry.role == DemoRole::Write));
        let _ = fs::remove_dir_all(path.parent().expect("test operation succeeded"));
    }

    #[test]
    fn different_owners_receive_isolated_tokens_and_revocation_is_owner_scoped() {
        let path = path();
        let provisioner = PrivateTokenProvisioner::new(&path).expect("test operation succeeded");
        let one = provisioner
            .provision(&identity("usr-owner-1", "subject-1", "one@example.com"), DemoRole::Write)
            .expect("test operation succeeded");
        let two = provisioner
            .provision(&identity("usr-owner-2", "subject-2", "two@example.com"), DemoRole::Write)
            .expect("test operation succeeded");
        assert_ne!(one.token, two.token);
        assert_ne!(one.name, two.name);
        let registry = TokenRegistry::load(path.clone()).expect("test operation succeeded");
        assert_eq!(
            registry
                .authenticate(&one.token)
                .expect("test operation succeeded")
                .owner_id()
                .map(|id| id.as_str()),
            Some("usr-owner-1")
        );
        assert_eq!(
            registry
                .authenticate(&two.token)
                .expect("test operation succeeded")
                .owner_id()
                .map(|id| id.as_str()),
            Some("usr-owner-2")
        );
        provisioner.revoke("usr-owner-1").expect("test operation succeeded");
        let registry = TokenRegistry::load(path.clone()).expect("test operation succeeded");
        assert!(registry.authenticate(&one.token).is_none());
        assert!(registry.authenticate(&two.token).is_some());
        let _ = fs::remove_dir_all(path.parent().expect("test operation succeeded"));
    }
    #[test]
    fn private_upstream_token_debug_output_is_redacted() {
        let token = ProvisionedToken {
            owner_id: "owner".into(),
            name: "stable-agent".into(),
            token: "secret-value".into(),
            role: DemoRole::Write,
        };
        assert!(!format!("{token:?}").contains("secret-value"));
        let owner = AuthorizedOwner {
            owner_id: "owner".into(),
            upstream_token: "secret-value".into(),
            role: DemoRole::Write,
        };
        assert!(!format!("{owner:?}").contains("secret-value"));
    }
}
