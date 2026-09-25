//! [`RemoteClient`] — concrete reqwest-backed implementation of [`RemoteApi`].

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use agentpalace_federation::{
    AckMessageRequest, AddDrawerRequest, AddDrawerResponse, ChangesQuery, ChangesResponse,
    CheckDuplicateRequest, CheckDuplicateResponse, CoordinationArtifactDto,
    CoordinationEventsQuery, CoordinationEventsResponse, CoordinationMessageDto,
    CoordinationTaskDto, CoordinationTaskResultDto, DrawerSearchRequest, DrawerSearchResponse,
    ErrorBody, FEDERATION_API_VERSION, InboxPageResponse, InboxQuery, InfoResponse,
    IngestBatchRequest, IngestBatchResponse, KgAddFactRequest, KgInvalidateRequest, KgQueryRequest,
    ListDrawersQuery, ListDrawersResponse, NewArtifactRequest, NewMessageRequest, NewTaskRequest,
    NewTaskResultRequest, TaskLeaseRequest, TransitionTaskRequest,
};

use tokio::sync::Mutex;

use crate::{
    RemoteApi, RemoteEndpoint, RemoteRevisionedWrite,
    error::{RemoteError, Result},
};

/// Capability string a remote must advertise on `GET /v1/info` before this client will attempt
/// any `/v1/coordination/*` route (issue #102 Stage 3/4).
const COORDINATION_CAPABILITY: &str = "coordination";

/// Maximum body length (in bytes) included verbatim in [`RemoteError::RemoteRejected`].
///
/// Bodies larger than this are truncated to avoid flooding logs.
const MAX_ERROR_BODY: usize = 2048;

/// Maximum response body (in bytes) accepted from a remote peer on success.
///
/// Responses larger than this are rejected as [`RemoteError::InvalidResponse`]
/// to prevent memory exhaustion (peer OOM).
const MAX_RESPONSE_BYTES: usize = 10 * 1024 * 1024;

/// Whether a call mutates remote state or only reads it.
///
/// Transport failures are classified differently per call kind (issue #127,
/// slice 2): reads keep the historical degradable [`RemoteError::Unreachable`]
/// behaviour regardless of why the transport failed, whereas a mutation that
/// may have reached and committed on the server surfaces as
/// [`RemoteError::UnknownOutcome`] — never as an authoritative failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CallKind {
    /// A call that only reads remote state.
    Read,
    /// A call that mutates remote state (add/delete/ingest/KG write or any
    /// coordination write).
    Mutation,
}

/// One HTTP response as read by `send_and_read`.
struct Exchange {
    status: reqwest::StatusCode,
    bytes: Vec<u8>,
    /// RFC 9728 `resource_metadata` from a `WWW-Authenticate` challenge, if any.
    challenge: Option<String>,
    /// The bearer token the request carried, so 401 recovery can tell a rotated grant from the
    /// rejected one.
    token: Option<String>,
}

/// What [`RemoteClient::logout`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogoutOutcome {
    /// Whether a stored record was deleted.
    pub store: crate::ClearOutcome,
    /// Whether the grant was revoked at the issuer.
    pub revocation: RevocationOutcome,
}

/// Issuer-side revocation result of a logout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevocationOutcome {
    /// The issuer accepted the RFC 7009 revocation request.
    Revoked,
    /// No grant was available to revoke.
    NoCredential,
    /// No trusted issuer metadata, or the issuer advertises no revocation endpoint.
    Unsupported,
    /// The issuer was unreachable or refused revocation; local credentials were still removed.
    Failed(String),
}

/// A reqwest-backed HTTP client for one remote AgentPalace federation endpoint.
///
/// Build with [`RemoteClient::new`]; then use via the [`RemoteApi`] trait.
#[derive(Debug)]
pub struct RemoteClient {
    /// Display name used in error messages and log output.
    name: String,
    /// Base URL, normalised to end with `'/'` so [`reqwest::Url::join`] works correctly.
    base_url: reqwest::Url,
    /// Exact OAuth resource identity (the configured URL, not the slash-terminated transport
    /// base). Credentials are stored and looked up under this identity.
    oauth_resource: String,
    /// Bearer token sent on every authenticated request: the static configured token, or the
    /// current OAuth access token.
    token: Mutex<Option<String>>,
    oauth: Option<crate::OAuthConfig>,
    /// The OAuth grant currently in use by this process.
    oauth_session: Mutex<Option<crate::OAuthSession>>,
    /// Authorization-server metadata validated by discovery in this process. Recovery reuses it
    /// instead of trusting an unauthenticated challenge.
    trusted_metadata: Mutex<Option<crate::AuthorizationServerMetadata>>,
    token_store: crate::SharedTokenStore,
    /// Serializes every grant transition (login, reload, refresh, logout).
    login_lock: Mutex<()>,
    /// Incremented by every logout. Recovery that started before a logout observes the change
    /// and abandons, so an in-flight reload or refresh can never resurrect a signed-out grant.
    auth_epoch: AtomicU64,
    /// Incremented whenever a grant is committed; lets concurrent logins share one result.
    session_generation: AtomicU64,
    /// Set by logout and cleared only by an explicit login or explicit stored-session load, so
    /// background recovery never reloads a credential the user signed out of.
    signed_out: AtomicBool,
    /// Shared reqwest HTTP client (connection-pool aware).
    http: reqwest::Client,
    /// Cached result of the initial `GET /v1/info` handshake.
    ///
    /// [`tokio::sync::OnceCell`] is used so the handshake is attempted at most
    /// once per successful call; transient failures leave the cell empty so the
    /// next call retries.
    info: tokio::sync::OnceCell<InfoResponse>,
}

impl RemoteClient {
    /// Return the slash-normalized REST transport base URL.
    pub fn base_url(&self) -> &str {
        self.base_url.as_str()
    }

    /// Return the exact OAuth resource identity supplied by the endpoint.
    pub fn oauth_resource(&self) -> &str {
        &self.oauth_resource
    }

    /// Construct a new client from a [`RemoteEndpoint`] descriptor.
    ///
    /// Returns [`RemoteError::InvalidConfig`] when the URL is unparseable or the
    /// underlying [`reqwest::Client`] cannot be built.
    ///
    /// The client is inert until the first method call, which performs a
    /// version-handshake via `GET /v1/info`.
    pub fn new(endpoint: RemoteEndpoint) -> Result<Self> {
        let raw_url = endpoint.base_url.clone();

        let mut base_url =
            reqwest::Url::parse(&raw_url).map_err(|e| RemoteError::InvalidConfig {
                remote: endpoint.name.clone(),
                message: format!("cannot parse base URL `{raw_url}`: {e}"),
            })?;
        let oauth_resource = base_url.to_string();

        // Normalize: ensure the path ends with '/' so that Url::join with a
        // relative path (e.g. "v1/info") appends rather than replaces the last
        // path segment. This matters when the server sits behind a reverse proxy
        // at a sub-path such as `/palace/`.
        if !base_url.path().ends_with('/') {
            base_url.set_path(&format!("{}/", base_url.path()));
        }

        let http = reqwest::Client::builder()
            .use_rustls_tls()
            .timeout(endpoint.timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| RemoteError::InvalidConfig {
                remote: endpoint.name.clone(),
                message: format!("failed to build HTTP client: {e}"),
            })?;

        let token_store: crate::SharedTokenStore =
            endpoint.oauth.as_ref().and_then(|config| config.token_store.clone()).unwrap_or_else(
                || {
                    if endpoint.oauth.as_ref().is_some_and(|config| config.allow_in_memory) {
                        Arc::new(crate::InMemoryTokenStore::default())
                    } else {
                        Arc::new(crate::UnavailableTokenStore)
                    }
                },
            );
        Ok(Self {
            name: endpoint.name,
            base_url,
            oauth_resource,
            token: Mutex::new(endpoint.token),
            oauth: endpoint.oauth,
            oauth_session: Mutex::new(None),
            trusted_metadata: Mutex::new(None),
            token_store,
            login_lock: Mutex::new(()),
            auth_epoch: AtomicU64::new(0),
            session_generation: AtomicU64::new(0),
            signed_out: AtomicBool::new(false),
            http,
            info: tokio::sync::OnceCell::new(),
        })
    }

    /// Build a URL by joining a relative path segment to [`Self::base_url`].
    ///
    /// `path` must NOT start with `'/'` — a leading slash would clobber the
    /// base path on reverse-proxy deployments.
    fn url(&self, path: &str) -> Result<reqwest::Url> {
        self.base_url.join(path).map_err(|e| RemoteError::InvalidConfig {
            remote: self.name.clone(),
            message: format!("cannot construct URL for path `{path}`: {e}"),
        })
    }

    /// Build a URL for a drawer resource while keeping the id in one encoded
    /// path segment. Starting from the collection path without a trailing
    /// slash avoids introducing an empty segment before the id.
    fn drawer_url(&self, drawer_id: &str) -> Result<reqwest::Url> {
        let mut url = self.url("v1/drawers")?;
        url.path_segments_mut()
            .map_err(|_| RemoteError::InvalidConfig {
                remote: self.name.clone(),
                message: "cannot append drawer id to a non-hierarchical URL".to_owned(),
            })?
            .push(drawer_id);
        Ok(url)
    }

    /// Perform the `GET /v1/info` handshake and return the response.
    ///
    /// This method does **not** call [`Self::ensure_handshake`]; it is the
    /// handshake itself.
    async fn fetch_info(&self) -> Result<InfoResponse> {
        let url = self.url("v1/info")?;
        // `execute` owns the single bounded authentication recovery. Keeping
        // the handshake on that path prevents a failed/revoked credential from
        // recursively re-entering recovery.
        self.execute(self.http.get(url), CallKind::Read).await
    }

    /// Recheck the protected resource when an MCP caller requests sign-in. This bypasses the
    /// cached version handshake so a grant revoked after an earlier success is not mistaken for
    /// an authenticated session.
    pub async fn login_challenge(&self) -> Result<Option<String>> {
        match self.fetch_info().await {
            Ok(_) => Ok(None),
            Err(error @ RemoteError::AuthenticationRequired { resource_metadata: None, .. }) => {
                Err(error)
            }
            Err(RemoteError::AuthenticationRequired { resource_metadata: Some(url), .. }) => {
                Ok(Some(url))
            }
            Err(error) => Err(error),
        }
    }

    /// Fetch the protected resource's RFC 9728 challenge without loading, refreshing, or
    /// sending a stored grant. Logout uses this side-effect-free path to discover the issuer
    /// before it selects and clears the matching credential-store record.
    pub async fn oauth_resource_metadata_challenge(&self) -> Result<Option<String>> {
        self.oauth_config()?;
        let url = self.url("v1/info")?;
        let response = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|error| self.classify_send_error(CallKind::Read, error))?;
        let status = response.status();
        let challenge = response
            .headers()
            .get(reqwest::header::WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok())
            .and_then(crate::oauth::resource_metadata_from_challenge);
        if status == reqwest::StatusCode::UNAUTHORIZED {
            return challenge.map(Some).ok_or_else(|| RemoteError::AuthenticationRequired {
                remote: self.name.clone(),
                action: "the remote did not advertise OAuth protected-resource metadata"
                    .to_owned(),
                resource_metadata: None,
            });
        }
        if status.is_success() {
            return Ok(challenge);
        }
        Err(RemoteError::RemoteRejected {
            remote: self.name.clone(),
            status: status.as_u16(),
            body: "OAuth issuer discovery request was rejected".to_owned(),
        })
    }

    /// Ensure the version handshake has been performed, returning a reference
    /// to the cached [`InfoResponse`].
    ///
    /// On success the cell is populated and subsequent calls are free.
    /// On transient failure the cell is left empty, allowing a retry next call.
    /// On version mismatch, [`RemoteError::VersionSkew`] is returned on every call.
    async fn ensure_handshake(&self) -> Result<&InfoResponse> {
        let info = self.info.get_or_try_init(|| self.fetch_info()).await?;
        if info.federation_api_version != FEDERATION_API_VERSION {
            return Err(RemoteError::VersionSkew {
                remote: self.name.clone(),
                ours: FEDERATION_API_VERSION,
                theirs: info.federation_api_version,
            });
        }
        Ok(info)
    }

    /// Send a prepared [`reqwest::RequestBuilder`] with auth injected, and read the full
    /// response body with a size cap (tighter for error responses than for success, since the
    /// server controls the success schema but an error body from a misbehaving proxy could be
    /// arbitrarily large). Shared by [`Self::execute`] and [`Self::execute_revisioned`] so the
    /// two only diverge in how they classify a non-2xx status, not in how bytes are read.
    ///
    /// `kind` steers transport-failure classification: reads degrade to
    /// [`RemoteError::Unreachable`], while a mutation that may have been
    /// delivered surfaces as [`RemoteError::UnknownOutcome`].
    async fn send_and_read(&self, rb: reqwest::RequestBuilder, kind: CallKind) -> Result<Exchange> {
        if self.oauth.is_some() {
            self.refresh_if_expiring().await;
        }
        let token = self.token.lock().await.clone();
        let rb = match &token {
            Some(tok) => rb.bearer_auth(tok),
            None => rb,
        };

        let response = rb.send().await.map_err(|e| self.classify_send_error(kind, e))?;

        let status = response.status();

        let mut bytes = Vec::new();
        let mut response = response;
        while let Some(chunk) =
            response.chunk().await.map_err(|e| self.classify_body_error(kind, status, e))?
        {
            bytes.extend_from_slice(&chunk);
            let cap = if status.is_success() { MAX_RESPONSE_BYTES } else { MAX_ERROR_BODY };
            if bytes.len() >= cap {
                break;
            }
        }
        let challenge = response
            .headers()
            .get(reqwest::header::WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok())
            .and_then(crate::oauth::resource_metadata_from_challenge);
        Ok(Exchange { status, bytes, challenge, token })
    }

    /// Map a [`reqwest::Error`] from [`reqwest::RequestBuilder::send`] into a
    /// [`RemoteError`].
    ///
    /// For reads any transport failure stays degradable
    /// [`RemoteError::Unreachable`]. For mutations, only errors that prove the
    /// request was never delivered are [`RemoteError::Unreachable`]:
    /// [`reqwest::Error::is_builder`] (the request could not even be built) and
    /// [`reqwest::Error::is_connect`] (DNS/connect refused — nothing reached the
    /// application).
    ///
    /// Everything else is ambiguous. In particular [`reqwest::Error::is_timeout`]
    /// does **not** mean "before send": reqwest wraps a request timeout as
    /// `Kind::Request` via `error::request`, so `is_request()` is true for a
    /// response that never arrived — the mutation may have committed on the
    /// server — and must surface as [`RemoteError::UnknownOutcome`], never as
    /// an authoritative failure. A dead handshake runs as a read, so a mutation
    /// gated behind a dead handshake surfaces as [`RemoteError::Unreachable`]
    /// (before send), never as `UnknownOutcome`.
    fn classify_send_error(&self, kind: CallKind, e: reqwest::Error) -> RemoteError {
        let remote = self.name.clone();
        let message = e.to_string();
        match kind {
            CallKind::Read => RemoteError::Unreachable { remote, message },
            CallKind::Mutation => {
                if e.is_builder() || e.is_connect() {
                    RemoteError::Unreachable { remote, message }
                } else {
                    RemoteError::UnknownOutcome { remote, message }
                }
            }
        }
    }

    /// Map a [`reqwest::Error`] from reading a response body
    /// ([`reqwest::Response::chunk`]) into a [`RemoteError`].
    ///
    /// A body-read failure happens only after the status line was received. A
    /// successful mutation may already have committed and is therefore
    /// [`RemoteError::UnknownOutcome`]. A non-success status is authoritative
    /// even when its explanatory body is truncated, so it retains the status
    /// classification instead of being mislabeled as an ambiguous commit.
    /// Reads keep their historical degradable behavior.
    fn classify_body_error(
        &self,
        kind: CallKind,
        status: reqwest::StatusCode,
        e: reqwest::Error,
    ) -> RemoteError {
        let remote = self.name.clone();
        let message = e.to_string();
        match kind {
            CallKind::Read => RemoteError::Unreachable { remote, message },
            CallKind::Mutation if status == reqwest::StatusCode::UNAUTHORIZED => {
                RemoteError::Unauthorized { remote, resource_metadata: None }
            }
            CallKind::Mutation if !status.is_success() => RemoteError::RemoteRejected {
                remote,
                status: status.as_u16(),
                body: format!("response body read failed: {message}"),
            },
            CallKind::Mutation => RemoteError::UnknownOutcome { remote, message },
        }
    }

    /// Map a `serde_json` failure decoding a 2xx response body into a
    /// [`RemoteError`].
    ///
    /// The status line was received, so the server processed the request; for a
    /// mutation we cannot hand back the resulting payload, and must not claim an
    /// authoritative failure, so it surfaces as [`RemoteError::UnknownOutcome`].
    /// Reads surface as [`RemoteError::InvalidResponse`] as before.
    fn decode_failure(&self, kind: CallKind, e: serde_json::Error) -> RemoteError {
        match kind {
            CallKind::Read => {
                RemoteError::InvalidResponse { remote: self.name.clone(), message: e.to_string() }
            }
            CallKind::Mutation => {
                RemoteError::UnknownOutcome { remote: self.name.clone(), message: e.to_string() }
            }
        }
    }

    /// Classifies a non-2xx, non-401 response into [`RemoteError::RemoteRejected`], decoding an
    /// [`ErrorBody`] when present so the message is `"{code}: {message}"` rather than raw JSON.
    fn remote_rejected(&self, status: reqwest::StatusCode, bytes: &[u8]) -> RemoteError {
        let raw = String::from_utf8_lossy(bytes).into_owned();
        let body = if let Ok(err_body) = serde_json::from_str::<ErrorBody>(&raw) {
            format!("{}: {}", err_body.code, err_body.message)
        } else if raw.len() > MAX_ERROR_BODY {
            let mut cut = MAX_ERROR_BODY;
            while !raw.is_char_boundary(cut) {
                cut -= 1;
            }
            format!("{}… (truncated)", &raw[..cut])
        } else {
            raw
        };
        RemoteError::RemoteRejected { remote: self.name.clone(), status: status.as_u16(), body }
    }

    /// Send a prepared [`reqwest::RequestBuilder`], inject auth, and decode the
    /// response body as `T`.
    ///
    /// Error classification (`kind` distinguishes reads from mutations; see
    /// [`CallKind`]):
    /// - Transport failure before the request was delivered → [`RemoteError::Unreachable`]
    /// - Mutation transport/decoding failure where the write may have committed
    ///   → [`RemoteError::UnknownOutcome`]
    /// - HTTP 401 → [`RemoteError::Unauthorized`]
    /// - Other non-2xx → [`RemoteError::RemoteRejected`] (body included)
    /// - 2xx with bad JSON → [`RemoteError::InvalidResponse`] (reads) or
    ///   [`RemoteError::UnknownOutcome`] (mutations)
    async fn execute<T: serde::de::DeserializeOwned>(
        &self,
        rb: reqwest::RequestBuilder,
        kind: CallKind,
    ) -> Result<T> {
        let exchange = self.send_authorized(rb, kind).await?;

        if exchange.status == reqwest::StatusCode::UNAUTHORIZED {
            return Err(self.unauthorized(exchange.challenge));
        }

        if !exchange.status.is_success() {
            return Err(self.remote_rejected(exchange.status, &exchange.bytes));
        }

        serde_json::from_slice(&exchange.bytes).map_err(|e| self.decode_failure(kind, e))
    }

    /// Send a request and, for an OAuth remote whose request was answered with HTTP 401,
    /// recover authorization once and re-send the identical request once.
    ///
    /// A 401 is a complete, authoritative response: the resource rejected the credential before
    /// executing anything, so re-sending the same request — the same method, URL, and body, and
    /// therefore the same mutation `operation_id` — cannot double-apply it. This holds for reads
    /// and mutations alike. A transport failure or unreadable response never produces a status
    /// here (it is returned as `Unreachable`/`UnknownOutcome` by `send_and_read`), so an unknown
    /// outcome is never replayed. A second 401 is returned to the caller without further recovery.
    async fn send_authorized(
        &self,
        rb: reqwest::RequestBuilder,
        kind: CallKind,
    ) -> Result<Exchange> {
        let replay = self.oauth.is_some().then(|| rb.try_clone()).flatten();
        let exchange = self.send_and_read(rb, kind).await?;
        if exchange.status == reqwest::StatusCode::UNAUTHORIZED
            && let Some(replay) = replay
            && self
                .recover_authorization(exchange.token.as_deref(), exchange.challenge.as_deref())
                .await?
        {
            return self.send_and_read(replay, kind).await;
        }
        Ok(exchange)
    }

    /// The error for a final HTTP 401: OAuth remotes report that interactive login is needed
    /// (preserving any RFC 9728 challenge); static-token remotes report rejected credentials.
    fn unauthorized(&self, challenge: Option<String>) -> RemoteError {
        if self.oauth.is_some() {
            RemoteError::AuthenticationRequired {
                remote: self.name.clone(),
                action: "start OAuth sign-in for this remote (MCP: agentpalace_remote_auth_start)".to_owned(),
                resource_metadata: challenge,
            }
        } else {
            RemoteError::Unauthorized { remote: self.name.clone(), resource_metadata: challenge }
        }
    }

    /// Like [`Self::execute`], but a `409` body whose `code` is `"revision_conflict"` decodes
    /// into `Ok(RemoteRevisionedWrite::Conflict)` carrying the remote's `actual_revision`,
    /// instead of an `Err` — the wire counterpart of how
    /// `agentpalace_storage::CoordinationStore::claim_task`/`renew_lease`/`transition_task` report
    /// the same conflict locally (Phase 3 Stage 4). A `409 coordination_conflict` (no revision
    /// pair — a live lease held by someone else, a terminal task, an invalid transition) has
    /// nothing this shape can carry and falls through to the ordinary `RemoteRejected`
    /// classification, same as any other non-2xx status.
    ///
    /// Every coordination write this runs is a mutation, so transport failures
    /// that may have reached the server surface as
    /// [`RemoteError::UnknownOutcome`] rather than an authoritative failure.
    async fn execute_revisioned<T: serde::de::DeserializeOwned>(
        &self,
        rb: reqwest::RequestBuilder,
    ) -> Result<RemoteRevisionedWrite<T>> {
        let Exchange { status, bytes, challenge, .. } =
            self.send_authorized(rb, CallKind::Mutation).await?;

        if status == reqwest::StatusCode::UNAUTHORIZED {
            return Err(self.unauthorized(challenge));
        }

        if status == reqwest::StatusCode::CONFLICT {
            #[derive(serde::Deserialize)]
            struct ConflictBody {
                code: String,
                #[serde(default)]
                actual_revision: Option<i64>,
            }
            if let Ok(conflict) = serde_json::from_slice::<ConflictBody>(&bytes)
                && conflict.code == "revision_conflict"
            {
                return Ok(RemoteRevisionedWrite::Conflict {
                    actual_revision: conflict.actual_revision,
                });
            }
        }

        if !status.is_success() {
            return Err(self.remote_rejected(status, &bytes));
        }

        serde_json::from_slice(&bytes)
            .map(RemoteRevisionedWrite::Applied)
            .map_err(|e| self.decode_failure(CallKind::Mutation, e))
    }

    /// Ensures the cached `/v1/info` handshake has run and the remote advertises
    /// `"coordination"` (issue #102 Stage 3). Every coordination method calls this before
    /// sending its request — cheap, since [`Self::ensure_handshake`] caches the result in a
    /// `OnceCell` that every other method already populates on first use, so this costs nothing
    /// beyond the handshake every call already pays for.
    async fn ensure_coordination_capability(&self) -> Result<()> {
        let info = self.ensure_handshake().await?;
        if info.capabilities.iter().any(|c| c == COORDINATION_CAPABILITY) {
            Ok(())
        } else {
            Err(RemoteError::CapabilityMissing {
                remote: self.name.clone(),
                capability: COORDINATION_CAPABILITY.to_owned(),
            })
        }
    }

    fn oauth_config(&self) -> Result<&crate::OAuthConfig> {
        self.oauth.as_ref().ok_or_else(|| RemoteError::InvalidConfig {
            remote: self.name.clone(),
            message: "OAuth operation requested for a remote without OAuth configuration"
                .to_owned(),
        })
    }

    fn store_error(&self, error: crate::TokenStoreError) -> RemoteError {
        RemoteError::CredentialStore {
            remote: self.name.clone(),
            kind: error.kind,
            message: error.message,
        }
    }

    fn login_failed(&self, action: String) -> RemoteError {
        RemoteError::AuthenticationRequired {
            remote: self.name.clone(),
            action,
            resource_metadata: None,
        }
    }

    fn resource_url(&self) -> Result<reqwest::Url> {
        reqwest::Url::parse(&self.oauth_resource).map_err(|_| RemoteError::InvalidConfig {
            remote: self.name.clone(),
            message: "invalid OAuth resource".to_owned(),
        })
    }

    /// Publish a grant in-process (caller holds `login_lock`).
    async fn publish_locked(&self, session: crate::OAuthSession) {
        *self.token.lock().await = Some(session.access_token.clone());
        *self.oauth_session.lock().await = Some(session);
        self.session_generation.fetch_add(1, Ordering::SeqCst);
        self.signed_out.store(false, Ordering::SeqCst);
    }

    /// Drop the in-process grant (caller holds `login_lock`).
    async fn forget_locked(&self) -> Option<crate::OAuthSession> {
        *self.token.lock().await = None;
        self.oauth_session.lock().await.take()
    }

    /// Publish a new grant and persist it (caller holds `login_lock`). The grant is published
    /// before persistence so a secure-store failure does not discard a grant that just cost the
    /// user an interactive login; the store failure is still returned for remediation.
    async fn commit_locked(&self, session: crate::OAuthSession) -> Result<()> {
        self.publish_locked(session.clone()).await;
        self.token_store.save(session).await.map_err(|error| self.store_error(error))
    }

    /// Discover and validate protected-resource and authorization-server metadata from an
    /// RFC 9728 `resource_metadata` URL. On success the issuer metadata becomes trusted context
    /// for later recovery in this process.
    pub async fn discover(
        &self,
        resource_metadata: &str,
    ) -> Result<(crate::ProtectedResourceMetadata, crate::AuthorizationServerMetadata)> {
        let config = self.oauth_config()?;
        let (protected, metadata) = crate::discover_metadata(
            &self.http,
            resource_metadata,
            &self.resource_url()?,
            &self.base_url,
            config.allow_loopback_demo,
        )
        .await
        .map_err(|message| RemoteError::AuthenticationRequired {
            remote: self.name.clone(),
            action: message,
            resource_metadata: Some(resource_metadata.to_owned()),
        })?;
        *self.trusted_metadata.lock().await = Some(metadata.clone());
        Ok((protected, metadata))
    }

    /// Fetch and validate RFC 8414 metadata for an issuer this client already holds a grant
    /// from. The document must name the same issuer, and its endpoints must satisfy the same
    /// origin and transport policy as discovery. On success the metadata becomes trusted context.
    pub async fn authorization_server_metadata(
        &self,
        issuer: &str,
    ) -> Result<crate::AuthorizationServerMetadata> {
        if let Some(metadata) =
            self.trusted_metadata.lock().await.clone().filter(|metadata| metadata.issuer == issuer)
        {
            return Ok(metadata);
        }
        let config = self.oauth_config()?;
        let invalid = |message: String| RemoteError::AuthenticationRequired {
            remote: self.name.clone(),
            action: message,
            resource_metadata: None,
        };
        let metadata = crate::fetch_authorization_server_metadata(
            &self.http,
            issuer,
            &self.base_url,
            config.allow_loopback_demo,
        )
        .await
        .map_err(invalid)?;
        let protected = crate::ProtectedResourceMetadata {
            resource: self.oauth_resource.clone(),
            authorization_servers: vec![issuer.to_owned()],
        };
        crate::validate_metadata(
            &protected,
            &metadata,
            &self.resource_url()?,
            &self.base_url,
            config.allow_loopback_demo,
        )
        .map_err(invalid)?;
        *self.trusted_metadata.lock().await = Some(metadata.clone());
        Ok(metadata)
    }

    /// Recover a request rejected with HTTP 401. Returns `Ok(true)` when a different credential
    /// is now in place and the request should be re-sent once.
    ///
    /// Trust comes only from context this process already validated: a challenge's
    /// `resource_metadata` is used only if it passes full discovery validation; otherwise the
    /// retained discovery result, or the issuer of the grant already in use, is used. The
    /// persistent store is authoritative: a grant rotated by another process is adopted without
    /// refreshing, a grant removed by another process is forgotten here too, and an unexpired
    /// grant the server rejected is refreshed once. Recovery that races a logout abandons.
    async fn recover_authorization(
        &self,
        rejected_token: Option<&str>,
        challenge: Option<&str>,
    ) -> Result<bool> {
        let Some(config) = self.oauth.as_ref() else { return Ok(false) };
        let epoch = self.auth_epoch.load(Ordering::SeqCst);
        if self.signed_out.load(Ordering::SeqCst) {
            return Ok(false);
        }

        let mut metadata = None;
        if let Some(challenge) = challenge {
            metadata = self.discover(challenge).await.ok().map(|(_, metadata)| metadata);
        }
        if metadata.is_none() {
            metadata = self.trusted_metadata.lock().await.clone();
        }
        if metadata.is_none() {
            let issuer =
                self.oauth_session.lock().await.as_ref().map(|session| session.issuer.clone());
            if let Some(issuer) = issuer {
                metadata = self.authorization_server_metadata(&issuer).await.ok();
            }
        }
        let Some(metadata) = metadata else { return Ok(false) };

        let _guard = self.login_lock.lock().await;
        if self.auth_epoch.load(Ordering::SeqCst) != epoch || self.signed_out.load(Ordering::SeqCst)
        {
            return Ok(false);
        }
        let stored = self
            .token_store
            .load(
                &self.oauth_resource,
                &metadata.issuer,
                &config.client_id,
                config.account.as_deref(),
            )
            .await
            .map_err(|error| self.store_error(error))?;
        let Some(current) = stored else {
            // The authoritative store holds no grant: another process signed out.
            self.forget_locked().await;
            return Ok(false);
        };
        if rejected_token != Some(current.access_token.as_str()) {
            self.publish_locked(current).await;
            return Ok(true);
        }
        match crate::refresh(&self.http, &metadata, &current).await {
            Ok(session) => {
                self.commit_locked(session).await?;
                Ok(true)
            }
            Err(crate::TokenEndpointFailure::Rejected(_)) => {
                self.forget_locked().await;
                self.token_store
                    .clear(
                        &current.resource,
                        &current.issuer,
                        &current.client_id,
                        current.account.as_deref(),
                    )
                    .await
                    .map_err(|error| self.store_error(error))?;
                Ok(false)
            }
            Err(crate::TokenEndpointFailure::Transient(message)) => {
                Err(RemoteError::Unreachable { remote: self.name.clone(), message })
            }
        }
    }

    /// Refresh an access token that is about to expire before sending a request. Best effort:
    /// on any failure the request is sent with the current token and a 401 is handled normally.
    async fn refresh_if_expiring(&self) {
        let Some(session) = self.oauth_session.lock().await.clone() else { return };
        let expiring = session
            .expires_at
            .is_some_and(|at| at <= crate::oauth::now_seconds().saturating_add(30));
        if !expiring || session.refresh_token.is_none() {
            return;
        }
        let Some(metadata) = self
            .trusted_metadata
            .lock()
            .await
            .clone()
            .filter(|metadata| metadata.issuer == session.issuer)
        else {
            return;
        };
        let _guard = self.login_lock.lock().await;
        let unchanged = self
            .oauth_session
            .lock()
            .await
            .as_ref()
            .is_some_and(|current| current.access_token == session.access_token);
        if !unchanged || self.signed_out.load(Ordering::SeqCst) {
            return;
        }
        match crate::refresh(&self.http, &metadata, &session).await {
            Ok(fresh) => {
                if let Err(error) = self.commit_locked(fresh).await {
                    tracing::warn!(remote = %self.name, %error, "refreshed OAuth grant could not be persisted");
                }
            }
            Err(crate::TokenEndpointFailure::Rejected(_)) => {
                self.forget_locked().await;
                if let Err(error) = self
                    .token_store
                    .clear(
                        &session.resource,
                        &session.issuer,
                        &session.client_id,
                        session.account.as_deref(),
                    )
                    .await
                {
                    tracing::warn!(remote = %self.name, %error, "rejected OAuth grant could not be removed from the credential store");
                }
            }
            Err(crate::TokenEndpointFailure::Transient(_)) => {}
        }
    }

    /// Complete one explicit browser login for an OAuth-configured endpoint. Concurrent callers
    /// share one in-flight grant instead of opening multiple browsers.
    pub async fn login(
        &self,
        metadata: &crate::AuthorizationServerMetadata,
        resource: &str,
    ) -> Result<()> {
        self.interactive_login(metadata, resource, agentpalace_config::OAuthLoginMode::Browser)
            .await
    }

    /// Discover metadata from a preserved RFC 9728 challenge and perform one explicit login
    /// using the configured login mode.
    pub async fn login_from_challenge(&self, resource_metadata: &str) -> Result<()> {
        self.login_from_challenge_with_mode(resource_metadata, None).await
    }

    /// Discover metadata from a preserved challenge and perform login using an
    /// optional foreground override, otherwise the configured login mode.
    pub async fn login_from_challenge_with_mode(
        &self,
        resource_metadata: &str,
        mode: Option<agentpalace_config::OAuthLoginMode>,
    ) -> Result<()> {
        self.login_from_challenge_with_interaction(resource_metadata, mode, None).await
    }

    /// Discover a challenged issuer using a host-provided prompt surface. MCP can return a
    /// device verification link to its caller instead of printing it to hidden stderr.
    pub async fn login_from_challenge_with_interaction(
        &self,
        resource_metadata: &str,
        mode: Option<agentpalace_config::OAuthLoginMode>,
        interaction: Option<std::sync::Arc<dyn crate::LoginInteraction>>,
    ) -> Result<()> {
        let config = self.oauth_config()?;
        let (protected, metadata) = self.discover(resource_metadata).await?;
        let mode = crate::select_login_mode(
            mode.unwrap_or(config.login_mode),
            crate::browser_callback_usable(),
        );
        self.interactive_login_with_interaction(&metadata, &protected.resource, mode, interaction)
            .await
    }

    async fn interactive_login(
        &self,
        metadata: &crate::AuthorizationServerMetadata,
        resource: &str,
        mode: agentpalace_config::OAuthLoginMode,
    ) -> Result<()> {
        self.interactive_login_with_interaction(metadata, resource, mode, None).await
    }

    async fn interactive_login_with_interaction(
        &self,
        metadata: &crate::AuthorizationServerMetadata,
        resource: &str,
        mode: agentpalace_config::OAuthLoginMode,
        interaction: Option<std::sync::Arc<dyn crate::LoginInteraction>>,
    ) -> Result<()> {
        let mut config = self.oauth_config()?.clone();
        if let Some(interaction) = interaction {
            config.interaction = Some(interaction);
        }
        let observed = self.session_generation.load(Ordering::SeqCst);
        let _guard = self.login_lock.lock().await;
        // A caller that waited while another caller committed a grant for the same identity
        // shares it instead of starting a second interactive login. A grant that already existed
        // before this call started is not reused: an explicit login always re-authorizes.
        let shared = self.session_generation.load(Ordering::SeqCst) != observed
            && self.oauth_session.lock().await.as_ref().is_some_and(|session| {
                crate::resource_key(&session.resource) == crate::resource_key(resource)
                    && session.issuer == metadata.issuer
                    && session.client_id == config.client_id
                    && session.account.as_deref() == config.account.as_deref()
            });
        if shared {
            return Ok(());
        }
        let session = match mode {
            agentpalace_config::OAuthLoginMode::Device => {
                crate::device_login(&self.http, metadata, &config, resource).await
            }
            _ => crate::browser_login(&self.http, metadata, &config, resource).await,
        }
        .map_err(|message| self.login_failed(message))?;
        *self.trusted_metadata.lock().await = Some(metadata.clone());
        self.commit_locked(session).await
    }

    /// Load a previously authorized grant for this remote's exact OAuth resource and the given
    /// issuer. `Ok(false)` means no grant is stored; a store failure is returned as
    /// [`RemoteError::CredentialStore`], never as absence.
    pub async fn load_stored_session(&self, issuer: &str) -> Result<bool> {
        let config = self.oauth_config()?;
        let _guard = self.login_lock.lock().await;
        let stored = self
            .token_store
            .load(&self.oauth_resource, issuer, &config.client_id, config.account.as_deref())
            .await
            .map_err(|error| self.store_error(error))?;
        let Some(session) = stored else { return Ok(false) };
        self.publish_locked(session).await;
        Ok(true)
    }

    /// Refresh the current grant once, replacing the access and rotating refresh token together.
    /// An authoritative rejection forgets the grant in-process and in the store; a transient
    /// failure keeps it and is reported as [`RemoteError::Unreachable`].
    pub async fn refresh(&self, metadata: &crate::AuthorizationServerMetadata) -> Result<()> {
        let _guard = self.login_lock.lock().await;
        let current = self.oauth_session.lock().await.clone().ok_or_else(|| {
            self.login_failed("start OAuth sign-in for this remote (MCP: agentpalace_remote_auth_start)".to_owned())
        })?;
        match crate::refresh(&self.http, metadata, &current).await {
            Ok(session) => self.commit_locked(session).await,
            Err(crate::TokenEndpointFailure::Rejected(message)) => {
                self.forget_locked().await;
                self.token_store
                    .clear(
                        &current.resource,
                        &current.issuer,
                        &current.client_id,
                        current.account.as_deref(),
                    )
                    .await
                    .map_err(|error| self.store_error(error))?;
                Err(self.login_failed(message))
            }
            Err(crate::TokenEndpointFailure::Transient(message)) => {
                Err(RemoteError::Unreachable { remote: self.name.clone(), message })
            }
        }
    }

    /// Sign out: forget the grant in-process, revoke it at the issuer where possible, and delete
    /// the stored record for this remote's exact OAuth resource.
    ///
    /// `issuer` selects the stored record; when `None`, the issuer of the grant in use is used.
    /// Revocation uses `metadata` when given, otherwise metadata already trusted by this process.
    /// After logout, background recovery never reloads a stored grant until an explicit login
    /// or [`Self::load_stored_session`].
    pub async fn logout(
        &self,
        issuer: Option<&str>,
        metadata: Option<&crate::AuthorizationServerMetadata>,
    ) -> Result<LogoutOutcome> {
        let config = self.oauth_config()?;
        let _guard = self.login_lock.lock().await;
        self.auth_epoch.fetch_add(1, Ordering::SeqCst);
        self.signed_out.store(true, Ordering::SeqCst);
        let in_memory = self.forget_locked().await;
        let issuer = issuer
            .map(str::to_owned)
            .or_else(|| in_memory.as_ref().map(|session| session.issuer.clone()));
        let Some(issuer) = issuer else {
            return Ok(LogoutOutcome {
                store: crate::ClearOutcome::Absent,
                revocation: RevocationOutcome::NoCredential,
            });
        };
        let in_memory = in_memory.filter(|session| session.issuer == issuer);
        // A corrupt or unreadable record must still be deletable, so a load failure only
        // prevents revocation; the delete below reports the store's real state.
        let stored = self
            .token_store
            .load(&self.oauth_resource, &issuer, &config.client_id, config.account.as_deref())
            .await;
        let grant = in_memory.or(stored.ok().flatten());
        let trusted = self.trusted_metadata.lock().await.clone();
        let metadata = metadata.cloned().or(trusted).filter(|metadata| metadata.issuer == issuer);
        let revocation = match (&grant, &metadata) {
            (None, _) => RevocationOutcome::NoCredential,
            (Some(_), Some(metadata)) if metadata.revocation_endpoint.is_none() => {
                RevocationOutcome::Unsupported
            }
            (Some(_), None) => RevocationOutcome::Unsupported,
            (Some(grant), Some(metadata)) => match crate::revoke(&self.http, metadata, grant).await
            {
                Ok(()) => RevocationOutcome::Revoked,
                Err(message) => RevocationOutcome::Failed(message),
            },
        };
        let store = self
            .token_store
            .clear(&self.oauth_resource, &issuer, &config.client_id, config.account.as_deref())
            .await
            .map_err(|error| self.store_error(error))?;
        Ok(LogoutOutcome { store, revocation })
    }
}

#[async_trait::async_trait]
impl RemoteApi for RemoteClient {
    /// Return the cached server info, performing the handshake if needed.
    async fn info(&self) -> Result<InfoResponse> {
        Ok(self.ensure_handshake().await?.clone())
    }

    /// Return whether the remote handshake advertised receipt-backed mutation idempotency.
    async fn idempotent_mutations_capability(&self) -> Result<Option<bool>> {
        let info = self.ensure_handshake().await?;
        Ok(Some(info.capabilities.iter().any(|capability| capability == "idempotent_mutations")))
    }

    /// Search drawers using semantic full-text matching (`POST /v1/drawers/search`).
    async fn search_drawers(&self, req: DrawerSearchRequest) -> Result<DrawerSearchResponse> {
        self.ensure_handshake().await?;
        let url = self.url("v1/drawers/search")?;
        let rb = self.http.post(url).json(&req);
        self.execute(rb, CallKind::Read).await
    }

    /// Check whether content is a near-duplicate of an existing drawer (`POST /v1/drawers/check_duplicate`).
    async fn check_duplicate(&self, req: CheckDuplicateRequest) -> Result<CheckDuplicateResponse> {
        self.ensure_handshake().await?;
        let url = self.url("v1/drawers/check_duplicate")?;
        let rb = self.http.post(url).json(&req);
        self.execute(rb, CallKind::Read).await
    }

    /// Add a new drawer to the remote palace (`POST /v1/drawers`).
    async fn add_drawer(&self, req: AddDrawerRequest) -> Result<AddDrawerResponse> {
        self.ensure_handshake().await?;
        let url = self.url("v1/drawers")?;
        let rb = self.http.post(url).json(&req);
        self.execute(rb, CallKind::Mutation).await
    }

    /// List drawers with optional filtering and pagination (`GET /v1/drawers`).
    ///
    /// `query` is serialized as URL query parameters via `serde_urlencoded`;
    /// `None` fields are omitted automatically.
    async fn list_drawers(&self, query: ListDrawersQuery) -> Result<ListDrawersResponse> {
        self.ensure_handshake().await?;
        let url = self.url("v1/drawers")?;
        let rb = self.http.get(url).query(&query);
        self.execute(rb, CallKind::Read).await
    }

    /// Retrieve a single drawer by its stable identifier (`GET /v1/drawers/{id}`).
    async fn get_drawer(&self, drawer_id: &str) -> Result<serde_json::Value> {
        self.ensure_handshake().await?;
        let url = self.drawer_url(drawer_id)?;
        let rb = self.http.get(url);
        self.execute(rb, CallKind::Read).await
    }

    /// Delete a drawer by its stable identifier (`DELETE /v1/drawers/{id}`).
    async fn delete_drawer(&self, drawer_id: &str) -> Result<()> {
        self.delete_drawer_with_operation_id(drawer_id, None).await
    }

    /// Delete a drawer by its stable identifier, carrying an optional operation
    /// id as a query parameter (`DELETE /v1/drawers/{id}?operation_id=`).
    ///
    /// The operation id lets a durable replication outbox retry a delete
    /// safely: the receiving endpoint can dedupe a replayed mutation, and
    /// `DeleteDrawerQuery` keeps old callers (that omit it) wire-compatible.
    async fn delete_drawer_with_operation_id(
        &self,
        drawer_id: &str,
        operation_id: Option<&str>,
    ) -> Result<()> {
        self.ensure_handshake().await?;
        // Build the final path segment through `Url` rather than interpolating it into a
        // string. Drawer ids may legitimately contain `/` (for example `wing/room/hash`),
        // which must be percent-encoded as one segment for the server's `{id}` route.
        // Start from the collection path without a trailing slash. `Url` keeps
        // a trailing slash as an empty path segment, so pushing onto
        // `v1/drawers/` would produce `v1/drawers//{id}` and miss the server
        // route.
        let url = self.drawer_url(drawer_id)?;
        let rb = self.http.delete(url);
        let rb = match operation_id {
            Some(op) => rb.query(&[("operation_id", op)]),
            None => rb,
        };
        self.execute::<serde_json::Value>(rb, CallKind::Mutation).await.map(|_| ())
    }

    /// Query the knowledge graph for an entity (`POST /v1/kg/query`).
    async fn kg_query(&self, req: KgQueryRequest) -> Result<serde_json::Value> {
        self.ensure_handshake().await?;
        let url = self.url("v1/kg/query")?;
        let rb = self.http.post(url).json(&req);
        self.execute(rb, CallKind::Read).await
    }

    /// Add a fact to the knowledge graph (`POST /v1/kg/facts`).
    async fn kg_add_fact(&self, req: KgAddFactRequest) -> Result<serde_json::Value> {
        self.ensure_handshake().await?;
        let url = self.url("v1/kg/facts")?;
        let rb = self.http.post(url).json(&req);
        self.execute(rb, CallKind::Mutation).await
    }

    /// Invalidate a knowledge-graph fact (`POST /v1/kg/facts/invalidate`).
    async fn kg_invalidate(&self, req: KgInvalidateRequest) -> Result<serde_json::Value> {
        self.ensure_handshake().await?;
        let url = self.url("v1/kg/facts/invalidate")?;
        let rb = self.http.post(url).json(&req);
        self.execute(rb, CallKind::Mutation).await
    }

    /// Retrieve the knowledge-graph timeline, optionally filtered by entity (`GET /v1/kg/timeline`).
    async fn kg_timeline(&self, entity: Option<&str>) -> Result<serde_json::Value> {
        self.ensure_handshake().await?;
        let url = self.url("v1/kg/timeline")?;
        let rb = match entity {
            Some(e) => self.http.get(url).query(&[("entity", e)]),
            None => self.http.get(url),
        };
        self.execute(rb, CallKind::Read).await
    }

    /// Retrieve knowledge-graph statistics (`GET /v1/kg/stats`).
    async fn kg_stats(&self) -> Result<serde_json::Value> {
        self.ensure_handshake().await?;
        let url = self.url("v1/kg/stats")?;
        let rb = self.http.get(url);
        self.execute(rb, CallKind::Read).await
    }

    /// Retrieve the palace taxonomy (`GET /v1/taxonomy`).
    async fn taxonomy(&self) -> Result<serde_json::Value> {
        self.ensure_handshake().await?;
        let url = self.url("v1/taxonomy")?;
        let rb = self.http.get(url);
        self.execute(rb, CallKind::Read).await
    }

    /// List the wings in the remote palace (`GET /v1/wings`).
    async fn wings(&self) -> Result<serde_json::Value> {
        self.ensure_handshake().await?;
        let url = self.url("v1/wings")?;
        let rb = self.http.get(url);
        self.execute(rb, CallKind::Read).await
    }

    /// List rooms, optionally filtered by wing (`GET /v1/rooms`).
    async fn rooms(&self, wing: Option<&str>) -> Result<serde_json::Value> {
        self.ensure_handshake().await?;
        let url = self.url("v1/rooms")?;
        let rb = match wing {
            Some(w) => self.http.get(url).query(&[("wing", w)]),
            None => self.http.get(url),
        };
        self.execute(rb, CallKind::Read).await
    }

    /// Retrieve paginated change events (`GET /v1/changes`).
    ///
    /// `query` is serialized as URL query parameters via `serde_urlencoded`;
    /// `None` fields are omitted automatically.
    async fn changes(&self, query: ChangesQuery) -> Result<ChangesResponse> {
        self.ensure_handshake().await?;
        let url = self.url("v1/changes")?;
        let rb = self.http.get(url).query(&query);
        self.execute(rb, CallKind::Read).await
    }

    /// Bulk-ingest pre-chunked file content into the remote palace
    /// (`POST /v1/ingest/batch`).
    ///
    /// A 413 response (body too large) surfaces as
    /// [`RemoteError::RemoteRejected`] with `status: 413`; no client-side
    /// splitting is attempted.
    async fn ingest_batch(&self, req: IngestBatchRequest) -> Result<IngestBatchResponse> {
        let info = self.ensure_handshake().await?;
        // Durable records must reach receipt replay even if the checkout has
        // moved since their first application. The server validates fresh records.
        if req.replication.is_none()
            && info.capabilities.iter().any(|capability| capability == "ingest_preflight")
        {
            let preflight = agentpalace_federation::IngestPreflightRequest {
                wing: req.wing.clone(),
                commit_hash: req.commit_hash.clone(),
                files: req
                    .files
                    .iter()
                    .filter(|file| !file.chunks.is_empty())
                    .filter_map(|file| {
                        file.file_hash.as_ref().map(|file_hash| {
                            agentpalace_federation::IngestPreflightFile {
                                relative_path: file.relative_path.clone(),
                                file_hash: file_hash.clone(),
                            }
                        })
                    })
                    .collect(),
            };
            if !preflight.files.is_empty() {
                let url = self.url("v1/ingest/preflight")?;
                let _: agentpalace_federation::IngestPreflightResponse =
                    self.execute(self.http.post(url).json(&preflight), CallKind::Read).await?;
            }
        }
        let url = self.url("v1/ingest/batch")?;
        let rb = self.http.post(url).json(&req);
        self.execute(rb, CallKind::Mutation).await
    }

    /// Create a task (`POST /v1/coordination/tasks`).
    async fn coordination_task_create(&self, req: NewTaskRequest) -> Result<CoordinationTaskDto> {
        self.ensure_coordination_capability().await?;
        let url = self.url("v1/coordination/tasks")?;
        let rb = self.http.post(url).json(&req);
        self.execute(rb, CallKind::Mutation).await
    }

    /// Get one task by exact ID (`GET /v1/coordination/tasks/{id}`).
    async fn coordination_task_get(&self, task_id: &str) -> Result<CoordinationTaskDto> {
        self.ensure_coordination_capability().await?;
        let path = format!("v1/coordination/tasks/{task_id}");
        let url = self.url(&path)?;
        let rb = self.http.get(url);
        self.execute(rb, CallKind::Read).await
    }

    /// Claim a task, or reclaim an expired lease (`POST /v1/coordination/tasks/{id}/claim`).
    async fn coordination_task_claim(
        &self,
        task_id: &str,
        req: TaskLeaseRequest,
    ) -> Result<RemoteRevisionedWrite<CoordinationTaskDto>> {
        self.ensure_coordination_capability().await?;
        let path = format!("v1/coordination/tasks/{task_id}/claim");
        let url = self.url(&path)?;
        let rb = self.http.post(url).json(&req);
        self.execute_revisioned(rb).await
    }

    /// Renew a live lease (`POST /v1/coordination/tasks/{id}/renew`).
    async fn coordination_task_renew(
        &self,
        task_id: &str,
        req: TaskLeaseRequest,
    ) -> Result<RemoteRevisionedWrite<CoordinationTaskDto>> {
        self.ensure_coordination_capability().await?;
        let path = format!("v1/coordination/tasks/{task_id}/renew");
        let url = self.url(&path)?;
        let rb = self.http.post(url).json(&req);
        self.execute_revisioned(rb).await
    }

    /// Transition a task's lifecycle state (`POST /v1/coordination/tasks/{id}/transition`).
    async fn coordination_task_transition(
        &self,
        task_id: &str,
        req: TransitionTaskRequest,
    ) -> Result<RemoteRevisionedWrite<CoordinationTaskDto>> {
        self.ensure_coordination_capability().await?;
        let path = format!("v1/coordination/tasks/{task_id}/transition");
        let url = self.url(&path)?;
        let rb = self.http.post(url).json(&req);
        self.execute_revisioned(rb).await
    }

    /// Send an addressed message (`POST /v1/coordination/messages`).
    async fn coordination_message_send(
        &self,
        req: NewMessageRequest,
    ) -> Result<CoordinationMessageDto> {
        self.ensure_coordination_capability().await?;
        let url = self.url("v1/coordination/messages")?;
        let rb = self.http.post(url).json(&req);
        self.execute(rb, CallKind::Mutation).await
    }

    /// Get one message by exact ID (`GET /v1/coordination/messages/{id}`).
    async fn coordination_message_get(&self, message_id: &str) -> Result<CoordinationMessageDto> {
        self.ensure_coordination_capability().await?;
        let path = format!("v1/coordination/messages/{message_id}");
        let url = self.url(&path)?;
        let rb = self.http.get(url);
        self.execute(rb, CallKind::Read).await
    }

    /// Acknowledge a message (`POST /v1/coordination/messages/{id}/ack`).
    async fn coordination_message_ack(
        &self,
        message_id: &str,
        req: AckMessageRequest,
    ) -> Result<CoordinationMessageDto> {
        self.ensure_coordination_capability().await?;
        let path = format!("v1/coordination/messages/{message_id}/ack");
        let url = self.url(&path)?;
        let rb = self.http.post(url).json(&req);
        self.execute(rb, CallKind::Mutation).await
    }

    /// Read an addressed inbox, cursor-paginated (`GET /v1/coordination/inbox`).
    async fn coordination_inbox(&self, query: InboxQuery) -> Result<InboxPageResponse> {
        self.ensure_coordination_capability().await?;
        let url = self.url("v1/coordination/inbox")?;
        let rb = self.http.get(url).query(&query);
        self.execute(rb, CallKind::Read).await
    }

    /// Store an immutable artifact (`POST /v1/coordination/artifacts`).
    async fn coordination_artifact_put(
        &self,
        req: NewArtifactRequest,
    ) -> Result<CoordinationArtifactDto> {
        self.ensure_coordination_capability().await?;
        let url = self.url("v1/coordination/artifacts")?;
        let rb = self.http.post(url).json(&req);
        self.execute(rb, CallKind::Mutation).await
    }

    /// Get one artifact by exact ID (`GET /v1/coordination/artifacts/{id}`).
    async fn coordination_artifact_get(
        &self,
        artifact_id: &str,
    ) -> Result<CoordinationArtifactDto> {
        self.ensure_coordination_capability().await?;
        let path = format!("v1/coordination/artifacts/{artifact_id}");
        let url = self.url(&path)?;
        let rb = self.http.get(url);
        self.execute(rb, CallKind::Read).await
    }

    /// Store an immutable task result (`POST /v1/coordination/results`).
    async fn coordination_result_put(
        &self,
        req: NewTaskResultRequest,
    ) -> Result<CoordinationTaskResultDto> {
        self.ensure_coordination_capability().await?;
        let url = self.url("v1/coordination/results")?;
        let rb = self.http.post(url).json(&req);
        self.execute(rb, CallKind::Mutation).await
    }

    /// Get one task result by exact ID (`GET /v1/coordination/results/{id}`).
    async fn coordination_result_get(&self, result_id: &str) -> Result<CoordinationTaskResultDto> {
        self.ensure_coordination_capability().await?;
        let path = format!("v1/coordination/results/{result_id}");
        let url = self.url(&path)?;
        let rb = self.http.get(url);
        self.execute(rb, CallKind::Read).await
    }

    /// Discover tasks with compact metadata and an opaque cursor (`GET /v1/coordination/tasks`).
    async fn coordination_tasks(
        &self,
        query: agentpalace_federation::CoordinationTasksQuery,
    ) -> Result<agentpalace_federation::CoordinationTasksResponse> {
        let info = self.ensure_handshake().await?;
        if !info.capabilities.iter().any(|c| c == "coordination_task_list") {
            return Err(RemoteError::CapabilityMissing {
                remote: self.name.clone(),
                capability: "coordination_task_list".into(),
            });
        }
        let url = self.url("v1/coordination/tasks")?;
        self.execute(self.http.get(url).query(&query), CallKind::Read).await
    }

    /// Read the coordination audit-event feed, cursor-paginated (`GET /v1/coordination/events`).
    async fn coordination_events(
        &self,
        query: CoordinationEventsQuery,
    ) -> Result<CoordinationEventsResponse> {
        self.ensure_coordination_capability().await?;
        let url = self.url("v1/coordination/events")?;
        let rb = self.http.get(url).query(&query);
        self.execute(rb, CallKind::Read).await
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use axum::response::IntoResponse;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tempfile::tempdir;

    use super::*;
    use crate::error::is_transient_http_status;
    use crate::{DEFAULT_TIMEOUT, TokenStore};

    fn endpoint(base_url: &str) -> RemoteEndpoint {
        RemoteEndpoint {
            name: "test-remote".to_owned(),
            base_url: base_url.to_owned(),
            token: None,
            oauth: None,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// Helper: build a client and return its normalised base URL string.
    fn base_url_str(raw: &str) -> String {
        let client = RemoteClient::new(endpoint(raw)).unwrap();
        client.base_url.to_string()
    }

    #[test]
    fn url_normalization_no_trailing_slash() {
        // Base without trailing slash — join must not clobber the host.
        let base = base_url_str("https://x.example");
        let url = reqwest::Url::parse(&base).unwrap().join("v1/info").unwrap();
        assert_eq!(url.as_str(), "https://x.example/v1/info");
    }

    #[test]
    fn url_normalization_with_trailing_slash() {
        // Base with trailing slash — same result.
        let base = base_url_str("https://x.example/");
        let url = reqwest::Url::parse(&base).unwrap().join("v1/info").unwrap();
        assert_eq!(url.as_str(), "https://x.example/v1/info");
    }

    #[test]
    fn url_normalization_sub_path() {
        // Reverse-proxy sub-path case — the sub-path must be preserved.
        let base = base_url_str("https://x.example/palace");
        let url = reqwest::Url::parse(&base).unwrap().join("v1/info").unwrap();
        assert_eq!(url.as_str(), "https://x.example/palace/v1/info");
    }

    #[test]
    fn invalid_url_returns_invalid_config() {
        let result = RemoteClient::new(endpoint("not a url"));
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), RemoteError::InvalidConfig { .. }));
    }

    #[test]
    fn is_degradable_unreachable_only() {
        let mk_name = || "r".to_owned();

        assert!(
            RemoteError::Unreachable { remote: mk_name(), message: "x".to_owned() }.is_degradable()
        );
        assert!(
            !RemoteError::Unauthorized { remote: mk_name(), resource_metadata: None }
                .is_degradable()
        );
        assert!(
            !RemoteError::VersionSkew { remote: mk_name(), ours: 1, theirs: 2 }.is_degradable()
        );
        assert!(
            !RemoteError::RemoteRejected { remote: mk_name(), status: 404, body: String::new() }
                .is_degradable()
        );
        assert!(
            !RemoteError::InvalidResponse { remote: mk_name(), message: "x".to_owned() }
                .is_degradable()
        );
        assert!(
            !RemoteError::InvalidConfig { remote: mk_name(), message: "x".to_owned() }
                .is_degradable()
        );
        assert!(
            !RemoteError::CapabilityMissing { remote: mk_name(), capability: "x".to_owned() }
                .is_degradable()
        );
        assert!(
            !RemoteError::UnknownOutcome { remote: mk_name(), message: "x".to_owned() }
                .is_degradable()
        );
    }

    #[test]
    fn outbox_classification_helpers() {
        let mk_name = || "r".to_owned();

        // Unreachable = definitely-not-sent, degradable, retryable-without-key.
        let unreachable = RemoteError::Unreachable { remote: mk_name(), message: "x".to_owned() };
        assert!(unreachable.is_unreachable_before_send());
        assert!(!unreachable.is_unknown_outcome());
        assert!(unreachable.is_retryable());
        assert!(!unreachable.is_terminal());

        // UnknownOutcome = only retryable-with-operation-id; never authoritative.
        let unknown = RemoteError::UnknownOutcome { remote: mk_name(), message: "x".to_owned() };
        assert!(!unknown.is_unreachable_before_send());
        assert!(unknown.is_unknown_outcome());
        assert!(unknown.is_retryable());
        assert!(!unknown.is_terminal());

        // Transient rejections (408/425/429/5xx) are retryable/non-terminal.
        for status in [408, 425, 429, 500, 502, 503, 599] {
            assert!(is_transient_http_status(status), "status {status} must be transient");
            let err =
                RemoteError::RemoteRejected { remote: mk_name(), status, body: String::new() };
            assert!(err.is_retryable(), "status {status} must be retryable");
            assert!(!err.is_terminal(), "status {status} must not be terminal");
        }
        // Ordinary 4xx are terminal/non-retryable.
        for status in [400, 403, 404, 409, 422] {
            assert!(!is_transient_http_status(status), "status {status} must not be transient");
            let err =
                RemoteError::RemoteRejected { remote: mk_name(), status, body: String::new() };
            assert!(!err.is_retryable(), "status {status} must not be retryable");
            assert!(err.is_terminal(), "status {status} must be terminal");
        }

        // Authoritative / config errors are terminal and never retryable.
        for err in [
            RemoteError::Unauthorized { remote: mk_name(), resource_metadata: None },
            RemoteError::VersionSkew { remote: mk_name(), ours: 1, theirs: 2 },
            RemoteError::InvalidResponse { remote: mk_name(), message: "x".to_owned() },
            RemoteError::InvalidConfig { remote: mk_name(), message: "x".to_owned() },
            RemoteError::CapabilityMissing { remote: mk_name(), capability: "c".to_owned() },
        ] {
            assert!(!err.is_retryable(), "unexpected retryable: {err:?}");
            assert!(err.is_terminal(), "unexpected non-terminal: {err:?}");
        }
    }

    #[test]
    fn client_url_helper_builds_correct_paths() {
        let client = RemoteClient::new(endpoint("https://x.example/palace")).unwrap();

        let info_url = client.url("v1/info").unwrap();
        assert_eq!(info_url.as_str(), "https://x.example/palace/v1/info");

        let search_url = client.url("v1/drawers/search").unwrap();
        assert_eq!(search_url.as_str(), "https://x.example/palace/v1/drawers/search");
    }

    #[test]
    fn drawer_url_uses_one_path_separator_and_encodes_the_id() {
        let client = RemoteClient::new(endpoint("https://x.example/palace")).unwrap();

        let url = client.drawer_url("wing/room/hash").unwrap();
        assert_eq!(url.as_str(), "https://x.example/palace/v1/drawers/wing%2Froom%2Fhash");
        assert!(!url.path().contains("//"));
    }

    #[test]
    fn default_timeout_is_five_seconds() {
        assert_eq!(DEFAULT_TIMEOUT, Duration::from_secs(5));
    }

    // ─── Mutation-outcome classification (issue #127, slice 2) ─────────────────

    fn client_for_addr(addr: std::net::SocketAddr, timeout: Duration) -> RemoteClient {
        RemoteClient::new(RemoteEndpoint {
            name: "test-remote".to_owned(),
            base_url: format!("http://{addr}"),
            token: None,
            oauth: None,
            timeout,
        })
        .unwrap()
    }

    async fn spawn_stub(app: axum::Router) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        addr
    }

    /// A stub that answers `GET /v1/info` correctly so the client handshake
    /// succeeds, and mounts `federation_api_version`-compatible info plus a
    /// caller-supplied handler on `POST /v1/drawers`.
    fn drawer_stub(drawers_post: axum::routing::MethodRouter<()>) -> axum::Router {
        axum::Router::new()
            .route(
                "/v1/info",
                axum::routing::get(|| async {
                    axum::Json(serde_json::json!({
                        "server_version": "1.0.0-stub",
                        "federation_api_version": 1u32,
                        "embedding_profile": "balanced",
                        "capabilities": ["drawers", "kg"]
                    }))
                }),
            )
            .route("/v1/drawers", drawers_post)
    }

    fn add_request() -> AddDrawerRequest {
        AddDrawerRequest {
            wing: "w".to_owned(),
            room: "r".to_owned(),
            content: "c".to_owned(),
            source_file: None,
            added_by: None,
            drawer_id: None,
            operation_id: None,
        }
    }

    #[tokio::test]
    async fn ingest_preflight_blocks_upload_but_preserves_legacy_and_receipt_replay() {
        for (capable, locator, durable, rejected) in [
            (true, true, false, true),
            (true, true, false, false),
            (false, true, false, true),
            (true, false, false, true),
            (true, true, true, true),
        ] {
            let uploads = Arc::new(AtomicUsize::new(0));
            let preflights = Arc::new(AtomicUsize::new(0));
            let upload_hits = Arc::clone(&uploads);
            let preflight_hits = Arc::clone(&preflights);
            let app = axum::Router::new()
                .route("/v1/info", axum::routing::get(move || async move {
                    axum::Json(serde_json::json!({"server_version":"test", "federation_api_version":1,
                        "embedding_profile":"balanced", "capabilities":if capable {
                            vec!["ingest", "ingest_preflight"] } else { vec!["ingest"] }}))
                }))
                .route("/v1/ingest/preflight", axum::routing::post(move |axum::Json(body): axum::Json<serde_json::Value>| {
                    let hits = Arc::clone(&preflight_hits);
                    async move {
                        hits.fetch_add(1, Ordering::SeqCst);
                        assert_eq!(body["files"][0]["relative_path"], "a.rs");
                        assert!(!body.to_string().contains("private source text"));
                        if rejected {
                            (axum::http::StatusCode::CONFLICT, axum::Json(serde_json::json!({
                                "code":"checkout_unavailable", "message":"remote checkout commit differs"})))
                        } else {
                            (axum::http::StatusCode::OK, axum::Json(serde_json::json!({"checkout_commit":null})))
                        }
                    }
                }))
                .route("/v1/ingest/batch", axum::routing::post(move || {
                    let hits = Arc::clone(&upload_hits);
                    async move {
                        hits.fetch_add(1, Ordering::SeqCst);
                        axum::Json(serde_json::json!({"files":[{"relative_path":"a.rs","status":"ingested"}]}))
                    }
                }));
            let addr = spawn_stub(app).await;
            let client = client_for_addr(addr, Duration::from_secs(5));
            let request = serde_json::from_value(serde_json::json!({
                "wing":"wing_test","repo_id":"repo", "replication":if durable {
                    serde_json::json!({"batch_id":"b","record_id":"r"}) } else { serde_json::Value::Null },
                "files":[{"relative_path":"a.rs", "content_hash":"h", "file_hash":if locator { Some("hash") } else {None},
                    "chunks":[{"chunk_index":0,"room":"general","text":"private source text"}]}]
            })).unwrap();
            let result = client.ingest_batch(request).await;
            let checked = capable && locator && !durable;
            assert_eq!(preflights.load(Ordering::SeqCst), usize::from(checked));
            if checked && rejected {
                assert!(matches!(result, Err(RemoteError::RemoteRejected { status: 409, .. })));
                assert_eq!(uploads.load(Ordering::SeqCst), 0);
            } else {
                assert!(result.is_ok(), "{result:?}");
                assert_eq!(uploads.load(Ordering::SeqCst), 1);
            }
        }
    }

    #[tokio::test]
    async fn mutation_send_timeout_is_unknown_outcome() {
        // The server receives the mutation (counter increments) and then hangs
        // longer than the client's per-request timeout: the write may well have
        // committed, but the client cannot confirm it. Must be `UnknownOutcome`,
        // never an authoritative failure.
        let hits = Arc::new(AtomicUsize::new(0));
        let server_hits = Arc::clone(&hits);
        let post = axum::routing::post(move || {
            let hits = Arc::clone(&server_hits);
            async move {
                hits.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_secs(30)).await;
                axum::Json(serde_json::json!({"success": true}))
            }
        });
        let addr = spawn_stub(drawer_stub(post)).await;
        let client = client_for_addr(addr, Duration::from_millis(300));

        let result = client.add_drawer(add_request()).await;
        match result {
            Err(err @ RemoteError::UnknownOutcome { .. }) => {
                assert!(err.is_unknown_outcome());
                assert!(!err.is_unreachable_before_send());
                assert!(err.is_retryable());
                assert!(!err.is_terminal());
            }
            other => panic!("expected UnknownOutcome on mutation timeout, got: {other:?}"),
        }
        assert!(
            hits.load(Ordering::SeqCst) >= 1,
            "the server must have received the mutation — that is the ambiguity UnknownOutcome exists to report"
        );
    }

    #[tokio::test]
    async fn mutation_connect_failure_is_unreachable_before_send() {
        // Nothing is listening: even the handshake cannot run, so the mutation
        // was definitely never sent — `Unreachable` (and degradable), never
        // `UnknownOutcome`. This also pins the rule that a dead handshake in
        // front of a mutation is "before send", not "unknown outcome".
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let client = client_for_addr(addr, Duration::from_secs(5));

        let result = client.add_drawer(add_request()).await;
        match result {
            Err(err @ RemoteError::Unreachable { .. }) => {
                assert!(err.is_unreachable_before_send());
                assert!(!err.is_unknown_outcome());
                assert!(err.is_degradable());
                assert!(err.is_retryable());
            }
            other => {
                panic!("expected Unreachable (before send) on connect failure, got: {other:?}")
            }
        }
    }

    #[tokio::test]
    async fn classify_connect_error_is_unreachable_for_mutations() {
        // Exercising `classify_send_error` directly against a real connect error
        // pins the mutation mapping (connect/DNS/build => definitely-not-sent ≡
        // `Unreachable`) without the handshake in the way.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let client = client_for_addr(addr, Duration::from_secs(5));

        let reqwest_err =
            client.http.get(format!("http://{addr}/v1/drawers")).send().await.unwrap_err();
        assert!(reqwest_err.is_connect(), "expected a connect error, got: {reqwest_err:?}");

        let classified = client.classify_send_error(CallKind::Mutation, reqwest_err);
        assert!(classified.is_unreachable_before_send(), "got: {classified:?}");
        assert!(!classified.is_unknown_outcome());
    }

    #[tokio::test]
    async fn mutation_authoritative_4xx_is_remote_rejected() {
        // The server responded 422: an authoritative rejection, terminal for an
        // outbox retry, and distinct from both `Unreachable` and `UnknownOutcome`.
        let post = axum::routing::post(|| async {
            (
                axum::http::StatusCode::UNPROCESSABLE_ENTITY,
                axum::Json(serde_json::json!({
                    "code": "invalid_params",
                    "message": "drawer rejected by stub"
                })),
            )
        });
        let addr = spawn_stub(drawer_stub(post)).await;
        let client = client_for_addr(addr, Duration::from_secs(5));

        let result = client.add_drawer(add_request()).await;
        match result {
            Err(err @ RemoteError::RemoteRejected { status: 422, .. }) => {
                assert!(err.is_terminal());
                assert!(!err.is_retryable());
                assert!(!err.is_degradable());
            }
            other => panic!("expected RemoteRejected(422), got: {other:?}"),
        }
    }

    /// A stub whose `POST /v1/drawers` returns a given status code with an
    /// [`agentpalace_federation::ErrorBody`]-shaped body.
    fn error_status_stub(status: axum::http::StatusCode) -> axum::Router {
        drawer_stub(axum::routing::post(move || {
            let status = status;
            async move { (status, axum::Json(serde_json::json!({"code": "x", "message": "x"}))) }
        }))
    }

    #[tokio::test]
    async fn mutation_transient_429_is_retryable() {
        // 429 Too Many Requests: the remote is reachable and understood the
        // request but is overloaded. An outbox must retry (same operation id),
        // so this must be retryable/non-terminal — not a permanent failure.
        let addr = spawn_stub(error_status_stub(axum::http::StatusCode::TOO_MANY_REQUESTS)).await;
        let client = client_for_addr(addr, Duration::from_secs(5));

        let result = client.add_drawer(add_request()).await;
        match result {
            Err(err @ RemoteError::RemoteRejected { status: 429, .. }) => {
                assert!(err.is_retryable(), "429 must be retryable");
                assert!(!err.is_terminal(), "429 must not be terminal");
            }
            other => panic!("expected RemoteRejected(429), got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn mutation_transient_503_is_retryable() {
        // 503 Service Unavailable: transient server overload/failure, retryable.
        let addr = spawn_stub(error_status_stub(axum::http::StatusCode::SERVICE_UNAVAILABLE)).await;
        let client = client_for_addr(addr, Duration::from_secs(5));

        let result = client.add_drawer(add_request()).await;
        match result {
            Err(err @ RemoteError::RemoteRejected { status: 503, .. }) => {
                assert!(err.is_retryable(), "503 must be retryable");
                assert!(!err.is_terminal(), "503 must not be terminal");
            }
            other => panic!("expected RemoteRejected(503), got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn classify_timeout_error_is_unknown_outcome_even_when_is_request() {
        // Pins the review rule: reqwest wraps a request timeout as `Kind::Request`
        // (`error::request(TimedOut)`), so `is_request()` is true for a response
        // that never arrived. For a mutation that must NOT count as pre-send
        // (`Unreachable`) — the timeout is exactly the ambiguous case and must
        // be `UnknownOutcome`.
        let hits = Arc::new(AtomicUsize::new(0));
        let server_hits = Arc::clone(&hits);
        let post = axum::routing::post(move || {
            let hits = Arc::clone(&server_hits);
            async move {
                hits.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_secs(30)).await;
                axum::Json(serde_json::json!({"success": true}))
            }
        });
        let addr = spawn_stub(drawer_stub(post)).await;
        let client = client_for_addr(addr, Duration::from_millis(300));

        let reqwest_err =
            client.http.post(format!("http://{addr}/v1/drawers")).send().await.unwrap_err();
        assert!(reqwest_err.is_timeout(), "expected a timeout error, got: {reqwest_err:?}");

        // The point of the review: `is_request()` alone is NOT proof of pre-send.
        assert!(
            reqwest_err.is_request(),
            "reqwest wraps this request timeout as Kind::Request (is_request), which is why is_request cannot prove pre-send"
        );

        let classified = client.classify_send_error(CallKind::Mutation, reqwest_err);
        assert!(
            classified.is_unknown_outcome(),
            "timeout with is_request()==true must be UnknownOutcome, got: {classified:?}"
        );
        assert!(!classified.is_unreachable_before_send());
        assert!(
            hits.load(Ordering::SeqCst) >= 1,
            "the server must have received the mutation — the ambiguity is why this is UnknownOutcome"
        );
    }

    #[tokio::test]
    async fn mutation_authoritative_401_is_unauthorized_terminal() {
        // 401 must stay its own distinct variant (never folded into
        // RemoteRejected) and be terminal — an outbox must not blind-retry a
        // rejected credential.
        let post = axum::routing::post(|| async {
            (
                axum::http::StatusCode::UNAUTHORIZED,
                axum::Json(serde_json::json!({"code": "unauthorized", "message": "nope"})),
            )
        });
        let addr = spawn_stub(drawer_stub(post)).await;
        let client = client_for_addr(addr, Duration::from_secs(5));

        let result = client.add_drawer(add_request()).await;
        match result {
            Err(err @ RemoteError::Unauthorized { .. }) => {
                assert!(err.is_terminal());
                assert!(!err.is_retryable());
            }
            other => panic!("expected Unauthorized, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn mutation_undecodable_2xx_is_unknown_outcome() {
        // A 2xx whose body we cannot decode: the server accepted the mutation,
        // but we cannot return the resulting payload. Never claim an
        // authoritative failure — surface `UnknownOutcome`.
        let post = axum::routing::post(|| async { "this is not json" });
        let addr = spawn_stub(drawer_stub(post)).await;
        let client = client_for_addr(addr, Duration::from_secs(5));

        let result = client.add_drawer(add_request()).await;
        match result {
            Err(err @ RemoteError::UnknownOutcome { .. }) => {
                assert!(err.is_unknown_outcome());
                assert!(err.is_retryable());
            }
            other => panic!("expected UnknownOutcome on undecodable 2xx mutation, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn read_undecodable_2xx_stays_invalid_response() {
        // Reads keep the historical behaviour: an undecodable 2xx is
        // `InvalidResponse`, not `UnknownOutcome`.
        let search_post = axum::routing::post(|| async { "this is not json" });
        let app = axum::Router::new()
            .route(
                "/v1/info",
                axum::routing::get(|| async {
                    axum::Json(serde_json::json!({
                        "server_version": "1.0.0-stub",
                        "federation_api_version": 1u32,
                        "embedding_profile": "balanced",
                        "capabilities": ["drawers", "kg"]
                    }))
                }),
            )
            .route("/v1/drawers/search", search_post);
        let addr = spawn_stub(app).await;
        let client = client_for_addr(addr, Duration::from_secs(5));

        let result = client
            .search_drawers(DrawerSearchRequest {
                query: "q".to_owned(),
                wing: None,
                room: None,
                view: None,
                limit: None,
            })
            .await;
        match result {
            Err(err @ RemoteError::InvalidResponse { .. }) => {
                assert!(err.is_terminal());
                assert!(!err.is_retryable());
            }
            other => panic!("expected InvalidResponse for undecodable read, got: {other:?}"),
        }
    }

    // ── OAuth grant lifecycle ────────────────────────────────────────────────

    fn oauth_endpoint(base_url: &str, store: crate::SharedTokenStore) -> RemoteEndpoint {
        RemoteEndpoint {
            name: "oauth-test-remote".to_owned(),
            base_url: base_url.to_owned(),
            token: None,
            oauth: Some(crate::OAuthConfig {
                client_id: "test-client".to_owned(),
                account: Some("test-account".to_owned()),
                allow_in_memory: false,
                allow_loopback_demo: true,
                login_mode: agentpalace_config::OAuthLoginMode::Device,
                token_store: Some(store),
                interaction: None,
                login_timeout_seconds: 5,
            }),
            timeout: DEFAULT_TIMEOUT,
        }
    }

    fn oauth_session(resource: &str, issuer: &str, access_token: &str) -> crate::OAuthSession {
        crate::OAuthSession {
            access_token: access_token.to_owned(),
            refresh_token: Some(format!("{access_token}-refresh")),
            expires_at: None,
            resource: resource.to_owned(),
            issuer: issuer.to_owned(),
            client_id: "test-client".to_owned(),
            account: Some("test-account".to_owned()),
        }
    }

    async fn stored_token(store: &dyn TokenStore, resource: &str, issuer: &str) -> Option<String> {
        store
            .load(resource, issuer, "test-client", Some("test-account"))
            .await
            .expect("store load")
            .map(|session| session.access_token)
    }

    /// A store whose every operation outcome is scripted, for deterministic failure cases that
    /// never touch a real OS credential store.
    #[derive(Debug, Default)]
    struct ScriptedStore {
        inner: crate::InMemoryTokenStore,
        load_error: std::sync::Mutex<Option<crate::TokenStoreError>>,
        save_error: std::sync::Mutex<Option<crate::TokenStoreError>>,
        clear_error: std::sync::Mutex<Option<crate::TokenStoreError>>,
    }

    impl ScriptedStore {
        fn fail(
            slot: &std::sync::Mutex<Option<crate::TokenStoreError>>,
            error: crate::TokenStoreError,
        ) {
            *slot.lock().expect("script lock") = Some(error);
        }

        fn scripted(
            slot: &std::sync::Mutex<Option<crate::TokenStoreError>>,
        ) -> std::result::Result<(), crate::TokenStoreError> {
            slot.lock().expect("script lock").clone().map_or(Ok(()), Err)
        }
    }

    #[async_trait::async_trait]
    impl crate::TokenStore for ScriptedStore {
        async fn load(
            &self,
            resource: &str,
            issuer: &str,
            client_id: &str,
            account: Option<&str>,
        ) -> std::result::Result<Option<crate::OAuthSession>, crate::TokenStoreError> {
            Self::scripted(&self.load_error)?;
            self.inner.load(resource, issuer, client_id, account).await
        }

        async fn save(
            &self,
            session: crate::OAuthSession,
        ) -> std::result::Result<(), crate::TokenStoreError> {
            Self::scripted(&self.save_error)?;
            self.inner.save(session).await
        }

        async fn clear(
            &self,
            resource: &str,
            issuer: &str,
            client_id: &str,
            account: Option<&str>,
        ) -> std::result::Result<crate::ClearOutcome, crate::TokenStoreError> {
            Self::scripted(&self.clear_error)?;
            self.inner.clear(resource, issuer, client_id, account).await
        }
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum RefreshBehaviour {
        Rotate,
        Reject,
        Unavailable,
    }

    /// A minimal issuer + protected resource. `/v1/info` accepts only tokens in `valid`;
    /// `/v1/drawers` (a mutation) always answers 401. Every endpoint counts its hits.
    #[derive(Clone)]
    struct MockIssuer {
        base: String,
        valid: Arc<std::sync::Mutex<Vec<String>>>,
        reject_all: Arc<std::sync::atomic::AtomicBool>,
        refresh: Arc<std::sync::Mutex<RefreshBehaviour>>,
        challenge_metadata: bool,
        info_hits: Arc<AtomicUsize>,
        token_hits: Arc<AtomicUsize>,
        revoke_hits: Arc<AtomicUsize>,
        mutation_hits: Arc<AtomicUsize>,
        /// Tokens the mutation routes refuse although `/v1/info` accepts them.
        mutation_rejects: Arc<std::sync::Mutex<Vec<String>>>,
        mutation_reject_all: Arc<std::sync::atomic::AtomicBool>,
        /// Milliseconds a mutation route waits before answering (to force a client timeout).
        mutation_delay_ms: Arc<std::sync::atomic::AtomicU64>,
        /// `(bearer, body)` of every mutation request, in order.
        mutation_requests: Arc<std::sync::Mutex<Vec<(Option<String>, serde_json::Value)>>>,
        bearers: Arc<std::sync::Mutex<Vec<Option<String>>>>,
        /// When set, the protected-resource metadata handler waits for this before answering.
        metadata_gate: Arc<std::sync::Mutex<Option<Arc<tokio::sync::Notify>>>>,
        metadata_entered: Arc<tokio::sync::Notify>,
    }

    impl MockIssuer {
        async fn start(challenge_metadata: bool) -> (Self, tokio::task::JoinHandle<()>) {
            let listener =
                tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("mock listener");
            let base = format!("http://{}", listener.local_addr().expect("mock address"));
            let mock = Self {
                base,
                valid: Arc::default(),
                reject_all: Arc::default(),
                refresh: Arc::new(std::sync::Mutex::new(RefreshBehaviour::Rotate)),
                challenge_metadata,
                info_hits: Arc::default(),
                token_hits: Arc::default(),
                revoke_hits: Arc::default(),
                mutation_hits: Arc::default(),
                mutation_rejects: Arc::default(),
                mutation_reject_all: Arc::default(),
                mutation_delay_ms: Arc::default(),
                mutation_requests: Arc::default(),
                bearers: Arc::default(),
                metadata_gate: Arc::default(),
                metadata_entered: Arc::default(),
            };
            let app = axum::Router::new()
                .route("/.well-known/oauth-protected-resource", axum::routing::get(Self::protected))
                .route("/.well-known/oauth-authorization-server", axum::routing::get(Self::server))
                .route("/token", axum::routing::post(Self::token))
                .route("/revoke", axum::routing::post(Self::revoke))
                .route("/v1/info", axum::routing::get(Self::info))
                .route("/v1/drawers", axum::routing::post(Self::add_drawer))
                .route("/v1/coordination/tasks/{id}/claim", axum::routing::post(Self::claim))
                .with_state(mock.clone());
            let task = tokio::spawn(async move {
                axum::serve(listener, app).await.expect("mock server");
            });
            (mock, task)
        }

        fn resource(&self) -> String {
            format!("{}/", self.base)
        }

        fn accept(&self, token: &str) {
            self.valid.lock().expect("valid tokens").push(token.to_owned());
        }

        fn set_refresh(&self, behaviour: RefreshBehaviour) {
            *self.refresh.lock().expect("refresh behaviour") = behaviour;
        }

        fn metadata(&self) -> crate::AuthorizationServerMetadata {
            crate::AuthorizationServerMetadata {
                issuer: self.base.clone(),
                authorization_endpoint: format!("{}/authorize", self.base),
                token_endpoint: format!("{}/token", self.base),
                revocation_endpoint: Some(format!("{}/revoke", self.base)),
                device_authorization_endpoint: None,
            }
        }

        async fn protected(
            axum::extract::State(mock): axum::extract::State<Self>,
        ) -> axum::response::Response {
            let gate = mock.metadata_gate.lock().expect("gate").clone();
            if let Some(gate) = gate {
                mock.metadata_entered.notify_one();
                gate.notified().await;
            }
            axum::Json(serde_json::json!({"resource": mock.resource(), "authorization_servers": [mock.base]})).into_response()
        }

        async fn server(
            axum::extract::State(mock): axum::extract::State<Self>,
        ) -> axum::response::Response {
            let metadata = mock.metadata();
            axum::Json(serde_json::json!({
                "issuer": metadata.issuer, "authorization_endpoint": metadata.authorization_endpoint,
                "token_endpoint": metadata.token_endpoint, "revocation_endpoint": metadata.revocation_endpoint,
            }))
            .into_response()
        }

        async fn token(
            axum::extract::State(mock): axum::extract::State<Self>,
        ) -> axum::response::Response {
            let n = mock.token_hits.fetch_add(1, Ordering::SeqCst) + 1;
            match *mock.refresh.lock().expect("refresh behaviour") {
                RefreshBehaviour::Rotate => {
                    let access = format!("refreshed-{n}");
                    mock.accept(&access);
                    axum::Json(serde_json::json!({"access_token": access, "refresh_token": format!("rotated-{n}"), "token_type": "Bearer", "expires_in": 900})).into_response()
                }
                RefreshBehaviour::Reject => (
                    axum::http::StatusCode::BAD_REQUEST,
                    axum::Json(serde_json::json!({"error": "invalid_grant"})),
                )
                    .into_response(),
                RefreshBehaviour::Unavailable => {
                    axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response()
                }
            }
        }

        async fn revoke(
            axum::extract::State(mock): axum::extract::State<Self>,
        ) -> axum::http::StatusCode {
            mock.revoke_hits.fetch_add(1, Ordering::SeqCst);
            axum::http::StatusCode::OK
        }

        fn bearer(headers: &axum::http::HeaderMap) -> Option<String> {
            headers
                .get(axum::http::header::AUTHORIZATION)?
                .to_str()
                .ok()?
                .strip_prefix("Bearer ")
                .map(str::to_owned)
        }

        fn challenge(&self) -> axum::response::Response {
            let value = if self.challenge_metadata {
                format!(
                    "Bearer error=\"invalid_token\", resource_metadata=\"{}/.well-known/oauth-protected-resource\"",
                    self.base
                )
            } else {
                "Bearer error=\"invalid_token\"".to_owned()
            };
            (
                axum::http::StatusCode::UNAUTHORIZED,
                [(axum::http::header::WWW_AUTHENTICATE, value)],
                "unauthorized",
            )
                .into_response()
        }

        async fn info(
            axum::extract::State(mock): axum::extract::State<Self>,
            headers: axum::http::HeaderMap,
        ) -> axum::response::Response {
            mock.info_hits.fetch_add(1, Ordering::SeqCst);
            let bearer = Self::bearer(&headers);
            mock.bearers.lock().expect("bearers").push(bearer.clone());
            if !mock.reject_all.load(Ordering::SeqCst)
                && bearer
                    .is_some_and(|token| mock.valid.lock().expect("valid tokens").contains(&token))
            {
                axum::Json(serde_json::json!({"server_version":"test","federation_api_version":1u32,"embedding_profile":"balanced","capabilities":["coordination"]})).into_response()
            } else {
                mock.challenge()
            }
        }

        /// Record a mutation and return the 401 challenge if its bearer is refused.
        async fn mutation_refusal(
            &self,
            headers: &axum::http::HeaderMap,
            body: &[u8],
        ) -> Option<axum::response::Response> {
            self.mutation_hits.fetch_add(1, Ordering::SeqCst);
            let bearer = Self::bearer(headers);
            let body = serde_json::from_slice(body).unwrap_or(serde_json::Value::Null);
            self.mutation_requests.lock().expect("mutation requests").push((bearer.clone(), body));
            let delay = self.mutation_delay_ms.load(Ordering::SeqCst);
            if delay > 0 {
                tokio::time::sleep(Duration::from_millis(delay)).await;
            }
            let accepted = !self.mutation_reject_all.load(Ordering::SeqCst)
                && bearer.is_some_and(|token| {
                    self.valid.lock().expect("valid tokens").contains(&token)
                        && !self.mutation_rejects.lock().expect("mutation rejects").contains(&token)
                });
            (!accepted).then(|| self.challenge())
        }

        async fn add_drawer(
            axum::extract::State(mock): axum::extract::State<Self>,
            headers: axum::http::HeaderMap,
            body: axum::body::Bytes,
        ) -> axum::response::Response {
            if let Some(refusal) = mock.mutation_refusal(&headers, &body).await {
                return refusal;
            }
            axum::Json(serde_json::json!({"success": true, "drawer_id": "drawer-1", "wing": "wing", "room": "room"})).into_response()
        }

        /// A revisioned coordination write; an accepted request answers with a revision conflict,
        /// which the client decodes without needing a full task DTO.
        async fn claim(
            axum::extract::State(mock): axum::extract::State<Self>,
            headers: axum::http::HeaderMap,
            body: axum::body::Bytes,
        ) -> axum::response::Response {
            if let Some(refusal) = mock.mutation_refusal(&headers, &body).await {
                return refusal;
            }
            (
                axum::http::StatusCode::CONFLICT,
                axum::Json(serde_json::json!({"code": "revision_conflict", "message": "stale", "actual_revision": 7})),
            )
                .into_response()
        }
    }

    /// A client for `mock` holding `session` in-process and in `store`.
    async fn signed_in_client(
        mock: &MockIssuer,
        store: Arc<dyn TokenStore>,
        access: &str,
    ) -> RemoteClient {
        store.save(oauth_session(&mock.resource(), &mock.base, access)).await.expect("seed store");
        let client = RemoteClient::new(oauth_endpoint(&mock.base, store)).expect("client");
        assert!(client.load_stored_session(&mock.base).await.expect("load stored session"));
        client
    }

    fn oauth_add_request() -> AddDrawerRequest {
        AddDrawerRequest {
            wing: "wing".to_owned(),
            room: "room".to_owned(),
            content: "content".to_owned(),
            source_file: None,
            added_by: None,
            drawer_id: None,
            operation_id: None,
        }
    }

    #[tokio::test]
    async fn stored_session_reloads_into_a_new_remote_client_under_the_exact_resource() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("oauth.json");
        let store: Arc<dyn TokenStore> = Arc::new(crate::FileTokenStore::new(&path));
        store
            .save(oauth_session(
                "https://hub.example/",
                "https://issuer.example",
                "persisted-access",
            ))
            .await
            .unwrap();

        // A different process (a second client over a fresh handle to the same file).
        let second = RemoteClient::new(oauth_endpoint(
            "https://hub.example",
            Arc::new(crate::FileTokenStore::new(&path)),
        ))
        .unwrap();
        assert!(second.load_stored_session("https://issuer.example").await.unwrap());
        assert_eq!(second.token.lock().await.as_deref(), Some("persisted-access"));
        // A path resource never matches the root resource's record.
        let path_client =
            RemoteClient::new(oauth_endpoint("https://hub.example/api", store)).unwrap();
        assert!(!path_client.load_stored_session("https://issuer.example").await.unwrap());
    }

    #[tokio::test]
    async fn store_load_failures_are_distinct_from_absence() {
        for kind in [
            crate::TokenStoreErrorKind::Unavailable,
            crate::TokenStoreErrorKind::Corrupt,
            crate::TokenStoreErrorKind::Backend,
        ] {
            let store = Arc::new(ScriptedStore::default());
            ScriptedStore::fail(
                &store.load_error,
                crate::TokenStoreError { kind, message: "scripted".to_owned() },
            );
            let client =
                RemoteClient::new(oauth_endpoint("https://hub.example/api", store)).unwrap();
            match client.load_stored_session("https://issuer.example").await {
                Err(RemoteError::CredentialStore { kind: reported, .. }) => {
                    assert_eq!(reported, kind)
                }
                other => panic!("expected a {kind} credential-store error, got {other:?}"),
            }
        }
        let absent = RemoteClient::new(oauth_endpoint(
            "https://hub.example/api",
            Arc::new(ScriptedStore::default()),
        ))
        .unwrap();
        assert!(!absent.load_stored_session("https://issuer.example").await.unwrap());
        // The unavailable store never reports "no credential".
        let unavailable = RemoteClient::new(oauth_endpoint(
            "https://hub.example/api",
            Arc::new(crate::UnavailableTokenStore),
        ))
        .unwrap();
        assert!(matches!(
            unavailable.load_stored_session("https://issuer.example").await,
            Err(RemoteError::CredentialStore { kind: crate::TokenStoreErrorKind::Unavailable, .. })
        ));
    }

    #[tokio::test]
    async fn logout_reports_removed_absent_and_delete_failure() {
        let store = Arc::new(ScriptedStore::default());
        store
            .save(oauth_session("https://hub.example/api", "https://issuer.example", "access"))
            .await
            .unwrap();
        let client =
            RemoteClient::new(oauth_endpoint("https://hub.example/api", store.clone())).unwrap();
        assert!(client.load_stored_session("https://issuer.example").await.unwrap());
        let removed = client.logout(None, None).await.unwrap();
        assert_eq!(removed.store, crate::ClearOutcome::Removed);
        assert_eq!(removed.revocation, RevocationOutcome::Unsupported);
        let absent = client.logout(Some("https://issuer.example"), None).await.unwrap();
        assert_eq!(
            absent,
            LogoutOutcome {
                store: crate::ClearOutcome::Absent,
                revocation: RevocationOutcome::NoCredential
            }
        );

        store
            .save(oauth_session("https://hub.example/api", "https://issuer.example", "access"))
            .await
            .unwrap();
        assert!(client.load_stored_session("https://issuer.example").await.unwrap());
        ScriptedStore::fail(
            &store.clear_error,
            crate::TokenStoreError::backend("scripted delete failure"),
        );
        match client.logout(None, None).await {
            Err(RemoteError::CredentialStore {
                kind: crate::TokenStoreErrorKind::Backend, ..
            }) => {}
            other => panic!("expected a propagated delete failure, got {other:?}"),
        }
        assert!(
            client.token.lock().await.is_none(),
            "the in-process grant is dropped even when deletion fails"
        );
        assert!(client.oauth_session.lock().await.is_none());
    }

    #[tokio::test]
    async fn persistence_failure_is_reported_and_the_new_grant_stays_in_process() {
        let store = Arc::new(ScriptedStore::default());
        store
            .save(oauth_session("https://hub.example/", "https://issuer.example", "stale-access"))
            .await
            .unwrap();
        let client =
            RemoteClient::new(oauth_endpoint("https://hub.example", store.clone())).unwrap();
        assert!(client.load_stored_session("https://issuer.example").await.unwrap());
        ScriptedStore::fail(
            &store.save_error,
            crate::TokenStoreError::unavailable("scripted keychain locked"),
        );
        let _guard = client.login_lock.lock().await;
        let error = client
            .commit_locked(oauth_session(
                "https://hub.example/",
                "https://issuer.example",
                "fresh-access",
            ))
            .await
            .expect_err("save failure must be explicit");
        assert!(matches!(
            error,
            RemoteError::CredentialStore { kind: crate::TokenStoreErrorKind::Unavailable, .. }
        ));
        assert_eq!(client.token.lock().await.as_deref(), Some("fresh-access"));
        assert_eq!(
            stored_token(&store.inner, "https://hub.example/", "https://issuer.example")
                .await
                .as_deref(),
            Some("stale-access")
        );
    }

    #[tokio::test]
    async fn unexpired_rejected_grant_refreshes_once_using_the_grant_issuer_without_challenge_metadata()
     {
        let (mock, task) = MockIssuer::start(false).await;
        let store: Arc<dyn TokenStore> = Arc::new(crate::InMemoryTokenStore::default());
        // Unexpired locally, but the resource no longer accepts it; no trusted metadata yet and
        // the challenge carries no resource_metadata.
        let client = signed_in_client(&mock, store.clone(), "server-rejected").await;
        let info = client.info().await.expect("recovered read");
        assert_eq!(info.federation_api_version, 1);
        assert_eq!(
            mock.info_hits.load(Ordering::SeqCst),
            2,
            "one rejected attempt and exactly one retry"
        );
        assert_eq!(mock.token_hits.load(Ordering::SeqCst), 1, "exactly one forced refresh");
        assert_eq!(
            stored_token(store.as_ref(), &mock.resource(), &mock.base).await.as_deref(),
            Some("refreshed-1")
        );
        task.abort();
    }

    #[tokio::test]
    async fn persistent_rejection_is_bounded_to_one_refresh_and_one_retry() {
        let (mock, task) = MockIssuer::start(true).await;
        // The issuer rotates happily, but the resource never accepts anything.
        let store: Arc<dyn TokenStore> = Arc::new(crate::InMemoryTokenStore::default());
        let client = signed_in_client(&mock, store, "server-rejected").await;
        mock.reject_all.store(true, Ordering::SeqCst);
        let refused = client.info().await;
        assert!(matches!(
            refused,
            Err(RemoteError::Unauthorized { .. }) | Err(RemoteError::AuthenticationRequired { .. })
        ));
        assert_eq!(mock.info_hits.load(Ordering::SeqCst), 2);
        assert_eq!(mock.token_hits.load(Ordering::SeqCst), 1);
        task.abort();
    }

    #[tokio::test]
    async fn grant_rotated_by_another_process_is_adopted_without_refreshing() {
        let (mock, task) = MockIssuer::start(true).await;
        let store: Arc<dyn TokenStore> = Arc::new(crate::InMemoryTokenStore::default());
        let client = signed_in_client(&mock, store.clone(), "old-access").await;
        // Another process logged in again and replaced the stored grant.
        store
            .save(oauth_session(&mock.resource(), &mock.base, "other-process-access"))
            .await
            .unwrap();
        mock.accept("other-process-access");
        client.info().await.expect("adopted grant");
        assert_eq!(
            mock.token_hits.load(Ordering::SeqCst),
            0,
            "a rotated grant must not be refreshed again"
        );
        assert_eq!(client.token.lock().await.as_deref(), Some("other-process-access"));
        task.abort();
    }

    #[tokio::test]
    async fn grant_removed_by_another_process_is_forgotten_not_refreshed() {
        let (mock, task) = MockIssuer::start(true).await;
        let store: Arc<dyn TokenStore> = Arc::new(crate::InMemoryTokenStore::default());
        let client = signed_in_client(&mock, store.clone(), "old-access").await;
        assert_eq!(
            store.clear(&mock.resource(), &mock.base, "test-client", Some("test-account")).await,
            Ok(crate::ClearOutcome::Removed)
        );
        assert!(matches!(client.info().await, Err(RemoteError::AuthenticationRequired { .. })));
        assert_eq!(mock.token_hits.load(Ordering::SeqCst), 0);
        assert!(client.oauth_session.lock().await.is_none());
        task.abort();
    }

    #[tokio::test]
    async fn rejected_refresh_clears_the_grant_but_a_transient_failure_keeps_it() {
        let (mock, task) = MockIssuer::start(true).await;
        let store: Arc<dyn TokenStore> = Arc::new(crate::InMemoryTokenStore::default());
        let client = signed_in_client(&mock, store.clone(), "server-rejected").await;

        mock.set_refresh(RefreshBehaviour::Unavailable);
        assert!(
            matches!(client.info().await, Err(RemoteError::Unreachable { .. })),
            "an unreachable issuer is not a sign-out"
        );
        assert_eq!(
            stored_token(store.as_ref(), &mock.resource(), &mock.base).await.as_deref(),
            Some("server-rejected")
        );
        assert!(client.oauth_session.lock().await.is_some());

        mock.set_refresh(RefreshBehaviour::Reject);
        assert!(matches!(client.info().await, Err(RemoteError::AuthenticationRequired { .. })));
        assert_eq!(stored_token(store.as_ref(), &mock.resource(), &mock.base).await, None);
        assert!(client.token.lock().await.is_none());
        assert!(client.oauth_session.lock().await.is_none());
        task.abort();
    }

    #[tokio::test]
    async fn rejected_mutation_is_recovered_and_replayed_once_with_the_same_operation() {
        let (mock, task) = MockIssuer::start(true).await;
        let store: Arc<dyn TokenStore> = Arc::new(crate::InMemoryTokenStore::default());
        let client = signed_in_client(&mock, store, "old-access").await;
        // Reads still accept the old token; the write path rejects it with a definite 401.
        mock.accept("old-access");
        mock.mutation_rejects.lock().expect("rejects").push("old-access".to_owned());
        let mut request = oauth_add_request();
        request.operation_id = Some("op-stable-1".to_owned());
        request.drawer_id = Some("drawer-1".to_owned());

        let response = client.add_drawer(request).await.expect("replayed mutation succeeds");
        assert_eq!(response.drawer_id.as_deref(), Some("drawer-1"));
        assert_eq!(
            mock.mutation_hits.load(Ordering::SeqCst),
            2,
            "one rejected attempt and one replay"
        );
        assert_eq!(mock.token_hits.load(Ordering::SeqCst), 1, "one forced refresh");
        let requests = mock.mutation_requests.lock().expect("requests").clone();
        assert_eq!(requests[0].0.as_deref(), Some("old-access"));
        assert_eq!(requests[1].0.as_deref(), Some("refreshed-1"));
        assert_eq!(requests[0].1, requests[1].1, "the replay carries the identical body");
        assert_eq!(requests[1].1["operation_id"], "op-stable-1", "the operation id is preserved");
        task.abort();
    }

    #[tokio::test]
    async fn rejected_revisioned_write_is_replayed_once_with_the_same_body() {
        let (mock, task) = MockIssuer::start(true).await;
        let store: Arc<dyn TokenStore> = Arc::new(crate::InMemoryTokenStore::default());
        let client = signed_in_client(&mock, store, "old-access").await;
        mock.accept("old-access");
        mock.mutation_rejects.lock().expect("rejects").push("old-access".to_owned());
        let lease = TaskLeaseRequest {
            expected_revision: 3,
            lease_seconds: 60,
            worker: Some("worker".to_owned()),
        };

        let outcome =
            client.coordination_task_claim("task-1", lease).await.expect("replayed claim");
        assert!(matches!(outcome, RemoteRevisionedWrite::Conflict { actual_revision: Some(7) }));
        assert_eq!(mock.mutation_hits.load(Ordering::SeqCst), 2);
        let requests = mock.mutation_requests.lock().expect("requests").clone();
        assert_eq!(requests[0].1, requests[1].1);
        assert_eq!(requests[1].1["expected_revision"], 3);
        task.abort();
    }

    #[tokio::test]
    async fn persistently_rejected_mutation_is_replayed_at_most_once() {
        let (mock, task) = MockIssuer::start(true).await;
        let store: Arc<dyn TokenStore> = Arc::new(crate::InMemoryTokenStore::default());
        let client = signed_in_client(&mock, store, "access").await;
        mock.accept("access");
        mock.mutation_reject_all.store(true, Ordering::SeqCst);
        let result = client.add_drawer(oauth_add_request()).await;
        assert!(matches!(result, Err(RemoteError::AuthenticationRequired { .. })), "{result:?}");
        assert_eq!(mock.mutation_hits.load(Ordering::SeqCst), 2, "never more than one replay");
        assert_eq!(mock.token_hits.load(Ordering::SeqCst), 1);
        task.abort();
    }

    #[tokio::test]
    async fn mutation_with_an_unknown_outcome_is_never_replayed() {
        let (mock, task) = MockIssuer::start(true).await;
        let store: Arc<dyn TokenStore> = Arc::new(crate::InMemoryTokenStore::default());
        store
            .save(oauth_session(&mock.resource(), &mock.base, "access"))
            .await
            .expect("seed store");
        let mut endpoint = oauth_endpoint(&mock.base, store);
        endpoint.timeout = Duration::from_millis(400);
        let client = RemoteClient::new(endpoint).expect("client");
        assert!(client.load_stored_session(&mock.base).await.expect("stored session"));
        mock.accept("access");
        client.info().await.expect("handshake");
        // The write reaches the server but no response arrives before the client times out.
        mock.mutation_delay_ms.store(1_500, Ordering::SeqCst);
        let result = client.add_drawer(oauth_add_request()).await;
        assert!(matches!(result, Err(RemoteError::UnknownOutcome { .. })), "{result:?}");
        tokio::time::sleep(Duration::from_millis(1_600)).await;
        assert_eq!(
            mock.mutation_hits.load(Ordering::SeqCst),
            1,
            "an unconfirmed write is not re-sent"
        );
        assert_eq!(mock.token_hits.load(Ordering::SeqCst), 0);
        task.abort();
    }

    #[tokio::test]
    async fn expiring_grant_is_refreshed_before_a_mutation_is_sent() {
        let (mock, task) = MockIssuer::start(true).await;
        let store: Arc<dyn TokenStore> = Arc::new(crate::InMemoryTokenStore::default());
        let mut expiring = oauth_session(&mock.resource(), &mock.base, "expiring");
        expiring.expires_at = Some(crate::oauth::now_seconds());
        store.save(expiring).await.unwrap();
        let client = RemoteClient::new(oauth_endpoint(&mock.base, store)).unwrap();
        client
            .discover(&format!("{}/.well-known/oauth-protected-resource", mock.base))
            .await
            .expect("trusted discovery");
        assert!(client.load_stored_session(&mock.base).await.unwrap());
        mock.accept("expiring");
        let _ = client.add_drawer(oauth_add_request()).await;
        assert_eq!(
            mock.token_hits.load(Ordering::SeqCst),
            1,
            "the refresh happens before the request is sent"
        );
        assert_eq!(client.token.lock().await.as_deref(), Some("refreshed-1"));
        task.abort();
    }

    #[tokio::test]
    async fn delayed_recovery_racing_logout_cannot_resurrect_the_session() {
        let (mock, task) = MockIssuer::start(true).await;
        let store: Arc<dyn TokenStore> = Arc::new(crate::InMemoryTokenStore::default());
        let client = Arc::new(signed_in_client(&mock, store.clone(), "server-rejected").await);

        // Hold recovery inside discovery: it has observed the 401 but not yet reloaded.
        let gate = Arc::new(tokio::sync::Notify::new());
        *mock.metadata_gate.lock().expect("gate") = Some(gate.clone());
        let reader = {
            let client = Arc::clone(&client);
            tokio::spawn(async move { client.info().await })
        };
        mock.metadata_entered.notified().await;

        // Logout completes while recovery is suspended.
        let outcome = client.logout(None, None).await.expect("logout");
        assert_eq!(outcome.store, crate::ClearOutcome::Removed);
        // A stale copy reappears in the store (for example a slow concurrent writer); recovery
        // must still not adopt or refresh it.
        store.save(oauth_session(&mock.resource(), &mock.base, "stale-copy")).await.unwrap();
        mock.accept("stale-copy");
        *mock.metadata_gate.lock().expect("gate") = None;
        gate.notify_one();

        let result = reader.await.expect("reader task");
        assert!(matches!(result, Err(RemoteError::AuthenticationRequired { .. })), "{result:?}");
        assert_eq!(mock.token_hits.load(Ordering::SeqCst), 0, "no refresh after logout");
        assert!(client.token.lock().await.is_none());
        assert!(client.oauth_session.lock().await.is_none());
        // Later background reads stay signed out too.
        assert!(client.info().await.is_err());
        assert_eq!(
            mock.bearers.lock().expect("bearers").last().cloned(),
            Some(None),
            "no credential is sent after logout"
        );
        task.abort();
    }

    #[tokio::test]
    async fn failed_delete_on_logout_does_not_let_recovery_reload_the_surviving_record() {
        let (mock, task) = MockIssuer::start(true).await;
        let store = Arc::new(ScriptedStore::default());
        let client = signed_in_client(&mock, store.clone(), "access").await;
        ScriptedStore::fail(
            &store.clear_error,
            crate::TokenStoreError::backend("scripted delete failure"),
        );
        assert!(matches!(
            client.logout(None, Some(&mock.metadata())).await,
            Err(RemoteError::CredentialStore { .. })
        ));
        assert_eq!(
            mock.revoke_hits.load(Ordering::SeqCst),
            1,
            "revocation is attempted before the local delete"
        );
        mock.accept("access");
        assert!(
            client.info().await.is_err(),
            "the surviving record must not be reloaded by background recovery"
        );
        assert_eq!(mock.token_hits.load(Ordering::SeqCst), 0);
        // An explicit load is a deliberate user action and does reload it.
        assert!(client.load_stored_session(&mock.base).await.unwrap());
        client.info().await.expect("explicitly reloaded grant");
        task.abort();
    }

    #[tokio::test]
    async fn logout_clears_the_exact_resource_record_for_both_slash_forms() {
        let store: Arc<dyn TokenStore> = Arc::new(crate::InMemoryTokenStore::default());
        store
            .save(oauth_session("https://hub.example/api", "https://issuer.example", "no-slash"))
            .await
            .unwrap();
        store
            .save(oauth_session("https://hub.example/api/", "https://issuer.example", "slash"))
            .await
            .unwrap();

        let client =
            RemoteClient::new(oauth_endpoint("https://hub.example/api", store.clone())).unwrap();
        assert_eq!(client.oauth_resource(), "https://hub.example/api");
        assert_eq!(
            client.base_url(),
            "https://hub.example/api/",
            "transport base is normalized separately"
        );
        let outcome = client.logout(Some("https://issuer.example"), None).await.unwrap();
        assert_eq!(outcome.store, crate::ClearOutcome::Removed);
        assert_eq!(
            stored_token(store.as_ref(), "https://hub.example/api", "https://issuer.example").await,
            None
        );
        assert_eq!(
            stored_token(store.as_ref(), "https://hub.example/api/", "https://issuer.example")
                .await
                .as_deref(),
            Some("slash")
        );

        let slash_client =
            RemoteClient::new(oauth_endpoint("https://hub.example/api/", store.clone())).unwrap();
        assert_eq!(slash_client.oauth_resource(), "https://hub.example/api/");
        assert_eq!(
            slash_client.logout(Some("https://issuer.example"), None).await.unwrap().store,
            crate::ClearOutcome::Removed
        );
        assert_eq!(
            stored_token(store.as_ref(), "https://hub.example/api/", "https://issuer.example")
                .await,
            None
        );
    }
}
