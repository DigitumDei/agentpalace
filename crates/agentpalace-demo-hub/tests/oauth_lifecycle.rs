//! End-to-end OAuth evidence for the demo hub.
//!
//! Every test drives the real `agentpalace_remote::RemoteClient` against the real
//! `Gateway::router()` over loopback HTTP. The gateway's real `GoogleOidcVerifierAdapter` talks to
//! a mock Google identity provider that signs RS256 ID tokens with a fixture key and publishes
//! the matching JWKS. Each simulated browser is an independent cookie jar.
//!
//! The protected resource is a test-only `/v1/info` read that authorizes bearer tokens through
//! `Gateway::authorize_rest`; the gateway now forwards only the closed REST inventory using owner-scoped private engine tokens.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use agentpalace_core::{AuthenticatedOwner, Issuer, OwnerId};
use agentpalace_demo_hub::{
    access_policy::{AccessEntry, AccessPolicyStore, AccessRole, BootstrapAdmin},
    AdmissionIdentity, AdmissionPolicy, DeviceTiming, Gateway, GatewayConfig, GatewayMode,
    GoogleClaimError, GoogleOidcConfig, GoogleOidcVerifier, GoogleOidcVerifierAdapter,
    NativeClient, VerifiedIdentity,
};
use agentpalace_remote::{
    ClearOutcome, InMemoryTokenStore, LoginInteraction, OAuthConfig, OAuthLoginMode, OAuthSession,
    RemoteApi, RemoteClient, RemoteEndpoint, RemoteError, RevocationOutcome, TokenStore,
};
use axum::extract::{Form, Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use jsonwebtoken::{Algorithm, EncodingKey, Header};

const GOOGLE_CLIENT_ID: &str = "fixture-google-client";
const GOOGLE_CLIENT_SECRET: &str = "fixture-google-secret";
const NATIVE_CLIENT_ID: &str = "agentpalace-native";
const ACCOUNT: &str = "tester";
const SIGNING_KID: &str = "fixture-signing-key";
const SIGNING_PEM: &[u8] = include_bytes!("fixtures/oidc_signing.pem");
const ATTACKER_PEM: &[u8] = include_bytes!("fixtures/oidc_attacker.pem");
const SIGNING_MODULUS: &str = include_str!("fixtures/oidc_signing.n");
const ADMITTED_SUBJECTS: [&str; 2] = ["owner-subject", "second-subject"];

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |elapsed| elapsed.as_secs())
}

async fn bind() -> (tokio::net::TcpListener, String) {
    let listener =
        tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.expect("ephemeral listener");
    let base = format!("http://{}", listener.local_addr().expect("listener address"));
    (listener, base)
}

fn serve(listener: tokio::net::TcpListener, router: Router) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        axum::serve(listener, router).await.expect("test server");
    })
}

fn query(url: &str, key: &str) -> Option<String> {
    reqwest::Url::parse(url)
        .ok()?
        .query_pairs()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.into_owned())
}

fn location(response: &reqwest::Response) -> String {
    response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("redirect location")
        .to_owned()
}

fn form_value(html: &str, name: &str) -> String {
    let marker = format!("name=\"{name}\" value=\"");
    html.split(&marker)
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("hidden form value")
        .to_owned()
}

async fn oauth_error(response: reqwest::Response) -> (StatusCode, String) {
    let status = response.status();
    let body = response.json::<serde_json::Value>().await.unwrap_or_default();
    (status, body["error"].as_str().unwrap_or_default().to_owned())
}

// ── Mock Google identity provider ────────────────────────────────────────────

/// How the mock provider signs the ID token it returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Signing {
    /// RS256 with the key published in the JWKS.
    Valid,
    /// RS256 under the published `kid`, but with a different private key.
    UnpublishedKey,
    /// HS256 keyed with the public modulus (an algorithm-confusion forgery).
    Hs256,
    /// RS256 with the published key, but no `kid` header.
    MissingKid,
}

/// The upstream account a simulated user signs in with, plus deliberate claim defects.
#[derive(Debug, Clone)]
struct Account {
    sub: String,
    email: String,
    overrides: serde_json::Map<String, serde_json::Value>,
    signing: Signing,
}

impl Account {
    fn named(sub: &str) -> Self {
        Self {
            sub: sub.to_owned(),
            email: format!("{sub}@example.test"),
            overrides: serde_json::Map::new(),
            signing: Signing::Valid,
        }
    }

    fn owner() -> Self {
        Self::named("owner-subject")
    }

    /// Replace a claim; `null` removes it.
    fn claim(mut self, name: &str, value: serde_json::Value) -> Self {
        self.overrides.insert(name.to_owned(), value);
        self
    }

    fn signed(mut self, signing: Signing) -> Self {
        self.signing = signing;
        self
    }
}

#[derive(Debug)]
struct IssuedCode {
    nonce: String,
    redirect_uri: String,
    account: Account,
}

#[derive(Debug, Default)]
struct IdpState {
    codes: HashMap<String, IssuedCode>,
    /// `redirect_uri` of every successful code exchange, in order.
    exchanges: Vec<String>,
    next_code: usize,
    token_down: bool,
    jwks_down: bool,
}

#[derive(Debug, Clone)]
struct Idp {
    base: String,
    state: Arc<Mutex<IdpState>>,
}

impl Idp {
    async fn start() -> Self {
        let (listener, base) = bind().await;
        let idp = Self { base, state: Arc::default() };
        let router = Router::new()
            .route("/token", post(Self::token))
            .route("/jwks", get(Self::jwks))
            .with_state(idp.clone());
        serve(listener, router);
        idp
    }

    fn state(&self) -> std::sync::MutexGuard<'_, IdpState> {
        self.state.lock().expect("idp state")
    }

    fn exchanges(&self) -> Vec<String> {
        self.state().exchanges.clone()
    }

    /// Play Google's authorization endpoint: validate the hub's redirect, and issue a code
    /// bound to its `redirect_uri` and `nonce`. Returns `(code, state)`.
    fn authorize(&self, google_url: &str, account: Account) -> (String, String) {
        let url = reqwest::Url::parse(google_url).expect("Google authorization URL");
        assert_eq!(url.host_str(), Some("accounts.google.com"));
        assert_eq!(url.path(), "/o/oauth2/v2/auth");
        assert_eq!(query(google_url, "client_id").as_deref(), Some(GOOGLE_CLIENT_ID));
        assert_eq!(query(google_url, "response_type").as_deref(), Some("code"));
        assert_eq!(
            query(google_url, "scope").as_deref(),
            Some("openid email"),
            "only sign-in scopes may be requested"
        );
        let nonce = query(google_url, "nonce").expect("nonce");
        let redirect_uri = query(google_url, "redirect_uri").expect("redirect_uri");
        let state = query(google_url, "state").expect("state");
        let mut idp = self.state();
        idp.next_code += 1;
        let code = format!("google-code-{}", idp.next_code);
        idp.codes.insert(code.clone(), IssuedCode { nonce, redirect_uri, account });
        (code, state)
    }

    fn sign(claims: &serde_json::Value, signing: Signing) -> String {
        let rsa = |pem: &[u8], kid: Option<&str>| {
            let mut header = Header::new(Algorithm::RS256);
            header.kid = kid.map(str::to_owned);
            jsonwebtoken::encode(
                &header,
                claims,
                &EncodingKey::from_rsa_pem(pem).expect("fixture RSA key"),
            )
            .expect("RS256 signature")
        };
        match signing {
            Signing::Valid => rsa(SIGNING_PEM, Some(SIGNING_KID)),
            Signing::UnpublishedKey => rsa(ATTACKER_PEM, Some(SIGNING_KID)),
            Signing::MissingKid => rsa(SIGNING_PEM, None),
            Signing::Hs256 => {
                let mut header = Header::new(Algorithm::HS256);
                header.kid = Some(SIGNING_KID.to_owned());
                jsonwebtoken::encode(
                    &header,
                    claims,
                    &EncodingKey::from_secret(SIGNING_MODULUS.trim().as_bytes()),
                )
                .expect("HS256 forgery")
            }
        }
    }

    async fn token(State(idp): State<Self>, Form(form): Form<HashMap<String, String>>) -> Response {
        let mut state = idp.state();
        if state.token_down {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        let field = |name: &str| form.get(name).map(String::as_str).unwrap_or_default();
        if field("grant_type") != "authorization_code"
            || field("client_id") != GOOGLE_CLIENT_ID
            || field("client_secret") != GOOGLE_CLIENT_SECRET
        {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "invalid_client"})),
            )
                .into_response();
        }
        // Codes are single use and bound to the redirect_uri they were issued for.
        let Some(issued) = state.codes.remove(field("code")) else {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid_grant"})))
                .into_response();
        };
        if field("redirect_uri") != issued.redirect_uri {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid_grant"})))
                .into_response();
        }
        state.exchanges.push(issued.redirect_uri.clone());
        let issued_at = now();
        let mut claims = serde_json::json!({
            "iss": "https://accounts.google.com", "aud": GOOGLE_CLIENT_ID, "azp": GOOGLE_CLIENT_ID,
            "sub": issued.account.sub, "email": issued.account.email, "email_verified": true,
            "iat": issued_at, "exp": issued_at + 600, "nonce": issued.nonce,
        });
        let object = claims.as_object_mut().expect("claims object");
        for (name, value) in &issued.account.overrides {
            if value.is_null() {
                object.remove(name);
            } else {
                object.insert(name.clone(), value.clone());
            }
        }
        let id_token = Self::sign(&claims, issued.account.signing);
        Json(serde_json::json!({"id_token": id_token, "access_token": "upstream-access", "token_type": "Bearer", "expires_in": 3599})).into_response()
    }

    async fn jwks(State(idp): State<Self>) -> Response {
        if idp.state().jwks_down {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
        Json(serde_json::json!({"keys": [{"kty": "RSA", "kid": SIGNING_KID, "alg": "RS256", "use": "sig", "n": SIGNING_MODULUS.trim(), "e": "AQAB"}]}))
            .into_response()
    }

    fn google(&self) -> GoogleOidcConfig {
        GoogleOidcConfig {
            client_id: GOOGLE_CLIENT_ID.to_owned(),
            client_secret: GOOGLE_CLIENT_SECRET.to_owned(),
            issuer: Issuer::new("https://accounts.google.com").expect("Google issuer"),
            scopes: ["openid", "email"].into_iter().map(str::to_owned).collect(),
        }
    }

    fn adapter(&self) -> GoogleOidcVerifierAdapter {
        GoogleOidcVerifierAdapter::new_with_endpoints(
            self.google(),
            format!("{}/token", self.base),
            format!("{}/jwks", self.base),
        )
        .expect("OIDC adapter")
    }
}

// ── Hub under test ───────────────────────────────────────────────────────────

struct AllowSubjects;

impl AdmissionPolicy for AllowSubjects {
    fn admit(&self, identity: &VerifiedIdentity) -> Option<AdmissionIdentity> {
        ADMITTED_SUBJECTS.contains(&identity.subject.as_str()).then_some(())?;
        let owner_id = format!("owner-{}", identity.subject);
        let owner = AuthenticatedOwner::parse(
            &owner_id,
            &identity.issuer,
            &identity.subject,
            &identity.email,
        )
        .ok()?;
        Some(AdmissionIdentity::new(OwnerId::new(&owner_id).ok()?, owner))
    }
}

#[derive(Clone)]
struct Hub {
    base: String,
    resource: String,
    info_path: String,
    /// Requests to either protected read (`/v1/info`, `/v1/drawers/{id}`).
    read_hits: Arc<AtomicUsize>,
    token_hits: Arc<AtomicUsize>,
    /// Access tokens the resource refuses although the hub still considers them valid.
    rejected: Arc<Mutex<BTreeSet<String>>>,
    reject_all: Arc<AtomicBool>,
    omit_challenge_metadata: Arc<AtomicBool>,
}

impl Hub {
    async fn start(idp: &Idp, resource_path: &str, timing: DeviceTiming) -> Self {
        Self::start_configured(idp, resource_path, timing, None).await
    }

    async fn start_with_access_policy(
        idp: &Idp,
        resource_path: &str,
        timing: DeviceTiming,
        access: Arc<AccessPolicyStore>,
    ) -> Self {
        Self::start_configured(idp, resource_path, timing, Some(access)).await
    }

    async fn start_configured(
        idp: &Idp,
        resource_path: &str,
        timing: DeviceTiming,
        access: Option<Arc<AccessPolicyStore>>,
    ) -> Self {
        let (listener, base) = bind().await;
        let resource = format!("{base}{resource_path}");
        let config = GatewayConfig {
            issuer: base.clone(),
            resource: resource.clone(),
            mode: GatewayMode::LoopbackDemo,
            google: idp.google(),
            native_client: NativeClient {
                client_id: NATIVE_CLIENT_ID.to_owned(),
                redirect_uri: "http://127.0.0.1:49152/callback".to_owned(),
            },
        };
        let mut gateway = Gateway::new(config, Arc::new(AllowSubjects))
            .expect("gateway configuration")
            .with_google_verifier(Arc::new(idp.adapter()))
            .with_device_timing(timing);
        if let Some(access) = access {
            gateway = gateway.with_access_policy_store(access);
        }
        let hub = Self {
            base,
            resource,
            info_path: format!("{}/v1/info", resource_path.trim_end_matches('/')),
            read_hits: Arc::default(),
            token_hits: Arc::default(),
            rejected: Arc::default(),
            reject_all: Arc::default(),
            omit_challenge_metadata: Arc::default(),
        };
        let read = |body: serde_json::Value| {
            let hub = hub.clone();
            let gateway = gateway.clone();
            move |headers: HeaderMap| {
                let (hub, gateway, body) = (hub.clone(), gateway.clone(), body.clone());
                async move { hub.protected_read(&gateway, &headers, body) }
            }
        };
        let info = read(
            serde_json::json!({"server_version": "demo-hub-fixture", "federation_api_version": 1, "capabilities": []}),
        );
        let drawer = read(serde_json::json!({"id": "fixture-drawer"}));
        let drawer_path = hub.info_path.replace("/v1/info", "/v1/drawers/{id}");
        let token_hits = Arc::clone(&hub.token_hits);
        let count_token_requests = move |request: Request, next: Next| {
            let token_hits = Arc::clone(&token_hits);
            async move {
                if request.uri().path() == "/token" {
                    token_hits.fetch_add(1, Ordering::SeqCst);
                }
                next.run(request).await
            }
        };
        let router = gateway
            .router()
            .route(&hub.info_path, get(info))
            .route(&drawer_path, get(drawer))
            .layer(axum::middleware::from_fn(count_token_requests));
        serve(listener, router);
        hub
    }

    /// Test-only protected read: `body` for a live hub access token bound to this resource,
    /// otherwise an RFC 6750 challenge carrying the RFC 9728 metadata URL.
    fn protected_read(
        &self,
        gateway: &Gateway,
        headers: &HeaderMap,
        body: serde_json::Value,
    ) -> Response {
        self.read_hits.fetch_add(1, Ordering::SeqCst);
        let bearer = headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "));
        let accepted = bearer.is_some_and(|token| {
            !self.reject_all.load(Ordering::SeqCst)
                && !self.rejected.lock().expect("rejected tokens").contains(token)
                && gateway.authorize_rest(token, &self.resource).is_ok()
        });
        if accepted {
            return Json(body).into_response();
        }
        let challenge = if self.omit_challenge_metadata.load(Ordering::SeqCst) {
            "Bearer error=\"invalid_token\"".to_owned()
        } else {
            format!("Bearer error=\"invalid_token\", resource_metadata=\"{}\"", self.metadata_url())
        };
        (StatusCode::UNAUTHORIZED, [(header::WWW_AUTHENTICATE, challenge)]).into_response()
    }

    fn metadata_url(&self) -> String {
        format!("{}/.well-known/oauth-protected-resource", self.base)
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    async fn raw_info(&self, access_token: &str) -> StatusCode {
        reqwest::Client::new()
            .get(self.url(&self.info_path))
            .bearer_auth(access_token)
            .send()
            .await
            .expect("resource request")
            .status()
    }

    async fn raw_refresh(&self, refresh_token: &str) -> (StatusCode, String) {
        let response = reqwest::Client::new()
            .post(self.url("/token"))
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
                ("client_id", NATIVE_CLIENT_ID),
                ("resource", &self.resource),
            ])
            .send()
            .await
            .expect("refresh request");
        oauth_error(response).await
    }

    async fn raw_device_grant(&self) -> serde_json::Value {
        reqwest::Client::new()
            .post(self.url("/device"))
            .form(&[("client_id", NATIVE_CLIENT_ID), ("resource", &self.resource)])
            .send()
            .await
            .expect("device authorization")
            .json()
            .await
            .expect("device grant")
    }

    async fn raw_device_poll(&self, device_code: &str) -> (StatusCode, String) {
        let response = reqwest::Client::new()
            .post(self.url("/token"))
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("device_code", device_code),
                ("client_id", NATIVE_CLIENT_ID),
                ("resource", &self.resource),
            ])
            .send()
            .await
            .expect("device poll");
        oauth_error(response).await
    }
}

const FAST_DEVICE: DeviceTiming = DeviceTiming { interval_seconds: 1, lifetime_seconds: 600 };

// ── Simulated browsers and user ──────────────────────────────────────────────

/// One browser profile: its own HTTP client and its own cookie jar. Redirects are never
/// followed automatically so every hop is asserted.
#[derive(Debug)]
struct Browser {
    http: reqwest::Client,
    cookies: Mutex<BTreeMap<String, String>>,
}

impl Browser {
    fn new() -> Arc<Self> {
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("browser client");
        Arc::new(Self { http, cookies: Mutex::default() })
    }

    fn cookie(&self, name: &str) -> Option<String> {
        self.cookies.lock().expect("cookie jar").get(name).cloned()
    }

    fn attach(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        let jar = self.cookies.lock().expect("cookie jar");
        if jar.is_empty() {
            return request;
        }
        let header = jar
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("; ");
        request.header(header::COOKIE, header)
    }

    fn absorb(&self, response: &reqwest::Response) {
        let mut jar = self.cookies.lock().expect("cookie jar");
        for value in response.headers().get_all(header::SET_COOKIE) {
            if let Some((name, value)) = value
                .to_str()
                .ok()
                .and_then(|value| value.split(';').next())
                .and_then(|pair| pair.split_once('='))
            {
                jar.insert(name.to_owned(), value.to_owned());
            }
        }
    }

    async fn get(&self, url: &str) -> reqwest::Response {
        let response = self.attach(self.http.get(url)).send().await.expect("browser GET");
        self.absorb(&response);
        response
    }

    async fn post(&self, url: &str, form: &[(&str, &str)]) -> reqwest::Response {
        let response =
            self.attach(self.http.post(url)).form(form).send().await.expect("browser POST");
        self.absorb(&response);
        response
    }
}

/// What the simulated user does at the hub.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Decision {
    Approve,
    Deny,
    /// Cancel at Google, which returns `error=access_denied` to the hub callback.
    UpstreamDenied,
}

/// Drive a browser from the hub's `/authorize` URL through Google sign-in and hub consent.
/// Returns the final redirect to the native client's loopback callback.
async fn browser_authorize(
    browser: &Browser,
    idp: &Idp,
    hub: &str,
    authorize_url: &str,
    account: Account,
    decision: Decision,
) -> String {
    let start = browser.get(authorize_url).await;
    assert_eq!(start.status(), StatusCode::TEMPORARY_REDIRECT, "authorize must redirect to Google");
    let google = location(&start);
    assert_eq!(
        query(&google, "redirect_uri").as_deref(),
        Some(format!("{hub}/auth/google/callback").as_str())
    );
    let transaction = query(&google, "state").expect("hub transaction");
    if decision == Decision::UpstreamDenied {
        let callback = browser
            .get(&format!("{hub}/auth/google/callback?state={transaction}&error=access_denied"))
            .await;
        assert_eq!(callback.status(), StatusCode::SEE_OTHER);
        return location(&callback);
    }
    let (code, _) = idp.authorize(&google, account);
    let callback =
        browser.get(&format!("{hub}/auth/google/callback?state={transaction}&code={code}")).await;
    if callback.status() == StatusCode::SEE_OTHER {
        // The hub refused the upstream assertion and told the native client directly.
        return location(&callback);
    }
    assert_eq!(callback.status(), StatusCode::OK, "a verified sign-in shows the consent page");
    let page = callback.text().await.expect("consent page");
    let consent = if decision == Decision::Approve { "true" } else { "false" };
    let submitted = browser
        .post(
            &format!("{hub}/auth/google/consent"),
            &[
                ("transaction", &form_value(&page, "transaction")),
                ("csrf_token", &form_value(&page, "csrf_token")),
                ("consent", consent),
            ],
        )
        .await;
    assert_eq!(
        submitted.status(),
        StatusCode::SEE_OTHER,
        "consent must redirect the browser to the native client with GET"
    );
    location(&submitted)
}

/// Drive a browser through device verification. Returns the final hub response status.
async fn device_verify(
    browser: &Browser,
    idp: &Idp,
    hub: &str,
    verification_uri: &str,
    account: Account,
    decision: Decision,
) -> StatusCode {
    let start = browser.get(verification_uri).await;
    assert_eq!(
        start.status(),
        StatusCode::TEMPORARY_REDIRECT,
        "verification must redirect to Google"
    );
    let google = location(&start);
    assert_eq!(
        query(&google, "redirect_uri").as_deref(),
        Some(format!("{hub}/auth/google/device-callback").as_str())
    );
    let state = query(&google, "state").expect("device verification state");
    if decision == Decision::UpstreamDenied {
        return browser
            .get(&format!("{hub}/auth/google/device-callback?state={state}&error=access_denied"))
            .await
            .status();
    }
    let (code, _) = idp.authorize(&google, account);
    let callback =
        browser.get(&format!("{hub}/auth/google/device-callback?state={state}&code={code}")).await;
    if callback.status() != StatusCode::OK {
        // The hub refused the upstream assertion before showing consent.
        return callback.status();
    }
    let page = callback.text().await.expect("device consent page");
    let consent = if decision == Decision::Approve { "true" } else { "false" };
    browser
        .post(
            &format!("{hub}/auth/google/device-consent"),
            &[
                ("user_code", &form_value(&page, "user_code")),
                ("state", &form_value(&page, "state")),
                ("csrf_token", &form_value(&page, "csrf_token")),
                ("consent", consent),
            ],
        )
        .await
        .status()
}

/// The person at the keyboard, injected into `RemoteClient` as its `LoginInteraction`: it opens
/// the authorization URL in its own browser profile and reports device prompts to the test.
#[derive(Debug)]
struct ScriptedUser {
    browser: Arc<Browser>,
    idp: Idp,
    hub: String,
    account: Account,
    decision: Decision,
    authorize_urls: Mutex<Vec<String>>,
    browser_runs: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    device_prompts: tokio::sync::mpsc::UnboundedSender<(String, String)>,
}

impl ScriptedUser {
    fn new(
        idp: &Idp,
        hub: &Hub,
        account: Account,
        decision: Decision,
    ) -> (Arc<Self>, tokio::sync::mpsc::UnboundedReceiver<(String, String)>) {
        let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
        let user = Self {
            browser: Browser::new(),
            idp: idp.clone(),
            hub: hub.base.clone(),
            account,
            decision,
            authorize_urls: Mutex::default(),
            browser_runs: Mutex::default(),
            device_prompts: sender,
        };
        (Arc::new(user), receiver)
    }

    fn authorize_urls(&self) -> Vec<String> {
        self.authorize_urls.lock().expect("authorize URLs").clone()
    }

    /// Surface any assertion failure from the spawned browser run.
    async fn finish_browser(&self) {
        let runs = std::mem::take(&mut *self.browser_runs.lock().expect("browser runs"));
        for run in runs {
            run.await.expect("scripted browser run");
        }
    }
}

impl LoginInteraction for ScriptedUser {
    fn open_browser(&self, url: &str) -> Result<(), String> {
        self.authorize_urls.lock().expect("authorize URLs").push(url.to_owned());
        let (browser, idp, hub, account, decision, url) = (
            Arc::clone(&self.browser),
            self.idp.clone(),
            self.hub.clone(),
            self.account.clone(),
            self.decision,
            url.to_owned(),
        );
        let run = tokio::spawn(async move {
            let callback = browser_authorize(&browser, &idp, &hub, &url, account, decision).await;
            assert!(
                callback.starts_with("http://127.0.0.1:"),
                "the hub must return to the native loopback: {callback}"
            );
            // The browser lands on the client's loopback listener, which completes the login.
            let landed = reqwest::get(&callback).await.expect("loopback callback");
            assert!(landed.status().is_success() || landed.status() == StatusCode::BAD_REQUEST);
        });
        self.browser_runs.lock().expect("browser runs").push(run);
        Ok(())
    }

    fn show_device_code(&self, verification_uri: &str, user_code: &str) {
        let _ = self.device_prompts.send((verification_uri.to_owned(), user_code.to_owned()));
    }
}

/// Wait for the client's device prompt, failing fast if device authorization never started.
async fn next_prompt(
    prompts: &mut tokio::sync::mpsc::UnboundedReceiver<(String, String)>,
) -> (String, String) {
    tokio::time::timeout(Duration::from_secs(15), prompts.recv())
        .await
        .expect("the client never showed a device prompt")
        .expect("device prompt channel")
}

fn client_for(
    url: &str,
    store: Arc<dyn TokenStore>,
    user: Arc<ScriptedUser>,
    login_timeout_seconds: u64,
) -> RemoteClient {
    let config = OAuthConfig {
        client_id: NATIVE_CLIENT_ID.to_owned(),
        account: Some(ACCOUNT.to_owned()),
        allow_in_memory: true,
        allow_loopback_demo: true,
        login_mode: OAuthLoginMode::Auto,
        token_store: Some(store),
        interaction: Some(user),
        login_timeout_seconds,
    };
    RemoteClient::new(RemoteEndpoint::with_oauth("demo-hub", url, config, Duration::from_secs(10)))
        .expect("remote client")
}

async fn stored(store: &dyn TokenStore, resource: &str, issuer: &str) -> Option<OAuthSession> {
    store.load(resource, issuer, NATIVE_CLIENT_ID, Some(ACCOUNT)).await.expect("credential store")
}

/// A protected read that always reaches the resource (unlike `info`, which serves the cached
/// handshake after its first success).
async fn read(client: &RemoteClient) -> Result<(), RemoteError> {
    client.get_drawer("fixture-drawer").await.map(|_| ())
}

/// First contact: an unauthenticated read must fail with the RFC 9728 challenge preserved.
async fn challenge(client: &RemoteClient) -> String {
    match client.info().await {
        Err(RemoteError::AuthenticationRequired { resource_metadata: Some(url), .. }) => url,
        other => panic!("expected an authentication challenge, got {other:?}"),
    }
}

/// Complete an approved browser login for `client` and return the stored grant.
async fn browser_login(
    client: &RemoteClient,
    user: &ScriptedUser,
    hub: &Hub,
    store: &dyn TokenStore,
) -> OAuthSession {
    let metadata = challenge(client).await;
    assert_eq!(metadata, hub.metadata_url());
    client
        .login_from_challenge_with_mode(&metadata, Some(OAuthLoginMode::Browser))
        .await
        .expect("browser login");
    user.finish_browser().await;
    // Complete (and cache) the version handshake so later hit counts see only the reads under test.
    client.info().await.expect("authorized handshake");
    stored(store, &hub.resource, &hub.base).await.expect("persisted grant")
}

// ── Browser authorization ────────────────────────────────────────────────────

#[tokio::test]
async fn consent_post_redirects_with_get_to_native_loopback() {
    let idp = Idp::start().await;
    let hub = Hub::start(&idp, "/api", FAST_DEVICE).await;
    let browser = Browser::new();
    let (listener, callback_base) = bind().await;
    let callback_url = format!("{callback_base}/callback");
    let mut authorize = reqwest::Url::parse(&hub.url("/authorize")).expect("authorize URL");
    authorize.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", NATIVE_CLIENT_ID)
        .append_pair("redirect_uri", &callback_url)
        .append_pair("code_challenge", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        .append_pair("code_challenge_method", "S256")
        .append_pair("state", "consent-get-regression")
        .append_pair("resource", &hub.resource);

    let start = browser.get(authorize.as_str()).await;
    assert_eq!(start.status(), StatusCode::TEMPORARY_REDIRECT);
    let google = location(&start);
    let transaction = query(&google, "state").expect("hub transaction");
    let (code, _) = idp.authorize(&google, Account::owner());
    let consent = browser.get(&hub.url(&format!(
        "/auth/google/callback?state={transaction}&code={code}"
    ))).await;
    assert_eq!(consent.status(), StatusCode::OK);
    let page = consent.text().await.expect("consent page");

    let callback = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("native callback");
        let mut request = [0_u8; 2048];
        let count = tokio::io::AsyncReadExt::read(&mut socket, &mut request).await.expect("request");
        let first_line = String::from_utf8_lossy(&request[..count])
            .lines().next().unwrap_or_default().to_owned();
        tokio::io::AsyncWriteExt::write_all(
            &mut socket,
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK",
        ).await.expect("callback response");
        first_line
    });
    let following_browser = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::limited(5))
        .build().expect("browser with redirects");
    let finished = browser.attach(following_browser.post(hub.url("/auth/google/consent")))
        .form(&[
            ("transaction", form_value(&page, "transaction")),
            ("csrf_token", form_value(&page, "csrf_token")),
            ("consent", "true".to_owned()),
        ])
        .send().await.expect("consent submission and redirect");
    assert_eq!(finished.status(), StatusCode::OK);
    let request = callback.await.expect("native callback capture");
    assert_eq!(request.split_whitespace().next(), Some("GET"), "callback must use GET");
    assert!(request.starts_with("GET /callback?"), "callback must target /callback");
}

#[tokio::test]
async fn browser_login_uses_a_dynamic_loopback_and_reaches_the_protected_resource() {
    let idp = Idp::start().await;
    let hub = Hub::start(&idp, "/api", FAST_DEVICE).await;
    let store: Arc<dyn TokenStore> = Arc::new(InMemoryTokenStore::default());
    let (user, _) = ScriptedUser::new(&idp, &hub, Account::owner(), Decision::Approve);
    let client =
        client_for(&format!("{}/api", hub.base), Arc::clone(&store), Arc::clone(&user), 30);

    let grant = browser_login(&client, &user, &hub, store.as_ref()).await;
    read(&client).await.expect("authorized read");

    // The grant is bound to the hub issuer and the exact advertised resource.
    assert_eq!(grant.issuer, hub.base);
    assert_eq!(grant.resource, hub.resource);
    assert!(grant.refresh_token.is_some() && grant.expires_at.is_some());

    // RFC 8252: an ephemeral loopback port, not the registered example port, with S256 PKCE.
    let authorize = user.authorize_urls().pop().expect("authorize URL");
    let redirect = reqwest::Url::parse(&query(&authorize, "redirect_uri").expect("redirect_uri"))
        .expect("loopback redirect");
    assert_eq!(redirect.host_str(), Some("127.0.0.1"));
    assert_eq!(redirect.path(), "/callback");
    assert_ne!(redirect.port(), Some(49152));
    assert_eq!(query(&authorize, "code_challenge_method").as_deref(), Some("S256"));
    assert_eq!(query(&authorize, "resource").as_deref(), Some(hub.resource.as_str()));

    // The upstream code was exchanged exactly once, at the browser callback.
    assert_eq!(idp.exchanges(), vec![format!("{}/auth/google/callback", hub.base)]);
}

#[tokio::test]
async fn browser_and_device_verification_exchange_upstream_codes_at_distinct_redirects() {
    let idp = Idp::start().await;
    let hub = Hub::start(&idp, "/api", FAST_DEVICE).await;
    let store: Arc<dyn TokenStore> = Arc::new(InMemoryTokenStore::default());

    let (browser_user, _) = ScriptedUser::new(&idp, &hub, Account::owner(), Decision::Approve);
    let browser_client =
        client_for(&format!("{}/api", hub.base), Arc::clone(&store), Arc::clone(&browser_user), 30);
    browser_login(&browser_client, &browser_user, &hub, store.as_ref()).await;

    let device_store: Arc<dyn TokenStore> = Arc::new(InMemoryTokenStore::default());
    let (device_user, mut prompts) =
        ScriptedUser::new(&idp, &hub, Account::owner(), Decision::Approve);
    let device_client = Arc::new(client_for(
        &format!("{}/api", hub.base),
        Arc::clone(&device_store),
        device_user,
        30,
    ));
    let metadata = challenge(&device_client).await;
    let login = {
        let client = Arc::clone(&device_client);
        tokio::spawn(async move {
            client.login_from_challenge_with_mode(&metadata, Some(OAuthLoginMode::Device)).await
        })
    };
    let (verification_uri, _) = next_prompt(&mut prompts).await;
    let phone = Browser::new();
    assert_eq!(
        device_verify(
            &phone,
            &idp,
            &hub.base,
            &verification_uri,
            Account::owner(),
            Decision::Approve
        )
        .await,
        StatusCode::OK
    );
    login.await.expect("device login task").expect("device login");
    read(&device_client).await.expect("device-authorized read");

    assert_eq!(
        idp.exchanges(),
        vec![
            format!("{}/auth/google/callback", hub.base),
            format!("{}/auth/google/device-callback", hub.base)
        ],
        "browser sign-in and device verification must each present their own registered callback"
    );
}

#[tokio::test]
async fn browser_refusals_reach_the_waiting_client_as_denied_and_store_nothing() {
    let idp = Idp::start().await;
    let hub = Hub::start(&idp, "/api", FAST_DEVICE).await;
    for (account, decision, expected_message) in [
        (Account::owner(), Decision::Deny, "denied by the user"),
        (Account::owner(), Decision::UpstreamDenied, "denied by the user"),
        // Signs in successfully upstream but is not admitted by the hub policy.
        (Account::named("stranger"), Decision::Approve, "not admitted"),
        // An ID token Google would never issue: the hub refuses it before consent.
        (
            Account::owner().claim("email_verified", serde_json::json!(false)),
            Decision::Approve,
            "denied by the user",
        ),
        (
            Account::owner().signed(Signing::UnpublishedKey),
            Decision::Approve,
            "denied by the user",
        ),
    ] {
        let store: Arc<dyn TokenStore> = Arc::new(InMemoryTokenStore::default());
        let (user, _) = ScriptedUser::new(&idp, &hub, account.clone(), decision);
        let client =
            client_for(&format!("{}/api", hub.base), Arc::clone(&store), Arc::clone(&user), 30);
        let metadata = challenge(&client).await;
        let error = client
            .login_from_challenge_with_mode(&metadata, Some(OAuthLoginMode::Browser))
            .await
            .expect_err("refused login");
        user.finish_browser().await;
        assert!(
            error.to_string().contains(expected_message),
            "{decision:?}/{}: {error}",
            account.sub
        );
        assert!(stored(store.as_ref(), &hub.resource, &hub.base).await.is_none());
        assert!(matches!(client.info().await, Err(RemoteError::AuthenticationRequired { .. })));
    }
}

#[tokio::test]
async fn stolen_consent_forms_forged_csrf_replay_and_mismatched_exchanges_are_rejected() {
    let idp = Idp::start().await;
    let hub = Hub::start(&idp, "/api", FAST_DEVICE).await;
    let (verifier, challenge) = agentpalace_remote::new_pkce_pair();
    let redirect_uri = "http://127.0.0.1:50123/callback";
    let authorize = |state: &str, challenge: &str| {
        let mut url = reqwest::Url::parse(&hub.url("/authorize")).expect("authorize URL");
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", NATIVE_CLIENT_ID)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("code_challenge", challenge)
            .append_pair("code_challenge_method", "S256")
            .append_pair("state", state)
            .append_pair("resource", &hub.resource);
        url.to_string()
    };
    let victim = Browser::new();
    let attacker = Browser::new();

    let started = victim.get(&authorize("victim-state", &challenge)).await;
    let google = location(&started);
    let transaction = query(&google, "state").expect("transaction");
    let (code, _) = idp.authorize(&google, Account::owner());
    let _ = attacker.get(&authorize("attacker-state", "attacker-challenge")).await;
    assert_ne!(
        victim.cookie("agentpalace_browser"),
        attacker.cookie("agentpalace_browser"),
        "browser jars are independent"
    );

    // The attacker cannot complete the victim's Google callback, even with the real code.
    let stolen_callback = attacker
        .get(&hub.url(&format!("/auth/google/callback?state={transaction}&code={code}")))
        .await;
    assert_eq!(
        oauth_error(stolen_callback).await,
        (StatusCode::BAD_REQUEST, "access_denied".to_owned())
    );
    // The upstream code was not consumed by the rejected attempt.
    let consent_page = victim
        .get(&hub.url(&format!("/auth/google/callback?state={transaction}&code={code}")))
        .await;
    assert_eq!(consent_page.status(), StatusCode::OK);
    let page = consent_page.text().await.expect("consent page");
    let csrf = form_value(&page, "csrf_token");

    let stolen_form = attacker
        .post(
            &hub.url("/auth/google/consent"),
            &[("transaction", &transaction), ("csrf_token", &csrf), ("consent", "true")],
        )
        .await;
    assert_eq!(
        oauth_error(stolen_form).await,
        (StatusCode::BAD_REQUEST, "access_denied".to_owned())
    );
    let forged = victim
        .post(
            &hub.url("/auth/google/consent"),
            &[("transaction", &transaction), ("csrf_token", "forged"), ("consent", "true")],
        )
        .await;
    assert_eq!(oauth_error(forged).await, (StatusCode::BAD_REQUEST, "invalid_request".to_owned()));
    let approved = victim
        .post(
            &hub.url("/auth/google/consent"),
            &[("transaction", &transaction), ("csrf_token", &csrf), ("consent", "true")],
        )
        .await;
    assert_eq!(approved.status(), StatusCode::SEE_OTHER);
    let callback = location(&approved);
    assert!(callback.starts_with(redirect_uri));
    assert_eq!(query(&callback, "state").as_deref(), Some("victim-state"));
    let hub_code = query(&callback, "code").expect("hub authorization code");
    let replay = victim
        .post(
            &hub.url("/auth/google/consent"),
            &[("transaction", &transaction), ("csrf_token", &csrf), ("consent", "true")],
        )
        .await;
    assert_eq!(
        replay.status(),
        StatusCode::BAD_REQUEST,
        "a consumed consent form cannot be replayed"
    );

    let exchange = |redirect: &'static str, verifier: String| {
        let (hub, code) = (hub.clone(), hub_code.clone());
        async move {
            let response = reqwest::Client::new()
                .post(hub.url("/token"))
                .form(&[
                    ("grant_type", "authorization_code"),
                    ("code", &code),
                    ("client_id", NATIVE_CLIENT_ID),
                    ("redirect_uri", redirect),
                    ("code_verifier", &verifier),
                    ("resource", &hub.resource),
                ])
                .send()
                .await
                .expect("code exchange");
            let status = response.status();
            (status, response.json::<serde_json::Value>().await.expect("token response"))
        }
    };
    let (status, body) = exchange("http://127.0.0.1:50124/callback", verifier.clone()).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_grant")),
        "the code is bound to its exact redirect_uri"
    );
    let (status, body) = exchange(redirect_uri, "wrong-verifier".to_owned()).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_grant")),
        "the code is bound to the S256 challenge"
    );
    let (status, body) = exchange(redirect_uri, verifier.clone()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        hub.raw_info(body["access_token"].as_str().expect("access token")).await,
        StatusCode::OK
    );
    let (status, body) = exchange(redirect_uri, verifier).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_grant")),
        "codes are single use"
    );
}

// ── Device authorization ─────────────────────────────────────────────────────

#[tokio::test]
async fn device_login_polls_while_pending_then_completes_after_browser_approval() {
    let idp = Idp::start().await;
    let hub = Hub::start(&idp, "/api", FAST_DEVICE).await;
    let store: Arc<dyn TokenStore> = Arc::new(InMemoryTokenStore::default());
    let (user, mut prompts) = ScriptedUser::new(&idp, &hub, Account::owner(), Decision::Approve);
    let client = Arc::new(client_for(&format!("{}/api", hub.base), Arc::clone(&store), user, 30));
    let metadata = challenge(&client).await;
    let login = {
        let client = Arc::clone(&client);
        tokio::spawn(async move {
            client.login_from_challenge_with_mode(&metadata, Some(OAuthLoginMode::Device)).await
        })
    };
    let (verification_uri, user_code) = next_prompt(&mut prompts).await;
    assert_eq!(query(&verification_uri, "user_code").as_deref(), Some(user_code.as_str()));
    assert!(user_code.len() == 9 && user_code.as_bytes()[4] == b'-', "{user_code}");

    // Wait until the client has polled at least once while the grant is still pending.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while hub.token_hits.load(Ordering::SeqCst) == 0 {
        assert!(tokio::time::Instant::now() < deadline, "client never polled");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(!login.is_finished(), "a pending grant must not complete the login");

    let phone = Browser::new();
    assert_eq!(phone.get(&hub.url("/hub/connections")).await.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        device_verify(
            &phone,
            &idp,
            &hub.base,
            &verification_uri,
            Account::owner(),
            Decision::Approve
        )
        .await,
        StatusCode::OK
    );
    assert!(phone.cookie("agentpalace_session").is_some(), "device browser gets a session");
    assert!(phone.cookie("agentpalace_csrf").is_some(), "device browser gets CSRF protection");
    login.await.expect("device login task").expect("device login");
    read(&client).await.expect("device-authorized read");
    let grant =
        stored(store.as_ref(), &hub.resource, &hub.base).await.expect("persisted device grant");
    assert_eq!(grant.resource, hub.resource);
    let connections = phone.get(&hub.url("/hub/connections")).await;
    assert_eq!(connections.status(), StatusCode::OK);
    assert_eq!(connections.headers().get(header::CACHE_CONTROL).expect("cache policy"), "no-store");
    let page = connections.text().await.expect("device browser connections");
    assert!(page.contains(&hub.resource));
    let token = form_value(&page, "token");
    let csrf = form_value(&page, "csrf_token");
    assert_eq!(
        phone.post(&hub.url("/connections/revoke"), &[("token", &token), ("csrf_token", &csrf)])
            .await.status(),
        StatusCode::NO_CONTENT,
    );
    let after = phone.get(&hub.url("/hub/connections")).await;
    assert_eq!(after.status(), StatusCode::OK);
    assert!(after.text().await.expect("connections after revoke").contains("No active connections"));
}

#[tokio::test]
async fn device_refusals_end_polling_with_a_denial() {
    let idp = Idp::start().await;
    let hub = Hub::start(&idp, "/api", FAST_DEVICE).await;
    for (account, decision, expected_message) in [
        (Account::owner(), Decision::Deny, "denied by the user"),
        (Account::owner(), Decision::UpstreamDenied, "denied by the user"),
        (Account::named("stranger"), Decision::Approve, "not admitted"),
        // ID tokens that fail verification at the device callback end the grant, too.
        (
            Account::owner().signed(Signing::UnpublishedKey),
            Decision::Approve,
            "denied by the user",
        ),
        (
            Account::owner().claim("email_verified", serde_json::json!(false)),
            Decision::Approve,
            "denied by the user",
        ),
        (
            Account::owner().claim("nonce", serde_json::json!("replayed-nonce")),
            Decision::Approve,
            "denied by the user",
        ),
    ] {
        let store: Arc<dyn TokenStore> = Arc::new(InMemoryTokenStore::default());
        let (user, mut prompts) = ScriptedUser::new(&idp, &hub, account.clone(), decision);
        let client =
            Arc::new(client_for(&format!("{}/api", hub.base), Arc::clone(&store), user, 30));
        let metadata = challenge(&client).await;
        let login = {
            let client = Arc::clone(&client);
            tokio::spawn(async move {
                client.login_from_challenge_with_mode(&metadata, Some(OAuthLoginMode::Device)).await
            })
        };
        let (verification_uri, _) = next_prompt(&mut prompts).await;
        let browser = Browser::new();
        let final_status = device_verify(
            &browser,
            &idp,
            &hub.base,
            &verification_uri,
            account.clone(),
            decision,
        )
        .await;
        assert!(browser.cookie("agentpalace_session").is_none(), "refused device login has no session");
        let expected = match decision {
            Decision::Deny => StatusCode::OK,
            Decision::UpstreamDenied => StatusCode::NO_CONTENT,
            Decision::Approve => StatusCode::BAD_REQUEST,
        };
        assert_eq!(final_status, expected, "{decision:?}/{}", account.sub);
        let error = login.await.expect("device login task").expect_err("refused device login");
        assert!(
            error.to_string().contains(expected_message),
            "{decision:?}/{}: {error}",
            account.sub
        );
        assert!(stored(store.as_ref(), &hub.resource, &hub.base).await.is_none());
    }
}

#[tokio::test]
async fn json_device_approval_creates_a_browser_session() {
    let idp = Idp::start().await;
    let hub = Hub::start(&idp, "/api", FAST_DEVICE).await;
    let grant = hub.raw_device_grant().await;
    let user_code = grant["user_code"].as_str().expect("user code");
    let browser = Browser::new();
    let google = location(&browser.get(grant["verification_uri"].as_str().expect("URI")).await);
    let state = query(&google, "state").expect("device state");
    let (callback_code, _) = idp.authorize(&google, Account::owner());
    let page = browser
        .get(&hub.url(&format!("/auth/google/device-callback?state={state}&code={callback_code}")))
        .await;
    assert_eq!(page.status(), StatusCode::OK);
    let csrf = form_value(&page.text().await.expect("device consent page"), "csrf_token");
    let (code, _) = idp.authorize(&google, Account::owner());
    let response = browser.attach(browser.http.post(hub.url("/device/verify")))
        .json(&serde_json::json!({"user_code": user_code, "state": state, "code": code,
            "consent": true, "csrf_token": csrf}))
        .send().await.expect("JSON device approval");
    browser.absorb(&response);
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(browser.cookie("agentpalace_session").is_some());
    assert_eq!(browser.get(&hub.url("/hub/connections")).await.status(), StatusCode::OK);
}

#[tokio::test]
async fn json_device_verification_denies_on_rejected_tokens_but_retries_upstream_outages() {
    let idp = Idp::start().await;
    let hub = Hub::start(&idp, "/api", FAST_DEVICE).await;
    let grant = hub.raw_device_grant().await;
    let device_code = grant["device_code"].as_str().expect("device code");
    let user_code = grant["user_code"].as_str().expect("user code");
    let browser = Browser::new();
    let google = location(&browser.get(grant["verification_uri"].as_str().expect("URI")).await);
    let state = query(&google, "state").expect("device verification state");
    // A verified sign-in yields the page carrying the CSRF value the JSON path also requires.
    let (code, _) = idp.authorize(&google, Account::owner());
    let page = browser
        .get(&hub.url(&format!("/auth/google/device-callback?state={state}&code={code}")))
        .await;
    assert_eq!(page.status(), StatusCode::OK);
    let csrf = form_value(&page.text().await.expect("device consent page"), "csrf_token");
    let verify = |code: String| {
        let (browser, hub, state, csrf, user_code) =
            (Arc::clone(&browser), hub.clone(), state.clone(), csrf.clone(), user_code.to_owned());
        async move {
            let cookie = format!(
                "agentpalace_device_browser={}",
                browser.cookie("agentpalace_device_browser").expect("binding cookie")
            );
            let response = reqwest::Client::new()
                .post(hub.url("/device/verify"))
                .header(header::COOKIE, cookie)
                .json(&serde_json::json!({"user_code": user_code, "state": state, "code": code, "consent": true, "csrf_token": csrf}))
                .send()
                .await
                .expect("JSON device verification");
            oauth_error(response).await
        }
    };

    // An upstream outage is retryable and leaves the grant pending.
    idp.state().token_down = true;
    let (retry_code, _) = idp.authorize(&google, Account::owner());
    assert_eq!(
        verify(retry_code).await,
        (StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable".to_owned())
    );
    assert_eq!(hub.raw_device_poll(device_code).await.1, "authorization_pending");
    idp.state().token_down = false;

    // A token that fails verification ends the grant: the polling client is told immediately.
    let (bad_code, _) = idp.authorize(&google, Account::owner().signed(Signing::UnpublishedKey));
    assert_eq!(verify(bad_code).await, (StatusCode::BAD_REQUEST, "access_denied".to_owned()));
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    assert_eq!(
        hub.raw_device_poll(device_code).await,
        (StatusCode::BAD_REQUEST, "access_denied".to_owned())
    );
}

#[tokio::test]
async fn anonymous_repeated_denials_are_bounded_and_do_not_block_device_login() {
    let idp = Idp::start().await;
    let hub = Hub::start(&idp, "/api", FAST_DEVICE).await;
    // Request a code, open its verification URI, and deny it at the device callback without
    // ever signing in upstream — repeatedly, past the hub's per-client record bound (32).
    let mut device_codes = Vec::new();
    for _ in 0..40 {
        let grant = hub.raw_device_grant().await;
        assert!(grant["device_code"].is_string(), "a new grant is always issued: {grant}");
        let browser = Browser::new();
        let google = location(&browser.get(grant["verification_uri"].as_str().expect("URI")).await);
        let state = query(&google, "state").expect("state");
        let denied =
            browser
                .get(&hub.url(&format!(
                    "/auth/google/device-callback?state={state}&error=access_denied"
                )))
                .await;
        assert_eq!(denied.status(), StatusCode::NO_CONTENT);
        device_codes.push(grant["device_code"].as_str().expect("device code").to_owned());
    }
    // The oldest denials were evicted to stay within the bound; recent ones are still readable.
    assert_eq!(
        hub.raw_device_poll(&device_codes[0]).await,
        (StatusCode::BAD_REQUEST, "invalid_grant".to_owned())
    );
    let latest = device_codes.last().expect("latest denial");
    assert_eq!(
        hub.raw_device_poll(latest).await,
        (StatusCode::BAD_REQUEST, "access_denied".to_owned())
    );

    // A legitimate device login still completes.
    let store: Arc<dyn TokenStore> = Arc::new(InMemoryTokenStore::default());
    let (user, mut prompts) = ScriptedUser::new(&idp, &hub, Account::owner(), Decision::Approve);
    let client = Arc::new(client_for(&format!("{}/api", hub.base), Arc::clone(&store), user, 30));
    let metadata = challenge(&client).await;
    let login = {
        let client = Arc::clone(&client);
        tokio::spawn(async move {
            client.login_from_challenge_with_mode(&metadata, Some(OAuthLoginMode::Device)).await
        })
    };
    let (verification_uri, _) = next_prompt(&mut prompts).await;
    assert_eq!(
        device_verify(
            &Browser::new(),
            &idp,
            &hub.base,
            &verification_uri,
            Account::owner(),
            Decision::Approve
        )
        .await,
        StatusCode::OK
    );
    login.await.expect("device login task").expect("device login after a denial flood");
    read(&client).await.expect("authorized read");
}

#[tokio::test]
async fn restarted_device_verification_invalidates_earlier_verified_callbacks() {
    let idp = Idp::start().await;
    let hub = Hub::start(&idp, "/api", FAST_DEVICE).await;
    let grant = hub.raw_device_grant().await;
    let verification_uri = grant["verification_uri"].as_str().expect("URI");
    let device_code = grant["device_code"].as_str().expect("device code");
    let browser = Browser::new();
    // Repeatedly complete the verified Google callback on one grant, then restart verification
    // before consenting. Each restart supersedes the parked claims of the previous attempt.
    let mut abandoned_forms = Vec::new();
    for _ in 0..5 {
        let google = location(&browser.get(verification_uri).await);
        let state = query(&google, "state").expect("state");
        let (code, _) = idp.authorize(&google, Account::owner());
        let page = browser
            .get(&hub.url(&format!("/auth/google/device-callback?state={state}&code={code}")))
            .await;
        assert_eq!(page.status(), StatusCode::OK);
        let page = page.text().await.expect("device consent page");
        abandoned_forms.push([
            form_value(&page, "user_code"),
            form_value(&page, "state"),
            form_value(&page, "csrf_token"),
        ]);
    }
    // The last attempt is the live one; every earlier form is dead, even with valid CSRF.
    let live = abandoned_forms.pop().expect("live form");
    for [user_code, state, csrf] in &abandoned_forms {
        let stale = browser
            .post(
                &hub.url("/auth/google/device-consent"),
                &[
                    ("user_code", user_code),
                    ("state", state),
                    ("csrf_token", csrf),
                    ("consent", "true"),
                ],
            )
            .await;
        assert_eq!(
            stale.status(),
            StatusCode::BAD_REQUEST,
            "a superseded verification cannot be consented"
        );
    }
    assert_eq!(hub.raw_device_poll(device_code).await.1, "authorization_pending");
    let [user_code, state, csrf] = &live;
    let approved = browser
        .post(
            &hub.url("/auth/google/device-consent"),
            &[
                ("user_code", user_code),
                ("state", state),
                ("csrf_token", csrf),
                ("consent", "true"),
            ],
        )
        .await;
    assert_eq!(approved.status(), StatusCode::OK);
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    assert_eq!(hub.raw_device_poll(device_code).await.0, StatusCode::OK);
}

#[tokio::test]
async fn mixed_device_transactions_are_rejected_and_unrelated_grants_are_preserved() {
    let idp = Idp::start().await;
    let hub = Hub::start(&idp, "/api", FAST_DEVICE).await;
    let first = hub.raw_device_grant().await;
    let second = hub.raw_device_grant().await;
    let first_uri = first["verification_uri"].as_str().expect("first verification URI");
    let second_uri = second["verification_uri"].as_str().expect("second verification URI");
    let first_device = first["device_code"].as_str().expect("first device code");
    let second_device = second["device_code"].as_str().expect("second device code");
    assert_ne!(first["user_code"], second["user_code"]);
    assert!(
        !first_device.contains(&first["user_code"].as_str().expect("user code").replace('-', "")),
        "the user code is not derived from the device code"
    );

    let owner = Browser::new();
    let other = Browser::new();
    let owner_google = location(&owner.get(first_uri).await);
    let other_google = location(&other.get(second_uri).await);
    let owner_state = query(&owner_google, "state").expect("owner state");
    let other_state = query(&other_google, "state").expect("other state");
    assert_ne!(owner_state, other_state);

    // The other browser cannot deny, or complete, the owner's transaction.
    let mixed_denial =
        other
            .get(&hub.url(&format!(
                "/auth/google/device-callback?state={owner_state}&error=access_denied"
            )))
            .await;
    assert_eq!(
        oauth_error(mixed_denial).await,
        (StatusCode::BAD_REQUEST, "invalid_grant".to_owned())
    );
    let (owner_code, _) = idp.authorize(&owner_google, Account::owner());
    let mixed_code =
        other
            .get(&hub.url(&format!(
                "/auth/google/device-callback?state={owner_state}&code={owner_code}"
            )))
            .await;
    assert_eq!(
        oauth_error(mixed_code).await,
        (StatusCode::BAD_REQUEST, "invalid_grant".to_owned())
    );

    // The owner's transaction, and its not-yet-consumed upstream code, are intact.
    let page =
        owner
            .get(&hub.url(&format!(
                "/auth/google/device-callback?state={owner_state}&code={owner_code}"
            )))
            .await;
    assert_eq!(page.status(), StatusCode::OK);
    let page = page.text().await.expect("device consent page");
    let form = [
        ("user_code", form_value(&page, "user_code")),
        ("state", form_value(&page, "state")),
        ("csrf_token", form_value(&page, "csrf_token")),
        ("consent", "true".to_owned()),
    ];
    let form: Vec<(&str, &str)> =
        form.iter().map(|(name, value)| (*name, value.as_str())).collect();
    let stolen = other.post(&hub.url("/auth/google/device-consent"), &form).await;
    assert_eq!(
        oauth_error(stolen).await,
        (StatusCode::BAD_REQUEST, "invalid_request".to_owned()),
        "a stolen device consent form is bound to its browser"
    );
    assert_eq!(
        owner.post(&hub.url("/auth/google/device-consent"), &form).await.status(),
        StatusCode::OK
    );
    let replay = owner.post(&hub.url("/auth/google/device-consent"), &form).await;
    assert_eq!(replay.status(), StatusCode::BAD_REQUEST, "device consent cannot be replayed");

    let (status, _) = hub.raw_device_poll(first_device).await;
    assert_eq!(status, StatusCode::OK, "the approved grant issues tokens");
    assert_eq!(
        hub.raw_device_poll(second_device).await,
        (StatusCode::BAD_REQUEST, "authorization_pending".to_owned()),
        "the unrelated grant is untouched"
    );
    assert_eq!(
        hub.raw_device_poll(first_device).await,
        (StatusCode::BAD_REQUEST, "invalid_grant".to_owned()),
        "a device code redeems once"
    );
}

#[tokio::test]
async fn device_polling_enforces_slow_down_and_expiry_over_http() {
    let idp = Idp::start().await;
    let hub =
        Hub::start(&idp, "/api", DeviceTiming { interval_seconds: 1, lifetime_seconds: 3 }).await;
    let grant = hub.raw_device_grant().await;
    assert_eq!((grant["interval"].as_u64(), grant["expires_in"].as_u64()), (Some(1), Some(3)));
    let device_code = grant["device_code"].as_str().expect("device code");
    assert_eq!(hub.raw_device_poll(device_code).await.1, "authorization_pending");
    assert_eq!(
        hub.raw_device_poll(device_code).await.1,
        "slow_down",
        "polling faster than the interval"
    );
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    assert_eq!(
        hub.raw_device_poll(device_code).await.1,
        "slow_down",
        "slow_down lengthens the interval by five seconds"
    );
    tokio::time::sleep(Duration::from_millis(3_000)).await;
    assert_eq!(hub.raw_device_poll(device_code).await.1, "expired_token");
}

#[tokio::test]
async fn device_expiry_and_client_cancellation_store_no_credential() {
    let idp = Idp::start().await;
    // The hub expires the grant before the client gives up.
    let short_hub =
        Hub::start(&idp, "/api", DeviceTiming { interval_seconds: 1, lifetime_seconds: 2 }).await;
    // The client gives up (its login timeout) while the hub grant is still live.
    let long_hub = Hub::start(&idp, "/api", FAST_DEVICE).await;
    for (hub, timeout) in [(&short_hub, 30), (&long_hub, 2)] {
        let store: Arc<dyn TokenStore> = Arc::new(InMemoryTokenStore::default());
        let (user, mut prompts) = ScriptedUser::new(&idp, hub, Account::owner(), Decision::Approve);
        let client = client_for(&format!("{}/api", hub.base), Arc::clone(&store), user, timeout);
        let metadata = challenge(&client).await;
        let error = client
            .login_from_challenge_with_mode(&metadata, Some(OAuthLoginMode::Device))
            .await
            .expect_err("unapproved device login");
        if hub.base == short_hub.base {
            assert!(error.to_string().contains("expired"), "{error}");
        } else {
            assert!(error.to_string().contains("timed out locally"), "{error}");
        }
        let (verification_uri, _) = next_prompt(&mut prompts).await;
        if hub.base == long_hub.base {
            // Approval after the client stopped polling cannot deliver a credential to it.
            assert_eq!(
                device_verify(
                    &Browser::new(),
                    &idp,
                    &hub.base,
                    &verification_uri,
                    Account::owner(),
                    Decision::Approve
                )
                .await,
                StatusCode::OK
            );
        }
        assert!(stored(store.as_ref(), &hub.resource, &hub.base).await.is_none());
        assert!(matches!(client.info().await, Err(RemoteError::AuthenticationRequired { .. })));
    }
}

// ── Refresh, revocation, and recovery ────────────────────────────────────────

#[tokio::test]
async fn refresh_rotates_and_reuse_revokes_the_family_including_issued_access() {
    let idp = Idp::start().await;
    let hub = Hub::start(&idp, "/api", FAST_DEVICE).await;
    let store: Arc<dyn TokenStore> = Arc::new(InMemoryTokenStore::default());
    let (user, _) = ScriptedUser::new(&idp, &hub, Account::owner(), Decision::Approve);
    let client =
        client_for(&format!("{}/api", hub.base), Arc::clone(&store), Arc::clone(&user), 30);
    let first = browser_login(&client, &user, &hub, store.as_ref()).await;

    let metadata =
        client.authorization_server_metadata(&hub.base).await.expect("trusted issuer metadata");
    client.refresh(&metadata).await.expect("rotation");
    let second = stored(store.as_ref(), &hub.resource, &hub.base).await.expect("rotated grant");
    assert_ne!(second.access_token, first.access_token);
    assert_ne!(second.refresh_token, first.refresh_token);
    read(&client).await.expect("read with the rotated access token");

    // Reusing the superseded refresh token is treated as theft: the whole family dies.
    let old_refresh = first.refresh_token.as_deref().expect("first refresh token");
    assert_eq!(
        hub.raw_refresh(old_refresh).await,
        (StatusCode::BAD_REQUEST, "invalid_grant".to_owned())
    );
    assert_eq!(hub.raw_info(&first.access_token).await, StatusCode::UNAUTHORIZED);
    assert_eq!(
        hub.raw_info(&second.access_token).await,
        StatusCode::UNAUTHORIZED,
        "issued access tokens die with the family"
    );

    // The client's single recovery attempt refreshes once, is refused, and forgets the grant.
    let token_hits = hub.token_hits.load(Ordering::SeqCst);
    assert!(matches!(read(&client).await, Err(RemoteError::AuthenticationRequired { .. })));
    assert_eq!(hub.token_hits.load(Ordering::SeqCst), token_hits + 1);
    assert!(stored(store.as_ref(), &hub.resource, &hub.base).await.is_none());
}

#[tokio::test]
async fn disabling_an_account_revokes_its_grant_and_reenable_requires_new_sign_in() {
    let idp = Idp::start().await;
    let temp = tempfile::tempdir().expect("access-policy tempdir");
    let access = Arc::new(
        AccessPolicyStore::open(
            temp.path().join("access.json"),
            temp.path().join("bindings.json"),
            temp.path().join("audit.jsonl"),
            Some(BootstrapAdmin {
                email: Account::owner().email,
                mailbox_proven: true,
            }),
        )
        .expect("access policy"),
    );
    let snapshot = access.snapshot().expect("initial policy");
    let mut users = snapshot.users;
    users.insert(
        "backup-admin@example.test".to_owned(),
        AccessEntry { role: AccessRole::Admin, enabled: true, mailbox_proven: true },
    );
    access.replace(snapshot.revision, "fixture", users).expect("backup administrator");

    let hub =
        Hub::start_with_access_policy(&idp, "/api", FAST_DEVICE, Arc::clone(&access)).await;
    let store: Arc<dyn TokenStore> = Arc::new(InMemoryTokenStore::default());
    let (user, _) = ScriptedUser::new(&idp, &hub, Account::owner(), Decision::Approve);
    let client =
        client_for(&format!("{}/api", hub.base), Arc::clone(&store), Arc::clone(&user), 30);
    let grant = browser_login(&client, &user, &hub, store.as_ref()).await;

    let snapshot = access.snapshot().expect("enabled policy");
    let mut users = snapshot.users;
    users.get_mut("owner-subject@example.test").expect("owner row").enabled = false;
    access.replace(snapshot.revision, "disable owner", users).expect("disable owner");

    assert!(matches!(read(&client).await, Err(RemoteError::AuthenticationRequired { .. })));
    assert!(stored(store.as_ref(), &hub.resource, &hub.base).await.is_none());

    let snapshot = access.snapshot().expect("disabled policy");
    let mut users = snapshot.users;
    users.get_mut("owner-subject@example.test").expect("owner row").enabled = true;
    access.replace(snapshot.revision, "re-enable owner", users).expect("re-enable owner");

    assert!(matches!(read(&client).await, Err(RemoteError::AuthenticationRequired { .. })));
    assert_eq!(hub.raw_info(&grant.access_token).await, StatusCode::UNAUTHORIZED);
    assert_eq!(
        hub.raw_refresh(grant.refresh_token.as_deref().expect("refresh token")).await,
        (StatusCode::BAD_REQUEST, "invalid_grant".to_owned())
    );
}

#[tokio::test]
async fn logout_revokes_at_the_hub_and_rejects_every_issued_token() {
    let idp = Idp::start().await;
    let hub = Hub::start(&idp, "/api", FAST_DEVICE).await;
    let store: Arc<dyn TokenStore> = Arc::new(InMemoryTokenStore::default());
    let (user, _) = ScriptedUser::new(&idp, &hub, Account::owner(), Decision::Approve);
    let client =
        client_for(&format!("{}/api", hub.base), Arc::clone(&store), Arc::clone(&user), 30);
    let grant = browser_login(&client, &user, &hub, store.as_ref()).await;

    let outcome = client.logout(None, None).await.expect("logout");
    assert_eq!(outcome.store, ClearOutcome::Removed);
    assert_eq!(outcome.revocation, RevocationOutcome::Revoked);
    assert_eq!(hub.raw_info(&grant.access_token).await, StatusCode::UNAUTHORIZED);
    assert_eq!(
        hub.raw_refresh(grant.refresh_token.as_deref().expect("refresh token")).await,
        (StatusCode::BAD_REQUEST, "invalid_grant".to_owned())
    );
    assert!(stored(store.as_ref(), &hub.resource, &hub.base).await.is_none());
    let before = hub.read_hits.load(Ordering::SeqCst);
    assert!(read(&client).await.is_err());
    assert_eq!(
        hub.read_hits.load(Ordering::SeqCst),
        before + 1,
        "a signed-out client does not retry"
    );
}

#[tokio::test]
async fn server_rejected_unexpired_access_recovers_with_one_bounded_refresh() {
    let idp = Idp::start().await;
    let hub = Hub::start(&idp, "/api", FAST_DEVICE).await;
    let store: Arc<dyn TokenStore> = Arc::new(InMemoryTokenStore::default());
    let (user, _) = ScriptedUser::new(&idp, &hub, Account::owner(), Decision::Approve);
    let client =
        client_for(&format!("{}/api", hub.base), Arc::clone(&store), Arc::clone(&user), 30);
    let grant = browser_login(&client, &user, &hub, store.as_ref()).await;
    assert!(
        grant.expires_at.is_some_and(|expiry| expiry > now() + 60),
        "the access token is not locally expired"
    );

    // The resource stops accepting the current token and its challenge omits resource_metadata:
    // recovery must use the issuer metadata this client already validated.
    hub.rejected.lock().expect("rejected tokens").insert(grant.access_token.clone());
    hub.omit_challenge_metadata.store(true, Ordering::SeqCst);
    let (info, token) =
        (hub.read_hits.load(Ordering::SeqCst), hub.token_hits.load(Ordering::SeqCst));
    read(&client).await.expect("recovered read");
    assert_eq!(hub.read_hits.load(Ordering::SeqCst), info + 2, "one rejected read and one retry");
    assert_eq!(hub.token_hits.load(Ordering::SeqCst), token + 1, "one forced refresh");
    let refreshed =
        stored(store.as_ref(), &hub.resource, &hub.base).await.expect("refreshed grant");
    assert_ne!(refreshed.access_token, grant.access_token);

    // A resource that rejects everything gets exactly one refresh and one retry, never a loop.
    hub.reject_all.store(true, Ordering::SeqCst);
    let (info, token) =
        (hub.read_hits.load(Ordering::SeqCst), hub.token_hits.load(Ordering::SeqCst));
    assert!(matches!(read(&client).await, Err(RemoteError::AuthenticationRequired { .. })));
    assert_eq!(hub.read_hits.load(Ordering::SeqCst), info + 2);
    assert_eq!(hub.token_hits.load(Ordering::SeqCst), token + 1);
}

// ── Issuer and resource identity ─────────────────────────────────────────────

#[tokio::test]
async fn grants_from_two_issuers_stay_isolated_in_one_credential_store() {
    let idp = Idp::start().await;
    let hub_a = Hub::start(&idp, "/api", FAST_DEVICE).await;
    let hub_b = Hub::start(&idp, "/api", FAST_DEVICE).await;
    let store: Arc<dyn TokenStore> = Arc::new(InMemoryTokenStore::default());
    let (user_a, _) = ScriptedUser::new(&idp, &hub_a, Account::owner(), Decision::Approve);
    let (user_b, _) =
        ScriptedUser::new(&idp, &hub_b, Account::named("second-subject"), Decision::Approve);
    let client_a =
        client_for(&format!("{}/api", hub_a.base), Arc::clone(&store), Arc::clone(&user_a), 30);
    let client_b =
        client_for(&format!("{}/api", hub_b.base), Arc::clone(&store), Arc::clone(&user_b), 30);
    let grant_a = browser_login(&client_a, &user_a, &hub_a, store.as_ref()).await;
    let grant_b = browser_login(&client_b, &user_b, &hub_b, store.as_ref()).await;
    assert_ne!(grant_a.issuer, grant_b.issuer);

    // Neither hub accepts the other's credentials.
    assert_eq!(hub_b.raw_info(&grant_a.access_token).await, StatusCode::UNAUTHORIZED);
    assert_eq!(hub_a.raw_info(&grant_b.access_token).await, StatusCode::UNAUTHORIZED);
    assert_eq!(
        hub_b.raw_refresh(grant_a.refresh_token.as_deref().expect("refresh token")).await.1,
        "invalid_grant"
    );
    // A client never adopts another resource's metadata.
    assert!(client_a.discover(&hub_b.metadata_url()).await.is_err());

    assert_eq!(client_a.logout(None, None).await.expect("logout A").store, ClearOutcome::Removed);
    assert!(stored(store.as_ref(), &hub_a.resource, &hub_a.base).await.is_none());
    assert_eq!(
        stored(store.as_ref(), &hub_b.resource, &hub_b.base).await.map(|grant| grant.access_token),
        Some(grant_b.access_token)
    );
    read(&client_b).await.expect("issuer B grant survives issuer A logout");
}

#[tokio::test]
async fn trailing_slash_resource_identity_is_exact_through_login_reuse_refresh_and_logout() {
    let idp = Idp::start().await;
    let hub = Hub::start(&idp, "/api/", FAST_DEVICE).await;
    let store: Arc<dyn TokenStore> = Arc::new(InMemoryTokenStore::default());
    let (user, _) = ScriptedUser::new(&idp, &hub, Account::owner(), Decision::Approve);
    let slash_url = format!("{}/api/", hub.base);
    let client = client_for(&slash_url, Arc::clone(&store), Arc::clone(&user), 30);
    assert_eq!(client.oauth_resource(), hub.resource);
    let grant = browser_login(&client, &user, &hub, store.as_ref()).await;
    assert_eq!(grant.resource, format!("{}/api/", hub.base));
    assert!(
        stored(store.as_ref(), &format!("{}/api", hub.base), &hub.base).await.is_none(),
        "no record under the slashless resource"
    );

    // The slashless form is a different resource: discovery refuses it and, although a grant
    // for the slash form is stored, none matches it.
    let slashless =
        client_for(&format!("{}/api", hub.base), Arc::clone(&store), Arc::clone(&user), 30);
    let refused = slashless.discover(&hub.metadata_url()).await.expect_err("different resource");
    assert!(refused.to_string().contains("does not identify the configured remote"), "{refused}");
    assert!(!slashless.load_stored_session(&hub.base).await.expect("store"));
    assert_eq!(
        slashless.logout(Some(&hub.base), None).await.expect("logout").store,
        ClearOutcome::Absent
    );
    assert!(
        stored(store.as_ref(), &hub.resource, &hub.base).await.is_some(),
        "the slash grant is untouched"
    );

    // Reuse from another client (for example a later CLI process).
    let reused = client_for(&slash_url, Arc::clone(&store), Arc::clone(&user), 30);
    assert!(reused.load_stored_session(&hub.base).await.expect("store"));
    read(&reused).await.expect("reused grant");
    // The hub checks the refresh resource by exact string, so success proves the identity.
    let metadata = reused.authorization_server_metadata(&hub.base).await.expect("issuer metadata");
    reused.refresh(&metadata).await.expect("refresh bound to the exact resource");
    read(&reused).await.expect("refreshed grant");
    let outcome = reused.logout(None, None).await.expect("logout");
    assert_eq!(
        (outcome.store, outcome.revocation),
        (ClearOutcome::Removed, RevocationOutcome::Revoked)
    );
    assert!(stored(store.as_ref(), &hub.resource, &hub.base).await.is_none());
}

// ── Upstream OIDC verification ───────────────────────────────────────────────

async fn verify(
    idp: &Idp,
    account: Account,
    nonce: &str,
    exchange_redirect: &str,
) -> Result<agentpalace_demo_hub::GoogleIdClaims, GoogleClaimError> {
    let mut google =
        reqwest::Url::parse("https://accounts.google.com/o/oauth2/v2/auth").expect("Google URL");
    google
        .query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", GOOGLE_CLIENT_ID)
        .append_pair("redirect_uri", "https://hub.example/auth/google/callback")
        .append_pair("scope", "openid email")
        .append_pair("state", "state")
        .append_pair("nonce", "expected-nonce");
    let (code, _) = idp.authorize(google.as_str(), account);
    idp.adapter().exchange_and_verify(&code, nonce, exchange_redirect).await
}

#[tokio::test]
async fn signed_id_tokens_are_verified_for_signature_and_every_required_claim() {
    let idp = Idp::start().await;
    let callback = "https://hub.example/auth/google/callback";
    let claims = verify(&idp, Account::owner(), "expected-nonce", callback)
        .await
        .expect("valid RS256 ID token");
    assert_eq!(
        (claims.sub.as_str(), claims.email.as_str()),
        ("owner-subject", "owner-subject@example.test")
    );
    assert!(claims.additional.contains_key("iat"), "realistic standard claims are accepted");

    let cases = [
        (
            "unpublished signing key",
            Account::owner().signed(Signing::UnpublishedKey),
            GoogleClaimError::Signature,
        ),
        (
            "HS256 algorithm confusion",
            Account::owner().signed(Signing::Hs256),
            GoogleClaimError::Signature,
        ),
        ("missing kid", Account::owner().signed(Signing::MissingKid), GoogleClaimError::Signature),
        (
            "issuer",
            Account::owner().claim("iss", serde_json::json!("https://issuer.invalid")),
            GoogleClaimError::Issuer,
        ),
        (
            "audience",
            Account::owner().claim("aud", serde_json::json!("another-client")),
            GoogleClaimError::Audience,
        ),
        (
            "expiry",
            Account::owner().claim("exp", serde_json::json!(now() - 5)),
            GoogleClaimError::Expired,
        ),
        (
            "missing expiry",
            Account::owner().claim("exp", serde_json::Value::Null),
            GoogleClaimError::Expired,
        ),
        (
            "nonce",
            Account::owner().claim("nonce", serde_json::json!("replayed-nonce")),
            GoogleClaimError::Nonce,
        ),
        (
            "unverified email",
            Account::owner().claim("email_verified", serde_json::json!(false)),
            GoogleClaimError::EmailUnverified,
        ),
        (
            "missing email",
            Account::owner().claim("email", serde_json::Value::Null),
            GoogleClaimError::MissingSubject,
        ),
        (
            "empty subject",
            Account::owner().claim("sub", serde_json::json!("")),
            GoogleClaimError::MissingSubject,
        ),
    ];
    for (label, account, expected) in cases {
        assert_eq!(
            verify(&idp, account, "expected-nonce", callback).await.map(|claims| claims.sub),
            Err(expected),
            "{label}"
        );
    }
}

#[tokio::test]
async fn upstream_exchange_and_network_failures_fail_closed() {
    let idp = Idp::start().await;
    let callback = "https://hub.example/auth/google/callback";
    // Google binds the code to the redirect it was issued for; presenting the device callback fails.
    assert_eq!(
        verify(
            &idp,
            Account::owner(),
            "expected-nonce",
            "https://hub.example/auth/google/device-callback"
        )
        .await
        .map(|c| c.sub),
        Err(GoogleClaimError::Upstream)
    );
    idp.state().token_down = true;
    assert_eq!(
        verify(&idp, Account::owner(), "expected-nonce", callback).await.map(|c| c.sub),
        Err(GoogleClaimError::Upstream)
    );
    idp.state().token_down = false;
    idp.state().jwks_down = true;
    assert_eq!(
        verify(&idp, Account::owner(), "expected-nonce", callback).await.map(|c| c.sub),
        Err(GoogleClaimError::Upstream)
    );
    let unreachable = GoogleOidcVerifierAdapter::new_with_endpoints(
        idp.google(),
        "http://127.0.0.1:1/token",
        "http://127.0.0.1:1/jwks",
    )
    .expect("adapter");
    assert_eq!(
        unreachable.exchange_and_verify("code", "expected-nonce", callback).await.map(|c| c.sub),
        Err(GoogleClaimError::Upstream)
    );
}

#[tokio::test]
async fn browser_binding_cookies_are_secure_outside_loopback_demo_mode() {
    let idp = Idp::start().await;
    for (mode, issuer, secure) in [
        (GatewayMode::Secure, "https://hub.example", true),
        (GatewayMode::LoopbackDemo, "http://127.0.0.1:8080", false),
    ] {
        let config = GatewayConfig {
            issuer: issuer.to_owned(),
            resource: format!("{issuer}/api"),
            mode,
            google: idp.google(),
            native_client: NativeClient {
                client_id: NATIVE_CLIENT_ID.to_owned(),
                redirect_uri: "http://127.0.0.1:49152/callback".to_owned(),
            },
        };
        let gateway = Gateway::new(config, Arc::new(AllowSubjects)).expect("gateway configuration");
        let (listener, base) = bind().await;
        serve(listener, gateway.router());
        let mut authorize =
            reqwest::Url::parse(&format!("{base}/authorize")).expect("authorize URL");
        authorize
            .query_pairs_mut()
            .append_pair("client_id", NATIVE_CLIENT_ID)
            .append_pair("redirect_uri", "http://127.0.0.1:50125/callback")
            .append_pair("code_challenge", "challenge")
            .append_pair("state", "state")
            .append_pair("resource", &format!("{issuer}/api"));
        let response = Browser::new().get(authorize.as_str()).await;
        let cookie = response
            .headers()
            .get(header::SET_COOKIE)
            .and_then(|value| value.to_str().ok())
            .expect("binding cookie")
            .to_owned();
        assert!(
            cookie.starts_with("agentpalace_browser=") && cookie.contains("HttpOnly"),
            "{cookie}"
        );
        assert_eq!(cookie.contains("; Secure"), secure, "{mode:?}: {cookie}");
    }
}
