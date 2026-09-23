//! Local-only hosting entry point for the demo authorization gateway.

use std::{
    collections::BTreeSet, env, error::Error, fs, net::SocketAddr, path::PathBuf, sync::Arc,
};

use agentpalace_core::Issuer;
use agentpalace_demo_hub::{
    DenyAllAdmission, GOOGLE_SCOPES, Gateway, GatewayConfig, GatewayMode, GoogleOidcConfig,
    GoogleOidcVerifierAdapter, NativeClient,
    access_policy::{AccessPolicyStore, BootstrapAdmin},
    forwarding::{Forwarder, PrivateTokenProvisioner},
};

fn required(name: &str) -> Result<String, Box<dyn Error>> {
    let value = env::var(name).map_err(|_| format!("{name} is required"))?;
    if value.trim().is_empty() {
        return Err(format!("{name} must not be empty").into());
    }
    Ok(value)
}

struct RuntimeSettings {
    config: GatewayConfig,
    bind: SocketAddr,
    state_dir: PathBuf,
    token_file: PathBuf,
    admin: BootstrapAdmin,
}

fn settings() -> Result<RuntimeSettings, Box<dyn Error>> {
    if required("DEMO_HUB_LOOPBACK_AUTH")? != "true" {
        return Err(
            "DEMO_HUB_LOOPBACK_AUTH must be exactly true for this localhost HTTP example".into()
        );
    }
    let origin = required("DEMO_HUB_ORIGIN")?;
    if origin != "http://localhost:8080" {
        return Err("DEMO_HUB_ORIGIN must be exactly http://localhost:8080".into());
    }
    let secret_path = PathBuf::from(required("DEMO_HUB_GOOGLE_CLIENT_SECRET_FILE")?);
    let secret = fs::read_to_string(&secret_path)
        .map_err(|_| "Google client secret file is missing or unreadable")?;
    let secret = secret.trim();
    if secret.is_empty() {
        return Err("Google client secret file is empty".into());
    }
    let config = GatewayConfig {
        issuer: origin.clone(),
        resource: origin,
        mode: GatewayMode::LoopbackDemo,
        google: GoogleOidcConfig {
            client_id: required("DEMO_HUB_GOOGLE_CLIENT_ID")?,
            client_secret: secret.to_owned(),
            issuer: Issuer::new("https://accounts.google.com")?,
            scopes: GOOGLE_SCOPES.into_iter().map(str::to_owned).collect::<BTreeSet<_>>(),
        },
        native_client: NativeClient {
            client_id: "agentpalace-local-demo".into(),
            redirect_uri: "http://127.0.0.1:8766/callback".into(),
        },
    };
    config.validate()?;
    let bind = required("DEMO_HUB_BIND")?.parse::<SocketAddr>()?;
    if bind.port() != 8080 {
        return Err("DEMO_HUB_BIND must use container port 8080".into());
    }
    let state_dir = PathBuf::from(required("DEMO_HUB_STATE_DIR")?);
    let token_file = PathBuf::from(required("DEMO_HUB_ENGINE_TOKEN_FILE")?);
    let admin = BootstrapAdmin {
        email: required("DEMO_HUB_BOOTSTRAP_ADMIN_EMAIL")?,
        mailbox_proven: env::var("DEMO_HUB_ADMIN_MAILBOX_PROVEN").as_deref() == Ok("true"),
    };
    Ok(RuntimeSettings { config, bind, state_dir, token_file, admin })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let RuntimeSettings { config, bind, state_dir, token_file, admin } = settings()?;
    fs::create_dir_all(&state_dir)?;
    let verifier = Arc::new(GoogleOidcVerifierAdapter::new(config.google.clone())?);
    let forwarder = Arc::new(Forwarder::new(&required("DEMO_HUB_ENGINE_ORIGIN")?)?);
    let provisioner = Arc::new(PrivateTokenProvisioner::new(token_file)?);
    let store = Arc::new(AccessPolicyStore::open(
        state_dir.join("access-policy.json"),
        state_dir.join("identity-bindings.json"),
        state_dir.join("access-audit.jsonl"),
        Some(admin),
    )?);
    let app = Gateway::new(config, Arc::new(DenyAllAdmission))?
        .with_google_verifier(verifier)
        .with_forwarder(forwarder)
        .with_token_provisioner(provisioner)
        .with_access_policy_store(store)
        .router();
    let listener = tokio::net::TcpListener::bind(bind).await?;
    eprintln!("demo hub listening on {bind}");
    axum::serve(listener, app).await?;
    Ok(())
}
