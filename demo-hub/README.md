# Local demo hub

This example runs a Google-backed authorization gateway and a pinned AgentPalace engine on one computer. The engine source is fixed at commit `ba2bb3d74845314d4f4031047101ad861dc49fb9` in [Dockerfile](Dockerfile); the gateway is built from this checkout. Only `127.0.0.1:8080` is published. The engine's REST and MCP ports stay on the Compose network. The engine uses real local embeddings by default. First boot downloads model assets into the persistent `palace_data` volume; no note content is sent to an embedding API.

## Prepare

1. Create your own Google OAuth **Web application** and register exactly `http://localhost:8080/auth/google/callback` and `http://localhost:8080/auth/google/device-callback`. Follow [Google setup](../docs/Demo-Hub-Google-Setup.md). The gateway contacts Google over HTTPS; no Google project or credentials are created by this package.
2. In this directory, copy `.env.example` to `.env`, then set your Google web client ID and your initial admin email. For a non-Gmail address, set `DEMO_HUB_ADMIN_MAILBOX_PROVEN=true` only after you have verified control of that mailbox. This is an explicit administrator attestation, not automatic Google proof.
3. Create `secrets/google-client-secret` containing only the Google web client secret. Keep the secret file and `.env` local; Git ignores both.

For example, from this directory:

```sh
cp .env.example .env
mkdir -p secrets
# Paste the real secret into secrets/google-client-secret using your local editor.
chmod 600 secrets/google-client-secret
docker compose up --build --wait -d
curl --fail http://localhost:8080/v1/health
```

On Windows PowerShell, the preparation commands are `Copy-Item .env.example .env`, `New-Item -ItemType Directory -Force secrets`, and `notepad secrets/google-client-secret`; then use the same `docker compose up --build --wait -d` command. The browser on the Windows host must reach `http://localhost:8080`.

The build fetches the pinned engine commit and locked Rust dependencies. The first engine start downloads a real embedding model, so it needs outbound access and may take several minutes. Its cache lives under `palace_data` and survives container restarts; after a successful first start, set `AGENTPALACE_EMBED_ALLOW_DOWNLOADS=0` in `.env` to require offline starts. Set `AGENTPALACE_STUB_EMBEDDINGS=1` only for offline auth/packaging tests: its placeholder vectors do not give representative search relevance. Do not mix stub and real embeddings in the same palace; reset this demo's volumes before switching modes. Run `docker compose ps` to inspect health and `docker compose logs -f gateway engine` for startup diagnostics. The first boot creates three named volumes: `palace_data` (engine config and data), `engine_tokens` (private owner-scoped engine credentials), and `hub_state` (access policy, identity bindings, audit). The gateway creates the admin entry **only if** the policy file is absent. Existing policy and role edits are never overwritten by a restart.

```sh
docker compose stop                   # keep containers and volumes
docker compose start                  # restart without rebuilding
docker compose down                   # remove containers, retain data
docker compose down --volumes         # deliberate reset: erase this demo's policy, bindings, tokens and palace
```

The final command deletes the demo volumes and cannot be undone. It does not touch another AgentPalace installation.

## Connect a local client

Merge [client-config.example.json](client-config.example.json) into the configuration used by your local AgentPalace MCP server. Append the `demo` entry to `federation.remotes` and add `wing_demo` to `federation.wings`; keep every existing remote, route, and other setting. Restart the MCP connection to load the changed configuration. The added remote and route are:

```json
{
  "federation": {
    "remotes": [{
      "name": "demo",
      "url": "http://localhost:8080",
      "oauth": {
        "client_id": "agentpalace-local-demo",
        "allow_loopback_demo": true,
        "login_mode": "auto"
      }
    }],
    "default_mode": "local",
    "wings": {
      "wing_demo": {"mode": "remote", "remote": "demo"}
    }
  }
}
```

If you are adding `demo` to a config that already has one remote and uses `default_mode: combined` or `remote`, set `federation.default_remote` to the **existing** remote. Also give every existing remote/combined wing or coordination rule an explicit `remote` name; single-remote inference becomes ambiguous once `demo` is added. This preserves the existing routes while only `wing_demo` points to the demo.

The exact `allow_loopback_demo` opt-in is necessary for this localhost issuer. It does not permit other HTTP OAuth servers. The MCP server uses the configured remote directly; the public gateway's `/mcp` path remains private/404.

Ask the connected MCP agent to read `wing_demo`. On the first protected request it receives `authentication_required` and should immediately call `agentpalace_remote_auth_start` with `{"remote":"demo"}`. With `login_mode: auto`, a desktop MCP process opens the system browser for a loopback callback and returns `authorization_url` as a manual link if no tab appears. When a browser/callback is unavailable or launching the browser fails, it returns `verification_uri` and `user_code` instead; open that link and enter the code. The agent calls `agentpalace_remote_auth_status` until it reports `authenticated`, then retries the original MCP request. For WSL or other headless clients, set `login_mode: device` if you need to sign in from a different browser profile without an inbound callback. Do not paste private device codes, bearer tokens, or client secrets into a tool response.

For device mode, enter the displayed user code at [http://localhost:8080/device/verify](http://localhost:8080/device/verify). The browser consent page confirms a login, and [your connections](http://localhost:8080/hub/connections) lists and revokes only grants associated with your signed-in browser session. A gateway restart preserves policy and data but ends in-memory browser/OAuth sessions; sign in again afterward.

To exercise roles, add your second test email through the admin-only `/hub/v1/access/{email}` API, using a current admin browser session, its `agentpalace_csrf` cookie as `X-CSRF-Token`, and the revision from `GET /hub/v1/access` as `If-Match`. Grant `write` and `readonly` to separate test accounts. Google's test-user list and the hub allowlist are separate: both must admit the account. As a writer, mine a project whose wing is `wing_demo`, then search it from a second client. A readonly user can search but a write must be rejected; a non-admin access edit must be rejected. The returned drawer and change metadata must carry the writer's authenticated owner identity, independently of the LLM's claimed agent name. Restart with `docker compose restart`, sign in again, and confirm the same policy, identity binding, palace content, and owner attribution. The [federation guide](../docs/Federation.md) describes wing routing and provenance in detail.

## Local reachability

On Docker Desktop for Windows or macOS, open `http://localhost:8080` in a browser on the host and run `curl http://localhost:8080/v1/health` from the client environment. In WSL, Docker Desktop's WSL integration usually makes host localhost reachable; verify it with that curl command before device login. If your WSL network mode cannot reach that URL, use a desktop client or adjust your local Docker/WSL integration so both browser and client reach the **same** loopback origin. Do not change the Compose port binding to `0.0.0.0` or replace the OAuth origin with an arbitrary LAN URL. Phones and remote SSH clients cannot use this loopback-only package without a separate, intentionally secured deployment.

The real-browser flow requires tester-owned Google credentials. Automated tests use a mock OIDC verifier and do not prove a live Google account, Google resource, or cloud deployment.