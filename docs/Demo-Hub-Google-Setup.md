# Google OAuth setup for the local demo

Status: preparation guide, 2026-09-17. The Docker demo is still a proposal.
The localhost URL and callback below are the proposed package defaults; confirm
them against the implemented example before creating credentials. No Google
Cloud resources have been created by this work.

The tester performs this setup in their own Google Cloud project. It provides
Google sign-in for containers running on their machine; it does not deploy
AgentPalace to Google Cloud. No hosted domain or public TLS endpoint is needed.

## 1. Configure the Google application

Open the [Google Cloud Console](https://console.cloud.google.com/) and select
or create a project for your experiment. In Google Auth Platform:

1. Configure Branding with an application name, support email, and contact email.
2. Choose an audience suitable for your test. For personal accounts, use
   External and keep the application in Testing; add your test accounts under
   Audience. An organization's Internal option only suits eligible users.
3. Request only basic sign-in information: openid and email. Do not add
   unrelated API permissions.

Google's [consent configuration guide](https://developers.google.com/workspace/guides/configure-oauth-consent)
describes these settings. Organization policy may restrict who can create or
use OAuth applications.

## 2. Create the Google OAuth client

Under Clients, create a **Web application** client for the demo gateway.
Register this exact proposed authorized redirect URI:

~~~text
http://localhost:8080/auth/google/callback
~~~

Save the client ID and client secret privately. Google supports localhost HTTP
redirects for testing; the registered scheme, host, port, and path must match
the gateway's callback.
[Google web-server OAuth setup](https://developers.google.com/identity/protocols/oauth2/web-server#creatingcred).

This is a web client because the gateway handles Google's callback, even though
Docker runs locally. It is separate from the AgentPalace public/native client
registration that the demo gateway supplies for connecting local palaces.
Both desktop and device-code login use this same gateway-to-Google web login;
do not create a Google TV/device client.

The proposed gateway uses server-side redirects, so browser JavaScript origins
are not needed for this flow. If implementation changes that, update this guide
to match before use.

## 3. Supply the tester's local settings

The package will provide an example environment/configuration file with these
inputs (exact variable names will be finalized with implementation):

| Setting | Value |
|---|---|
| Google client ID | From your Google web application |
| Google client secret | From that application; local secret, never committed |
| Initial admin email | The Google account you will use to test |
| Local hub origin | http://localhost:8080 |
| Google callback | http://localhost:8080/auth/google/callback |

Bootstrap the initial admin into the editable allowlist once. For role testing,
add your other test emails as write or readonly. Google's app/test-user settings
and the hub allowlist are separate checks; Google sign-in alone grants no
palace access. The package must not contain the maintainer's email or credentials.

## 4. Run and exercise the example

Once implemented, the package's README will provide its exact Docker Compose
start, stop, and deliberate reset commands. The intended walkthrough is:

1. Start the local containers and open the local hub in your browser.
2. Sign in with your admin account.
3. Configure the local palace with the demo remote URL and its explicit
   loopback demo-auth mode.
4. Connect using browser login, then repeat using the device-code flow.
5. Add a memory as a writer, read it as readonly, and verify its owner attribution.
6. Verify readonly writes and non-admin access-list changes are rejected.
7. Restart the containers and verify data and access-list changes persist.

No cloud hosting, backup setup, or retention policy is part of this example.

## Local browser and WSL notes

The browser and connecting client both need to reach the configured hub origin.
A localhost link names the browser's own machine: it will not open this Docker
demo from a phone. Device login still works from the Windows browser while the
client runs in WSL, provided both can reach the same local hub.

WSL/Docker placement affects localhost reachability. Validate the documented
Docker Desktop/WSL configuration during implementation; device login removes the
callback into the client, not the need to reach the hub. Do not solve a local
test by publishing the container on every network interface.

For an SSH-hosted client, device authorization remains supported when the hub
is reachable from that client and the browser. Exposing or tunneling a remotely
hosted hub is outside this local package's required setup.

## Troubleshooting

- **redirect_uri_mismatch:** compare the full registered callback to the
  gateway configuration; localhost and 127.0.0.1 are not interchangeable values.
- **Google access denied:** check the account, audience/test settings, and any
  organization restrictions.
- **Hub access denied after Google login:** check enabled status, email, role,
  and account binding in the hub allowlist.
- **Local page unreachable:** check container health, loopback port publication,
  and where Docker/WSL are running.
- **Repeated login after changing configuration:** remove the local authorization
  through the documented logout flow and reconnect to the intended hub origin.

Do not paste client secrets, access tokens, or refresh tokens into issue reports.
