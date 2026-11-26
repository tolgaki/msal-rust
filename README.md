# Microsoft Authentication Library (MSAL) for Rust

[![Crates.io](https://img.shields.io/crates/v/msal.svg)](https://crates.io/crates/msal)
[![Documentation](https://docs.rs/msal/badge.svg)](https://docs.rs/msal)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/tolgaki/msal-rust/actions/workflows/ci.yml/badge.svg)](https://github.com/tolgaki/msal-rust/actions)

A Rust implementation of the [Microsoft Authentication Library (MSAL)](https://learn.microsoft.com/en-us/entra/msal/),
enabling authentication with the Microsoft identity platform (Azure AD, Microsoft
personal accounts, Azure AD B2C).

This is an independent Rust port, not an official Microsoft-supported MSAL
library. Official implementations include
[msal-js](https://github.com/AzureAD/microsoft-authentication-library-for-js),
[MSAL.NET](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet),
[MSAL Python](https://github.com/AzureAD/microsoft-authentication-library-for-python),
[MSAL Java](https://github.com/AzureAD/microsoft-authentication-library-for-java),
and [MSAL Go](https://github.com/AzureAD/microsoft-authentication-library-for-go).

## Features

- **Public client** authentication for desktop apps, CLI tools, and devices
- **Confidential client** authentication for web apps, daemons, and APIs
- **Brokered authentication** via Windows WAM and macOS Enterprise SSO for device-bound tokens and system-wide SSO
- In-memory **token cache** with client, account, tenant, environment and request-context isolation, plus import/export for caller-owned protected persistence
- **Authority discovery** via OpenID Connect metadata
- Support for Azure AD, Azure AD B2C, ADFS, and CIAM authorities
- Fully **async** with [Tokio](https://tokio.rs/)

### Supported Authentication Flows

| Flow | Public | Confidential |
|------|--------|--------------|
| Authorization Code (PKCE) | Yes | Yes |
| Device Code | Yes | - |
| Client Credentials | - | Yes |
| On-Behalf-Of | - | Yes |
| Refresh Token | Yes | Yes |
| Silent (cache + refresh) | Yes | Yes |
| Username/Password (ROPC) | Yes | - |
| Interactive (native broker) | Yes | - |

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
msal = "0.1"
tokio = { version = "1", features = ["full"] }
```

For native broker support:

```toml
# Windows (Web Account Manager)
msal = { version = "0.1", features = ["broker-wam"] }

# macOS (Enterprise SSO plug-in)
msal = { version = "0.1", features = ["broker-macos"] }
```

## Quick Start

### Device Code Flow (CLI apps)

```rust,no_run
use msal::{Configuration, PublicClientApplication};
use msal::request::DeviceCodeRequest;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Configuration::builder("your-client-id")
        .authority("https://login.microsoftonline.com/common")
        .build();

    let app = PublicClientApplication::new(config)?;

    let result = app
        .acquire_token_by_device_code(
            DeviceCodeRequest::new(vec!["user.read".into()]),
            |info| println!("{}", info.message),
        )
        .await?;

    println!("Signed in, access token: {}...", &result.access_token[..20]);
    Ok(())
}
```

### Client Credentials (Daemons / Services)

```rust,no_run
use msal::{Configuration, ConfidentialClientApplication};
use msal::request::ClientCredentialRequest;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Configuration::builder("your-client-id")
        .authority("https://login.microsoftonline.com/your-tenant-id")
        .client_secret("your-client-secret")
        .build();

    let app = ConfidentialClientApplication::new(config)?;

    let request = ClientCredentialRequest::new(
        vec!["https://graph.microsoft.com/.default".into()],
    );

    let result = app.acquire_token_by_client_credential(request).await?;
    println!("Token: {}...", &result.access_token[..20]);
    Ok(())
}
```

### Authorization Code Flow (Web Apps)

```rust,no_run
use msal::{Configuration, PublicClientApplication};
use msal::request::{AuthorizationCodeRequest, SilentFlowRequest};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Configuration::builder("your-client-id")
        .authority("https://login.microsoftonline.com/common")
        .build();

    let app = PublicClientApplication::new(config)?;

    // Step 1: Generate the authorization URL (synchronous).
    let scopes = vec!["user.read".into()];
    let (auth_url, pkce) = app.authorization_url(
        &scopes,
        "http://localhost:3000/redirect",
        None,
    )?;

    println!("Visit: {auth_url}");

    // Step 2: Exchange the authorization code.
    let mut request = AuthorizationCodeRequest::new(
        "code-from-redirect".into(),
        scopes.clone(),
        "http://localhost:3000/redirect".into(),
    );
    request.code_verifier = Some(pkce.verifier);
    request.nonce = Some(pkce.nonce);

    let result = app.acquire_token_by_code(request).await?;
    println!("Signed in as: {}", result.account.unwrap().username);

    // Step 3: Silent token renewal (from cache or refresh token).
    // let silent = SilentFlowRequest::new(scopes, account);
    // let cached = app.acquire_token_silent(silent).await?;
    Ok(())
}
```

### Brokered Authentication (Windows / macOS)

The Tokio-main sample below works with Windows WAM. On macOS, a GUI must
already drive its main run loop, or a CLI must run the Tokio work elsewhere and
drive `run_main_loop_until` on its main thread. **Do not run this sample
unchanged as a macOS CLI**: setting the broker alone does not run Apple's loop.

```rust,no_run
use msal::{Configuration, PublicClientApplication};
use msal::broker::BrokerTokenRequest;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Configuration::builder("your-client-id")
        .authority("https://login.microsoftonline.com/your-tenant-id")
        .build();

    let app = PublicClientApplication::new(config)?;

    // Set up the platform-specific broker.
    #[cfg(all(target_os = "windows", feature = "broker-wam"))]
    {
        let broker = msal::broker::wam::WamBroker::new().await?;
        app.set_broker(Box::new(broker)).await;
    }
    #[cfg(all(target_os = "macos", feature = "broker-macos"))]
    {
        // For CLI tools (unsigned binaries):
        let broker = msal::broker::macos::MacOsBroker::new_for_cli(
            "https://login.microsoftonline.com/your-tenant-id",
        )?;
        // For .app bundles, use MacOsBroker::new("msauth.{bundle_id}://auth", authority)
        app.set_broker(Box::new(broker)).await;
    }

    let request = BrokerTokenRequest {
        scopes: vec!["user.read".into()],
        account: None,
        claims: None,
        correlation_id: None,
        window_handle: None,
        authentication_scheme: Default::default(),
        pop_params: None,
        force_refresh: false,
        authority: None,
        extra_query_parameters: Default::default(),
        cancellation_token: None,
    };

    let result = app.acquire_token_interactive(request).await?;
    println!("Token: {}...", &result.access_token[..20]);
    Ok(())
}
```

## Authentication contracts and limits

User login requests include `openid profile offline_access` and `client_info=1`.
`home_account_id` comes from `client_info`; the resource tenant and local account
come from the ID token, **not** from the home tenant. Missing/malformed identity
on a login fails explicitly. Account selection compares home ID, local ID,
tenant and environment, never a display username.

Refresh responses can omit the ID token, `client_info`, scopes and a rotated
refresh token. Silent refresh keeps the previously authenticated cache identity;
direct refresh accepts that identity in `RefreshTokenRequest.account`. Supply
only trusted state associated with that refresh token. With no prior account
and no new ID token, the result has `account: None` and is not user-cached.
New response identity must match the requested account, tenant and environment.

All OAuth request types expose `claims`, `extra_query_parameters` and
`cancellation_token`. Claims are sent on device initiation, polling and token
exchanges, without an unchallenged retry. OAuth interaction errors preserve
`error`, `description`, `correlation_id`, `claims` and `suberror` in
`MsalError::InteractionRequiredWithClaims`. Use `is_interaction_required()` and
`claims()` instead of matching only the legacy local `InteractionRequired`.

`extra_query_parameters: BTreeMap<String, String>` sends opaque server
parameters in the OAuth form body. `authorization_url_with_options` also sends
them on `/authorize`. Library-owned fields such as `client_id`, `claims`,
`scope`, `nonce`, `state`, credentials and PKCE fields cannot be overridden.
The existing `client_session` wire parameter is permitted. It is sent to the
server unchanged; neither successful transmission nor an
`access_token.client_session` claims-cache partition proves server enforcement.
Native mapping follows the official adapter/extension contracts described
below, but installed-broker compatibility and server enforcement still require
separate runtime validation. Consumers requiring verified broker-enforced agent
sessions must retain that guard.

Claims and extra parameters partition both access and refresh cache entries.
A new claims/session context cannot reuse a token from another context; it may
require interactive acquisition to seed its own refresh entry. This is cache
isolation, not session binding. `force_refresh` skips the local access cache.
Broker requests must honor it natively or return `Unsupported`, never silently
ignore it. Broker failures do not automatically fall back to a different flow.

`request::CancellationToken::new()`, `cancel()`, `is_cancelled()` and
`cancelled().await` support cooperative HTTP/device cancellation. Cancellation
drops the HTTP/body/polling future and prevents subsequent cache writes. It does
not revoke a token, invalidate an already-issued server device session, or
guarantee that the server did not complete a submitted request. Native
cancellation support is platform-specific; an unsupported guarantee must error,
not leave UI running while claiming it was cancelled.

Both applications expose `export_cache() -> Result<TokenCacheSnapshot>` and
`import_cache(snapshot) -> Result<()>`. The serde-compatible snapshot is
**plaintext secret-bearing in-memory data**, not a file format or protected
store. Import atomically replaces this client's cache and rejects a different
client ID or malformed identity. The caller owns encryption, integrity,
cross-process transactions and deletion. Native broker refresh tokens remain
under OS ownership. Legacy cache convenience lookups remain available; new
fallible `try_` APIs and acquisition methods surface poisoned-lock errors.

### ID-token trust boundary

The public client's identity input is a direct response from its configured
TLS token endpoint or native broker, not a JWT supplied by an arbitrary caller.
Endpoint HTTP redirects are disabled; HTTP loopback is permitted only for
development and mock tests. Response parsing checks audience, issuer, expiry,
tenant and requested-account consistency. Public authorization-code exchanges
require the original PKCE verifier **and nonce**; copy both from the returned
`PkceParams`. Validate redirect state in the caller before exchanging the code.

`crypto::decode_jwt_payload` is explicitly an **unverified decoder**, not an
authentication or API-authorization function. No access token is decoded to
guess account identity. The earlier blanket allegation that public clients must
always perform local ID-token signature validation was overstated:
[Microsoft documents ID-token validation for confidential clients](https://learn.microsoft.com/en-us/entra/identity-platform/id-tokens#validate-tokens),
and [OIDC Core 3.1.3.7](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation)
permits direct token-endpoint TLS provenance in the code flow. This port uses
that direct-response boundary and the maintained `jsonwebtoken` parser; it does
not add mandatory public-client JWKS calls. It is **not** a complete
confidential-client relying-party JWT validator: applications receiving tokens
outside this direct endpoint/broker boundary must use a maintained OIDC/JWT
validator with appropriate signature, issuer, audience, nonce and flow checks.
Mock regressions exercise consistency and rejection, not live cryptographic
broker authenticity.

Default endpoint/identity handling targets Entra v2.0. AAD B2C, ADFS and CIAM
issuer/policy discovery and native behavior have not been runtime-validated by
these Windows checks; do not treat an inferred endpoint pattern as verification.

### Native broker guarantees and remaining limitations

| Contract | Windows raw WAM adapter | macOS Enterprise SSO extension |
|----------|-------------------------|-------------------------------|
| Claims | Native `claims` property; exposed error metadata preserved | Separate `claims` option; OAuth/NSError challenge metadata preserved where exposed |
| Extra parameters including `client_session` | Each validated key/value becomes a `WebTokenRequest.Properties` property | WWW-form-encoded map in `extra_query_param`, not invented top-level extension options |
| Force refresh | `Unsupported` before dispatch: no verified raw-WAM bypass property | `force_refresh="1"` (or `"0"`) per native serializer; runtime-unverified here |
| Selected account | `RequestTokenWithWebAccountAsync`, plus complete returned-identity checks | `home_account_id` plus complete returned-identity checks |
| Cancellation token | Already cancelled: `OperationCancelled`; otherwise `Unsupported` before dispatch | Same: no claim that detached UI is cancelled |
| Enumeration/sign-out | Only client-specific verified account associations; sign-out via `SignOutWithClientIdAsync` | Both explicitly `Unsupported`, not empty enumeration or no-op success |

WAM associations map complete identity to the opaque native account ID **in this
broker instance and client only**. They are established by a successfully
identity-validated native response. Cold selected-account/silent requests or
enumerations containing an unassociated account fail closed; a username, home
tenant or opaque WAM ID is not used to guess the missing resource identity.
`NativeBroker::account(home_id)` is unsupported because a home ID alone cannot
select client/resource-tenant context. Restoring OAuth cache snapshots does not
restore these native associations. WAM force-refresh and explicit HWND parenting
remain unsupported in this raw adapter.

macOS authorization dispatch still needs the real main thread/run loop.
`run_main_loop_until(done)` processes the default mode in finite 50ms iterations
and checks the predicate again; this is **not an authentication timeout or UI
cancellation API**. Invoke it on the main thread while the Tokio future executes
elsewhere, as in the platform's existing lifecycle example. The native
controller/delegate survives until its callback, including when an awaiting
future is dropped. macOS compilation/runtime and installed extension behavior
are not verified on Windows. A cross-target check was attempted, but `ring`
requires a Darwin C toolchain unavailable on this host.

Mappings were checked against pinned official source:
[MSAL.NET WamAdapters](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/blob/0661b34a41255bfdd7980663572be0544578117e/src/client/Microsoft.Identity.Client/Platforms/Features/WamBroker/WamAdapters.cs),
[AadPlugin](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/blob/0661b34a41255bfdd7980663572be0544578117e/src/client/Microsoft.Identity.Client/Platforms/Features/WamBroker/AadPlugin.cs),
and Microsoft's
[MSIDBrokerOperationTokenRequest](https://github.com/AzureAD/microsoft-authentication-library-common-for-objc/blob/33e84282e0ac6f075421dd1f7c989e1384fad59d/IdentityCore/src/broker_operation/request/token_request/MSIDBrokerOperationTokenRequest.m).
Offline mapping tests and Windows compilation do not establish live eSTS
session enforcement, device binding or cross-tenant broker correctness.

## Azure App Registration

Before using this library, register your application in the
[Azure Portal](https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade):

1. Go to **Azure Active Directory** > **App registrations** > **New registration**
2. Set a name and select supported account types
3. Set a redirect URI:
   - Web apps: `http://localhost:3000/redirect`
   - WAM broker: `ms-appx-web://Microsoft.AAD.BrokerPlugin/{client_id}`
   - macOS broker: `msauth.{bundle_id}://auth`
4. Note your **Application (client) ID** and **Directory (tenant) ID**
5. For confidential clients: go to **Certificates & secrets** and create a client secret

## Architecture

```
msal (crate root)
 +-- config         Configuration builder
 +-- client
 |    +-- public         PublicClientApplication (user flows)
 |    +-- confidential   ConfidentialClientApplication (app flows)
 +-- broker
 |    +-- mod            NativeBroker trait
 |    +-- wam            Windows WAM (feature: broker-wam)
 |    +-- macos          macOS Enterprise SSO (feature: broker-macos)
 +-- authority       Authority resolution and OpenID discovery
 +-- cache           In-memory token cache
 +-- account         AccountInfo, IdTokenClaims, ClientInfo
 +-- request         Request parameter types for each flow
 +-- response        AuthenticationResult, TokenResponse
 +-- crypto          PKCE, nonce generation, JWT decoding
 +-- error           MsalError enum
```

## Feature Flags

| Feature | Default | Platform | Description |
|---------|---------|----------|-------------|
| `broker-wam` | No | Windows | Web Account Manager for device-bound tokens and SSO |
| `broker-macos` | No | macOS | Enterprise SSO plug-in via Company Portal |

## Minimum Supported Rust Version (MSRV)

This crate requires Rust **1.75** or later.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

See [SECURITY.md](SECURITY.md) for the security policy and how to report vulnerabilities.

## License

This project is licensed under the [MIT License](LICENSE).
