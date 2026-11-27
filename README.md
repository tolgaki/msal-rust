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

User login requests include `openid profile offline_access`. Device-code
initiation omits `client_info`; authorization URLs and all token exchanges
(including device polling, refresh and authorization-code redemption) include
`client_info=1`.
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
| Selected account | Desktop `RequestTokenWithWebAccountForWindowAsync`, plus complete returned-identity checks | `home_account_id` plus complete returned-identity checks |
| Cancellation token | `IAsyncInfo::Cancel`, then wait up to 5s for terminal completion before returning `OperationCancelled`; cancellation failure surfaces, no UI-dismissal promise | Already cancelled: `OperationCancelled`; otherwise `Unsupported` before dispatch |
| Enumeration/sign-out | `FindAllAccountsWithClientIdAsync`, returning only accounts with restored/verified associations; sign-out via `SignOutWithClientIdAsync` | Unentitled CLI: typed `get_accounts_operation`; entitled enumeration and client-only native sign-out: `Unsupported` |

WAM associations map complete identity to the opaque native account ID **in this
broker and client only**, shared by `WamBroker::clone()`. They are established
by a successfully identity-validated native response or restored from trusted,
integrity-protected consumer state. Cold selected-account/silent requests for an
unassociated account fail closed, and enumeration skips native accounts without
an association instead of failing for all of them; a username, home tenant or
opaque WAM ID is not used to guess the missing resource identity. Export leaves
out associations whose environment is not in the broker authority's cloud,
since they cannot be restored under that binding.
`NativeBroker::account(home_id)` is unsupported because a home ID alone cannot
select client/resource-tenant context. Restoring OAuth cache snapshots does not
restore these native associations automatically.

The Windows public APIs are:

```text
WamBroker::export_account_associations(&self, client_id: &str) -> Result<WamAccountSnapshot>
WamBroker::import_account_associations(&self, client_id: &str, snapshot: WamAccountSnapshot) -> Result<()>
async WamBroker::account_for_client(&self, client_id: &str, account: &AccountInfo) -> Result<AccountInfo>
```

`WamAccountSnapshot` is serde-compatible with fields `version: u32`,
`client_id`, `authority`, `provider_id` (strings), and
`accounts: Vec<WamAccountAssociation>`. Each association has
`native_account_id: String` and `account: AccountInfo`, preserving home/local
IDs, resource tenant, environment and display metadata. Import validates version
1, exact client/provider/configured-authority binding, complete identity,
cloud binding and duplicate identities **before** replacing this client's
state under one lock. Failure leaves previous state unchanged. Multiple resource
identities may legitimately share one native ID. Accounts acquired using an
explicit resource-tenant override can round-trip even when the configured default
authority is a different GUID tenant; restoration preserves that tenant rather
than rewriting it. Acquisition still requires the matching explicit authority
override when the default authority names another tenant. Lookup checks native existence;
subsequent token responses still check the complete selected identity.

The snapshot contains identity metadata, not tokens. It is not encrypted and
structural validation is **not authentication of imported state**. Use the
consumer's existing protected store with integrity and client/authority binding;
this library creates no credential files. Keep a clone before moving the broker
into `app.set_broker(Box::new(broker))`, then export that shared handle after
successful acquisition and sign-out. Persist association deletion together with
the consumer's own sign-out transaction; importing stale protected state does not
undo native sign-out or prove a native account is still usable.

WAM interactive acquisition uses
[`IWebAuthenticationCoreManagerInterop`](https://learn.microsoft.com/en-us/windows/win32/api/webauthenticationcoremanagerinterop/nn-webauthenticationcoremanagerinterop-iwebauthenticationcoremanagerinterop)
from the `WebAuthenticationCoreManager` activation factory. The no-account path
calls `RequestTokenForWindowAsync`; selection calls
`RequestTokenWithWebAccountForWindowAsync`. These desktop APIs avoid the UWP
`RequestTokenAsync` CoreWindow requirement (`0x80073B27` on console threads).
Silent acquisition and account enumeration retain their non-UI WinRT APIs;
neither needs an HWND or a CoreWindow/UI thread.

Encode a GUI parent as `Some((hwnd as isize).to_le_bytes().to_vec())` in
`BrokerTokenRequest::window_handle` (for windows-rs `HWND`, use `hwnd.0 as isize`).
The encoding is native pointer width: exactly 4 bytes for a 32-bit process, 8
for a 64-bit process. Keep that window alive until native completion. Null,
malformed and invalid handles are rejected, not silently replaced.
`None` follows the
[official MSAL.NET console/terminal helper](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/wiki/WAM/6a7a5afdb89cc328ef1575459629c982fa3f1bf0#parent-window-handles):
`GetAncestor(GetConsoleWindow(), GA_ROOTOWNER)`, including the Windows Terminal
pseudo-console case. If it returns no valid parent (for example, a headless
process), acquisition fails with an actionable error; supply an explicit HWND.
There is no foreground-window or desktop fallback. Availability of the broker
alone does not prove a usable UI parent. Offline handle tests and Windows
compilation do not prove live interactive authentication succeeds.
Microsoft Learn currently lists Windows 10 build 20348 as the interop interface's
minimum; availability on earlier builds is not runtime-verified here. Activation
and native operation errors propagate rather than falling back to UWP dispatch.

Raw WAM force-refresh remains unsupported. Current
[MSAL.NET RuntimeBroker](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/blob/3d50649ef8551ea2f88a8426cc25cda84df8e5b2/src/client/Microsoft.Identity.Client.Broker/RuntimeBroker.cs)
implements `ForceRefresh` by first obtaining an access token, setting native
`AuthParameters.AccessTokenToRenew`, and acquiring again through MSALRuntime.
That is not a documented `WebTokenRequest.Properties` field; the pinned raw
WAM adapter below has no equivalent bypass contract. `ForceAuthentication`
is a prompt type, not proof of bypassing the native access-token cache. This
port therefore rejects raw-WAM force refresh rather than inventing a property.

`NativeBroker::supports_native_cancellation() -> bool` defaults to false; WAM
returns true. Public silent acquisition forwards cancellation to capable native
adapters and does not drop their futures at an outer wait-only cancellation
boundary. Legacy silent adapters retain wait-only cancellation. WAM cancels the
account lookup/token `IAsyncOperation`, waits up to 5 seconds for it to finish,
then returns `OperationCancelled` even if it has not (an interactive prompt can
stay open), and never returns a result racing cancellation. A failed `Cancel` or
an unexpected terminal native error is surfaced after that bounded wait. A
capable adapter must return promptly once cancellation is requested, because the
public client adds no outer bound; it also rechecks the token before caching. [WinRT cancellation is cooperative](https://learn.microsoft.com/en-us/windows/uwp/threading-async/cancel-an-async-operation):
neither a successful call nor `OperationCancelled` proves UI dismissal, server
rollback or token revocation. Dropping an acquisition future without using its
cancellation token does not promise native cancellation.

macOS `new_for_cli` account operations use protocol 4 and signed-in-only
enumeration. `accounts` is a JSON array encoded inside a string response header,
not token data. The adapter checks operation response type/success and rejects
missing or partial identity instead of guessing the resource tenant from home
ID. It uses native `home_account_id`, `local_account_id`, `realm` and
`environment`; display username never selects the account. Its exact lookup is
`async MacOsBroker::account_for_client(&self, client_id: &str, account: &AccountInfo,
correlation_id: &str) -> Result<AccountInfo>`.

macOS native sign-out remains `Unsupported`, before dispatch.
The official `signout_account_operation` exposes `signout_from_browser`,
`clear_sso_extension_cookies`, `wipe_account` and `wipe_cache_all_accounts`.
[Microsoft warns that `wipeAccount` is destructive shared-cache removal](https://azuread.github.io/microsoft-authentication-library-for-objc/Classes/MSALSignoutParameters.html),
not isolated client sign-out. Neither setting all those flags to zero nor
accepting a generic success acknowledgement proves native client state was
removed. The current `BrokerSignOutRequest` does not express consent to those
broader effects; this adapter will not turn local cache deletion into claimed
native sign-out or dispatch a device/shared-cache wipe as a shortcut.
`MacOsBroker::new(...)` does not enable typed enumeration: Microsoft's
base operation serializer requires a broker key for entitled apps; the official
macOS unentitled runtime path permits omission. This adapter implements only
that omission path with `new_for_cli`, not a new keychain/broker-key store.
Installed extension versions can reject it, and native errors propagate.

macOS authorization dispatch still needs the real main thread/run loop.
`run_main_loop_until(done)` processes the default mode in finite 50ms iterations
and checks the predicate again; this is **not an authentication timeout or UI
cancellation API**. Invoke it on the main thread while the Tokio future executes
elsewhere. The native
controller/delegate survives until its callback, including when an awaiting
future is dropped. Construct `MacOsBroker::new_for_cli(authority)` on the actual
main thread **before** creating async work. Do not put construction inside
`#[tokio::main]` worker work or block the main thread on `block_on`/`join` before
pumping callbacks.

`examples/broker_macos_cli.rs` is a runnable lifecycle example. On an unsigned,
unentitled macOS CLI with Company Portal/MDM SSO configured and the unsigned-app
redirect registered, set `MSAL_CLIENT_ID` and `MSAL_AUTHORITY`, then run:

```text
cargo run --example broker_macos_cli --features broker-macos
```

It constructs the broker on main, moves acquisition to a Tokio runtime on a
worker thread and pumps main until that worker completes. No token is printed.
The main-loop polling deadline is not an auth timeout. CI runs
`cargo test --features broker-macos` on macOS and checks both
`x86_64-apple-darwin` and `aarch64-apple-darwin`. That verifies compilation and
offline protocol tests, not the installed SSO extension's runtime behavior.
Signed-in enumeration lists an identity once even when the extension reports it
under several environment aliases.
No live authentication, keychain, device-registration or tenant mutation was
performed to test these changes.

Mappings were checked against pinned official source:
[MSAL.NET WamAdapters](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/blob/0661b34a41255bfdd7980663572be0544578117e/src/client/Microsoft.Identity.Client/Platforms/Features/WamBroker/WamAdapters.cs),
[AadPlugin](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/blob/0661b34a41255bfdd7980663572be0544578117e/src/client/Microsoft.Identity.Client/Platforms/Features/WamBroker/AadPlugin.cs),
and Microsoft's
[MSIDBrokerOperationTokenRequest](https://github.com/AzureAD/microsoft-authentication-library-common-for-objc/blob/33e84282e0ac6f075421dd1f7c989e1384fad59d/IdentityCore/src/broker_operation/request/token_request/MSIDBrokerOperationTokenRequest.m).
Typed Apple operations were checked at the same revision:
[get-accounts request](https://github.com/AzureAD/microsoft-authentication-library-common-for-objc/blob/33e84282e0ac6f075421dd1f7c989e1384fad59d/IdentityCore/src/broker_operation/request/account_request/MSIDBrokerOperationGetAccountsRequest.m),
[get-accounts response](https://github.com/AzureAD/microsoft-authentication-library-common-for-objc/blob/33e84282e0ac6f075421dd1f7c989e1384fad59d/IdentityCore/src/broker_operation/response/MSIDBrokerOperationGetAccountsResponse.m),
[account metadata](https://github.com/AzureAD/microsoft-authentication-library-common-for-objc/blob/33e84282e0ac6f075421dd1f7c989e1384fad59d/IdentityCore/src/oauth2/account/MSIDAccount.m),
[sign-out request](https://github.com/AzureAD/microsoft-authentication-library-common-for-objc/blob/33e84282e0ac6f075421dd1f7c989e1384fad59d/IdentityCore/src/broker_operation/request/account_request/MSIDBrokerOperationSignoutFromDeviceRequest.m),
[broker-key requirement](https://github.com/AzureAD/microsoft-authentication-library-common-for-objc/blob/33e84282e0ac6f075421dd1f7c989e1384fad59d/IdentityCore/src/broker_operation/request/MSIDBrokerOperationRequest.m),
and [response-header transport](https://github.com/AzureAD/microsoft-authentication-library-common-for-objc/blob/33e84282e0ac6f075421dd1f7c989e1384fad59d/IdentityCore/src/requests/broker/MSIDSSOExtensionRequestDelegate.m).
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
