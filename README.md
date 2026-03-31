# Microsoft Authentication Library (MSAL) for Rust

[![Crates.io](https://img.shields.io/crates/v/msal.svg)](https://crates.io/crates/msal)
[![Documentation](https://docs.rs/msal/badge.svg)](https://docs.rs/msal)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/tolgaki/msal-rust/actions/workflows/ci.yml/badge.svg)](https://github.com/tolgaki/msal-rust/actions)

A Rust implementation of the [Microsoft Authentication Library (MSAL)](https://learn.microsoft.com/en-us/entra/msal/),
enabling authentication with the Microsoft identity platform (Azure AD, Microsoft
personal accounts, Azure AD B2C).

This crate is part of the MSAL family of libraries alongside
[msal-js](https://github.com/AzureAD/microsoft-authentication-library-for-js),
[MSAL.NET](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet),
[MSAL Python](https://github.com/AzureAD/microsoft-authentication-library-for-python),
[MSAL Java](https://github.com/AzureAD/microsoft-authentication-library-for-java),
and [MSAL Go](https://github.com/AzureAD/microsoft-authentication-library-for-go).

## Features

- **Public client** authentication for desktop apps, CLI tools, and devices
- **Confidential client** authentication for web apps, daemons, and APIs
- **Brokered authentication** via Windows WAM and macOS Enterprise SSO for device-bound tokens and system-wide SSO
- In-memory **token cache** with automatic expiration handling
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

    let result = app.acquire_token_by_code(request).await?;
    println!("Signed in as: {}", result.account.unwrap().username);

    // Step 3: Silent token renewal (from cache or refresh token).
    // let silent = SilentFlowRequest::new(scopes, account);
    // let cached = app.acquire_token_silent(silent).await?;
    Ok(())
}
```

### Brokered Authentication (Windows / macOS)

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
    };

    let result = app.acquire_token_interactive(request).await?;
    println!("Token: {}...", &result.access_token[..20]);
    Ok(())
}
```

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
