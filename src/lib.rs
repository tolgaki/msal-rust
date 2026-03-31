//! # Microsoft Authentication Library (MSAL) for Rust
//!
//! `msal` enables Rust applications to authenticate with the
//! [Microsoft identity platform](https://learn.microsoft.com/en-us/entra/identity-platform/)
//! (Azure AD, Microsoft personal accounts, Azure AD B2C).
//!
//! It provides two client types matching the OAuth 2.0 client model:
//!
//! - [`PublicClientApplication`] — for desktop apps, CLI tools, and mobile apps
//!   that cannot securely store a client secret.
//! - [`ConfidentialClientApplication`] — for web apps, daemons, and APIs that
//!   can securely store a client secret or certificate.
//!
//! # Quick Start
//!
//! ## Device Code Flow (CLI / headless)
//!
//! ```no_run
//! use msal::{PublicClientApplication, Configuration};
//! use msal::request::DeviceCodeRequest;
//!
//! # async fn example() -> Result<(), msal::MsalError> {
//! let config = Configuration::builder("your-client-id")
//!     .authority("https://login.microsoftonline.com/common")
//!     .build();
//!
//! let app = PublicClientApplication::new(config)?;
//!
//! let result = app
//!     .acquire_token_by_device_code(
//!         DeviceCodeRequest::new(vec!["user.read".into()]),
//!         |info| println!("{}", info.message),
//!     )
//!     .await?;
//!
//! println!("Access token: {}", result.access_token);
//! # Ok(())
//! # }
//! ```
//!
//! ## Client Credentials (daemon / service)
//!
//! ```no_run
//! use msal::{ConfidentialClientApplication, Configuration};
//! use msal::request::ClientCredentialRequest;
//!
//! # async fn example() -> Result<(), msal::MsalError> {
//! let config = Configuration::builder("your-client-id")
//!     .authority("https://login.microsoftonline.com/your-tenant-id")
//!     .client_secret("your-secret")
//!     .build();
//!
//! let app = ConfidentialClientApplication::new(config)?;
//!
//! let result = app
//!     .acquire_token_by_client_credential(
//!         ClientCredentialRequest::new(vec!["https://graph.microsoft.com/.default".into()]),
//!     )
//!     .await?;
//! println!("Token: {}", result.access_token);
//! # Ok(())
//! # }
//! ```
//!
//! # Feature Flags
//!
//! | Feature | Platform | Description |
//! |---------|----------|-------------|
//! | `broker-wam` | Windows | Web Account Manager for device-bound tokens and SSO |
//! | `broker-macos` | macOS | Enterprise SSO plug-in via Company Portal |
//!
//! # Modules
//!
//! | Module | Purpose |
//! |--------|---------|
//! | [`client`] | `PublicClientApplication` and `ConfidentialClientApplication` |
//! | [`broker`] | Native broker trait + platform implementations (WAM, macOS SSO) |
//! | [`config`] | Configuration builder |
//! | [`request`] | Request types with `::new()` constructors for each flow |
//! | [`response`] | [`AuthenticationResult`] returned by all acquire-token methods |
//! | [`account`] | [`AccountInfo`] and token claims |
//! | [`authority`] | Authority resolution and OpenID Connect discovery |
//! | [`cache`] | In-memory token cache |
//! | [`error`] | [`MsalError`] variants |
//! | [`crypto`] | PKCE, nonce generation, JWT utilities |

pub mod account;
pub mod authority;
pub mod broker;
pub mod cache;
pub mod client;
pub mod config;
pub mod crypto;
pub mod error;
pub(crate) mod network;
pub mod request;
pub mod response;

pub use account::AccountInfo;
pub use client::confidential::ConfidentialClientApplication;
pub use client::public::PublicClientApplication;
pub use config::{Configuration, ConfigurationBuilder};
pub use error::MsalError;
pub use response::AuthenticationResult;
