//! Native authentication broker support.
//!
//! Brokered authentication delegates to a platform-native authentication broker
//! (WAM on Windows, Enterprise SSO on macOS) for device-bound tokens, SSO across
//! apps, and conditional access compliance.
//!
//! # Usage
//!
//! ```no_run
//! use msal::{Configuration, PublicClientApplication};
//! use msal::broker::BrokerTokenRequest;
//!
//! # async fn example() -> Result<(), msal::MsalError> {
//! # let config = Configuration::builder("client-id").build();
//! let app = PublicClientApplication::new(config)?;
//!
//! // Enable brokered auth (platform-specific)
//! #[cfg(target_os = "windows")]
//! app.set_broker(Box::new(msal::broker::wam::WamBroker::new()?)).await;
//!
//! let request = BrokerTokenRequest {
//!     scopes: vec!["user.read".into()],
//!     account: None,
//!     claims: None,
//!     correlation_id: None,
//!     window_handle: None,
//!     authentication_scheme: Default::default(),
//!     pop_params: None,
//! };
//!
//! // Will use broker if available, otherwise falls back to standard flow
//! let result = app.acquire_token_interactive(request).await?;
//! # Ok(())
//! # }
//! ```

#[cfg(all(target_os = "windows", feature = "broker-wam"))]
pub mod wam;

use std::future::Future;
use std::pin::Pin;

use crate::account::AccountInfo;
use crate::error::Result;
use crate::response::AuthenticationResult;

/// Authentication scheme for token requests.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum AuthenticationScheme {
    #[default]
    Bearer,
    /// Proof-of-Possession: tokens are bound to the requesting client.
    Pop,
}

/// Parameters for Proof-of-Possession token binding.
#[derive(Debug, Clone)]
pub struct PopParams {
    /// HTTP method for the resource request (GET, POST, etc.).
    pub resource_request_method: String,
    /// URI of the resource being accessed.
    pub resource_request_uri: String,
    /// Server-provided nonce for the signed HTTP request.
    pub shr_nonce: Option<String>,
}

/// Request for broker token acquisition (interactive or silent).
#[derive(Debug, Clone)]
pub struct BrokerTokenRequest {
    /// OAuth 2.0 scopes to request.
    pub scopes: Vec<String>,
    /// Account for silent flow (required for silent, optional for interactive).
    pub account: Option<AccountInfo>,
    /// Additional claims requested.
    pub claims: Option<String>,
    /// Correlation ID for request tracing.
    pub correlation_id: Option<String>,
    /// Native window handle for parenting the broker UI (interactive only).
    /// On Windows this is an HWND. Pass `None` for console apps.
    pub window_handle: Option<Vec<u8>>,
    /// Token type: Bearer (default) or PoP.
    pub authentication_scheme: AuthenticationScheme,
    /// Proof-of-Possession parameters (required when scheme is PoP).
    pub pop_params: Option<PopParams>,
}

/// Request for broker sign-out.
#[derive(Debug, Clone)]
pub struct BrokerSignOutRequest {
    pub account: AccountInfo,
    pub correlation_id: Option<String>,
}

/// Trait for native authentication broker plugins.
///
/// Implementors bridge MSAL to platform-specific authentication infrastructure
/// (WAM on Windows, Enterprise SSO on macOS, etc.).
///
/// # Important behavioral notes
///
/// - **No fallback on broker failure**: if the broker returns an error, MSAL does
///   NOT fall back to browser-based auth. The error propagates to the caller.
/// - **`force_refresh` is ignored**: the broker manages its own cache and decides
///   when to refresh tokens.
/// - **Tokens are device-bound**: refresh tokens are managed by the OS, not by MSAL's cache.
pub trait NativeBroker: Send + Sync {
    /// Returns `true` if the broker is available on this platform.
    fn is_available(&self) -> bool;

    /// Acquire a token silently (no user prompts).
    ///
    /// The `request.account` field must be `Some`. Returns a cached or refreshed
    /// token without user interaction.
    fn acquire_token_silent<'a>(
        &'a self,
        client_id: &'a str,
        request: &'a BrokerTokenRequest,
    ) -> Pin<Box<dyn Future<Output = Result<AuthenticationResult>> + Send + 'a>>;

    /// Acquire a token interactively (may show system prompts).
    ///
    /// Shows OS-native authentication UI (not a browser window). The window handle
    /// in the request is used to parent the broker dialog.
    fn acquire_token_interactive<'a>(
        &'a self,
        client_id: &'a str,
        request: &'a BrokerTokenRequest,
    ) -> Pin<Box<dyn Future<Output = Result<AuthenticationResult>> + Send + 'a>>;

    /// Sign out a user from the broker.
    fn sign_out<'a>(
        &'a self,
        client_id: &'a str,
        request: &'a BrokerSignOutRequest,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;

    /// Get all accounts known to the broker for this client.
    fn get_all_accounts<'a>(
        &'a self,
        client_id: &'a str,
        correlation_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<AccountInfo>>> + Send + 'a>>;

    /// Get a specific account by its home_account_id.
    fn get_account<'a>(
        &'a self,
        account_id: &'a str,
        correlation_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<AccountInfo>> + Send + 'a>>;
}
