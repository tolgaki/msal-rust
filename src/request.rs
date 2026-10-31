//! Request parameter types for each authentication flow.
//!
//! Each acquire-token method on [`PublicClientApplication`](crate::PublicClientApplication)
//! and [`ConfidentialClientApplication`](crate::ConfidentialClientApplication)
//! takes a dedicated request struct. Use the provided constructors for common
//! cases, or set all fields directly for full control.
//!
//! ```
//! use msal::request::DeviceCodeRequest;
//!
//! // Short form:
//! let req = DeviceCodeRequest::new(vec!["user.read".into()]);
//!
//! // Full form (equivalent):
//! let req = DeviceCodeRequest {
//!     scopes: vec!["user.read".into()],
//!     claims: None,
//!     correlation_id: None,
//!     extra_query_parameters: Default::default(),
//!     cancellation_token: None,
//! };
//! ```

use crate::error::{MsalError, Result};
use std::collections::BTreeMap;

/// Cloneable cooperative cancellation for HTTP and device polling.
///
/// Cancelling drops the in-flight HTTP future. It does not revoke tokens, cancel
/// a server-side device session, or imply that detached native UI was closed.
#[derive(Debug, Clone)]
pub struct CancellationToken {
    sender: tokio::sync::watch::Sender<bool>,
}

impl CancellationToken {
    pub fn new() -> Self {
        let (sender, _) = tokio::sync::watch::channel(false);
        Self { sender }
    }

    pub fn cancel(&self) {
        self.sender.send_replace(true);
    }

    pub fn is_cancelled(&self) -> bool {
        *self.sender.borrow()
    }

    pub fn check_cancelled(&self) -> Result<()> {
        if self.is_cancelled() {
            Err(MsalError::OperationCancelled)
        } else {
            Ok(())
        }
    }

    pub async fn cancelled(&self) {
        let mut receiver = self.sender.subscribe();
        receiver
            .wait_for(|cancelled| *cancelled)
            .await
            .expect("sender retained by token");
    }
}

impl Default for CancellationToken {
    fn default() -> Self {
        Self::new()
    }
}

/// Reject extra parameters that could override library-owned OAuth/security fields.
///
/// `client_session` is deliberately allowed as an opaque server parameter.
/// Transmission does not prove that a particular server enforces session binding.
pub fn validate_extra_query_parameters(parameters: &BTreeMap<String, String>) -> Result<()> {
    const RESERVED: &[&str] = &[
        "client_id",
        "client_secret",
        "client_assertion",
        "client_assertion_type",
        "grant_type",
        "code",
        "code_verifier",
        "code_challenge",
        "code_challenge_method",
        "redirect_uri",
        "response_type",
        "response_mode",
        "scope",
        "claims",
        "nonce",
        "state",
        "refresh_token",
        "device_code",
        "username",
        "password",
        "assertion",
        "requested_token_use",
        "client_info",
        "client-request-id",
        "return-client-request-id",
        "authority",
        "account_id",
        "tenant_id",
        "force_refresh",
        "token_type",
        "req_cnf",
    ];
    let mut seen = std::collections::BTreeSet::new();
    for (key, value) in parameters {
        if key.is_empty()
            || key.trim() != key
            || !key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            || RESERVED.contains(&key.to_ascii_lowercase().as_str())
            || value.trim().is_empty()
            || !seen.insert(key.to_ascii_lowercase())
        {
            return Err(MsalError::InvalidConfiguration(format!(
                "invalid or reserved extra parameter: {key}"
            )));
        }
    }
    Ok(())
}

pub(crate) fn validate_claims(claims: &Option<String>) -> Result<()> {
    if let Some(claims) = claims {
        if !serde_json::from_str::<serde_json::Value>(claims)?.is_object() {
            return Err(MsalError::InvalidConfiguration(
                "claims must be a JSON object".into(),
            ));
        }
    }
    Ok(())
}

pub(crate) fn append_request_parameters<'a>(
    params: &mut Vec<(&'a str, &'a str)>,
    claims: &'a Option<String>,
    correlation_id: &'a Option<String>,
    extra: &'a BTreeMap<String, String>,
) -> Result<()> {
    validate_extra_query_parameters(extra)?;
    validate_claims(claims)?;
    if let Some(claims) = claims {
        params.push(("claims", claims));
    }
    if let Some(id) = correlation_id {
        params.push(("client-request-id", id));
        params.push(("return-client-request-id", "true"));
    }
    params.extend(
        extra
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str())),
    );
    Ok(())
}

pub(crate) fn user_scopes(scopes: &[String]) -> Vec<String> {
    let mut scopes = scopes.to_vec();
    for scope in ["openid", "profile", "offline_access"] {
        if !scopes.iter().any(|existing| existing == scope) {
            scopes.push(scope.into());
        }
    }
    scopes
}

/// Parameters for the authorization code exchange.
///
/// Used with [`PublicClientApplication::acquire_token_by_code`](crate::PublicClientApplication::acquire_token_by_code)
/// and [`ConfidentialClientApplication::acquire_token_by_code`](crate::ConfidentialClientApplication::acquire_token_by_code).
#[derive(Debug, Clone)]
pub struct AuthorizationCodeRequest {
    /// The authorization code received from the authorization endpoint.
    pub code: String,
    /// Scopes to request.
    pub scopes: Vec<String>,
    /// The redirect URI that was used in the authorization request.
    pub redirect_uri: String,
    /// The PKCE code verifier (required for public clients).
    pub code_verifier: Option<String>,
    /// Additional claims requested by the resource (claims challenge).
    pub claims: Option<String>,
    /// Correlation ID for request tracing.
    pub correlation_id: Option<String>,
    /// Nonce returned by `authorization_url_with_options`, checked on the ID token.
    pub nonce: Option<String>,
    /// Additional server parameters; cannot override OAuth-owned fields.
    pub extra_query_parameters: BTreeMap<String, String>,
    pub cancellation_token: Option<CancellationToken>,
}

impl AuthorizationCodeRequest {
    /// Create a request with the required fields; optional fields default to `None`.
    pub fn new(code: String, scopes: Vec<String>, redirect_uri: String) -> Self {
        Self {
            code,
            scopes,
            redirect_uri,
            code_verifier: None,
            claims: None,
            correlation_id: None,
            nonce: None,
            extra_query_parameters: BTreeMap::new(),
            cancellation_token: None,
        }
    }
}

/// Parameters for the client credentials flow (app-only, no user).
///
/// Used with [`ConfidentialClientApplication::acquire_token_by_client_credential`](crate::ConfidentialClientApplication::acquire_token_by_client_credential).
#[derive(Debug, Clone)]
pub struct ClientCredentialRequest {
    /// Scopes to request (typically `["https://graph.microsoft.com/.default"]`).
    pub scopes: Vec<String>,
    /// Additional claims requested by the resource.
    pub claims: Option<String>,
    /// Correlation ID for request tracing.
    pub correlation_id: Option<String>,
    pub extra_query_parameters: BTreeMap<String, String>,
    pub cancellation_token: Option<CancellationToken>,
}

impl ClientCredentialRequest {
    /// Create a request with scopes; optional fields default to `None`.
    pub fn new(scopes: Vec<String>) -> Self {
        Self {
            scopes,
            claims: None,
            correlation_id: None,
            extra_query_parameters: BTreeMap::new(),
            cancellation_token: None,
        }
    }
}

/// Parameters for the device code flow.
///
/// Used with [`PublicClientApplication::acquire_token_by_device_code`](crate::PublicClientApplication::acquire_token_by_device_code).
#[derive(Debug, Clone)]
pub struct DeviceCodeRequest {
    /// Scopes to request.
    pub scopes: Vec<String>,
    /// Additional claims requested by the resource.
    pub claims: Option<String>,
    /// Correlation ID for request tracing.
    pub correlation_id: Option<String>,
    pub extra_query_parameters: BTreeMap<String, String>,
    pub cancellation_token: Option<CancellationToken>,
}

impl DeviceCodeRequest {
    /// Create a request with scopes; optional fields default to `None`.
    pub fn new(scopes: Vec<String>) -> Self {
        Self {
            scopes,
            claims: None,
            correlation_id: None,
            extra_query_parameters: BTreeMap::new(),
            cancellation_token: None,
        }
    }
}

/// Parameters for silent token acquisition (cache and/or refresh token).
///
/// Used with [`PublicClientApplication::acquire_token_silent`](crate::PublicClientApplication::acquire_token_silent)
/// and [`ConfidentialClientApplication::acquire_token_silent`](crate::ConfidentialClientApplication::acquire_token_silent).
#[derive(Debug, Clone)]
pub struct SilentFlowRequest {
    /// Scopes to request.
    pub scopes: Vec<String>,
    /// The account to acquire a token for.
    pub account: crate::account::AccountInfo,
    /// Force a token refresh even if a cached token is available.
    pub force_refresh: bool,
    /// Additional claims requested by the resource.
    pub claims: Option<String>,
    /// Correlation ID for request tracing.
    pub correlation_id: Option<String>,
    pub extra_query_parameters: BTreeMap<String, String>,
    pub cancellation_token: Option<CancellationToken>,
}

impl SilentFlowRequest {
    /// Create a request with the required fields; `force_refresh` defaults to `false`.
    pub fn new(scopes: Vec<String>, account: crate::account::AccountInfo) -> Self {
        Self {
            scopes,
            account,
            force_refresh: false,
            claims: None,
            correlation_id: None,
            extra_query_parameters: BTreeMap::new(),
            cancellation_token: None,
        }
    }
}

/// Parameters for a direct refresh token exchange.
///
/// Used with [`PublicClientApplication::acquire_token_by_refresh_token`](crate::PublicClientApplication::acquire_token_by_refresh_token).
#[derive(Debug, Clone)]
pub struct RefreshTokenRequest {
    /// The refresh token to exchange.
    pub refresh_token: String,
    /// Scopes to request.
    pub scopes: Vec<String>,
    /// Additional claims requested by the resource.
    pub claims: Option<String>,
    /// Correlation ID for request tracing.
    pub correlation_id: Option<String>,
    /// Previously authenticated identity associated with this refresh token.
    ///
    /// Only supply trusted protected-cache state, never identity guessed from a
    /// username or an access token. Without it, identity-less refresh results
    /// have `account: None` and cannot be cached as a user.
    pub account: Option<crate::account::AccountInfo>,
    pub extra_query_parameters: BTreeMap<String, String>,
    pub cancellation_token: Option<CancellationToken>,
}

impl RefreshTokenRequest {
    /// Create a request with the required fields.
    pub fn new(refresh_token: String, scopes: Vec<String>) -> Self {
        Self {
            refresh_token,
            scopes,
            claims: None,
            correlation_id: None,
            account: None,
            extra_query_parameters: BTreeMap::new(),
            cancellation_token: None,
        }
    }
}

/// Parameters for the on-behalf-of flow.
///
/// Used with [`ConfidentialClientApplication::acquire_token_on_behalf_of`](crate::ConfidentialClientApplication::acquire_token_on_behalf_of).
#[derive(Debug, Clone)]
pub struct OnBehalfOfRequest {
    /// The incoming user assertion (access token from the upstream client).
    pub user_assertion: String,
    /// Scopes to request for the downstream API.
    pub scopes: Vec<String>,
    /// Additional claims requested by the resource.
    pub claims: Option<String>,
    /// Correlation ID for request tracing.
    pub correlation_id: Option<String>,
    pub extra_query_parameters: BTreeMap<String, String>,
    pub cancellation_token: Option<CancellationToken>,
}

impl OnBehalfOfRequest {
    /// Create a request with the required fields.
    pub fn new(user_assertion: String, scopes: Vec<String>) -> Self {
        Self {
            user_assertion,
            scopes,
            claims: None,
            correlation_id: None,
            extra_query_parameters: BTreeMap::new(),
            cancellation_token: None,
        }
    }
}

/// Parameters for the username/password (ROPC) flow.
///
/// **Warning**: This flow is not recommended by Microsoft. Prefer device code
/// or authorization code flows. ROPC does not support MFA or conditional access.
///
/// Used with [`PublicClientApplication::acquire_token_by_username_password`](crate::PublicClientApplication::acquire_token_by_username_password).
#[derive(Debug, Clone)]
pub struct UsernamePasswordRequest {
    /// The user's username (UPN or email).
    pub username: String,
    /// The user's password.
    pub password: String,
    /// Scopes to request.
    pub scopes: Vec<String>,
    /// Additional claims requested by the resource.
    pub claims: Option<String>,
    /// Correlation ID for request tracing.
    pub correlation_id: Option<String>,
    pub extra_query_parameters: BTreeMap<String, String>,
    pub cancellation_token: Option<CancellationToken>,
}

impl UsernamePasswordRequest {
    /// Create a request with the required fields.
    pub fn new(username: String, password: String, scopes: Vec<String>) -> Self {
        Self {
            username,
            password,
            scopes,
            claims: None,
            correlation_id: None,
            extra_query_parameters: BTreeMap::new(),
            cancellation_token: None,
        }
    }
}

/// Information returned when initiating the device code flow.
///
/// Passed to the callback in
/// [`PublicClientApplication::acquire_token_by_device_code`](crate::PublicClientApplication::acquire_token_by_device_code).
#[derive(Debug, Clone)]
pub struct DeviceCodeInfo {
    /// The short code the user must enter.
    pub user_code: String,
    /// The device code used internally for polling (not shown to the user).
    pub device_code: String,
    /// The URL the user should visit.
    pub verification_uri: String,
    /// A human-readable message to display (includes the code and URL).
    pub message: String,
    /// Seconds until the device code expires.
    pub expires_in: u64,
    /// Polling interval in seconds.
    pub interval: u64,
}
