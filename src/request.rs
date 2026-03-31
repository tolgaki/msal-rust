//! Request parameter types for each authentication flow.
//!
//! Each acquire-token method on [`PublicClientApplication`](crate::PublicClientApplication)
//! and [`ConfidentialClientApplication`](crate::ConfidentialClientApplication)
//! takes a dedicated request struct. Fields common across requests (like
//! `claims` and `correlation_id`) are optional.

/// A list of OAuth 2.0 scopes.
pub type Scopes = Vec<String>;

/// Parameters for the authorization code exchange.
///
/// Used with [`PublicClientApplication::acquire_token_by_code`](crate::PublicClientApplication::acquire_token_by_code)
/// and [`ConfidentialClientApplication::acquire_token_by_code`](crate::ConfidentialClientApplication::acquire_token_by_code).
#[derive(Debug, Clone)]
pub struct AuthorizationCodeRequest {
    /// The authorization code received from the authorization endpoint.
    pub code: String,
    /// Scopes to request.
    pub scopes: Scopes,
    /// The redirect URI that was used in the authorization request.
    pub redirect_uri: String,
    /// The PKCE code verifier (required for public clients).
    pub code_verifier: Option<String>,
    /// Additional claims requested by the resource (claims challenge).
    pub claims: Option<String>,
    /// Correlation ID for request tracing.
    pub correlation_id: Option<String>,
}

/// Parameters for the client credentials flow (app-only, no user).
///
/// Used with [`ConfidentialClientApplication::acquire_token_by_client_credential`](crate::ConfidentialClientApplication::acquire_token_by_client_credential).
#[derive(Debug, Clone)]
pub struct ClientCredentialRequest {
    /// Scopes to request (typically `["https://graph.microsoft.com/.default"]`).
    pub scopes: Scopes,
    /// Additional claims requested by the resource.
    pub claims: Option<String>,
    /// Correlation ID for request tracing.
    pub correlation_id: Option<String>,
}

/// Parameters for the device code flow.
///
/// Used with [`PublicClientApplication::acquire_token_by_device_code`](crate::PublicClientApplication::acquire_token_by_device_code).
#[derive(Debug, Clone)]
pub struct DeviceCodeRequest {
    /// Scopes to request.
    pub scopes: Scopes,
    /// Additional claims requested by the resource.
    pub claims: Option<String>,
    /// Correlation ID for request tracing.
    pub correlation_id: Option<String>,
}

/// Parameters for silent token acquisition (cache and/or refresh token).
///
/// Used with [`PublicClientApplication::acquire_token_silent`](crate::PublicClientApplication::acquire_token_silent)
/// and [`ConfidentialClientApplication::acquire_token_silent`](crate::ConfidentialClientApplication::acquire_token_silent).
#[derive(Debug, Clone)]
pub struct SilentFlowRequest {
    /// Scopes to request.
    pub scopes: Scopes,
    /// The account to acquire a token for.
    pub account: crate::account::AccountInfo,
    /// Force a token refresh even if a cached token is available.
    pub force_refresh: bool,
    /// Additional claims requested by the resource.
    pub claims: Option<String>,
    /// Correlation ID for request tracing.
    pub correlation_id: Option<String>,
}

/// Parameters for a direct refresh token exchange.
///
/// Used with [`PublicClientApplication::acquire_token_by_refresh_token`](crate::PublicClientApplication::acquire_token_by_refresh_token).
#[derive(Debug, Clone)]
pub struct RefreshTokenRequest {
    /// The refresh token to exchange.
    pub refresh_token: String,
    /// Scopes to request.
    pub scopes: Scopes,
    /// Additional claims requested by the resource.
    pub claims: Option<String>,
    /// Correlation ID for request tracing.
    pub correlation_id: Option<String>,
}

/// Parameters for the on-behalf-of flow.
///
/// Used with [`ConfidentialClientApplication::acquire_token_on_behalf_of`](crate::ConfidentialClientApplication::acquire_token_on_behalf_of).
#[derive(Debug, Clone)]
pub struct OnBehalfOfRequest {
    /// The incoming user assertion (access token from the upstream client).
    pub user_assertion: String,
    /// Scopes to request for the downstream API.
    pub scopes: Scopes,
    /// Additional claims requested by the resource.
    pub claims: Option<String>,
    /// Correlation ID for request tracing.
    pub correlation_id: Option<String>,
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
    pub scopes: Scopes,
    /// Additional claims requested by the resource.
    pub claims: Option<String>,
    /// Correlation ID for request tracing.
    pub correlation_id: Option<String>,
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
