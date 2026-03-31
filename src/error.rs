//! Error types for MSAL operations.
//!
//! All fallible operations in this crate return [`Result<T>`], which is an alias
//! for `std::result::Result<T, MsalError>`.

use thiserror::Error;

/// Errors that can occur during MSAL authentication operations.
///
/// Error variants are organized by category:
///
/// - **Authentication** — failures during the auth flow itself.
/// - **Configuration** — invalid or missing configuration values.
/// - **Token** — expired, invalid, or missing tokens.
/// - **Cache** — token cache read/write failures.
/// - **Authority** — OpenID discovery or validation failures.
/// - **Network** — HTTP transport errors.
/// - **Server** — error responses from the token endpoint.
/// - **Device Code** — device code flow-specific errors.
/// - **Serialization** — JSON or URL parsing errors.
#[derive(Debug, Error)]
pub enum MsalError {
    // ── Authentication ──────────────────────────────────────────────────
    /// A general authentication failure with a descriptive message.
    #[error("authentication failed: {0}")]
    AuthenticationFailed(String),

    /// The token endpoint requires user interaction (e.g., consent, MFA).
    ///
    /// Callers should retry with an interactive flow such as device code
    /// or authorization code.
    #[error("interaction required: {0}")]
    InteractionRequired(String),

    /// The user cancelled the authentication prompt (broker flows).
    #[error("user cancelled the authentication flow")]
    UserCancelled,

    // ── Configuration ───────────────────────────────────────────────────
    /// The provided configuration is invalid.
    #[error("invalid configuration: {0}")]
    InvalidConfiguration(String),

    /// A required parameter was not supplied.
    #[error("missing required parameter: {0}")]
    MissingParameter(String),

    // ── Token ───────────────────────────────────────────────────────────
    /// The access token has expired and no refresh token is available.
    #[error("token expired")]
    TokenExpired,

    /// A token could not be parsed or validated.
    #[error("invalid token: {0}")]
    InvalidToken(String),

    /// No matching tokens were found in the cache.
    #[error("no tokens found in cache")]
    NoTokensFound,

    // ── Cache ───────────────────────────────────────────────────────────
    /// An error occurred reading from or writing to the token cache.
    #[error("cache error: {0}")]
    CacheError(String),

    // ── Authority ───────────────────────────────────────────────────────
    /// The authority URL failed validation.
    #[error("authority validation failed: {0}")]
    AuthorityValidation(String),

    /// The OpenID Connect discovery document could not be fetched.
    #[error("authority metadata not found: {0}")]
    AuthorityMetadataNotFound(String),

    // ── Network ─────────────────────────────────────────────────────────
    /// An HTTP transport error (timeout, DNS, TLS, etc.).
    #[error("network error: {0}")]
    Network(#[from] reqwest::Error),

    /// A non-success HTTP status code with the response body.
    #[error("HTTP {status}: {body}")]
    HttpError {
        /// The HTTP status code.
        status: u16,
        /// The response body text.
        body: String,
    },

    /// The request was throttled by the server.
    #[error("request throttled, retry after {retry_after_secs}s")]
    Throttled {
        /// Seconds to wait before retrying.
        retry_after_secs: u64,
    },

    // ── Server ──────────────────────────────────────────────────────────
    /// An OAuth 2.0 error response from the token endpoint.
    #[error("server error [{error}]: {description}")]
    ServerError {
        /// The OAuth 2.0 `error` code (e.g., `"invalid_grant"`).
        error: String,
        /// The human-readable `error_description`.
        description: String,
        /// Server-assigned correlation ID for support requests.
        correlation_id: Option<String>,
        /// Additional claims requested by the resource (for claims challenges).
        claims: Option<String>,
        /// Sub-error code for finer-grained classification.
        suberror: Option<String>,
    },

    // ── Device Code ─────────────────────────────────────────────────────
    /// The device code has expired before the user completed authentication.
    #[error("device code expired")]
    DeviceCodeExpired,

    /// The device code flow is waiting for the user to authenticate.
    ///
    /// This is an internal sentinel used during polling and should not
    /// normally be seen by callers.
    #[error("device code authorization pending")]
    AuthorizationPending,

    // ── Crypto / Serialization ──────────────────────────────────────────
    /// A cryptographic operation failed.
    #[error("crypto error: {0}")]
    CryptoError(String),

    /// JSON serialization or deserialization failed.
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// A URL could not be parsed.
    #[error("URL parse error: {0}")]
    UrlParse(#[from] url::ParseError),

    /// A JWT operation failed.
    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
}

/// A convenience type alias for `Result<T, MsalError>`.
pub type Result<T> = std::result::Result<T, MsalError>;
