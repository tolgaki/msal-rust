//! Authentication result and token response types.
//!
//! [`AuthenticationResult`] is the primary return type for all acquire-token
//! methods. It contains the access token, optional ID token, scopes, expiration,
//! and the authenticated account.

use crate::account::AccountInfo;

/// The result of a successful token acquisition.
///
/// Returned by all `acquire_token_*` methods on both
/// [`PublicClientApplication`](crate::PublicClientApplication) and
/// [`ConfidentialClientApplication`](crate::ConfidentialClientApplication).
#[derive(Debug, Clone)]
pub struct AuthenticationResult {
    /// The access token string (used as a Bearer token in API calls).
    pub access_token: String,
    /// The raw ID token JWT, if returned by the token endpoint.
    pub id_token: Option<String>,
    /// The scopes granted by the token endpoint.
    pub scopes: Vec<String>,
    /// Token expiration as a Unix timestamp (seconds since epoch).
    pub expires_on: i64,
    /// Extended token expiration (for resilience during outages), if available.
    pub ext_expires_on: Option<i64>,
    /// The authenticated account, if a user-based flow was used.
    ///
    /// This is `None` for client-credential flows (app-only, no user).
    pub account: Option<AccountInfo>,
    /// The tenant ID from the token response.
    pub tenant_id: Option<String>,
    /// Correlation ID echoed back by the server for request tracing.
    pub correlation_id: Option<String>,
    /// Token type (usually `"Bearer"`).
    pub token_type: String,
    /// Refresh token, if returned.
    ///
    /// Stored in the cache automatically. You typically do not need to
    /// use this directly — call `acquire_token_silent` instead.
    pub refresh_token: Option<String>,
}

/// Raw token response from the OAuth 2.0 token endpoint.
#[derive(Debug, serde::Deserialize)]
pub(crate) struct TokenResponse {
    pub access_token: String,
    pub token_type: Option<String>,
    pub expires_in: Option<i64>,
    pub ext_expires_in: Option<i64>,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
    pub scope: Option<String>,
    pub client_info: Option<String>,
    pub correlation_id: Option<String>,
}

impl TokenResponse {
    /// Convert the raw token response into an [`AuthenticationResult`].
    pub fn into_authentication_result(self) -> AuthenticationResult {
        let now = chrono::Utc::now().timestamp();
        let expires_in = self.expires_in.unwrap_or(3600);

        let scopes = self
            .scope
            .as_deref()
            .unwrap_or_default()
            .split_whitespace()
            .map(String::from)
            .collect();

        let account = self.build_account();

        AuthenticationResult {
            access_token: self.access_token,
            id_token: self.id_token,
            scopes,
            expires_on: now + expires_in,
            ext_expires_on: self.ext_expires_in.map(|e| now + e),
            account,
            tenant_id: None,
            correlation_id: self.correlation_id,
            token_type: self.token_type.unwrap_or_else(|| "Bearer".into()),
            refresh_token: self.refresh_token,
        }
    }

    /// Build an [`AccountInfo`] from the `client_info` and `id_token` claims.
    fn build_account(&self) -> Option<AccountInfo> {
        let client_info_str = self.client_info.as_deref()?;
        let client_info = crate::account::ClientInfo::from_base64(client_info_str).ok()?;
        let id_token = self.id_token.as_deref()?;
        let claims = crate::crypto::decode_jwt_payload(id_token).ok()?;

        Some(AccountInfo {
            home_account_id: client_info.home_account_id(),
            local_account_id: claims["oid"]
                .as_str()
                .or_else(|| claims["sub"].as_str())
                .unwrap_or_default()
                .to_string(),
            environment: "login.microsoftonline.com".into(),
            tenant_id: claims["tid"].as_str().unwrap_or_default().to_string(),
            username: claims["preferred_username"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            name: claims["name"].as_str().map(String::from),
            id_token_claims: Some(claims),
        })
    }
}
