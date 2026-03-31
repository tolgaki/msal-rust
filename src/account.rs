//! Account and identity types.
//!
//! [`AccountInfo`] represents an authenticated user and is returned as part of
//! [`AuthenticationResult`](crate::AuthenticationResult) after a successful
//! token acquisition. It is also used as input to silent-flow and sign-out
//! requests.

use serde::{Deserialize, Serialize};

/// An authenticated user account.
///
/// Returned by token acquisition methods and used for subsequent silent
/// token requests and cache lookups.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountInfo {
    /// Unique cross-tenant account identifier (`{uid}.{utid}`).
    pub home_account_id: String,
    /// Tenant-specific account identifier (object ID or subject).
    pub local_account_id: String,
    /// Identity provider host (e.g., `"login.microsoftonline.com"`).
    pub environment: String,
    /// The Azure AD tenant ID.
    pub tenant_id: String,
    /// The user's preferred username (UPN or email).
    pub username: String,
    /// The user's display name, if available.
    pub name: Option<String>,
    /// Raw ID token claims as JSON, if available.
    pub id_token_claims: Option<serde_json::Value>,
}

impl AccountInfo {
    /// Returns a cache key for this account (`"{home_account_id}-{environment}"`).
    pub fn cache_key(&self) -> String {
        format!("{}-{}", self.home_account_id, self.environment)
    }
}

/// Decoded claims from an ID token JWT.
///
/// Not all fields will be present in every token — the set of claims depends
/// on the scopes requested and the identity provider configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdTokenClaims {
    /// Subject identifier.
    pub sub: Option<String>,
    /// Object ID (Azure AD-specific).
    pub oid: Option<String>,
    /// Tenant ID.
    pub tid: Option<String>,
    /// Preferred username (UPN or email).
    pub preferred_username: Option<String>,
    /// Display name.
    pub name: Option<String>,
    /// Email address.
    pub email: Option<String>,
    /// Issued-at time (Unix timestamp).
    pub iat: Option<i64>,
    /// Expiration time (Unix timestamp).
    pub exp: Option<i64>,
    /// Issuer URL.
    pub iss: Option<String>,
    /// Audience (client ID).
    pub aud: Option<String>,
    /// Nonce echoed back from the authorization request.
    pub nonce: Option<String>,
}

/// Decoded `client_info` claim returned alongside tokens.
///
/// Contains the user ID (`uid`) and tenant ID (`utid`) used to construct
/// the [`AccountInfo::home_account_id`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientInfo {
    /// User identifier within the tenant.
    pub uid: String,
    /// Tenant identifier.
    pub utid: String,
}

impl ClientInfo {
    /// Decode a base64url-encoded `client_info` string.
    pub fn from_base64(encoded: &str) -> crate::error::Result<Self> {
        use base64::Engine;
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|e| {
                crate::error::MsalError::InvalidToken(format!("invalid client_info base64: {e}"))
            })?;
        serde_json::from_slice(&decoded).map_err(Into::into)
    }

    /// Build the home account ID (`"{uid}.{utid}"`).
    pub fn home_account_id(&self) -> String {
        format!("{}.{}", self.uid, self.utid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_key_format() {
        let account = AccountInfo {
            home_account_id: "uid.utid".into(),
            local_account_id: "oid".into(),
            environment: "login.microsoftonline.com".into(),
            tenant_id: "tenant".into(),
            username: "user@example.com".into(),
            name: None,
            id_token_claims: None,
        };
        assert_eq!(account.cache_key(), "uid.utid-login.microsoftonline.com");
    }

    #[test]
    fn client_info_from_base64() {
        use base64::Engine;
        let json = r#"{"uid":"user-id","utid":"tenant-id"}"#;
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json);
        let info = ClientInfo::from_base64(&encoded).unwrap();
        assert_eq!(info.uid, "user-id");
        assert_eq!(info.utid, "tenant-id");
        assert_eq!(info.home_account_id(), "user-id.tenant-id");
    }
}
