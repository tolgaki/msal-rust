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
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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
    pub fn into_authentication_result(
        self,
        authority: &crate::authority::Authority,
        client_id: &str,
        expected_account: Option<&AccountInfo>,
        nonce: Option<&str>,
        requested_scopes: &[String],
    ) -> crate::error::Result<AuthenticationResult> {
        use crate::error::MsalError;
        let now = chrono::Utc::now().timestamp();
        let expires_in = self.expires_in.unwrap_or(3600);
        if self.access_token.is_empty() || expires_in <= 0 {
            return Err(MsalError::InvalidToken(
                "missing access token or invalid expiration".into(),
            ));
        }

        let scopes = match &self.scope {
            Some(scope) => scope.split_whitespace().map(String::from).collect(),
            None => requested_scopes.to_vec(),
        };

        let account = self.build_account(authority, client_id, expected_account, nonce)?;
        let tenant_id = account.as_ref().map(|account| account.tenant_id.clone());

        Ok(AuthenticationResult {
            access_token: self.access_token,
            id_token: self.id_token,
            scopes,
            expires_on: now
                .checked_add(expires_in)
                .ok_or_else(|| MsalError::InvalidToken("expiration overflow".into()))?,
            ext_expires_on: self.ext_expires_in.and_then(|e| now.checked_add(e)),
            account,
            tenant_id,
            correlation_id: self.correlation_id,
            token_type: self.token_type.unwrap_or_else(|| "Bearer".into()),
            refresh_token: self.refresh_token,
        })
    }

    /// Build an [`AccountInfo`] from the `client_info` and `id_token` claims.
    fn build_account(
        &self,
        authority: &crate::authority::Authority,
        client_id: &str,
        expected: Option<&AccountInfo>,
        nonce: Option<&str>,
    ) -> crate::error::Result<Option<AccountInfo>> {
        use crate::error::MsalError;
        let client_info = self
            .client_info
            .as_deref()
            .map(crate::account::ClientInfo::from_base64)
            .transpose()?;
        if let Some(expected) = expected {
            validate_account_authority(expected, authority)?;
            if let Some(info) = &client_info {
                if info.home_account_id() != expected.home_account_id {
                    return Err(MsalError::InvalidToken(
                        "refresh returned a different home account".into(),
                    ));
                }
            }
        }
        let Some(id_token) = self.id_token.as_deref() else {
            if nonce.is_some() {
                return Err(MsalError::InvalidToken(
                    "nonce-bearing authorization requires an ID token".into(),
                ));
            }
            // Refresh responses may omit both ID token and client_info. Reuse only
            // the caller's already-authenticated, token-associated cache identity.
            return Ok(expected.cloned());
        };
        let claims = validate_endpoint_id_token(id_token, authority, client_id, nonce)?;
        let local_account_id = claims["oid"]
            .as_str()
            .or_else(|| claims["sub"].as_str())
            .filter(|id| !id.is_empty())
            .ok_or_else(|| {
                MsalError::InvalidToken("ID token has no local account identifier".into())
            })?;
        let tenant_id = claims["tid"]
            .as_str()
            .ok_or_else(|| MsalError::InvalidToken("ID token has no tenant identifier".into()))?;
        let home_account_id = match client_info {
            Some(info) => info.home_account_id(),
            None => match expected {
                Some(account) => account.home_account_id.clone(),
                None => {
                    return Err(MsalError::InvalidToken(
                        "ID token response missing client_info; cannot establish home account"
                            .into(),
                    ))
                }
            },
        };
        let account = AccountInfo {
            home_account_id,
            local_account_id: local_account_id.into(),
            environment: authority
                .canonical_authority
                .host_str()
                .unwrap_or_default()
                .into(),
            tenant_id: tenant_id.into(),
            username: claims["preferred_username"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            name: claims["name"].as_str().map(String::from),
            id_token_claims: Some(claims),
        };
        account.validate()?;
        if let Some(expected) = expected {
            if !account.same_identity(expected) {
                return Err(MsalError::InvalidToken(
                    "token response does not match requested account/tenant/environment".into(),
                ));
            }
        }
        Ok(Some(account))
    }
}

pub(crate) fn validate_account_authority(
    account: &AccountInfo,
    authority: &crate::authority::Authority,
) -> crate::error::Result<()> {
    use crate::error::MsalError;
    account.validate()?;
    if !account
        .environment
        .eq_ignore_ascii_case(authority.canonical_authority.host_str().unwrap_or_default())
    {
        return Err(MsalError::InvalidToken(
            "account environment differs from authority".into(),
        ));
    }
    validate_tenant(&account.tenant_id, authority)
}

fn validate_tenant(
    tenant: &str,
    authority: &crate::authority::Authority,
) -> crate::error::Result<()> {
    use crate::error::MsalError;
    if tenant.trim().is_empty() {
        return Err(MsalError::InvalidToken("empty tenant identifier".into()));
    }
    if uuid::Uuid::parse_str(&authority.tenant).is_ok()
        && !tenant.eq_ignore_ascii_case(&authority.tenant)
    {
        return Err(MsalError::InvalidToken(
            "token tenant differs from configured tenant".into(),
        ));
    }
    const CONSUMER_TENANT: &str = "9188040d-6c67-4c5b-b112-36a304b66dad";
    if (authority.tenant == "consumers" && tenant != CONSUMER_TENANT)
        || (authority.tenant == "organizations" && tenant == CONSUMER_TENANT)
    {
        return Err(MsalError::InvalidToken(
            "token tenant violates authority account type".into(),
        ));
    }
    Ok(())
}

/// Only for ID tokens received from the configured token endpoint over TLS.
/// This is not an arbitrary JWT authenticator or resource-server validator.
pub(crate) fn validate_endpoint_id_token(
    token: &str,
    authority: &crate::authority::Authority,
    client_id: &str,
    nonce: Option<&str>,
) -> crate::error::Result<serde_json::Value> {
    use crate::error::MsalError;
    let header = jsonwebtoken::decode_header(token)?;
    if header.alg != jsonwebtoken::Algorithm::RS256
        || token
            .rsplit('.')
            .next()
            .map_or(true, |signature| signature.is_empty())
    {
        return Err(MsalError::InvalidToken(
            "expected an Entra RS256 ID token".into(),
        ));
    }
    let claims = crate::crypto::decode_jwt_payload(token)?;
    if claims["aud"].as_str() != Some(client_id) {
        return Err(MsalError::InvalidToken(
            "ID token audience differs from client ID".into(),
        ));
    }
    if let Some(nonce) = nonce {
        if claims["nonce"].as_str() != Some(nonce) {
            return Err(MsalError::InvalidToken("ID token nonce mismatch".into()));
        }
    }
    let now = chrono::Utc::now().timestamp();
    if claims["exp"].as_i64().map_or(true, |exp| exp <= now)
        || claims
            .get("nbf")
            .is_some_and(|nbf| nbf.as_i64().map_or(true, |nbf| nbf > now + 60))
    {
        return Err(MsalError::InvalidToken(
            "ID token expired or not yet valid".into(),
        ));
    }
    let tenant = claims["tid"]
        .as_str()
        .ok_or_else(|| MsalError::InvalidToken("ID token missing tenant".into()))?;
    validate_tenant(tenant, authority)?;
    let issuer = claims["iss"]
        .as_str()
        .ok_or_else(|| MsalError::InvalidToken("ID token missing issuer".into()))?;
    let expected = if authority.authority_type == crate::authority::AuthorityType::Aad {
        format!(
            "https://{}/{tenant}/v2.0",
            authority.canonical_authority.host_str().unwrap_or_default()
        )
    } else {
        authority.issuer.clone()
    };
    if issuer != expected {
        return Err(MsalError::InvalidToken(
            "ID token issuer differs from authority/tenant".into(),
        ));
    }
    Ok(claims)
}
