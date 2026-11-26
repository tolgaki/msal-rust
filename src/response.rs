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
        let (claims, tenant_id) =
            validate_endpoint_id_token(id_token, authority, client_id, nonce)?;
        let local_account_id = claims["oid"]
            .as_str()
            .or_else(|| claims["sub"].as_str())
            .filter(|id| !id.is_empty())
            .ok_or_else(|| {
                MsalError::InvalidToken("ID token has no local account identifier".into())
            })?;
        let home_account_id = match (client_info, expected) {
            (Some(info), _) => info.home_account_id(),
            (None, Some(account)) => account.home_account_id.clone(),
            // ADFS issues no client_info; its subject is the stable home identity.
            (None, None) if authority.authority_type == crate::authority::AuthorityType::Adfs => {
                local_account_id.to_string()
            }
            (None, None) => {
                return Err(MsalError::InvalidToken(
                    "ID token response missing client_info; cannot establish home account".into(),
                ))
            }
        };
        let account = AccountInfo {
            home_account_id,
            local_account_id: local_account_id.into(),
            environment: crate::authority::canonical_environment(
                authority.canonical_authority.host_str().unwrap_or_default(),
            ),
            tenant_id,
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
    if !crate::authority::environments_equivalent(
        &account.environment,
        authority.canonical_authority.host_str().unwrap_or_default(),
    ) {
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
    let configured = authority.tenant.to_ascii_lowercase();
    if (configured == "consumers" && !tenant.eq_ignore_ascii_case(CONSUMER_TENANT))
        || (configured == "organizations" && tenant.eq_ignore_ascii_case(CONSUMER_TENANT))
    {
        return Err(MsalError::InvalidToken(
            "token tenant violates authority account type".into(),
        ));
    }
    Ok(())
}

/// Allowed clock skew for ID token `exp`/`nbf` checks, in seconds.
const ID_TOKEN_CLOCK_SKEW: i64 = 300;

/// Tenant identifier used for ADFS accounts, which carry no `tid` claim.
pub(crate) const ADFS_TENANT: &str = "adfs";

/// Only for ID tokens received from the configured token endpoint over TLS.
/// This is not an arbitrary JWT authenticator or resource-server validator.
///
/// Returns the decoded claims and the tenant the token was issued for.
pub(crate) fn validate_endpoint_id_token(
    token: &str,
    authority: &crate::authority::Authority,
    client_id: &str,
    nonce: Option<&str>,
) -> crate::error::Result<(serde_json::Value, String)> {
    use crate::authority::AuthorityType;
    use crate::error::MsalError;
    let header = jsonwebtoken::decode_header(token)?;
    if header.alg != jsonwebtoken::Algorithm::RS256
        || token
            .rsplit('.')
            .next()
            .map_or(true, |signature| signature.is_empty())
    {
        return Err(MsalError::InvalidToken(
            "expected an RS256-signed ID token".into(),
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
    if claims["exp"]
        .as_i64()
        .map_or(true, |exp| exp.saturating_add(ID_TOKEN_CLOCK_SKEW) <= now)
        || claims.get("nbf").is_some_and(|nbf| {
            nbf.as_i64()
                .map_or(true, |nbf| nbf > now.saturating_add(ID_TOKEN_CLOCK_SKEW))
        })
    {
        return Err(MsalError::InvalidToken(
            "ID token expired or not yet valid".into(),
        ));
    }
    let issuer = claims["iss"]
        .as_str()
        .and_then(|issuer| url::Url::parse(issuer).ok())
        .ok_or_else(|| MsalError::InvalidToken("ID token missing or invalid issuer".into()))?;
    let issuer_error =
        || MsalError::InvalidToken("ID token issuer differs from authority/tenant".into());
    if issuer.scheme() != "https"
        || !issuer.username().is_empty()
        || issuer.password().is_some()
        || issuer.query().is_some()
        || issuer.fragment().is_some()
    {
        return Err(issuer_error());
    }
    let authority_host = authority.canonical_authority.host_str().unwrap_or_default();
    let issuer_host = issuer.host_str().unwrap_or_default();
    let tid = claims["tid"].as_str().filter(|tid| !tid.trim().is_empty());
    // Path of a v2 issuer: `/{tenant}/v2.0`, with or without a trailing slash.
    let v2_issuer_tenant = || -> Option<&str> {
        let path = issuer.path().strip_suffix('/').unwrap_or(issuer.path());
        let tenant = path.strip_prefix('/')?.strip_suffix("/v2.0")?;
        (!tenant.is_empty() && !tenant.contains('/')).then_some(tenant)
    };
    let tenant = match authority.authority_type {
        AuthorityType::Aad => {
            let tid =
                tid.ok_or_else(|| MsalError::InvalidToken("ID token missing tenant".into()))?;
            if !crate::authority::environments_equivalent(issuer_host, authority_host)
                || v2_issuer_tenant() != Some(tid)
            {
                return Err(issuer_error());
            }
            tid.to_string()
        }
        AuthorityType::Ciam => {
            // CIAM issuers use the tenant ID as the subdomain, which may differ
            // from the tenant name used in the configured authority host.
            let tid =
                tid.ok_or_else(|| MsalError::InvalidToken("ID token missing tenant".into()))?;
            let expected_host = format!("{tid}.ciamlogin.com");
            if !(issuer_host.eq_ignore_ascii_case(authority_host)
                || issuer_host.eq_ignore_ascii_case(&expected_host))
                || v2_issuer_tenant() != Some(tid)
            {
                return Err(issuer_error());
            }
            tid.to_string()
        }
        AuthorityType::AadB2C => {
            // B2C issuers are `https://{host}/{tenant-id}/v2.0/`, without the policy.
            let issuer_tenant = v2_issuer_tenant().ok_or_else(issuer_error)?;
            if !issuer_host.eq_ignore_ascii_case(authority_host)
                || tid.is_some_and(|tid| !tid.eq_ignore_ascii_case(issuer_tenant))
            {
                return Err(issuer_error());
            }
            issuer_tenant.to_string()
        }
        AuthorityType::Adfs => {
            if !issuer_host.eq_ignore_ascii_case(authority_host)
                || issuer.path().trim_end_matches('/') != "/adfs"
            {
                return Err(issuer_error());
            }
            ADFS_TENANT.to_string()
        }
    };
    validate_tenant(&tenant, authority)?;
    Ok((claims, tenant))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    const TENANT: &str = "11111111-1111-4111-8111-111111111111";

    fn token(claims: serde_json::Value) -> String {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
        format!("{header}.{payload}.signature")
    }

    fn claims(issuer: &str) -> serde_json::Value {
        serde_json::json!({
            "aud": "client", "iss": issuer, "tid": TENANT, "oid": "object",
            "exp": chrono::Utc::now().timestamp() + 3600
        })
    }

    fn check(authority: &str, claims: serde_json::Value) -> crate::error::Result<String> {
        let authority = crate::authority::Authority::from_url_no_discovery(authority)?;
        validate_endpoint_id_token(&token(claims), &authority, "client", None)
            .map(|(_, tenant)| tenant)
    }

    #[test]
    fn aad_issuer_accepts_public_cloud_aliases_only() {
        let issuer = format!("https://login.microsoftonline.com/{TENANT}/v2.0");
        for authority in [
            "https://login.windows.net/common",
            "https://login.microsoft.com/organizations",
            "https://login.microsoftonline.com/common",
        ] {
            assert_eq!(check(authority, claims(&issuer)).unwrap(), TENANT);
        }
        assert!(check("https://login.microsoftonline.us/common", claims(&issuer)).is_err());
        let other_tenant = "https://login.microsoftonline.com/other/v2.0";
        assert!(check("https://login.windows.net/common", claims(other_tenant)).is_err());
    }

    #[test]
    fn ciam_issuer_uses_tenant_id_subdomain() {
        let issuer = format!("https://{TENANT}.ciamlogin.com/{TENANT}/v2.0");
        assert_eq!(
            check(
                "https://contoso.ciamlogin.com/contoso.onmicrosoft.com",
                claims(&issuer)
            )
            .unwrap(),
            TENANT
        );
        assert!(check(
            "https://contoso.ciamlogin.com/contoso.onmicrosoft.com",
            claims(&format!("https://evil.ciamlogin.com/{TENANT}/v2.0"))
        )
        .is_err());
    }

    #[test]
    fn b2c_issuer_is_tenant_scoped_without_policy() {
        let authority = "https://contoso.b2clogin.com/contoso.onmicrosoft.com/B2C_1_signin";
        let issuer = format!("https://contoso.b2clogin.com/{TENANT}/v2.0/");
        assert_eq!(check(authority, claims(&issuer)).unwrap(), TENANT);
        assert!(check(
            authority,
            claims(&format!("https://other.b2clogin.com/{TENANT}/v2.0/"))
        )
        .is_err());
    }

    #[test]
    fn expiry_allows_clock_skew_but_not_stale_tokens() {
        let issuer = format!("https://login.microsoftonline.com/{TENANT}/v2.0");
        let mut value = claims(&issuer);
        value["exp"] = (chrono::Utc::now().timestamp() - 60).into();
        assert!(check("https://login.microsoftonline.com/common", value.clone()).is_ok());
        value["exp"] = (chrono::Utc::now().timestamp() - 3600).into();
        assert!(check("https://login.microsoftonline.com/common", value).is_err());
    }
}
