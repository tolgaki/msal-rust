//! Authority resolution and OpenID Connect discovery.
//!
//! An *authority* identifies the token issuer — it determines which token
//! endpoint, authorization endpoint, and device-code endpoint to use.
//!
//! MSAL supports four authority types:
//!
//! | Type | Example URL |
//! |------|-------------|
//! | Azure AD | `https://login.microsoftonline.com/{tenant}` |
//! | Azure AD B2C | `https://{tenant}.b2clogin.com/{tenant}/{policy}` |
//! | ADFS | `https://adfs.contoso.com/adfs` |
//! | CIAM | `https://{tenant}.ciamlogin.com/{tenant}` |

use serde::Deserialize;
use url::Url;

use crate::error::{MsalError, Result};

/// The type of identity authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthorityType {
    /// Azure Active Directory (single-tenant or multi-tenant).
    Aad,
    /// Azure Active Directory B2C (customer-facing identity).
    AadB2C,
    /// Active Directory Federation Services (on-premises).
    Adfs,
    /// Customer Identity and Access Management.
    Ciam,
}

/// A resolved authority with endpoint URLs.
///
/// Create via [`Authority::resolve`] (with network discovery) or
/// [`Authority::from_url_no_discovery`] (using default v2.0 endpoint patterns).
#[derive(Debug, Clone)]
pub struct Authority {
    /// Detected authority type.
    pub authority_type: AuthorityType,
    /// The canonical authority URL.
    pub canonical_authority: Url,
    /// The tenant path segment (e.g., `"common"`, a GUID, or a domain).
    pub tenant: String,
    /// OAuth 2.0 authorization endpoint.
    pub authorization_endpoint: String,
    /// OAuth 2.0 token endpoint.
    pub token_endpoint: String,
    /// OAuth 2.0 device authorization endpoint.
    pub device_code_endpoint: String,
    /// Token issuer identifier.
    pub issuer: String,
}

/// OpenID Connect discovery document response.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct OpenIdConfig {
    /// OAuth 2.0 authorization endpoint URL.
    pub authorization_endpoint: String,
    /// OAuth 2.0 token endpoint URL.
    pub token_endpoint: String,
    /// Device authorization endpoint URL (optional in the spec).
    #[serde(default)]
    pub device_authorization_endpoint: Option<String>,
    /// Token issuer identifier.
    pub issuer: String,
}

impl Authority {
    /// Resolve authority metadata by fetching the OpenID Connect discovery document.
    ///
    /// Issues a GET to `{authority}/.well-known/openid-configuration` and parses
    /// the response to populate endpoint URLs.
    pub async fn resolve(authority_url: &str, http: &reqwest::Client) -> Result<Self> {
        let url = Url::parse(authority_url)
            .map_err(|e| MsalError::AuthorityValidation(format!("invalid authority URL: {e}")))?;

        Self::validate_authority_url(&url)?;
        let authority_type = detect_authority_type(&url);
        let tenant = extract_tenant(&url);

        let discovery_url = format!(
            "{}/.well-known/openid-configuration",
            url.as_str().trim_end_matches('/')
        );

        let resp = http.get(&discovery_url).send().await?;

        if !resp.status().is_success() {
            return Err(MsalError::AuthorityMetadataNotFound(format!(
                "failed to fetch OpenID config from {discovery_url}: HTTP {}",
                resp.status()
            )));
        }

        let config: OpenIdConfig = resp.json().await?;

        let device_code_endpoint = config.device_authorization_endpoint.unwrap_or_else(|| {
            format!(
                "{}/oauth2/v2.0/devicecode",
                url.as_str().trim_end_matches('/')
            )
        });

        Ok(Authority {
            authority_type,
            canonical_authority: url,
            tenant,
            authorization_endpoint: config.authorization_endpoint,
            token_endpoint: config.token_endpoint,
            device_code_endpoint,
            issuer: config.issuer,
        })
    }

    /// Create an authority using default Azure AD v2.0 endpoint patterns,
    /// without issuing any network requests.
    ///
    /// This is useful for offline configuration or when the OpenID discovery
    /// document is not needed.
    pub fn from_url_no_discovery(authority_url: &str) -> Result<Self> {
        let url = Url::parse(authority_url)
            .map_err(|e| MsalError::AuthorityValidation(format!("invalid authority URL: {e}")))?;
        Self::validate_authority_url(&url)?;

        let authority_type = detect_authority_type(&url);
        let tenant = extract_tenant(&url);
        let base = url.as_str().trim_end_matches('/').to_string();

        Ok(Authority {
            authority_type,
            canonical_authority: url,
            tenant: tenant.clone(),
            authorization_endpoint: format!("{base}/oauth2/v2.0/authorize"),
            token_endpoint: format!("{base}/oauth2/v2.0/token"),
            device_code_endpoint: format!("{base}/oauth2/v2.0/devicecode"),
            issuer: format!("{base}/v2.0"),
        })
    }

    pub(crate) fn validate_authority_url(url: &Url) -> Result<()> {
        let loopback = matches!(
            url.host_str(),
            Some("localhost" | "127.0.0.1" | "[::1]" | "::1")
        );
        if (url.scheme() != "https" && !(url.scheme() == "http" && loopback))
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.host_str().is_none()
        {
            return Err(MsalError::AuthorityValidation("authority must be HTTPS without credentials, query or fragment (HTTP loopback is test/development only)".into()));
        }
        Ok(())
    }

    /// Whether identities for this authority must be bound to a tenant ID that
    /// only discovery can supply: an Entra or CIAM authority whose tenant is a
    /// domain name (`contoso.onmicrosoft.com`) rather than a GUID or one of the
    /// multi-tenant aliases.
    pub(crate) fn needs_tenant_resolution(&self) -> bool {
        matches!(
            self.authority_type,
            AuthorityType::Aad | AuthorityType::Ciam
        ) && !matches!(
            self.tenant.to_ascii_lowercase().as_str(),
            "common" | "organizations" | "consumers"
        ) && uuid::Uuid::parse_str(&self.tenant).is_err()
    }

    /// Return a copy of this authority whose `tenant` is the tenant GUID that
    /// the authority's own v2.0 OpenID configuration names in its issuer.
    ///
    /// Endpoints are left unchanged. Tenant validation then compares account
    /// and ID token tenants with this GUID, so tokens and cached identities
    /// from another tenant are rejected for domain-name authorities too.
    pub(crate) async fn resolve_tenant_id(&self, http: &reqwest::Client) -> Result<Self> {
        let discovery_url = format!(
            "{}/v2.0/.well-known/openid-configuration",
            self.canonical_authority.as_str().trim_end_matches('/')
        );
        let unresolved = |detail: String| {
            MsalError::AuthorityMetadataNotFound(format!(
                "cannot resolve tenant ID for {}: {detail}",
                self.canonical_authority
            ))
        };
        let response = http.get(&discovery_url).send().await?;
        if !response.status().is_success() {
            return Err(unresolved(format!("HTTP {}", response.status())));
        }
        let config: OpenIdConfig = response.json().await?;
        let issuer = Url::parse(&config.issuer)
            .map_err(|_| unresolved("discovery issuer is not a URL".into()))?;
        let mut segments = issuer
            .path_segments()
            .map(|segments| segments.filter(|segment| !segment.is_empty()))
            .ok_or_else(|| unresolved("discovery issuer has no path".into()))?;
        let tenant_id = match (segments.next(), segments.next(), segments.next()) {
            (Some(tenant), Some("v2.0"), None) if uuid::Uuid::parse_str(tenant).is_ok() => {
                tenant.to_ascii_lowercase()
            }
            _ => return Err(unresolved("discovery issuer names no tenant GUID".into())),
        };
        let authority_host = self.canonical_authority.host_str().unwrap_or_default();
        let issuer_host = issuer.host_str().unwrap_or_default();
        let host_matches = environments_equivalent(issuer_host, authority_host)
            || (self.authority_type == AuthorityType::Ciam
                && issuer_host.eq_ignore_ascii_case(&format!("{tenant_id}.ciamlogin.com")));
        if issuer.scheme() != "https" || !host_matches {
            return Err(unresolved(
                "discovery issuer host differs from authority".into(),
            ));
        }
        let mut resolved = self.clone();
        resolved.tenant = tenant_id;
        Ok(resolved)
    }

    /// Whether `other` names this same authority, ignoring host case, known
    /// public-cloud host aliases, tenant case and a trailing slash.
    pub(crate) fn is_same_authority(&self, other: &str) -> Result<bool> {
        let other = Url::parse(other)
            .map_err(|e| MsalError::AuthorityValidation(format!("invalid authority URL: {e}")))?;
        let this = &self.canonical_authority;
        let normalized_path = |url: &Url| url.path().trim_end_matches('/').to_ascii_lowercase();
        Ok(this.scheme() == other.scheme()
            && this.port_or_known_default() == other.port_or_known_default()
            && environments_equivalent(
                this.host_str().unwrap_or_default(),
                other.host_str().unwrap_or_default(),
            )
            && normalized_path(this) == normalized_path(&other)
            && other.query().is_none()
            && other.fragment().is_none())
    }
}

/// Host groups that Entra ID treats as one cloud environment. The first host
/// of each group is its canonical (preferred) environment.
const CLOUD_ALIAS_GROUPS: &[&[&str]] = &[
    &[
        "login.microsoftonline.com",
        "login.windows.net",
        "login.microsoft.com",
        "sts.windows.net",
    ],
    &["login.partner.microsoftonline.cn", "login.chinacloudapi.cn"],
    &["login.microsoftonline.us", "login.usgovcloudapi.net"],
];

/// Canonical, lowercase environment for cache keys and account identity.
pub(crate) fn canonical_environment(host: &str) -> String {
    CLOUD_ALIAS_GROUPS
        .iter()
        .find(|group| group.iter().any(|alias| alias.eq_ignore_ascii_case(host)))
        .map_or_else(|| host.to_ascii_lowercase(), |group| group[0].to_string())
}

/// Whether two environments name the same cloud (case-insensitive, alias-aware).
pub(crate) fn environments_equivalent(left: &str, right: &str) -> bool {
    canonical_environment(left) == canonical_environment(right)
}

fn detect_authority_type(url: &Url) -> AuthorityType {
    let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
    // Match the first path segment exactly: substring matching would classify
    // e.g. `/adfscorp.onmicrosoft.com` as ADFS and skip tenant checks.
    let first_segment = url
        .path_segments()
        .and_then(|mut segments| segments.next())
        .unwrap_or_default()
        .to_ascii_lowercase();

    if host.ends_with(".b2clogin.com") || first_segment == "tfp" {
        AuthorityType::AadB2C
    } else if host.ends_with(".ciamlogin.com") {
        AuthorityType::Ciam
    } else if first_segment == "adfs" {
        AuthorityType::Adfs
    } else {
        AuthorityType::Aad
    }
}

fn extract_tenant(url: &Url) -> String {
    url.path_segments()
        .and_then(|mut s| s.next())
        .unwrap_or("common")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_aad() {
        let url = Url::parse("https://login.microsoftonline.com/common").unwrap();
        assert_eq!(detect_authority_type(&url), AuthorityType::Aad);
    }

    #[test]
    fn detect_b2c() {
        let url = Url::parse("https://contoso.b2clogin.com/contoso/b2c_1_signin").unwrap();
        assert_eq!(detect_authority_type(&url), AuthorityType::AadB2C);
    }

    #[test]
    fn detect_adfs() {
        let url = Url::parse("https://adfs.contoso.com/adfs").unwrap();
        assert_eq!(detect_authority_type(&url), AuthorityType::Adfs);
    }

    #[test]
    fn detect_ciam() {
        let url = Url::parse("https://contoso.ciamlogin.com/contoso").unwrap();
        assert_eq!(detect_authority_type(&url), AuthorityType::Ciam);
    }

    #[test]
    fn extract_tenant_common() {
        let url = Url::parse("https://login.microsoftonline.com/common").unwrap();
        assert_eq!(extract_tenant(&url), "common");
    }

    #[test]
    fn extract_tenant_guid() {
        let url =
            Url::parse("https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47")
                .unwrap();
        assert_eq!(extract_tenant(&url), "72f988bf-86f1-41af-91ab-2d7cd011db47");
    }

    #[test]
    fn from_url_no_discovery_endpoints() {
        let authority =
            Authority::from_url_no_discovery("https://login.microsoftonline.com/my-tenant")
                .unwrap();
        assert_eq!(authority.tenant, "my-tenant");
        assert!(authority.token_endpoint.ends_with("/oauth2/v2.0/token"));
        assert!(authority
            .authorization_endpoint
            .ends_with("/oauth2/v2.0/authorize"));
    }
}
