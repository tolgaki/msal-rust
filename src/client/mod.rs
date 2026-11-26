//! Client application types for token acquisition.
//!
//! MSAL provides two client types following the OAuth 2.0 client model:
//!
//! - [`PublicClientApplication`](public::PublicClientApplication) — for
//!   desktop, mobile, and CLI apps that cannot securely store a client secret.
//! - [`ConfidentialClientApplication`](confidential::ConfidentialClientApplication) —
//!   for web apps, daemons, and APIs that can securely store credentials.

pub mod confidential;
pub mod public;

use crate::authority::Authority;
use crate::cache::TokenCache;
use crate::config::Configuration;
use crate::error::Result;
use crate::request::{append_request_parameters, CancellationToken};
use crate::response::{AuthenticationResult, TokenResponse};
use std::collections::BTreeMap;

pub(crate) struct ExchangeOptions<'a> {
    pub account: Option<&'a crate::account::AccountInfo>,
    pub nonce: Option<&'a str>,
    pub scopes: &'a [String],
    pub claims: &'a Option<String>,
    pub correlation_id: &'a Option<String>,
    pub extra: &'a BTreeMap<String, String>,
    pub cancellation: Option<&'a CancellationToken>,
}

/// Shared internal state for client applications.
///
/// Immutable after construction — `TokenCache` provides its own interior
/// mutability via `std::sync::RwLock`. Stored behind `Arc` (no outer lock).
pub(crate) struct AppState {
    pub config: Configuration,
    pub http: reqwest::Client,
    pub cache: TokenCache,
    pub authority: Authority,
}

impl AppState {
    pub fn new(config: Configuration) -> Result<Self> {
        let http = crate::network::build_http_client(&config.http)?;
        let authority = Authority::from_url_no_discovery(&config.auth.authority)?;
        let cache = TokenCache::for_client(config.auth.client_id.clone());
        Ok(Self {
            config,
            http,
            cache,
            authority,
        })
    }

    /// Exchange token endpoint parameters for an [`AuthenticationResult`],
    /// saving the result in the cache.
    pub async fn exchange_and_cache(
        &self,
        params: &[(&str, &str)],
        options: ExchangeOptions<'_>,
    ) -> Result<AuthenticationResult> {
        let authority = match options.account {
            Some(account) => {
                crate::response::validate_account_authority(account, &self.authority)?;
                if self.authority.authority_type == crate::authority::AuthorityType::Aad
                    && matches!(
                        self.authority.tenant.as_str(),
                        "common" | "organizations" | "consumers"
                    )
                {
                    let mut url = self.authority.canonical_authority.clone();
                    url.path_segments_mut()
                        .map_err(|_| {
                            crate::error::MsalError::AuthorityValidation(
                                "authority has no path".into(),
                            )
                        })?
                        .clear()
                        .push(&account.tenant_id);
                    Authority::from_url_no_discovery(url.as_str())?
                } else {
                    self.authority.clone()
                }
            }
            None => self.authority.clone(),
        };
        let mut params = params.to_vec();
        params.push(("client_info", "1"));
        append_request_parameters(
            &mut params,
            options.claims,
            options.correlation_id,
            options.extra,
        )?;
        let body = crate::network::cancellable(
            options.cancellation,
            crate::network::post_token_request(&self.http, &authority.token_endpoint, &params),
        )
        .await?;
        let token_resp: TokenResponse = serde_json::from_value(body)?;
        let mut result = token_resp.into_authentication_result(
            &authority,
            &self.config.auth.client_id,
            options.account,
            options.nonce,
            options.scopes,
        )?;
        let grant = params
            .iter()
            .find(|(key, _)| *key == "grant_type")
            .map(|(_, value)| *value);
        if matches!(
            grant,
            Some(
                "authorization_code" | "password" | "urn:ietf:params:oauth:grant-type:device_code"
            )
        ) && result.account.is_none()
        {
            return Err(crate::error::MsalError::InvalidToken(
                "login response cannot establish account identity; request openid and client_info"
                    .into(),
            ));
        }
        if grant == Some("refresh_token") && result.refresh_token.is_none() {
            result.refresh_token = params
                .iter()
                .find(|(key, _)| *key == "refresh_token")
                .map(|(_, value)| value.to_string());
        }
        // Cache before honoring a late cancellation: the server has already
        // issued (and possibly rotated) tokens, and dropping them here could
        // strand the cache with a refresh token that is no longer valid.
        let context = crate::cache::request_context(options.claims, options.extra);
        if self.config.cache.store_in_memory {
            self.cache.save_with_context(&result, &context)?;
        }
        if let Some(token) = options.cancellation {
            token.check_cancelled()?;
        }
        Ok(result)
    }
}
