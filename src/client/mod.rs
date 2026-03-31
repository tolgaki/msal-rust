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
use crate::response::{AuthenticationResult, TokenResponse};

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
        let cache = TokenCache::new();
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
    ) -> Result<AuthenticationResult> {
        let body =
            crate::network::post_token_request(&self.http, &self.authority.token_endpoint, params)
                .await?;
        let token_resp: TokenResponse = serde_json::from_value(body)?;
        let result = token_resp.into_authentication_result();
        self.cache.save(&result)?;
        Ok(result)
    }
}
