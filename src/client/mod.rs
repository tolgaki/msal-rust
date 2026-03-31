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

/// Shared internal state for client applications.
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

    /// Re-resolve authority metadata via OpenID Connect discovery.
    #[allow(dead_code)] // Used by clients that opt into runtime discovery.
    pub async fn resolve_authority(&mut self) -> Result<()> {
        self.authority = Authority::resolve(&self.config.auth.authority, &self.http).await?;
        Ok(())
    }
}
