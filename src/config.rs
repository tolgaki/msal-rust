//! Application configuration for MSAL clients.
//!
//! Use [`Configuration::builder`] to construct a configuration, then pass it to
//! [`PublicClientApplication::new`] or [`ConfidentialClientApplication::new`].
//!
//! ```
//! use msal::Configuration;
//!
//! let config = Configuration::builder("my-client-id")
//!     .authority("https://login.microsoftonline.com/my-tenant")
//!     .client_secret("my-secret")
//!     .timeout_ms(60_000)
//!     .build();
//!
//! assert_eq!(config.auth.client_id, "my-client-id");
//! assert!(config.is_confidential());
//! ```
//!
//! [`PublicClientApplication::new`]: crate::client::public::PublicClientApplication::new
//! [`ConfidentialClientApplication::new`]: crate::client::confidential::ConfidentialClientApplication::new

use crate::error::MsalError;

/// Client credential for [`ConfidentialClientApplication`](crate::ConfidentialClientApplication).
#[derive(Debug, Clone)]
pub enum ClientCredential {
    /// A client secret string.
    Secret(String),
    /// An X.509 certificate with its private key and thumbprint.
    Certificate {
        /// PEM-encoded private key.
        private_key_pem: String,
        /// Certificate thumbprint (SHA-1 hex).
        thumbprint: String,
    },
    /// A pre-built client assertion JWT.
    Assertion(String),
}

/// Top-level MSAL configuration.
#[derive(Debug, Clone)]
pub struct Configuration {
    /// Authentication parameters.
    pub auth: AuthConfig,
    /// Cache settings.
    pub cache: CacheConfig,
    /// HTTP client settings.
    pub http: HttpConfig,
}

/// Authentication-specific configuration.
#[derive(Debug, Clone)]
pub struct AuthConfig {
    /// The application (client) ID from Azure app registration.
    pub client_id: String,
    /// The authority URL (e.g., `https://login.microsoftonline.com/common`).
    pub authority: String,
    /// Client credential for confidential clients. `None` for public clients.
    pub client_credential: Option<ClientCredential>,
    /// Redirect URI for authorization code flows.
    pub redirect_uri: Option<String>,
    /// Additional trusted authority hosts for authority validation.
    pub known_authorities: Vec<String>,
}

/// Token cache configuration.
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Whether to store tokens in memory (default: `true`).
    pub store_in_memory: bool,
}

/// HTTP client configuration.
#[derive(Debug, Clone)]
pub struct HttpConfig {
    /// Request timeout in milliseconds (default: 30 000).
    pub timeout_ms: u64,
    /// Optional HTTP proxy URL (e.g., `http://proxy:8080`).
    pub proxy: Option<String>,
}

impl Configuration {
    /// Create a [`ConfigurationBuilder`] with the given client ID.
    pub fn builder(client_id: impl Into<String>) -> ConfigurationBuilder {
        ConfigurationBuilder::new(client_id)
    }

    /// Returns `true` if a client credential is configured (confidential client).
    pub fn is_confidential(&self) -> bool {
        self.auth.client_credential.is_some()
    }
}

/// Fluent builder for [`Configuration`].
pub struct ConfigurationBuilder {
    client_id: String,
    authority: String,
    client_credential: Option<ClientCredential>,
    redirect_uri: Option<String>,
    known_authorities: Vec<String>,
    store_in_memory: bool,
    timeout_ms: u64,
    proxy: Option<String>,
}

impl ConfigurationBuilder {
    /// Create a new builder with the given application (client) ID.
    pub fn new(client_id: impl Into<String>) -> Self {
        Self {
            client_id: client_id.into(),
            authority: "https://login.microsoftonline.com/common".into(),
            client_credential: None,
            redirect_uri: None,
            known_authorities: Vec::new(),
            store_in_memory: true,
            timeout_ms: 30_000,
            proxy: None,
        }
    }

    /// Set the authority URL.
    ///
    /// Defaults to `https://login.microsoftonline.com/common` (multi-tenant).
    /// For single-tenant apps, use `https://login.microsoftonline.com/{tenant-id}`.
    pub fn authority(mut self, authority: impl Into<String>) -> Self {
        self.authority = authority.into();
        self
    }

    /// Set a client secret credential (confidential client).
    pub fn client_secret(mut self, secret: impl Into<String>) -> Self {
        self.client_credential = Some(ClientCredential::Secret(secret.into()));
        self
    }

    /// Set a client certificate credential (confidential client).
    pub fn client_certificate(
        mut self,
        private_key_pem: impl Into<String>,
        thumbprint: impl Into<String>,
    ) -> Self {
        self.client_credential = Some(ClientCredential::Certificate {
            private_key_pem: private_key_pem.into(),
            thumbprint: thumbprint.into(),
        });
        self
    }

    /// Set a pre-built client assertion JWT (confidential client).
    pub fn client_assertion(mut self, assertion: impl Into<String>) -> Self {
        self.client_credential = Some(ClientCredential::Assertion(assertion.into()));
        self
    }

    /// Set the redirect URI for authorization code flows.
    pub fn redirect_uri(mut self, uri: impl Into<String>) -> Self {
        self.redirect_uri = Some(uri.into());
        self
    }

    /// Add trusted authority hosts for authority validation.
    pub fn known_authorities(
        mut self,
        authorities: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.known_authorities = authorities.into_iter().map(Into::into).collect();
        self
    }

    /// Set the HTTP request timeout in milliseconds (default: 30 000).
    pub fn timeout_ms(mut self, ms: u64) -> Self {
        self.timeout_ms = ms;
        self
    }

    /// Set an HTTP proxy URL.
    pub fn proxy(mut self, proxy: impl Into<String>) -> Self {
        self.proxy = Some(proxy.into());
        self
    }

    /// Build the [`Configuration`].
    pub fn build(self) -> Configuration {
        Configuration {
            auth: AuthConfig {
                client_id: self.client_id,
                authority: self.authority,
                client_credential: self.client_credential,
                redirect_uri: self.redirect_uri,
                known_authorities: self.known_authorities,
            },
            cache: CacheConfig {
                store_in_memory: self.store_in_memory,
            },
            http: HttpConfig {
                timeout_ms: self.timeout_ms,
                proxy: self.proxy,
            },
        }
    }

    /// Build and validate the configuration, returning an error if invalid.
    pub fn build_validated(self) -> crate::error::Result<Configuration> {
        if self.client_id.is_empty() {
            return Err(MsalError::InvalidConfiguration(
                "client_id must not be empty".into(),
            ));
        }
        if self.authority.is_empty() {
            return Err(MsalError::InvalidConfiguration(
                "authority must not be empty".into(),
            ));
        }
        Ok(self.build())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_defaults() {
        let config = Configuration::builder("test-id").build();
        assert_eq!(config.auth.client_id, "test-id");
        assert_eq!(
            config.auth.authority,
            "https://login.microsoftonline.com/common"
        );
        assert!(!config.is_confidential());
        assert_eq!(config.http.timeout_ms, 30_000);
    }

    #[test]
    fn builder_confidential() {
        let config = Configuration::builder("test-id")
            .client_secret("secret")
            .build();
        assert!(config.is_confidential());
    }

    #[test]
    fn build_validated_rejects_empty_client_id() {
        let result = Configuration::builder("").build_validated();
        assert!(result.is_err());
    }
}
