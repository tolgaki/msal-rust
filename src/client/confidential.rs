use std::sync::Arc;

use crate::account::AccountInfo;
use crate::client::{AppState, ExchangeOptions};
use crate::config::{ClientCredential, Configuration};
use crate::error::{MsalError, Result};
use crate::request::{
    AuthorizationCodeRequest, ClientCredentialRequest, OnBehalfOfRequest, RefreshTokenRequest,
    SilentFlowRequest,
};
use crate::response::AuthenticationResult;

/// Confidential client application for server-side authentication.
///
/// Use this for web apps, daemon services, and APIs that can securely
/// store a client secret or certificate.
#[derive(Clone)]
pub struct ConfidentialClientApplication {
    state: Arc<AppState>,
}

impl ConfidentialClientApplication {
    /// Create a new confidential client application.
    ///
    /// Returns an error if no client credential is configured.
    pub fn new(config: Configuration) -> Result<Self> {
        if config.auth.client_credential.is_none() {
            return Err(MsalError::InvalidConfiguration(
                "confidential client requires a client credential \
                 (secret, certificate, or assertion)"
                    .into(),
            ));
        }
        let state = AppState::new(config)?;
        Ok(Self {
            state: Arc::new(state),
        })
    }

    /// Acquire a token using client credentials (app-only, no user).
    pub async fn acquire_token_by_client_credential(
        &self,
        request: ClientCredentialRequest,
    ) -> Result<AuthenticationResult> {
        let scope_str = request.scopes.join(" ");
        let mut params = vec![
            ("client_id", self.state.config.auth.client_id.as_str()),
            ("grant_type", "client_credentials"),
            ("scope", scope_str.as_str()),
        ];
        append_credential(&self.state.config.auth.client_credential, &mut params)?;
        crate::request::append_request_parameters(
            &mut params,
            &request.claims,
            &request.correlation_id,
            &request.extra_query_parameters,
        )?;

        // Client credential flow has no user — don't cache (no account key).
        let body = crate::network::cancellable(
            request.cancellation_token.as_ref(),
            crate::network::post_token_request(
                &self.state.http,
                &self.state.authority.token_endpoint,
                &params,
            ),
        )
        .await?;
        let token_resp: crate::response::TokenResponse = serde_json::from_value(body)?;
        token_resp.into_authentication_result(
            &self.state.authority,
            &self.state.config.auth.client_id,
            None,
            None,
            &request.scopes,
        )
    }

    /// Exchange an authorization code for tokens.
    pub async fn acquire_token_by_code(
        &self,
        request: AuthorizationCodeRequest,
    ) -> Result<AuthenticationResult> {
        let scope_str = crate::request::user_scopes(&request.scopes).join(" ");
        let mut params = vec![
            ("client_id", self.state.config.auth.client_id.as_str()),
            ("grant_type", "authorization_code"),
            ("code", request.code.as_str()),
            ("redirect_uri", request.redirect_uri.as_str()),
            ("scope", scope_str.as_str()),
        ];
        if let Some(ref v) = request.code_verifier {
            params.push(("code_verifier", v));
        }
        append_credential(&self.state.config.auth.client_credential, &mut params)?;

        self.state
            .exchange_and_cache(
                &params,
                ExchangeOptions {
                    account: None,
                    nonce: request.nonce.as_deref(),
                    scopes: &request.scopes,
                    claims: &request.claims,
                    correlation_id: &request.correlation_id,
                    extra: &request.extra_query_parameters,
                    cancellation: request.cancellation_token.as_ref(),
                },
            )
            .await
    }

    /// Acquire a token on behalf of a user (OBO flow).
    pub async fn acquire_token_on_behalf_of(
        &self,
        request: OnBehalfOfRequest,
    ) -> Result<AuthenticationResult> {
        let scope_str = request.scopes.join(" ");
        let mut params = vec![
            ("client_id", self.state.config.auth.client_id.as_str()),
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", request.user_assertion.as_str()),
            ("scope", scope_str.as_str()),
            ("requested_token_use", "on_behalf_of"),
        ];
        append_credential(&self.state.config.auth.client_credential, &mut params)?;

        self.state
            .exchange_and_cache(
                &params,
                ExchangeOptions {
                    account: None,
                    nonce: None,
                    scopes: &request.scopes,
                    claims: &request.claims,
                    correlation_id: &request.correlation_id,
                    extra: &request.extra_query_parameters,
                    cancellation: request.cancellation_token.as_ref(),
                },
            )
            .await
    }

    /// Acquire a token silently from the cache, falling back to refresh token.
    pub async fn acquire_token_silent(
        &self,
        request: SilentFlowRequest,
    ) -> Result<AuthenticationResult> {
        crate::request::validate_extra_query_parameters(&request.extra_query_parameters)?;
        crate::request::validate_claims(&request.claims)?;
        crate::response::validate_account_authority(&request.account, &self.state.authority)?;
        if let Some(token) = &request.cancellation_token {
            token.check_cancelled()?;
        }
        let context =
            crate::cache::request_context(&request.claims, &request.extra_query_parameters);
        if !request.force_refresh {
            if let Some(cached) =
                self.state
                    .cache
                    .lookup_with_context(&request.account, &request.scopes, &context)?
            {
                return Ok(cached);
            }
        }

        if let Some(rt) = self
            .state
            .cache
            .refresh_with_context(&request.account, &context)?
        {
            let scope_str = crate::request::user_scopes(&request.scopes).join(" ");
            let mut params = vec![
                ("client_id", self.state.config.auth.client_id.as_str()),
                ("grant_type", "refresh_token"),
                ("refresh_token", rt.as_str()),
                ("scope", scope_str.as_str()),
            ];
            append_credential(&self.state.config.auth.client_credential, &mut params)?;

            return self
                .state
                .exchange_and_cache(
                    &params,
                    ExchangeOptions {
                        account: Some(&request.account),
                        nonce: None,
                        scopes: &request.scopes,
                        claims: &request.claims,
                        correlation_id: &request.correlation_id,
                        extra: &request.extra_query_parameters,
                        cancellation: request.cancellation_token.as_ref(),
                    },
                )
                .await;
        }

        Err(MsalError::InteractionRequired(
            "no cached token or refresh token available".into(),
        ))
    }

    /// Acquire a token using a refresh token directly.
    pub async fn acquire_token_by_refresh_token(
        &self,
        request: RefreshTokenRequest,
    ) -> Result<AuthenticationResult> {
        let scope_str = request.scopes.join(" ");
        let mut params = vec![
            ("client_id", self.state.config.auth.client_id.as_str()),
            ("grant_type", "refresh_token"),
            ("refresh_token", request.refresh_token.as_str()),
            ("scope", scope_str.as_str()),
        ];
        append_credential(&self.state.config.auth.client_credential, &mut params)?;

        self.state
            .exchange_and_cache(
                &params,
                ExchangeOptions {
                    account: request.account.as_ref(),
                    nonce: None,
                    scopes: &request.scopes,
                    claims: &request.claims,
                    correlation_id: &request.correlation_id,
                    extra: &request.extra_query_parameters,
                    cancellation: request.cancellation_token.as_ref(),
                },
            )
            .await
    }

    /// Return all accounts in the token cache.
    pub fn all_accounts(&self) -> Vec<AccountInfo> {
        self.state.cache.all_accounts()
    }

    pub fn try_all_accounts(&self) -> Result<Vec<AccountInfo>> {
        self.state.cache.try_all_accounts()
    }

    pub fn export_cache(&self) -> Result<crate::cache::TokenCacheSnapshot> {
        self.state.cache.export()
    }

    pub fn import_cache(&self, snapshot: crate::cache::TokenCacheSnapshot) -> Result<()> {
        self.state.cache.import(snapshot)
    }

    /// Remove an account from the cache.
    pub fn remove_account(&self, account: &AccountInfo) -> Result<()> {
        self.state.cache.remove_account(account)
    }
}

/// Build credential parameters as owned strings (needed because the credential
/// values must live long enough for the request). Returns a small vec that
/// callers extend into their params slice.
fn append_credential<'a>(
    credential: &'a Option<ClientCredential>,
    params: &mut Vec<(&'a str, &'a str)>,
) -> Result<()> {
    match credential {
        Some(ClientCredential::Secret(secret)) => {
            params.push(("client_secret", secret));
        }
        Some(ClientCredential::Assertion(assertion)) => {
            params.push((
                "client_assertion_type",
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            ));
            params.push(("client_assertion", assertion));
        }
        Some(ClientCredential::Certificate { .. }) => {
            return Err(MsalError::InvalidConfiguration(
                "certificate-based auth: build a JWT assertion and use \
                 client_assertion() instead"
                    .into(),
            ));
        }
        None => {
            return Err(MsalError::MissingParameter(
                "client credential is required".into(),
            ));
        }
    }
    Ok(())
}
