use std::sync::Arc;
use tokio::sync::RwLock;

use crate::account::AccountInfo;
use crate::client::AppState;
use crate::config::{ClientCredential, Configuration};
use crate::error::{MsalError, Result};
use crate::network::post_token_request;
use crate::request::{
    AuthorizationCodeRequest, ClientCredentialRequest, OnBehalfOfRequest, RefreshTokenRequest,
    SilentFlowRequest,
};
use crate::response::{AuthenticationResult, TokenResponse};

/// Confidential client application for server-side authentication.
///
/// Use this for web apps, daemon services, and APIs that can securely
/// store a client secret or certificate.
pub struct ConfidentialClientApplication {
    state: Arc<RwLock<AppState>>,
}

impl ConfidentialClientApplication {
    pub fn new(config: Configuration) -> Result<Self> {
        if config.auth.client_credential.is_none() {
            return Err(MsalError::InvalidConfiguration(
                "confidential client requires a client credential (secret, certificate, or assertion)".into(),
            ));
        }
        let state = AppState::new(config)?;
        Ok(Self {
            state: Arc::new(RwLock::new(state)),
        })
    }

    /// Acquire a token using client credentials (app-only, no user).
    pub async fn acquire_token_by_client_credential(
        &self,
        request: ClientCredentialRequest,
    ) -> Result<AuthenticationResult> {
        let s = self.state.read().await;
        let scope_str = request.scopes.join(" ");

        let mut params: Vec<(&str, String)> = vec![
            ("client_id", s.config.auth.client_id.clone()),
            ("grant_type", "client_credentials".into()),
            ("scope", scope_str),
        ];

        append_client_credential(&s.config.auth.client_credential, &mut params)?;

        let params_ref: Vec<(&str, &str)> = params.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let body = post_token_request(&s.http, &s.authority.token_endpoint, &params_ref).await?;
        let token_resp: TokenResponse = serde_json::from_value(body)?;
        Ok(token_resp.into_authentication_result())
    }

    /// Exchange an authorization code for tokens.
    pub async fn acquire_token_by_code(
        &self,
        request: AuthorizationCodeRequest,
    ) -> Result<AuthenticationResult> {
        let s = self.state.read().await;
        let scope_str = request.scopes.join(" ");

        let mut params: Vec<(&str, String)> = vec![
            ("client_id", s.config.auth.client_id.clone()),
            ("grant_type", "authorization_code".into()),
            ("code", request.code),
            ("redirect_uri", request.redirect_uri),
            ("scope", scope_str),
        ];

        if let Some(v) = request.code_verifier {
            params.push(("code_verifier", v));
        }

        append_client_credential(&s.config.auth.client_credential, &mut params)?;

        let params_ref: Vec<(&str, &str)> = params.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let body = post_token_request(&s.http, &s.authority.token_endpoint, &params_ref).await?;
        let token_resp: TokenResponse = serde_json::from_value(body)?;
        let result = token_resp.into_authentication_result();
        s.cache.save(&result);
        Ok(result)
    }

    /// Acquire a token on behalf of a user (OBO flow).
    pub async fn acquire_token_on_behalf_of(
        &self,
        request: OnBehalfOfRequest,
    ) -> Result<AuthenticationResult> {
        let s = self.state.read().await;
        let scope_str = request.scopes.join(" ");

        let mut params: Vec<(&str, String)> = vec![
            ("client_id", s.config.auth.client_id.clone()),
            (
                "grant_type",
                "urn:ietf:params:oauth:grant-type:jwt-bearer".into(),
            ),
            ("assertion", request.user_assertion),
            ("scope", scope_str),
            ("requested_token_use", "on_behalf_of".into()),
        ];

        append_client_credential(&s.config.auth.client_credential, &mut params)?;

        let params_ref: Vec<(&str, &str)> = params.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let body = post_token_request(&s.http, &s.authority.token_endpoint, &params_ref).await?;
        let token_resp: TokenResponse = serde_json::from_value(body)?;
        let result = token_resp.into_authentication_result();
        s.cache.save(&result);
        Ok(result)
    }

    /// Acquire a token silently from the cache, falling back to refresh token.
    pub async fn acquire_token_silent(
        &self,
        request: SilentFlowRequest,
    ) -> Result<AuthenticationResult> {
        let s = self.state.read().await;

        if !request.force_refresh {
            if let Some(cached) = s
                .cache
                .lookup_access_token(&request.account, &request.scopes)
            {
                return Ok(cached);
            }
        }

        if let Some(rt) = s.cache.lookup_refresh_token(&request.account) {
            let scope_str = request.scopes.join(" ");
            let mut params: Vec<(&str, String)> = vec![
                ("client_id", s.config.auth.client_id.clone()),
                ("grant_type", "refresh_token".into()),
                ("refresh_token", rt),
                ("scope", scope_str),
            ];

            append_client_credential(&s.config.auth.client_credential, &mut params)?;

            let params_ref: Vec<(&str, &str)> =
                params.iter().map(|(k, v)| (*k, v.as_str())).collect();
            let body =
                post_token_request(&s.http, &s.authority.token_endpoint, &params_ref).await?;
            let token_resp: TokenResponse = serde_json::from_value(body)?;
            let result = token_resp.into_authentication_result();
            s.cache.save(&result);
            return Ok(result);
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
        let s = self.state.read().await;
        let scope_str = request.scopes.join(" ");

        let mut params: Vec<(&str, String)> = vec![
            ("client_id", s.config.auth.client_id.clone()),
            ("grant_type", "refresh_token".into()),
            ("refresh_token", request.refresh_token),
            ("scope", scope_str),
        ];

        append_client_credential(&s.config.auth.client_credential, &mut params)?;

        let params_ref: Vec<(&str, &str)> = params.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let body = post_token_request(&s.http, &s.authority.token_endpoint, &params_ref).await?;
        let token_resp: TokenResponse = serde_json::from_value(body)?;
        let result = token_resp.into_authentication_result();
        s.cache.save(&result);
        Ok(result)
    }

    /// Get all accounts in the token cache.
    pub async fn get_all_accounts(&self) -> Vec<AccountInfo> {
        let s = self.state.read().await;
        s.cache.all_accounts()
    }

    /// Remove an account from the cache.
    pub async fn remove_account(&self, account: &AccountInfo) -> Result<()> {
        let s = self.state.read().await;
        s.cache.remove_account(account)
    }
}

fn append_client_credential(
    credential: &Option<ClientCredential>,
    params: &mut Vec<(&str, String)>,
) -> Result<()> {
    match credential {
        Some(ClientCredential::Secret(secret)) => {
            params.push(("client_secret", secret.clone()));
        }
        Some(ClientCredential::Assertion(assertion)) => {
            params.push((
                "client_assertion_type",
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".into(),
            ));
            params.push(("client_assertion", assertion.clone()));
        }
        Some(ClientCredential::Certificate { .. }) => {
            // Certificate-based auth requires building a JWT assertion from the cert.
            // For now, callers should use `client_assertion` with a pre-built JWT.
            return Err(MsalError::InvalidConfiguration(
                "certificate-based auth: build a JWT assertion and use client_assertion() instead"
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
