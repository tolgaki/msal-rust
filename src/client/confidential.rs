use std::sync::Arc;

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

        let mut params: Vec<(&str, String)> = vec![
            ("client_id", self.state.config.auth.client_id.clone()),
            ("grant_type", "client_credentials".into()),
            ("scope", scope_str),
        ];

        append_client_credential(&self.state.config.auth.client_credential, &mut params)?;

        let params_ref: Vec<(&str, &str)> = params.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let body = post_token_request(
            &self.state.http,
            &self.state.authority.token_endpoint,
            &params_ref,
        )
        .await?;
        let token_resp: TokenResponse = serde_json::from_value(body)?;
        Ok(token_resp.into_authentication_result())
    }

    /// Exchange an authorization code for tokens.
    pub async fn acquire_token_by_code(
        &self,
        request: AuthorizationCodeRequest,
    ) -> Result<AuthenticationResult> {
        let scope_str = request.scopes.join(" ");

        let mut params: Vec<(&str, String)> = vec![
            ("client_id", self.state.config.auth.client_id.clone()),
            ("grant_type", "authorization_code".into()),
            ("code", request.code),
            ("redirect_uri", request.redirect_uri),
            ("scope", scope_str),
        ];

        if let Some(v) = request.code_verifier {
            params.push(("code_verifier", v));
        }

        append_client_credential(&self.state.config.auth.client_credential, &mut params)?;

        let params_ref: Vec<(&str, &str)> = params.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let body = post_token_request(
            &self.state.http,
            &self.state.authority.token_endpoint,
            &params_ref,
        )
        .await?;
        let token_resp: TokenResponse = serde_json::from_value(body)?;
        let result = token_resp.into_authentication_result();
        self.state.cache.save(&result);
        Ok(result)
    }

    /// Acquire a token on behalf of a user (OBO flow).
    pub async fn acquire_token_on_behalf_of(
        &self,
        request: OnBehalfOfRequest,
    ) -> Result<AuthenticationResult> {
        let scope_str = request.scopes.join(" ");

        let mut params: Vec<(&str, String)> = vec![
            ("client_id", self.state.config.auth.client_id.clone()),
            (
                "grant_type",
                "urn:ietf:params:oauth:grant-type:jwt-bearer".into(),
            ),
            ("assertion", request.user_assertion),
            ("scope", scope_str),
            ("requested_token_use", "on_behalf_of".into()),
        ];

        append_client_credential(&self.state.config.auth.client_credential, &mut params)?;

        let params_ref: Vec<(&str, &str)> = params.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let body = post_token_request(
            &self.state.http,
            &self.state.authority.token_endpoint,
            &params_ref,
        )
        .await?;
        let token_resp: TokenResponse = serde_json::from_value(body)?;
        let result = token_resp.into_authentication_result();
        self.state.cache.save(&result);
        Ok(result)
    }

    /// Acquire a token silently from the cache, falling back to refresh token.
    pub async fn acquire_token_silent(
        &self,
        request: SilentFlowRequest,
    ) -> Result<AuthenticationResult> {
        if !request.force_refresh {
            if let Some(cached) = self
                .state
                .cache
                .lookup_access_token(&request.account, &request.scopes)
            {
                return Ok(cached);
            }
        }

        if let Some(rt) = self.state.cache.lookup_refresh_token(&request.account) {
            let scope_str = request.scopes.join(" ");
            let mut params: Vec<(&str, String)> = vec![
                ("client_id", self.state.config.auth.client_id.clone()),
                ("grant_type", "refresh_token".into()),
                ("refresh_token", rt),
                ("scope", scope_str),
            ];

            append_client_credential(&self.state.config.auth.client_credential, &mut params)?;

            let params_ref: Vec<(&str, &str)> =
                params.iter().map(|(k, v)| (*k, v.as_str())).collect();
            let body = post_token_request(
                &self.state.http,
                &self.state.authority.token_endpoint,
                &params_ref,
            )
            .await?;
            let token_resp: TokenResponse = serde_json::from_value(body)?;
            let result = token_resp.into_authentication_result();
            self.state.cache.save(&result);
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
        let scope_str = request.scopes.join(" ");

        let mut params: Vec<(&str, String)> = vec![
            ("client_id", self.state.config.auth.client_id.clone()),
            ("grant_type", "refresh_token".into()),
            ("refresh_token", request.refresh_token),
            ("scope", scope_str),
        ];

        append_client_credential(&self.state.config.auth.client_credential, &mut params)?;

        let params_ref: Vec<(&str, &str)> = params.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let body = post_token_request(
            &self.state.http,
            &self.state.authority.token_endpoint,
            &params_ref,
        )
        .await?;
        let token_resp: TokenResponse = serde_json::from_value(body)?;
        let result = token_resp.into_authentication_result();
        self.state.cache.save(&result);
        Ok(result)
    }

    /// Return all accounts in the token cache.
    pub fn all_accounts(&self) -> Vec<AccountInfo> {
        self.state.cache.all_accounts()
    }

    /// Remove an account from the cache.
    pub fn remove_account(&self, account: &AccountInfo) -> Result<()> {
        self.state.cache.remove_account(account)
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
