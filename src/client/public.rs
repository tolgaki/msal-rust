use std::sync::Arc;
use tokio::sync::RwLock;

use crate::account::AccountInfo;
use crate::broker::{BrokerSignOutRequest, BrokerTokenRequest, NativeBroker};
use crate::client::AppState;
use crate::config::Configuration;
use crate::crypto::PkceParams;
use crate::error::{MsalError, Result};
use crate::network::post_token_request;
use crate::request::{
    AuthorizationCodeRequest, DeviceCodeInfo, DeviceCodeRequest, RefreshTokenRequest,
    SilentFlowRequest, UsernamePasswordRequest,
};
use crate::response::{AuthenticationResult, TokenResponse};

/// Public client application for user-based authentication flows.
///
/// Use this for desktop apps, CLI tools, and other public clients that
/// cannot securely store a client secret.
///
/// # Brokered Authentication
///
/// Call [`set_broker`](Self::set_broker) to enable native broker support (WAM on Windows).
/// When a broker is set and available, `acquire_token_interactive` and
/// `acquire_token_silent` will delegate to the broker for device-bound tokens
/// and system-wide SSO. If the broker is not available, standard OAuth flows
/// are used.
///
/// **Important**: broker failures do NOT fall back to browser-based flows.
/// If the broker returns an error, it propagates to the caller.
#[derive(Clone)]
pub struct PublicClientApplication {
    state: Arc<AppState>,
    broker: Arc<RwLock<Option<Box<dyn NativeBroker>>>>,
}

impl PublicClientApplication {
    /// Create a new public client application.
    pub fn new(config: Configuration) -> Result<Self> {
        let state = AppState::new(config)?;
        Ok(Self {
            state: Arc::new(state),
            broker: Arc::new(RwLock::new(None)),
        })
    }

    /// Set a native authentication broker plugin.
    ///
    /// When set, `acquire_token_interactive` and `acquire_token_silent` will
    /// delegate to the broker if it reports itself as available.
    ///
    /// ```no_run
    /// # use msal::{Configuration, PublicClientApplication};
    /// # async fn example() -> Result<(), msal::MsalError> {
    /// # let config = Configuration::builder("id").build();
    /// let app = PublicClientApplication::new(config)?;
    ///
    /// #[cfg(target_os = "windows")]
    /// {
    ///     let broker = msal::broker::wam::WamBroker::new().await?;
    ///     app.set_broker(Box::new(broker)).await;
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn set_broker(&self, broker: Box<dyn NativeBroker>) {
        let mut b = self.broker.write().await;
        *b = Some(broker);
    }

    /// Returns `true` if a broker is configured and reports itself as available.
    pub async fn is_broker_available(&self) -> bool {
        let b = self.broker.read().await;
        b.as_ref().is_some_and(|br| br.is_available())
    }

    // ── Broker-aware flows ──────────────────────────────────────────────

    /// Acquire a token interactively.
    ///
    /// If a broker is configured and available, delegates to the broker which
    /// shows OS-native authentication prompts (not a browser). Otherwise returns
    /// an error indicating that interactive auth requires a broker or
    /// authorization code flow.
    pub async fn acquire_token_interactive(
        &self,
        request: BrokerTokenRequest,
    ) -> Result<AuthenticationResult> {
        let b = self.broker.read().await;
        if let Some(ref broker) = *b {
            if broker.is_available() {
                let result = broker
                    .acquire_token_interactive(&self.state.config.auth.client_id, &request)
                    .await?;
                self.state.cache.save(&result);
                return Ok(result);
            }
        }
        Err(MsalError::AuthenticationFailed(
            "interactive token acquisition requires a native broker (WAM) or use \
             acquire_token_by_code / acquire_token_by_device_code instead"
                .into(),
        ))
    }

    /// Acquire a token silently.
    ///
    /// Resolution order:
    /// 1. Local token cache (if not force_refresh).
    /// 2. Broker silent acquisition (if broker available).
    /// 3. Refresh token exchange (standard OAuth).
    /// 4. `InteractionRequired` error.
    pub async fn acquire_token_silent(
        &self,
        request: SilentFlowRequest,
    ) -> Result<AuthenticationResult> {
        // 1. Try local cache.
        if !request.force_refresh {
            if let Some(cached) = self
                .state
                .cache
                .lookup_access_token(&request.account, &request.scopes)
            {
                return Ok(cached);
            }
        }

        // 2. Try broker (broker manages its own cache and refresh tokens).
        {
            let b = self.broker.read().await;
            if let Some(ref broker) = *b {
                if broker.is_available() {
                    let broker_request = BrokerTokenRequest {
                        scopes: request.scopes.clone(),
                        account: Some(request.account.clone()),
                        claims: request.claims.clone(),
                        correlation_id: request.correlation_id.clone(),
                        window_handle: None,
                        authentication_scheme: Default::default(),
                        pop_params: None,
                    };
                    let result = broker
                        .acquire_token_silent(&self.state.config.auth.client_id, &broker_request)
                        .await?;
                    self.state.cache.save(&result);
                    return Ok(result);
                }
            }
        }

        // 3. Try refresh token (standard OAuth).
        if let Some(rt) = self.state.cache.lookup_refresh_token(&request.account) {
            let scope_str = request.scopes.join(" ");
            let params = [
                ("client_id", self.state.config.auth.client_id.as_str()),
                ("grant_type", "refresh_token"),
                ("refresh_token", rt.as_str()),
                ("scope", scope_str.as_str()),
            ];

            let body = post_token_request(
                &self.state.http,
                &self.state.authority.token_endpoint,
                &params,
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

    /// Sign out using the broker (if available), then clear local cache.
    ///
    /// If no broker is configured, only the local token cache is cleared.
    pub async fn sign_out(&self, account: &AccountInfo) -> Result<()> {
        // Try broker sign-out first.
        {
            let b = self.broker.read().await;
            if let Some(ref broker) = *b {
                if broker.is_available() {
                    let sign_out_request = BrokerSignOutRequest {
                        account: account.clone(),
                        correlation_id: None,
                    };
                    broker
                        .sign_out(&self.state.config.auth.client_id, &sign_out_request)
                        .await?;
                }
            }
        }

        // Clear local cache.
        self.state.cache.remove_account(account)
    }

    /// Return all accounts. If a broker is configured, returns broker accounts;
    /// otherwise returns accounts from the local token cache.
    pub async fn all_accounts(&self) -> Result<Vec<AccountInfo>> {
        let b = self.broker.read().await;
        if let Some(ref broker) = *b {
            if broker.is_available() {
                let correlation_id = crate::crypto::generate_correlation_id();
                return broker
                    .all_accounts(&self.state.config.auth.client_id, &correlation_id)
                    .await;
            }
        }

        Ok(self.state.cache.all_accounts())
    }

    // ── Standard OAuth flows (non-brokered) ─────────────────────────────

    /// Build the authorization URL for the authorization code flow.
    pub async fn authorization_url(
        &self,
        scopes: Vec<String>,
        redirect_uri: &str,
        state_param: Option<&str>,
    ) -> Result<(String, PkceParams)> {
        let pkce = PkceParams::generate();
        let nonce = crate::crypto::generate_nonce();

        let mut url = url::Url::parse(&self.state.authority.authorization_endpoint)?;
        url.query_pairs_mut()
            .append_pair("client_id", &self.state.config.auth.client_id)
            .append_pair("response_type", "code")
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("scope", &scopes.join(" "))
            .append_pair("code_challenge", &pkce.challenge)
            .append_pair("code_challenge_method", &pkce.challenge_method)
            .append_pair("nonce", &nonce);

        if let Some(st) = state_param {
            url.query_pairs_mut().append_pair("state", st);
        }

        Ok((url.to_string(), pkce))
    }

    /// Exchange an authorization code for tokens.
    pub async fn acquire_token_by_code(
        &self,
        request: AuthorizationCodeRequest,
    ) -> Result<AuthenticationResult> {
        let scope_str = request.scopes.join(" ");
        let mut params: Vec<(&str, &str)> = vec![
            ("client_id", &self.state.config.auth.client_id),
            ("grant_type", "authorization_code"),
            ("code", &request.code),
            ("redirect_uri", &request.redirect_uri),
            ("scope", &scope_str),
        ];

        if let Some(ref v) = request.code_verifier {
            params.push(("code_verifier", v));
        }

        let body = post_token_request(
            &self.state.http,
            &self.state.authority.token_endpoint,
            &params,
        )
        .await?;
        let token_resp: TokenResponse = serde_json::from_value(body)?;
        let result = token_resp.into_authentication_result();
        self.state.cache.save(&result);
        Ok(result)
    }

    /// Initiate the device code flow and poll for completion.
    ///
    /// The `callback` is invoked with the [`DeviceCodeInfo`] so the caller
    /// can display the user code and verification URL to the user.
    pub async fn acquire_token_by_device_code<F>(
        &self,
        request: DeviceCodeRequest,
        callback: F,
    ) -> Result<AuthenticationResult>
    where
        F: FnOnce(&DeviceCodeInfo),
    {
        // Step 1: Initiate device code flow.
        let scope_str = request.scopes.join(" ");
        let init_params = [
            ("client_id", self.state.config.auth.client_id.as_str()),
            ("scope", &scope_str),
        ];

        let resp = self
            .state
            .http
            .post(&self.state.authority.device_code_endpoint)
            .form(&init_params)
            .send()
            .await?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(MsalError::AuthenticationFailed(format!(
                "device code initiation failed: {body}"
            )));
        }

        let body: serde_json::Value = resp.json().await?;
        let device_info = DeviceCodeInfo {
            user_code: body["user_code"].as_str().unwrap_or_default().to_string(),
            device_code: body["device_code"].as_str().unwrap_or_default().to_string(),
            verification_uri: body["verification_uri"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            message: body["message"].as_str().unwrap_or_default().to_string(),
            expires_in: body["expires_in"].as_u64().unwrap_or(900),
            interval: body["interval"].as_u64().unwrap_or(5),
        };

        callback(&device_info);

        // Step 2: Poll for token (no lock held across awaits).
        let interval = std::time::Duration::from_secs(device_info.interval);
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_secs(device_info.expires_in);

        loop {
            tokio::time::sleep(interval).await;

            if std::time::Instant::now() > deadline {
                return Err(MsalError::DeviceCodeExpired);
            }

            let poll_params = [
                ("client_id", self.state.config.auth.client_id.as_str()),
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("device_code", &device_info.device_code),
            ];

            let poll_result = post_token_request(
                &self.state.http,
                &self.state.authority.token_endpoint,
                &poll_params,
            )
            .await;

            match poll_result {
                Ok(body) => {
                    let token_resp: TokenResponse = serde_json::from_value(body)?;
                    let result = token_resp.into_authentication_result();
                    self.state.cache.save(&result);
                    return Ok(result);
                }
                Err(MsalError::AuthorizationPending) => continue,
                Err(MsalError::DeviceCodeExpired) => return Err(MsalError::DeviceCodeExpired),
                Err(e) => return Err(e),
            }
        }
    }

    /// Acquire a token using a refresh token directly.
    pub async fn acquire_token_by_refresh_token(
        &self,
        request: RefreshTokenRequest,
    ) -> Result<AuthenticationResult> {
        let scope_str = request.scopes.join(" ");
        let params = [
            ("client_id", self.state.config.auth.client_id.as_str()),
            ("grant_type", "refresh_token"),
            ("refresh_token", request.refresh_token.as_str()),
            ("scope", scope_str.as_str()),
        ];

        let body = post_token_request(
            &self.state.http,
            &self.state.authority.token_endpoint,
            &params,
        )
        .await?;
        let token_resp: TokenResponse = serde_json::from_value(body)?;
        let result = token_resp.into_authentication_result();
        self.state.cache.save(&result);
        Ok(result)
    }

    /// Acquire a token using username and password (ROPC).
    ///
    /// **Warning**: This flow is not recommended. Use device code or authorization code instead.
    pub async fn acquire_token_by_username_password(
        &self,
        request: UsernamePasswordRequest,
    ) -> Result<AuthenticationResult> {
        let scope_str = request.scopes.join(" ");
        let params = [
            ("client_id", self.state.config.auth.client_id.as_str()),
            ("grant_type", "password"),
            ("username", request.username.as_str()),
            ("password", request.password.as_str()),
            ("scope", scope_str.as_str()),
        ];

        let body = post_token_request(
            &self.state.http,
            &self.state.authority.token_endpoint,
            &params,
        )
        .await?;
        let token_resp: TokenResponse = serde_json::from_value(body)?;
        let result = token_resp.into_authentication_result();
        self.state.cache.save(&result);
        Ok(result)
    }

    /// Remove an account from the local cache (does not sign out from broker).
    /// Use [`sign_out`](Self::sign_out) for full broker + cache cleanup.
    pub async fn remove_account(&self, account: &AccountInfo) -> Result<()> {
        self.state.cache.remove_account(account)
    }
}
