use std::sync::Arc;
use tokio::sync::RwLock;

use crate::account::AccountInfo;
use crate::broker::{BrokerSignOutRequest, BrokerTokenRequest, NativeBroker};
use crate::client::{AppState, ExchangeOptions};
use crate::config::Configuration;
use crate::crypto::PkceParams;
use crate::error::{MsalError, Result};
use crate::request::{
    AuthorizationCodeRequest, DeviceCodeInfo, DeviceCodeRequest, RefreshTokenRequest,
    SilentFlowRequest, UsernamePasswordRequest,
};
use crate::response::AuthenticationResult;

/// Public client application for user-based authentication flows.
///
/// Use this for desktop apps, CLI tools, and other public clients that
/// cannot securely store a client secret.
///
/// # Brokered Authentication
///
/// Call [`set_broker`](Self::set_broker) to enable native broker support (WAM on Windows,
/// Enterprise SSO on macOS). When a broker is set and available,
/// `acquire_token_interactive` and `acquire_token_silent` will delegate to
/// the broker for device-bound tokens and system-wide SSO.
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
    /// #[cfg(all(target_os = "windows", feature = "broker-wam"))]
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
        crate::request::validate_extra_query_parameters(&request.extra_query_parameters)?;
        crate::request::validate_claims(&request.claims)?;
        if let Some(token) = &request.cancellation_token {
            token.check_cancelled()?;
        }
        let mut request = request;
        if let Some(authority) = &request.authority {
            if !self.state.authority.is_same_authority(authority)? {
                return Err(MsalError::InvalidConfiguration("broker authority differs from application authority; construct a separate application".into()));
            }
        }
        request.authority = Some(self.state.config.auth.authority.clone());
        if let Some(account) = &request.account {
            crate::response::validate_account_authority(account, &self.state.authority)?;
        }
        let b = self.broker.read().await;
        if let Some(ref broker) = *b {
            if broker.is_available() {
                let result = broker
                    .acquire_token_interactive(&self.state.config.auth.client_id, &request)
                    .await?;
                self.validate_broker_result(&result, request.account.as_ref())?;
                if self.state.config.cache.store_in_memory {
                    self.state.cache.save_with_context(
                        &result,
                        &crate::cache::request_context(
                            &request.claims,
                            &request.extra_query_parameters,
                        ),
                    )?;
                }
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
        crate::request::validate_extra_query_parameters(&request.extra_query_parameters)?;
        crate::request::validate_claims(&request.claims)?;
        crate::response::validate_account_authority(&request.account, &self.state.authority)?;
        if let Some(token) = &request.cancellation_token {
            token.check_cancelled()?;
        }
        let context =
            crate::cache::request_context(&request.claims, &request.extra_query_parameters);
        // 1. Try local cache.
        if !request.force_refresh {
            if let Some(cached) =
                self.state
                    .cache
                    .lookup_with_context(&request.account, &request.scopes, &context)?
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
                        force_refresh: request.force_refresh,
                        authority: Some(self.state.config.auth.authority.clone()),
                        extra_query_parameters: request.extra_query_parameters.clone(),
                        // Native adapters cannot cancel an in-flight operation and
                        // reject requests carrying a token. A silent native call shows
                        // no UI, so cancellation here stops waiting for it and discards
                        // its result instead.
                        cancellation_token: None,
                    };
                    let result = crate::network::cancellable(
                        request.cancellation_token.as_ref(),
                        broker.acquire_token_silent(
                            &self.state.config.auth.client_id,
                            &broker_request,
                        ),
                    )
                    .await?;
                    self.validate_broker_result(&result, Some(&request.account))?;
                    if self.state.config.cache.store_in_memory {
                        self.state.cache.save_with_context(&result, &context)?;
                    }
                    return Ok(result);
                }
            }
        }

        // 3. Try refresh token (standard OAuth).
        if let Some(rt) = self
            .state
            .cache
            .refresh_with_context(&request.account, &context)?
        {
            let scope_str = request.scopes.join(" ");
            let params = [
                ("client_id", self.state.config.auth.client_id.as_str()),
                ("grant_type", "refresh_token"),
                ("refresh_token", rt.as_str()),
                ("scope", scope_str.as_str()),
            ];
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

    /// Sign out using the broker (if available), then clear local cache.
    ///
    /// If no broker is configured, only the local token cache is cleared.
    pub async fn sign_out(&self, account: &AccountInfo) -> Result<()> {
        // Only require a complete identity: removing local state for an account
        // whose environment/tenant no longer matches the authority must still work.
        account.validate()?;
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

        self.state.cache.try_all_accounts()
    }

    /// Export plaintext secret-bearing state for caller-owned protected persistence.
    pub fn export_cache(&self) -> Result<crate::cache::TokenCacheSnapshot> {
        self.state.cache.export()
    }

    /// Replace local cache with integrity-protected state for this client.
    pub fn import_cache(&self, snapshot: crate::cache::TokenCacheSnapshot) -> Result<()> {
        self.state.cache.import(snapshot)
    }

    fn validate_broker_result(
        &self,
        result: &AuthenticationResult,
        expected: Option<&AccountInfo>,
    ) -> Result<()> {
        let account = result
            .account
            .as_ref()
            .ok_or_else(|| MsalError::InvalidToken("broker returned no account".into()))?;
        crate::response::validate_account_authority(account, &self.state.authority)?;
        if result.tenant_id.as_deref() != Some(account.tenant_id.as_str())
            || expected.is_some_and(|expected| !account.same_identity(expected))
        {
            return Err(MsalError::InvalidToken(
                "broker returned wrong or incomplete tenant/account".into(),
            ));
        }
        Ok(())
    }

    // ── Standard OAuth flows (non-brokered) ─────────────────────────────

    /// Build the authorization URL for the authorization code flow.
    ///
    /// Returns the URL and the PKCE parameters. Pass `pkce.verifier` as the
    /// `code_verifier` when exchanging the authorization code.
    pub fn authorization_url(
        &self,
        scopes: &[String],
        redirect_uri: &str,
        state_param: Option<&str>,
    ) -> Result<(String, PkceParams)> {
        self.authorization_url_with_options(
            scopes,
            redirect_uri,
            state_param,
            None,
            &Default::default(),
        )
    }

    /// Build an authorization URL with claims and opaque server parameters.
    ///
    /// Copy the returned verifier and nonce to the code exchange request. The
    /// caller must validate the redirect's state before exchanging its code.
    pub fn authorization_url_with_options(
        &self,
        scopes: &[String],
        redirect_uri: &str,
        state_param: Option<&str>,
        claims: Option<&str>,
        extra_query_parameters: &std::collections::BTreeMap<String, String>,
    ) -> Result<(String, PkceParams)> {
        crate::request::validate_extra_query_parameters(extra_query_parameters)?;
        let pkce = PkceParams::generate();
        let scope_str = crate::request::user_scopes(scopes).join(" ");

        let mut url = url::Url::parse(&self.state.authority.authorization_endpoint)?;
        url.query_pairs_mut()
            .append_pair("client_id", &self.state.config.auth.client_id)
            .append_pair("response_type", "code")
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("scope", &scope_str)
            .append_pair("code_challenge", &pkce.challenge)
            .append_pair("code_challenge_method", pkce.challenge_method)
            .append_pair("nonce", &pkce.nonce)
            .append_pair("client_info", "1");
        let owned_claims = claims.map(String::from);
        let mut additional = Vec::new();
        let correlation_id = None;
        crate::request::append_request_parameters(
            &mut additional,
            &owned_claims,
            &correlation_id,
            extra_query_parameters,
        )?;
        url.query_pairs_mut().extend_pairs(additional);

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
        if request
            .code_verifier
            .as_deref()
            .map_or(true, |verifier| verifier.is_empty())
        {
            return Err(MsalError::MissingParameter(
                "public authorization code flow requires a PKCE verifier".into(),
            ));
        }
        if request
            .nonce
            .as_deref()
            .map_or(true, |nonce| nonce.is_empty())
        {
            return Err(MsalError::MissingParameter(
                "public authorization code flow requires the original authorization nonce".into(),
            ));
        }
        let scope_str = crate::request::user_scopes(&request.scopes).join(" ");
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
        crate::network::cancellable(
            request.cancellation_token.as_ref(),
            self.device_code_inner(&request, callback),
        )
        .await
    }

    async fn device_code_inner<F>(
        &self,
        request: &DeviceCodeRequest,
        callback: F,
    ) -> Result<AuthenticationResult>
    where
        F: FnOnce(&DeviceCodeInfo),
    {
        // Step 1: Initiate device code flow.
        let scope_str = crate::request::user_scopes(&request.scopes).join(" ");
        let mut init_params = vec![
            ("client_id", self.state.config.auth.client_id.as_str()),
            ("scope", &scope_str),
            ("client_info", "1"),
        ];
        crate::request::append_request_parameters(
            &mut init_params,
            &request.claims,
            &request.correlation_id,
            &request.extra_query_parameters,
        )?;
        let body = crate::network::post_token_request(
            &self.state.http,
            &self.state.authority.device_code_endpoint,
            &init_params,
        )
        .await?;

        let device_code = body["device_code"]
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                MsalError::AuthenticationFailed("missing device_code in response".into())
            })?
            .to_string();

        let required_string = |key: &str| -> Result<String> {
            body[key]
                .as_str()
                .filter(|value| !value.is_empty())
                .map(String::from)
                .ok_or_else(|| MsalError::InvalidToken(format!("device response missing {key}")))
        };
        let device_info = DeviceCodeInfo {
            user_code: required_string("user_code")?,
            device_code,
            verification_uri: required_string("verification_uri")?,
            message: body["message"].as_str().unwrap_or_default().to_string(),
            expires_in: body["expires_in"]
                .as_u64()
                .filter(|seconds| *seconds > 0)
                .ok_or_else(|| {
                    MsalError::InvalidToken("device response missing/invalid expires_in".into())
                })?,
            interval: body["interval"].as_u64().unwrap_or(5),
        };

        // Step 2: Poll for token (no lock held across awaits).
        let mut interval = std::time::Duration::from_secs(device_info.interval.max(1));
        let deadline = tokio::time::Instant::now()
            .checked_add(std::time::Duration::from_secs(device_info.expires_in))
            .ok_or_else(|| MsalError::InvalidToken("device response expiration overflow".into()))?;
        callback(&device_info);

        loop {
            let next_poll = tokio::time::Instant::now()
                .checked_add(interval)
                .ok_or_else(|| {
                    MsalError::InvalidToken("device polling interval overflow".into())
                })?;
            tokio::time::sleep_until(next_poll.min(deadline)).await;

            if tokio::time::Instant::now() >= deadline {
                return Err(MsalError::DeviceCodeExpired);
            }

            let poll_params = [
                ("client_id", self.state.config.auth.client_id.as_str()),
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("device_code", &device_info.device_code),
            ];

            match self
                .state
                .exchange_and_cache(
                    &poll_params,
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
            {
                Ok(result) => return Ok(result),
                Err(MsalError::AuthorizationPending) => continue,
                Err(MsalError::SlowDown) => {
                    interval += std::time::Duration::from_secs(5);
                    continue;
                }
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

    /// Acquire a token using username and password (ROPC).
    ///
    /// **Warning**: This flow is not recommended. Use device code or authorization code instead.
    pub async fn acquire_token_by_username_password(
        &self,
        request: UsernamePasswordRequest,
    ) -> Result<AuthenticationResult> {
        let scope_str = crate::request::user_scopes(&request.scopes).join(" ");
        let params = [
            ("client_id", self.state.config.auth.client_id.as_str()),
            ("grant_type", "password"),
            ("username", request.username.as_str()),
            ("password", request.password.as_str()),
            ("scope", scope_str.as_str()),
        ];
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

    /// Remove an account from the local cache (does not sign out from broker).
    /// Use [`sign_out`](Self::sign_out) for full broker + cache cleanup.
    pub fn remove_account(&self, account: &AccountInfo) -> Result<()> {
        self.state.cache.remove_account(account)
    }
}
