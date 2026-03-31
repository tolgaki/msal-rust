//! Windows Web Account Manager (WAM) broker implementation.
//!
//! This module provides brokered authentication through the Windows
//! Web Account Manager, enabling device-bound tokens, system-wide SSO,
//! and conditional access compliance on Windows 10/11 and Windows Server 2019+.
//!
//! # Requirements
//!
//! - Windows 10 version 1703+ or Windows Server 2019+
//! - App must register the broker redirect URI:
//!   `ms-appx-web://Microsoft.AAD.BrokerPlugin/{client_id}`
//!
//! # Feature flag
//!
//! Enable with the `broker-wam` feature in `Cargo.toml`:
//! ```toml
//! msal = { version = "0.1", features = ["broker-wam"] }
//! ```

use std::future::Future;
use std::pin::Pin;

use windows::core::HSTRING;
use windows::Security::Authentication::Web::Core::{
    WebAuthenticationCoreManager, WebTokenRequest, WebTokenRequestPromptType,
};
use windows::Security::Credentials::WebAccountProvider;

use crate::account::AccountInfo;
use crate::broker::{AuthenticationScheme, BrokerSignOutRequest, BrokerTokenRequest, NativeBroker};
use crate::error::{MsalError, Result};
use crate::response::AuthenticationResult;

const AAD_PROVIDER_ID: &str = "https://login.microsoft.com";

/// WAM-based native authentication broker for Windows.
pub struct WamBroker {
    provider: WebAccountProvider,
}

impl WamBroker {
    /// Create a new WAM broker, resolving the Azure AD web account provider.
    pub async fn new() -> Result<Self> {
        let provider =
            WebAuthenticationCoreManager::FindAccountProviderAsync(&HSTRING::from(AAD_PROVIDER_ID))
                .map_err(|e| MsalError::AuthenticationFailed(format!("WAM init error: {e}")))?
                .await
                .map_err(|e| {
                    MsalError::AuthenticationFailed(format!(
                        "WAM provider not found: {e}. Ensure Windows 10 1703+ or Server 2019+"
                    ))
                })?;

        Ok(Self { provider })
    }

    /// Create a new WAM broker with a specific authority (e.g., for a specific tenant).
    pub async fn with_authority(authority: &str) -> Result<Self> {
        let provider = WebAuthenticationCoreManager::FindAccountProviderWithAuthorityAsync(
            &HSTRING::from(AAD_PROVIDER_ID),
            &HSTRING::from(authority),
        )
        .map_err(|e| MsalError::AuthenticationFailed(format!("WAM init error: {e}")))?
        .await
        .map_err(|e| {
            MsalError::AuthenticationFailed(format!("WAM provider not found for {authority}: {e}"))
        })?;

        Ok(Self { provider })
    }

    fn build_token_request(
        &self,
        client_id: &str,
        scopes: &[String],
        prompt_type: WebTokenRequestPromptType,
    ) -> Result<WebTokenRequest> {
        let scope_str = scopes.join(" ");
        let request = WebTokenRequest::CreateWithPromptType(
            &self.provider,
            &HSTRING::from(scope_str),
            &HSTRING::from(client_id),
            prompt_type,
        )
        .map_err(|e| {
            MsalError::AuthenticationFailed(format!("failed to create WAM request: {e}"))
        })?;

        Ok(request)
    }

    fn parse_token_response(
        &self,
        response: &windows::Security::Authentication::Web::Core::WebTokenResponse,
    ) -> Result<AuthenticationResult> {
        let token = response
            .Token()
            .map_err(|e| MsalError::AuthenticationFailed(format!("no token in response: {e}")))?
            .to_string();

        let properties = response.Properties().map_err(|e| {
            MsalError::AuthenticationFailed(format!("no properties in response: {e}"))
        })?;

        // Extract fields from the response properties map.
        let id_token = properties
            .Lookup(&HSTRING::from("wamcompat_id_token"))
            .ok()
            .map(|s| s.to_string());

        let expires_in: i64 = properties
            .Lookup(&HSTRING::from("wamcompat_expires_in"))
            .ok()
            .and_then(|s| s.to_string().parse().ok())
            .unwrap_or(3600);

        let scopes_str = properties
            .Lookup(&HSTRING::from("wamcompat_scopes"))
            .ok()
            .map(|s| s.to_string())
            .unwrap_or_default();

        let scopes: Vec<String> = scopes_str.split_whitespace().map(String::from).collect();

        let now = chrono::Utc::now().timestamp();

        // Build account from the WebAccount in the response.
        let account = response.WebAccount().ok().map(|web_account| {
            let username = web_account
                .UserName()
                .map(|s| s.to_string())
                .unwrap_or_default();
            let id = web_account.Id().map(|s| s.to_string()).unwrap_or_default();
            AccountInfo {
                home_account_id: id.clone(),
                local_account_id: id,
                environment: crate::account::AAD_PUBLIC_CLOUD_ENVIRONMENT.into(),
                tenant_id: String::new(),
                username,
                name: None,
                id_token_claims: None,
            }
        });

        Ok(AuthenticationResult {
            access_token: token,
            id_token,
            scopes,
            expires_on: now + expires_in,
            ext_expires_on: None,
            account,
            tenant_id: None,
            correlation_id: None,
            token_type: "Bearer".into(),
            refresh_token: None, // Broker manages refresh tokens internally.
        })
    }
}

impl NativeBroker for WamBroker {
    fn is_available(&self) -> bool {
        // If we constructed successfully, WAM is available.
        true
    }

    fn acquire_token_silent<'a>(
        &'a self,
        client_id: &'a str,
        request: &'a BrokerTokenRequest,
    ) -> Pin<Box<dyn Future<Output = Result<AuthenticationResult>> + Send + 'a>> {
        Box::pin(async move {
            let account = request.account.as_ref().ok_or_else(|| {
                MsalError::MissingParameter("account is required for silent broker flow".into())
            })?;

            let wam_request = self.build_token_request(
                client_id,
                &request.scopes,
                WebTokenRequestPromptType::Default,
            )?;

            // Find the WebAccount by ID for the silent request.
            let web_account = WebAuthenticationCoreManager::FindAccountAsync(
                &self.provider,
                &HSTRING::from(&account.home_account_id),
            )
            .map_err(|e| MsalError::AuthenticationFailed(format!("WAM find account error: {e}")))?
            .await
            .map_err(|e| MsalError::AuthenticationFailed(format!("WAM account not found: {e}")))?;

            let result =
                WebAuthenticationCoreManager::GetTokenSilentlyAsync(&wam_request, &web_account)
                    .map_err(|e| MsalError::AuthenticationFailed(format!("WAM silent error: {e}")))?
                    .await
                    .map_err(|e| {
                        MsalError::AuthenticationFailed(format!("WAM silent failed: {e}"))
                    })?;

            let response_status = result
                .ResponseStatus()
                .map_err(|e| MsalError::AuthenticationFailed(format!("WAM status error: {e}")))?;

            use windows::Security::Authentication::Web::Core::WebTokenRequestStatus;
            match response_status {
                WebTokenRequestStatus::Success => {
                    let responses = result.ResponseData().map_err(|e| {
                        MsalError::AuthenticationFailed(format!("no response data: {e}"))
                    })?;
                    let response = responses.GetAt(0).map_err(|e| {
                        MsalError::AuthenticationFailed(format!("no response at index 0: {e}"))
                    })?;
                    self.parse_token_response(&response)
                }
                WebTokenRequestStatus::UserInteractionRequired => Err(
                    MsalError::InteractionRequired("WAM requires user interaction".into()),
                ),
                _ => {
                    let error = result.ResponseError().ok();
                    let msg = error
                        .and_then(|e| e.ErrorMessage().ok())
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "unknown WAM error".into());
                    Err(MsalError::AuthenticationFailed(msg))
                }
            }
        })
    }

    fn acquire_token_interactive<'a>(
        &'a self,
        client_id: &'a str,
        request: &'a BrokerTokenRequest,
    ) -> Pin<Box<dyn Future<Output = Result<AuthenticationResult>> + Send + 'a>> {
        Box::pin(async move {
            let wam_request = self.build_token_request(
                client_id,
                &request.scopes,
                WebTokenRequestPromptType::ForceAuthentication,
            )?;

            let result = WebAuthenticationCoreManager::RequestTokenAsync(&wam_request)
                .map_err(|e| {
                    MsalError::AuthenticationFailed(format!("WAM interactive error: {e}"))
                })?
                .await
                .map_err(|e| {
                    MsalError::AuthenticationFailed(format!("WAM interactive failed: {e}"))
                })?;

            let response_status = result
                .ResponseStatus()
                .map_err(|e| MsalError::AuthenticationFailed(format!("WAM status error: {e}")))?;

            use windows::Security::Authentication::Web::Core::WebTokenRequestStatus;
            match response_status {
                WebTokenRequestStatus::Success => {
                    let responses = result.ResponseData().map_err(|e| {
                        MsalError::AuthenticationFailed(format!("no response data: {e}"))
                    })?;
                    let response = responses.GetAt(0).map_err(|e| {
                        MsalError::AuthenticationFailed(format!("no response at index 0: {e}"))
                    })?;
                    self.parse_token_response(&response)
                }
                WebTokenRequestStatus::UserCancel => Err(MsalError::UserCancelled),
                _ => {
                    let error = result.ResponseError().ok();
                    let msg = error
                        .and_then(|e| e.ErrorMessage().ok())
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "unknown WAM error".into());
                    Err(MsalError::AuthenticationFailed(msg))
                }
            }
        })
    }

    fn sign_out<'a>(
        &'a self,
        _client_id: &'a str,
        request: &'a BrokerSignOutRequest,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            let web_account = WebAuthenticationCoreManager::FindAccountAsync(
                &self.provider,
                &HSTRING::from(&request.account.home_account_id),
            )
            .map_err(|e| MsalError::AuthenticationFailed(format!("WAM find account error: {e}")))?
            .await
            .map_err(|e| {
                MsalError::AuthenticationFailed(format!("WAM account not found for signout: {e}"))
            })?;

            web_account
                .SignOutAsync()
                .map_err(|e| MsalError::AuthenticationFailed(format!("WAM signout error: {e}")))?
                .await
                .map_err(|e| MsalError::AuthenticationFailed(format!("WAM signout failed: {e}")))?;

            Ok(())
        })
    }

    fn all_accounts<'a>(
        &'a self,
        client_id: &'a str,
        _correlation_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<AccountInfo>>> + Send + 'a>> {
        Box::pin(async move {
            let result = WebAuthenticationCoreManager::FindAllAccountsAsync(
                &self.provider,
                &HSTRING::from(client_id),
            )
            .map_err(|e| MsalError::AuthenticationFailed(format!("WAM find accounts error: {e}")))?
            .await
            .map_err(|e| {
                MsalError::AuthenticationFailed(format!("WAM find accounts failed: {e}"))
            })?;

            use windows::Security::Authentication::Web::Core::FindAllAccountsStatus;
            let status = result.Status().map_err(|e| {
                MsalError::AuthenticationFailed(format!("WAM accounts status error: {e}"))
            })?;

            if status != FindAllAccountsStatus::Success {
                return Err(MsalError::AuthenticationFailed(
                    "WAM failed to enumerate accounts".into(),
                ));
            }

            let accounts = result
                .Accounts()
                .map_err(|e| MsalError::AuthenticationFailed(format!("WAM accounts error: {e}")))?;

            let mut result_accounts = Vec::new();
            for i in 0..accounts.Size().unwrap_or(0) {
                if let Ok(web_account) = accounts.GetAt(i) {
                    let username = web_account
                        .UserName()
                        .map(|s| s.to_string())
                        .unwrap_or_default();
                    let id = web_account.Id().map(|s| s.to_string()).unwrap_or_default();
                    result_accounts.push(AccountInfo {
                        home_account_id: id.clone(),
                        local_account_id: id,
                        environment: crate::account::AAD_PUBLIC_CLOUD_ENVIRONMENT.into(),
                        tenant_id: String::new(),
                        username,
                        name: None,
                        id_token_claims: None,
                    });
                }
            }

            Ok(result_accounts)
        })
    }

    fn account<'a>(
        &'a self,
        account_id: &'a str,
        _correlation_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<AccountInfo>> + Send + 'a>> {
        Box::pin(async move {
            let web_account = WebAuthenticationCoreManager::FindAccountAsync(
                &self.provider,
                &HSTRING::from(account_id),
            )
            .map_err(|e| MsalError::AuthenticationFailed(format!("WAM find account error: {e}")))?
            .await
            .map_err(|e| MsalError::AuthenticationFailed(format!("WAM account not found: {e}")))?;

            let username = web_account
                .UserName()
                .map(|s| s.to_string())
                .unwrap_or_default();
            let id = web_account.Id().map(|s| s.to_string()).unwrap_or_default();

            Ok(AccountInfo {
                home_account_id: id.clone(),
                local_account_id: id,
                environment: crate::account::AAD_PUBLIC_CLOUD_ENVIRONMENT.into(),
                tenant_id: String::new(),
                username,
                name: None,
                id_token_claims: None,
            })
        })
    }
}
