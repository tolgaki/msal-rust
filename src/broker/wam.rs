//! Windows Web Account Manager (WAM) broker implementation.
//!
//! Requires Windows 10 1703+ and the registered redirect URI
//! `ms-appx-web://Microsoft.AAD.BrokerPlugin/{client_id}`.
//!
//! This is the raw AAD WAM provider, not MSALRuntime. Its compatibility
//! properties follow Microsoft's MSAL.NET 4.30.1 `AadPlugin`/`WamAdapters`.
//! Force-refresh and in-flight cancellation are not exposed by this adapter
//! and fail before native dispatch. Desktop HWND interop is not implemented.
//!
//! WAM account IDs are opaque and must not be treated as MSAL home IDs.
//! Verified associations are retained for this broker instance and client.
//! Cold account enumeration/selection requiring unresolved guest identities
//! returns `Unsupported` rather than guessing or acquiring tokens as a side effect.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;

use windows::core::HSTRING;
use windows::Security::Authentication::Web::Core::{
    FindAllWebAccountsStatus, WebAuthenticationCoreManager, WebTokenRequest,
    WebTokenRequestPromptType, WebTokenRequestResult, WebTokenRequestStatus, WebTokenResponse,
};
use windows::Security::Credentials::{WebAccount, WebAccountProvider};

use crate::account::AccountInfo;
use crate::broker::{
    account_from_native_response, same_account, validate_account_identity, validate_request,
    BrokerSignOutRequest, BrokerTokenRequest, NativeBroker,
};
use crate::error::{MsalError, Result};
use crate::response::AuthenticationResult;

const AAD_PROVIDER_ID: &str = "https://login.microsoft.com";
const DEFAULT_AUTHORITY: &str = "https://login.microsoftonline.com/common";

type AccountAssociations = HashMap<(String, String), (String, AccountInfo)>;

/// WAM-based native authentication broker for Windows.
pub struct WamBroker {
    provider: WebAccountProvider,
    authority: String,
    /// Client + complete MSAL identity -> native ID, authenticated by a token response.
    accounts: Mutex<AccountAssociations>,
}

impl WamBroker {
    /// Create a broker for the public-cloud AAD provider.
    pub async fn new() -> Result<Self> {
        let provider =
            WebAuthenticationCoreManager::FindAccountProviderAsync(&HSTRING::from(AAD_PROVIDER_ID))
                .map_err(native_error)?
                .await
                .map_err(native_error)?;
        Ok(Self {
            provider,
            authority: DEFAULT_AUTHORITY.into(),
            accounts: Mutex::new(HashMap::new()),
        })
    }

    /// Create a broker for a specific Entra authority.
    pub async fn with_authority(authority: &str) -> Result<Self> {
        validate_authority(authority)?;
        let provider = WebAuthenticationCoreManager::FindAccountProviderWithAuthorityAsync(
            &HSTRING::from(AAD_PROVIDER_ID),
            &HSTRING::from(authority),
        )
        .map_err(native_error)?
        .await
        .map_err(native_error)?;
        Ok(Self {
            provider,
            authority: authority.into(),
            accounts: Mutex::new(HashMap::new()),
        })
    }

    fn build_token_request(
        &self,
        client_id: &str,
        params: &BrokerTokenRequest,
    ) -> Result<WebTokenRequest> {
        let properties = request_properties(params, &self.authority)?;
        let request = WebTokenRequest::CreateWithPromptType(
            &self.provider,
            &HSTRING::from(crate::request::user_scopes(&params.scopes).join(" ")),
            &HSTRING::from(client_id),
            WebTokenRequestPromptType::Default,
        )
        .map_err(native_error)?;
        let map = request.Properties().map_err(native_error)?;
        for (key, value) in properties {
            map.Insert(&HSTRING::from(key), &HSTRING::from(value))
                .map_err(native_error)?;
        }
        if let Some(id) = &params.correlation_id {
            request
                .SetCorrelationId(&HSTRING::from(id))
                .map_err(native_error)?;
        }
        Ok(request)
    }

    fn mapped_id(&self, client_id: &str, account: &AccountInfo) -> Result<String> {
        let accounts = self
            .accounts
            .lock()
            .map_err(|_| MsalError::AuthenticationFailed("WAM account map poisoned".into()))?;
        mapped_account_id(&accounts, client_id, account)
    }

    async fn find_account(&self, client_id: &str, account: &AccountInfo) -> Result<WebAccount> {
        let id = self.mapped_id(client_id, account)?;
        WebAuthenticationCoreManager::FindAccountAsync(&self.provider, &HSTRING::from(id))
            .map_err(native_error)?
            .await
            .map_err(native_error)
    }

    fn parse_token_response(
        &self,
        client_id: &str,
        request: &BrokerTokenRequest,
        response: &WebTokenResponse,
    ) -> Result<AuthenticationResult> {
        let token = response.Token().map_err(native_error)?.to_string();
        if token.is_empty() {
            return Err(MsalError::AuthenticationFailed(
                "empty WAM access token".into(),
            ));
        }
        let properties = response.Properties().map_err(native_error)?;
        let property = |key: &str| {
            properties
                .Lookup(&HSTRING::from(key))
                .ok()
                .map(|value| value.to_string())
        };
        let id_token = property("wamcompat_id_token").ok_or_else(|| {
            MsalError::AuthenticationFailed("missing WAM ID token identity".into())
        })?;
        let client_info = property("wamcompat_client_info").ok_or_else(|| {
            MsalError::AuthenticationFailed("missing WAM client_info identity".into())
        })?;
        let authority = request.authority.as_deref().unwrap_or(&self.authority);
        let account = account_from_native_response(client_id, authority, &id_token, &client_info)?;
        if let Some(returned_authority) = property("Authority") {
            let returned = account_from_native_response(
                client_id,
                &returned_authority,
                &id_token,
                &client_info,
            )?;
            if !same_account(&returned, &account) {
                return Err(MsalError::AuthenticationFailed(
                    "WAM authority mismatch".into(),
                ));
            }
        } else {
            return Err(MsalError::AuthenticationFailed(
                "missing WAM authority".into(),
            ));
        }
        if request
            .account
            .as_ref()
            .is_some_and(|selected| !same_account(selected, &account))
        {
            return Err(MsalError::AuthenticationFailed(
                "WAM returned a different account than requested".into(),
            ));
        }
        let native_id = response
            .WebAccount()
            .map_err(native_error)?
            .Id()
            .map_err(native_error)?
            .to_string();
        if native_id.is_empty() {
            return Err(MsalError::AuthenticationFailed(
                "empty WAM account ID".into(),
            ));
        }
        self.accounts
            .lock()
            .map_err(|_| MsalError::AuthenticationFailed("WAM account map poisoned".into()))?
            .insert(
                (client_id.into(), account.cache_key()),
                (native_id, account.clone()),
            );
        // AadPlugin/CoreHelpers uses seconds since 1601, not FILETIME ticks.
        let expires_on = property("TokenExpiresOn")
            .as_deref()
            .and_then(windows_timestamp)
            .unwrap_or_else(|| chrono::Utc::now().timestamp());
        Ok(AuthenticationResult {
            access_token: token,
            id_token: Some(id_token),
            scopes: property("wamcompat_scopes")
                .unwrap_or_default()
                .split_whitespace()
                .map(String::from)
                .collect(),
            expires_on,
            ext_expires_on: property("ExtendedLifetimeToken")
                .as_deref()
                .and_then(windows_timestamp),
            tenant_id: Some(account.tenant_id.clone()),
            account: Some(account),
            correlation_id: property("correlationId").or_else(|| request.correlation_id.clone()),
            token_type: "Bearer".into(),
            refresh_token: None,
        })
    }

    fn handle_result(
        &self,
        client_id: &str,
        request: &BrokerTokenRequest,
        result: &WebTokenRequestResult,
    ) -> Result<AuthenticationResult> {
        let status = result.ResponseStatus().map_err(native_error)?;
        if status == WebTokenRequestStatus::Success
            || status == WebTokenRequestStatus::AccountSwitch
        {
            let response = result
                .ResponseData()
                .map_err(native_error)?
                .GetAt(0)
                .map_err(native_error)?;
            return self.parse_token_response(client_id, request, &response);
        }
        if status == WebTokenRequestStatus::UserCancel {
            return Err(MsalError::UserCancelled);
        }
        let error = result.ResponseError().ok();
        let description = error
            .as_ref()
            .and_then(|error| error.ErrorMessage().ok())
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown WAM error".into());
        let properties = error.as_ref().and_then(|error| error.Properties().ok());
        let property = |key: &str| {
            properties
                .as_ref()
                .and_then(|map| map.Lookup(&HSTRING::from(key)).ok())
                .map(|value| value.to_string())
        };
        let mut metadata = std::collections::BTreeMap::new();
        for key in [
            "error",
            "error_description",
            "claims",
            "suberror",
            "correlation_id",
            "correlationId",
        ] {
            if let Some(value) = property(key) {
                metadata.insert(key.into(), value);
            }
        }
        Err(wam_response_error(
            status,
            description,
            &metadata,
            request.correlation_id.clone(),
        ))
    }
}

fn mapped_account_id(
    accounts: &AccountAssociations,
    client_id: &str,
    account: &AccountInfo,
) -> Result<String> {
    validate_account_identity(account)?;
    accounts
        .get(&(client_id.into(), account.cache_key()))
        .filter(|(_, known)| same_account(known, account))
        .map(|(id, _)| id.clone())
        .ok_or_else(|| {
            MsalError::Unsupported(
                "no verified WAM ID for this client and complete account identity; \
             obtain an interactive result from this broker instance first"
                    .into(),
            )
        })
}

fn wam_response_error(
    status: WebTokenRequestStatus,
    description: String,
    properties: &std::collections::BTreeMap<String, String>,
    request_correlation_id: Option<String>,
) -> MsalError {
    let claims = properties.get("claims").cloned();
    let suberror = properties.get("suberror").cloned();
    let correlation_id = properties
        .get("correlation_id")
        .or_else(|| properties.get("correlationId"))
        .cloned()
        .or(request_correlation_id);
    let description = properties
        .get("error_description")
        .cloned()
        .unwrap_or(description);
    if status == WebTokenRequestStatus::UserInteractionRequired || claims.is_some() {
        MsalError::InteractionRequiredWithClaims {
            error: properties
                .get("error")
                .cloned()
                .unwrap_or_else(|| "interaction_required".into()),
            description,
            correlation_id,
            claims,
            suberror,
        }
    } else if let Some(error) = properties.get("error") {
        MsalError::ServerError {
            error: error.clone(),
            description,
            correlation_id,
            claims,
            suberror,
        }
    } else {
        MsalError::AuthenticationFailed(description)
    }
}

fn native_error(error: windows::core::Error) -> MsalError {
    MsalError::AuthenticationFailed(format!("WAM native error: {error}"))
}

fn validate_authority(authority: &str) -> Result<()> {
    let url = url::Url::parse(authority)
        .map_err(|_| MsalError::InvalidConfiguration("invalid broker authority URL".into()))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.port_or_known_default() != Some(443)
        || url.path().trim_matches('/').is_empty()
    {
        return Err(MsalError::InvalidConfiguration(
            "invalid broker authority URL".into(),
        ));
    }
    Ok(())
}

fn request_properties(
    request: &BrokerTokenRequest,
    default_authority: &str,
) -> Result<std::collections::BTreeMap<String, String>> {
    validate_request(request)?;
    if request.force_refresh {
        return Err(MsalError::Unsupported(
            "raw WAM has no verified force-refresh contract; MSALRuntime is required".into(),
        ));
    }
    if request.window_handle.is_some() {
        return Err(MsalError::Unsupported(
            "WAM desktop HWND interop is not implemented".into(),
        ));
    }
    let authority = request.authority.as_deref().unwrap_or(default_authority);
    validate_authority(authority)?;
    let mut authority = url::Url::parse(authority)
        .map_err(|_| MsalError::InvalidConfiguration("invalid broker authority URL".into()))?;
    if let Some(account) = &request.account {
        let host = authority.host_str().unwrap_or_default();
        let public_alias = matches!(host, "login.microsoftonline.com" | "login.windows.net");
        if !host.eq_ignore_ascii_case(&account.environment)
            && !(public_alias
                && account.environment == crate::account::AAD_PUBLIC_CLOUD_ENVIRONMENT)
        {
            return Err(MsalError::InvalidConfiguration(
                "selected account environment differs from WAM authority".into(),
            ));
        }
        let tenant = authority.path().trim_matches('/');
        if matches!(tenant, "common" | "organizations" | "consumers") {
            authority.set_path(&format!("/{}", account.tenant_id));
        } else if uuid::Uuid::parse_str(tenant).is_ok()
            && !tenant.eq_ignore_ascii_case(&account.tenant_id)
        {
            // A domain-name tenant cannot be compared with the account's tenant
            // GUID here; the client validates the returned tenant.
            return Err(MsalError::InvalidConfiguration(
                "selected account resource tenant differs from WAM authority".into(),
            ));
        }
    }
    let mut properties = request.extra_query_parameters.clone();
    // Broker routing, compatibility, identity and UI options are not server EQP.
    // Include native/camel-case spellings not covered by OAuth's shared validator.
    for key in [
        "wam_compat",
        "wamcompat",
        "validateAuthority",
        "LoginHint",
        "correlationId",
        "discover",
        "clientId",
        "redirectUri",
        "provider_type",
        "provider_id",
        "providerId",
        "webAccountProvider",
        "webAccount",
        "account_identifier",
        "home_account_id",
        "local_account_id",
        "account_home_tenant_id",
        "prompt",
        "promptType",
        "msal_request_type",
        "msal_identity_provider",
    ] {
        if properties
            .keys()
            .any(|candidate| candidate.eq_ignore_ascii_case(key))
        {
            return Err(MsalError::InvalidConfiguration(format!(
                "extra query parameter conflicts with WAM property: {key}"
            )));
        }
    }
    // Official raw-WAM EQP mapping has a special spelling for instance_aware.
    if properties
        .get("instance_aware")
        .is_some_and(|value| value == "true")
    {
        properties.remove("instance_aware");
        properties.insert("discover".into(), "home".into());
    }
    properties.insert("wam_compat".into(), "2.0".into());
    properties.insert("authority".into(), authority.into());
    properties.insert("validateAuthority".into(), "yes".into());
    if let Some(claims) = &request.claims {
        properties.insert("claims".into(), claims.clone());
    }
    Ok(properties)
}

fn windows_timestamp(value: &str) -> Option<i64> {
    value.parse::<i64>().ok()?.checked_sub(11_644_473_600)
}

impl NativeBroker for WamBroker {
    fn is_available(&self) -> bool {
        true
    }

    fn acquire_token_silent<'a>(
        &'a self,
        client_id: &'a str,
        request: &'a BrokerTokenRequest,
    ) -> Pin<Box<dyn Future<Output = Result<AuthenticationResult>> + Send + 'a>> {
        Box::pin(async move {
            let wam_request = self.build_token_request(client_id, request)?;
            let account = request.account.as_ref().ok_or_else(|| {
                MsalError::MissingParameter("account is required for silent broker flow".into())
            })?;
            let web_account = self.find_account(client_id, account).await?;
            let result = WebAuthenticationCoreManager::GetTokenSilentlyWithWebAccountAsync(
                &wam_request,
                &web_account,
            )
            .map_err(native_error)?
            .await
            .map_err(native_error)?;
            self.handle_result(client_id, request, &result)
        })
    }

    fn acquire_token_interactive<'a>(
        &'a self,
        client_id: &'a str,
        request: &'a BrokerTokenRequest,
    ) -> Pin<Box<dyn Future<Output = Result<AuthenticationResult>> + Send + 'a>> {
        Box::pin(async move {
            let wam_request = self.build_token_request(client_id, request)?;
            let operation = if let Some(account) = &request.account {
                let web_account = self.find_account(client_id, account).await?;
                WebAuthenticationCoreManager::RequestTokenWithWebAccountAsync(
                    &wam_request,
                    &web_account,
                )
            } else {
                WebAuthenticationCoreManager::RequestTokenAsync(&wam_request)
            }
            .map_err(native_error)?;
            let result = operation.await.map_err(native_error)?;
            self.handle_result(client_id, request, &result)
        })
    }

    fn sign_out<'a>(
        &'a self,
        client_id: &'a str,
        request: &'a BrokerSignOutRequest,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            let web_account = self.find_account(client_id, &request.account).await?;
            web_account
                .SignOutWithClientIdAsync(&HSTRING::from(client_id))
                .map_err(native_error)?
                .await
                .map_err(native_error)?;
            let native_id = web_account.Id().map_err(native_error)?.to_string();
            self.accounts
                .lock()
                .map_err(|_| MsalError::AuthenticationFailed("WAM account map poisoned".into()))?
                .retain(|(client, _), (id, _)| client != client_id || id != &native_id);
            Ok(())
        })
    }

    fn all_accounts<'a>(
        &'a self,
        client_id: &'a str,
        _correlation_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<AccountInfo>>> + Send + 'a>> {
        Box::pin(async move {
            let result = WebAuthenticationCoreManager::FindAllAccountsWithClientIdAsync(
                &self.provider,
                &HSTRING::from(client_id),
            )
            .map_err(native_error)?
            .await
            .map_err(native_error)?;
            if result.Status().map_err(native_error)? != FindAllWebAccountsStatus::Success {
                return Err(MsalError::AuthenticationFailed(
                    "WAM account enumeration failed".into(),
                ));
            }
            let native_accounts = result.Accounts().map_err(native_error)?;
            let known = self
                .accounts
                .lock()
                .map_err(|_| MsalError::AuthenticationFailed("WAM account map poisoned".into()))?;
            let mut accounts = Vec::new();
            for i in 0..native_accounts.Size().map_err(native_error)? {
                let id = native_accounts
                    .GetAt(i)
                    .map_err(native_error)?
                    .Id()
                    .map_err(native_error)?
                    .to_string();
                let matches: Vec<_> = known
                    .iter()
                    .filter(|((client, _), (native_id, _))| client == client_id && native_id == &id)
                    .map(|(_, (_, account))| account.clone())
                    .collect();
                if matches.is_empty() {
                    return Err(MsalError::Unsupported(
                        "raw WAM account metadata cannot establish guest-safe home/resource identity \
                         without a verified token response; no token acquisition was attempted".into(),
                    ));
                }
                accounts.extend(matches);
            }
            Ok(accounts)
        })
    }

    fn account<'a>(
        &'a self,
        _account_id: &'a str,
        _correlation_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<AccountInfo>> + Send + 'a>> {
        Box::pin(async move {
            Err(MsalError::Unsupported(
                "WAM lookup by home ID alone is ambiguous across clients and resource tenants; \
                 use all_accounts(client_id) and complete account identity"
                    .into(),
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> BrokerTokenRequest {
        BrokerTokenRequest {
            scopes: vec!["user.read".into()],
            account: None,
            claims: None,
            force_refresh: false,
            authority: None,
            extra_query_parameters: Default::default(),
            cancellation_token: None,
            correlation_id: None,
            window_handle: None,
            authentication_scheme: Default::default(),
            pop_params: None,
        }
    }

    #[test]
    fn native_properties_preserve_claims_authority_and_eqp() {
        let mut request = request();
        request.claims =
            Some(r#"{"access_token":{"client_session":{"values":["session"]}}}"#.into());
        request
            .extra_query_parameters
            .insert("client_session".into(), "session".into());
        request.authority = Some("https://login.microsoftonline.com/resource".into());
        let properties = request_properties(&request, DEFAULT_AUTHORITY).unwrap();
        assert_eq!(properties["claims"], request.claims.unwrap());
        assert_eq!(properties["client_session"], "session");
        assert_eq!(properties["authority"], request.authority.unwrap());
        assert_eq!(properties["wam_compat"], "2.0");
    }

    #[test]
    fn unsupported_refresh_and_cancellation_fail_preflight() {
        let mut request = request();
        request.force_refresh = true;
        assert!(matches!(
            request_properties(&request, DEFAULT_AUTHORITY),
            Err(MsalError::Unsupported(_))
        ));
        request.force_refresh = false;
        let token = crate::request::CancellationToken::new();
        request.cancellation_token = Some(token.clone());
        assert!(matches!(
            request_properties(&request, DEFAULT_AUTHORITY),
            Err(MsalError::Unsupported(_))
        ));
        token.cancel();
        assert!(matches!(
            request_properties(&request, DEFAULT_AUTHORITY),
            Err(MsalError::OperationCancelled)
        ));
    }

    #[test]
    fn wam_expiration_uses_windows_epoch() {
        assert_eq!(windows_timestamp("11644473600"), Some(0));
        assert_eq!(windows_timestamp("11644473660"), Some(60));
        assert_eq!(windows_timestamp("invalid"), None);
    }

    #[test]
    fn selected_guest_routes_to_resource_tenant_not_home_tenant() {
        let mut request = request();
        request.account = Some(AccountInfo {
            home_account_id: "home-user.home-tenant".into(),
            local_account_id: "guest-object".into(),
            tenant_id: "resource-tenant".into(),
            environment: crate::account::AAD_PUBLIC_CLOUD_ENVIRONMENT.into(),
            username: String::new(),
            name: None,
            id_token_claims: None,
        });
        let properties = request_properties(&request, DEFAULT_AUTHORITY).unwrap();
        assert_eq!(
            properties["authority"],
            "https://login.microsoftonline.com/resource-tenant"
        );
        request.authority = Some("https://login.microsoftonline.com/home-tenant".into());
        assert!(request_properties(&request, DEFAULT_AUTHORITY).is_err());
    }

    #[test]
    fn native_error_keeps_original_claims_code_and_metadata() {
        let metadata = std::collections::BTreeMap::from([
            ("error".into(), "invalid_grant".into()),
            ("error_description".into(), "MFA".into()),
            ("claims".into(), "{\"access_token\":{}}".into()),
            ("suberror".into(), "basic_action".into()),
            ("correlation_id".into(), "response-correlation".into()),
        ]);
        match wam_response_error(
            WebTokenRequestStatus::ProviderError,
            "WAM".into(),
            &metadata,
            Some("request".into()),
        ) {
            MsalError::InteractionRequiredWithClaims {
                error,
                description,
                claims,
                correlation_id,
                suberror,
            } => {
                assert_eq!(error, "invalid_grant");
                assert_eq!(description, "MFA");
                assert_eq!(claims.as_deref(), Some("{\"access_token\":{}}"));
                assert_eq!(correlation_id.as_deref(), Some("response-correlation"));
                assert_eq!(suberror.as_deref(), Some("basic_action"));
            }
            error => panic!("unexpected error: {error}"),
        }
    }

    #[test]
    fn association_is_client_and_complete_identity_scoped_and_cold_fails() {
        let account = AccountInfo {
            home_account_id: "home-user.home-tenant".into(),
            local_account_id: "guest".into(),
            environment: crate::account::AAD_PUBLIC_CLOUD_ENVIRONMENT.into(),
            tenant_id: "resource-tenant".into(),
            username: String::new(),
            name: None,
            id_token_claims: None,
        };
        let mut associations = AccountAssociations::new();
        assert!(matches!(
            mapped_account_id(&associations, "client", &account),
            Err(MsalError::Unsupported(_))
        ));
        associations.insert(
            ("client".into(), account.cache_key()),
            ("opaque-native-id".into(), account.clone()),
        );
        assert_eq!(
            mapped_account_id(&associations, "client", &account).unwrap(),
            "opaque-native-id"
        );
        assert!(mapped_account_id(&associations, "other-client", &account).is_err());
        let mut other = account.clone();
        other.tenant_id = "home-tenant".into();
        assert!(mapped_account_id(&associations, "client", &other).is_err());
        other = account.clone();
        other.local_account_id = "other-object".into();
        assert!(mapped_account_id(&associations, "client", &other).is_err());
        other = account.clone();
        other.environment = "login.microsoftonline.us".into();
        assert!(mapped_account_id(&associations, "client", &other).is_err());
    }

    #[test]
    fn eqp_cannot_override_native_security_owned_options() {
        for key in [
            "wam_compat",
            "wamcompat",
            "validateAuthority",
            "LoginHint",
            "correlationId",
            "discover",
            "clientId",
            "redirectUri",
            "provider_type",
            "provider_id",
            "providerId",
            "webAccountProvider",
            "webAccount",
            "account_identifier",
            "home_account_id",
            "local_account_id",
            "account_home_tenant_id",
            "prompt",
            "promptType",
            "msal_request_type",
            "msal_identity_provider",
        ] {
            for spelling in [key.to_string(), key.to_ascii_uppercase()] {
                let mut request = request();
                request
                    .extra_query_parameters
                    .insert(spelling.clone(), "override".into());
                assert!(
                    matches!(
                        request_properties(&request, DEFAULT_AUTHORITY),
                        Err(MsalError::InvalidConfiguration(_)),
                    ),
                    "{spelling}"
                );
            }
        }
        let mut request = request();
        request
            .extra_query_parameters
            .insert("client_session".into(), "session".into());
        assert_eq!(
            request_properties(&request, DEFAULT_AUTHORITY).unwrap()["client_session"],
            "session"
        );
    }
}
