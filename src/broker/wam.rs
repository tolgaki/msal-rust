//! Windows Web Account Manager (WAM) broker implementation.
//!
//! Provider APIs require Windows 10 1703+ and the registered redirect URI
//! `ms-appx-web://Microsoft.AAD.BrokerPlugin/{client_id}`.
//! Microsoft documents desktop interop from build 20348; earlier interop
//! availability is not runtime-verified here, and native activation errors propagate.
//!
//! This is the raw AAD WAM provider, not MSALRuntime. Its compatibility
//! properties follow Microsoft's MSAL.NET 4.30.1 `AadPlugin`/`WamAdapters`.
//! Force-refresh fails before dispatch; MSALRuntime's AccessTokenToRenew is
//! not a raw-WAM property. Cancellation calls IAsyncInfo::Cancel and waits for
//! native completion, without guaranteeing UI dismissal. Interactive requests use
//! HWND desktop interop, not CoreWindow-dependent UWP request APIs.
//!
//! WAM account IDs are opaque and must not be treated as MSAL home IDs.
//! Verified associations can be exported/imported using the caller's protected store.
//! Cold account enumeration/selection requiring unresolved guest identities
//! returns `Unsupported` rather than guessing or acquiring tokens as a side effect.

use std::collections::HashMap;
use std::future::Future;
use std::future::IntoFuture;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use windows::core::{RuntimeType, HSTRING};
use windows::Security::Authentication::Web::Core::{
    FindAllWebAccountsStatus, WebAuthenticationCoreManager, WebTokenRequest,
    WebTokenRequestPromptType, WebTokenRequestResult, WebTokenRequestStatus, WebTokenResponse,
};
use windows::Security::Credentials::{WebAccount, WebAccountProvider};
use windows::Win32::Foundation::HWND;
use windows::Win32::System::Console::GetConsoleWindow;
use windows::Win32::System::WinRT::IWebAuthenticationCoreManagerInterop;
use windows::Win32::UI::WindowsAndMessaging::{GetAncestor, IsWindow, GA_ROOTOWNER};
use windows_future::{AsyncStatus, IAsyncOperation};

use crate::account::AccountInfo;
use crate::broker::{
    account_from_native_response, same_account, validate_account_identity,
    validate_request_options, BrokerSignOutRequest, BrokerTokenRequest, NativeBroker,
};
use crate::error::{MsalError, Result};
use crate::response::AuthenticationResult;

const AAD_PROVIDER_ID: &str = "https://login.microsoft.com";
const DEFAULT_AUTHORITY: &str = "https://login.microsoftonline.com/common";

type AccountAssociations = HashMap<(String, String), (String, AccountInfo)>;

/// Plaintext identity associations, not tokens or a protected storage format.
/// Import only data authenticated by the consumer's existing protected store.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WamAccountSnapshot {
    pub version: u32,
    pub client_id: String,
    pub authority: String,
    pub provider_id: String,
    pub accounts: Vec<WamAccountAssociation>,
}

/// A token-response-validated complete identity and its opaque WAM account ID.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WamAccountAssociation {
    pub native_account_id: String,
    pub account: AccountInfo,
}

/// WAM-based native authentication broker for Windows.
#[derive(Clone)]
pub struct WamBroker {
    provider: WebAccountProvider,
    authority: String,
    /// Client + complete MSAL identity -> native ID, authenticated by a token response.
    accounts: Arc<Mutex<AccountAssociations>>,
}

impl WamBroker {
    /// Export this client's associations for the caller's protected persistence.
    /// No refresh/access tokens are exported. Save again after acquisition/sign-out.
    pub fn export_account_associations(&self, client_id: &str) -> Result<WamAccountSnapshot> {
        validate_client_id(client_id)?;
        let known = self
            .accounts
            .lock()
            .map_err(|_| MsalError::AuthenticationFailed("WAM account map poisoned".into()))?;
        snapshot_for_client(&known, client_id, &self.authority)
    }

    /// Atomically replace this client's associations from integrity-protected data.
    /// Rejects mismatched client/provider/authority, incomplete identity and
    /// duplicate identities. Structural validation does not authenticate a snapshot.
    /// Native enumeration/lookup checks existence; token results recheck identity.
    pub fn import_account_associations(
        &self,
        client_id: &str,
        snapshot: WamAccountSnapshot,
    ) -> Result<()> {
        let replacement = validate_snapshot(client_id, &self.authority, snapshot)?;
        let mut known = self
            .accounts
            .lock()
            .map_err(|_| MsalError::AuthenticationFailed("WAM account map poisoned".into()))?;
        known.retain(|(client, _), _| client != client_id);
        known.extend(replacement);
        Ok(())
    }

    /// Look up an exact client-bound identity and verify its WAM account exists.
    /// A home ID alone is insufficient for guest/resource-tenant selection.
    /// Uses the associated native ID with `FindAccountAsync`, not enumeration;
    /// provider permission to enumerate accounts is not required.
    pub async fn account_for_client(
        &self,
        client_id: &str,
        account: &AccountInfo,
    ) -> Result<AccountInfo> {
        let native_id = self
            .find_account(client_id, account, None)
            .await?
            .Id()
            .map_err(native_error)?
            .to_string();
        let known = self
            .accounts
            .lock()
            .map_err(|_| MsalError::AuthenticationFailed("WAM account map poisoned".into()))?;
        account_after_native_lookup(&known, client_id, account, &native_id)
    }

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
            accounts: Arc::new(Mutex::new(HashMap::new())),
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
            accounts: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    fn build_token_request(
        &self,
        client_id: &str,
        params: &BrokerTokenRequest,
    ) -> Result<WebTokenRequest> {
        validate_client_id(client_id)?;
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

    async fn find_account(
        &self,
        client_id: &str,
        account: &AccountInfo,
        cancellation: Option<&crate::request::CancellationToken>,
    ) -> Result<WebAccount> {
        let id = self.mapped_id(client_id, account)?;
        if let Some(token) = cancellation {
            token.check_cancelled()?;
        }
        let operation =
            WebAuthenticationCoreManager::FindAccountAsync(&self.provider, &HSTRING::from(&id))
                .map_err(native_error)?;
        let found = await_operation(operation, cancellation).await?;
        if found.Id().map_err(native_error)? != id.as_str() {
            return Err(MsalError::AuthenticationFailed(
                "WAM lookup returned a different native ID".into(),
            ));
        }
        Ok(found)
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
    validate_client_id(client_id)?;
    validate_account_identity(account)?;
    accounts
        .get(&(client_id.into(), account.cache_key()))
        .filter(|(_, known)| same_account(known, account))
        .map(|(id, _)| id.clone())
        .ok_or_else(|| {
            MsalError::Unsupported(
                "no verified WAM ID for this client and complete account identity; \
             restore protected account associations or obtain an interactive result first"
                    .into(),
            )
        })
}

/// Build and validate this client's export from the shared association map.
fn snapshot_for_client(
    known: &AccountAssociations,
    client_id: &str,
    authority: &str,
) -> Result<WamAccountSnapshot> {
    let authority_host = url::Url::parse(authority)
        .ok()
        .and_then(|url| url.host_str().map(String::from))
        .unwrap_or_default();
    // Accounts acquired through an authority in another cloud cannot be
    // restored under this broker's authority binding; leave them out rather
    // than making every later export fail.
    let mut accounts: Vec<_> = known
        .iter()
        .filter(|((client, _), (_, account))| {
            client == client_id
                && crate::authority::environments_equivalent(&authority_host, &account.environment)
        })
        .map(|(_, (id, account))| WamAccountAssociation {
            native_account_id: id.clone(),
            account: account.clone(),
        })
        .collect();
    accounts.sort_by_key(|entry| entry.account.cache_key());
    let snapshot = WamAccountSnapshot {
        version: 1,
        client_id: client_id.into(),
        authority: authority.into(),
        provider_id: AAD_PROVIDER_ID.into(),
        accounts,
    };
    validate_snapshot(client_id, authority, snapshot.clone())?;
    Ok(snapshot)
}

/// Verified identities for the native accounts WAM reports for this client.
///
/// Native accounts without a verified association are skipped, not guessed:
/// raw WAM metadata cannot establish a guest-safe home/resource identity, and
/// one unrelated or unrestored OS account must not hide the verified ones.
fn associated_accounts(
    accounts: &AccountAssociations,
    client_id: &str,
    native_ids: &[String],
) -> Vec<AccountInfo> {
    let mut found: Vec<AccountInfo> = accounts
        .iter()
        .filter(|((client, _), (native_id, _))| {
            client == client_id && native_ids.iter().any(|id| id == native_id)
        })
        .map(|(_, (_, account))| account.clone())
        .collect();
    found.sort_by_key(AccountInfo::cache_key);
    found
}

fn account_after_native_lookup(
    accounts: &AccountAssociations,
    client_id: &str,
    account: &AccountInfo,
    checked_native_id: &str,
) -> Result<AccountInfo> {
    accounts
        .get(&(client_id.into(), account.cache_key()))
        .filter(|(id, known)| id == checked_native_id && same_account(known, account))
        .map(|(_, account)| account.clone())
        .ok_or_else(|| {
            MsalError::AuthenticationFailed("WAM association changed during lookup".into())
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

fn check_enumeration_status(
    status: FindAllWebAccountsStatus,
    provider_diagnostics: impl FnOnce() -> String,
) -> Result<()> {
    let name = match status {
        FindAllWebAccountsStatus::Success => return Ok(()),
        FindAllWebAccountsStatus::NotAllowedByProvider => "NotAllowedByProvider",
        FindAllWebAccountsStatus::NotSupportedByProvider => "NotSupportedByProvider",
        FindAllWebAccountsStatus::ProviderError => "ProviderError",
        _ => "Unknown",
    };
    let description = format!(
        "WAM account enumeration status={name} ({}); {}",
        status.0,
        provider_diagnostics(),
    );
    if status == FindAllWebAccountsStatus::NotAllowedByProvider
        || status == FindAllWebAccountsStatus::NotSupportedByProvider
    {
        Err(MsalError::Unsupported(description))
    } else {
        Err(MsalError::AuthenticationFailed(description))
    }
}

fn validate_client_id(client_id: &str) -> Result<()> {
    if client_id.trim().is_empty() {
        return Err(MsalError::InvalidConfiguration(
            "WAM client ID is empty".into(),
        ));
    }
    Ok(())
}

fn validate_snapshot(
    client_id: &str,
    authority: &str,
    snapshot: WamAccountSnapshot,
) -> Result<AccountAssociations> {
    validate_client_id(client_id)?;
    if snapshot.version != 1
        || snapshot.client_id != client_id
        || snapshot.authority != authority
        || snapshot.provider_id != AAD_PROVIDER_ID
    {
        return Err(MsalError::InvalidConfiguration(
            "WAM snapshot version/client/provider/authority mismatch".into(),
        ));
    }
    validate_authority(authority)?;
    let authority_url = url::Url::parse(authority)
        .map_err(|_| MsalError::InvalidConfiguration("invalid snapshot authority".into()))?;
    let authority_host = authority_url
        .host_str()
        .ok_or_else(|| MsalError::InvalidConfiguration("missing snapshot authority host".into()))?;
    let mut replacement = AccountAssociations::new();
    for entry in snapshot.accounts {
        validate_account_identity(&entry.account)?;
        if entry.native_account_id.trim().is_empty() {
            return Err(MsalError::InvalidConfiguration(
                "WAM snapshot native ID is empty".into(),
            ));
        }
        // A response acquired with an explicit tenant override still belongs
        // to this broker. Preserve its resource tenant, not the default realm.
        if !crate::authority::environments_equivalent(authority_host, &entry.account.environment) {
            return Err(MsalError::InvalidConfiguration(
                "WAM snapshot account environment differs from broker authority".into(),
            ));
        }
        if replacement
            .insert(
                (client_id.into(), entry.account.cache_key()),
                (entry.native_account_id, entry.account),
            )
            .is_some()
        {
            return Err(MsalError::InvalidConfiguration(
                "duplicate WAM snapshot identity".into(),
            ));
        }
    }
    Ok(replacement)
}

async fn await_operation<T: RuntimeType + 'static>(
    operation: IAsyncOperation<T>,
    cancellation: Option<&crate::request::CancellationToken>,
) -> Result<T> {
    let future = async {
        operation.clone().into_future().await.map_err(|error| {
            if operation.Status().ok() == Some(AsyncStatus::Canceled) {
                MsalError::OperationCancelled
            } else {
                native_error(error)
            }
        })
    };
    crate::broker::await_with_cancellation(
        future,
        || operation.Cancel().map_err(native_error),
        cancellation,
        crate::broker::NATIVE_CANCEL_GRACE,
    )
    .await
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

fn decode_window_handle(bytes: &[u8]) -> Result<isize> {
    let bytes = bytes.try_into().map_err(|_| {
        MsalError::InvalidConfiguration(format!(
            "WAM window_handle must contain exactly {} little-endian bytes (isize)",
            std::mem::size_of::<isize>(),
        ))
    })?;
    let handle = isize::from_le_bytes(bytes);
    if handle == 0 {
        return Err(MsalError::InvalidConfiguration(
            "WAM window_handle must not be null".into(),
        ));
    }
    Ok(handle)
}

fn resolve_window_handle(
    bytes: Option<&[u8]>,
    console_window: impl FnOnce() -> isize,
    root_owner: impl FnOnce(isize) -> isize,
    is_window: impl FnOnce(isize) -> bool,
) -> Result<isize> {
    let handle = if let Some(bytes) = bytes {
        decode_window_handle(bytes)?
    } else {
        let console = console_window();
        if console == 0 {
            return Err(MsalError::MissingParameter(
                "WAM needs window_handle: this process has no console window".into(),
            ));
        }
        root_owner(console)
    };
    if handle == 0 || !is_window(handle) {
        return Err(MsalError::InvalidConfiguration(
            "WAM needs a valid parent window_handle; no valid console/terminal root owner was found or the supplied HWND is invalid".into(),
        ));
    }
    Ok(handle)
}

fn interactive_window_handle(bytes: Option<&[u8]>) -> Result<isize> {
    resolve_window_handle(
        bytes,
        || unsafe { GetConsoleWindow().0 as isize },
        |console| unsafe { GetAncestor(HWND(console as *mut _), GA_ROOTOWNER).0 as isize },
        |handle| unsafe { IsWindow(Some(HWND(handle as *mut _))).as_bool() },
    )
}

fn request_token_for_window(
    handle: isize,
    request: &WebTokenRequest,
    account: Option<&WebAccount>,
) -> Result<IAsyncOperation<WebTokenRequestResult>> {
    let window = HWND(handle as *mut _);
    // Account lookup can yield before dispatch; the caller must keep its window
    // alive, but reject a window already destroyed during that wait.
    if !unsafe { IsWindow(Some(window)).as_bool() } {
        return Err(MsalError::InvalidConfiguration(
            "WAM parent HWND is no longer a valid window".into(),
        ));
    }
    let interop = windows::core::factory::<
        WebAuthenticationCoreManager,
        IWebAuthenticationCoreManagerInterop,
    >()
    .map_err(native_error)?;
    // The projection supplies the IID of IAsyncOperation<WebTokenRequestResult>.
    // Windows owns the HWND; request/account are live WinRT references.
    unsafe {
        match account {
            Some(account) => {
                interop.RequestTokenWithWebAccountForWindowAsync(window, request, account)
            }
            None => interop.RequestTokenForWindowAsync(window, request),
        }
    }
    .map_err(native_error)
}

fn request_properties(
    request: &BrokerTokenRequest,
    default_authority: &str,
) -> Result<std::collections::BTreeMap<String, String>> {
    validate_request_options(request, true)?;
    if request.force_refresh {
        return Err(MsalError::Unsupported(
            "raw WAM has no verified force-refresh contract; MSALRuntime is required".into(),
        ));
    }
    if let Some(bytes) = &request.window_handle {
        decode_window_handle(bytes)?;
    }
    let authority = request.authority.as_deref().unwrap_or(default_authority);
    validate_authority(authority)?;
    let mut authority = url::Url::parse(authority)
        .map_err(|_| MsalError::InvalidConfiguration("invalid broker authority URL".into()))?;
    if let Some(account) = &request.account {
        let host = authority.host_str().unwrap_or_default();
        if !crate::authority::environments_equivalent(host, &account.environment) {
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

    fn supports_native_cancellation(&self) -> bool {
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
            let web_account = self
                .find_account(client_id, account, request.cancellation_token.as_ref())
                .await?;
            if let Some(token) = &request.cancellation_token {
                token.check_cancelled()?;
            }
            let operation = WebAuthenticationCoreManager::GetTokenSilentlyWithWebAccountAsync(
                &wam_request,
                &web_account,
            )
            .map_err(native_error)?;
            let result = await_operation(operation, request.cancellation_token.as_ref()).await?;
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
            let handle = interactive_window_handle(request.window_handle.as_deref())?;
            let operation = if let Some(account) = &request.account {
                let web_account = self
                    .find_account(client_id, account, request.cancellation_token.as_ref())
                    .await?;
                if let Some(token) = &request.cancellation_token {
                    token.check_cancelled()?;
                }
                request_token_for_window(handle, &wam_request, Some(&web_account))
            } else {
                request_token_for_window(handle, &wam_request, None)
            }?;
            let result = await_operation(operation, request.cancellation_token.as_ref()).await?;
            self.handle_result(client_id, request, &result)
        })
    }

    fn sign_out<'a>(
        &'a self,
        client_id: &'a str,
        request: &'a BrokerSignOutRequest,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            let web_account = self.find_account(client_id, &request.account, None).await?;
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
            validate_client_id(client_id)?;
            let result = WebAuthenticationCoreManager::FindAllAccountsWithClientIdAsync(
                &self.provider,
                &HSTRING::from(client_id),
            )
            .map_err(native_error)?
            .await
            .map_err(native_error)?;
            check_enumeration_status(result.Status().map_err(native_error)?, || {
                match result.ProviderError() {
                    Ok(error) => {
                        let code = match error.ErrorCode() {
                            Ok(code) => format!("{code} (0x{code:08X})"),
                            Err(error) => format!("unavailable: {error}"),
                        };
                        let message = match error.ErrorMessage() {
                            Ok(message) => message.to_string(),
                            Err(error) => format!("unavailable: {error}"),
                        };
                        format!(
                            "ProviderError.ErrorCode={code}; ProviderError.ErrorMessage={message}"
                        )
                    }
                    Err(error) => format!("ProviderError unavailable: {error}"),
                }
            })?;
            let native_accounts = result.Accounts().map_err(native_error)?;
            let mut native_ids = Vec::new();
            for i in 0..native_accounts.Size().map_err(native_error)? {
                native_ids.push(
                    native_accounts
                        .GetAt(i)
                        .map_err(native_error)?
                        .Id()
                        .map_err(native_error)?
                        .to_string(),
                );
            }
            let known = self
                .accounts
                .lock()
                .map_err(|_| MsalError::AuthenticationFailed("WAM account map poisoned".into()))?;
            Ok(associated_accounts(&known, client_id, &native_ids))
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

    #[test]
    fn successful_enumeration_does_not_require_provider_error_metadata() {
        assert!(
            check_enumeration_status(FindAllWebAccountsStatus::Success, || {
                panic!("success must not read optional error metadata")
            })
            .is_ok()
        );
    }

    #[test]
    fn provider_denied_or_unsupported_enumeration_is_distinct_from_auth_failure() {
        for (status, name) in [
            (
                FindAllWebAccountsStatus::NotAllowedByProvider,
                "NotAllowedByProvider (1)",
            ),
            (
                FindAllWebAccountsStatus::NotSupportedByProvider,
                "NotSupportedByProvider (2)",
            ),
        ] {
            let error = check_enumeration_status(status, || {
                "ProviderError unavailable: null native error".into()
            })
            .unwrap_err();
            let MsalError::Unsupported(description) = error else {
                panic!("enumeration capability must not be an authentication failure");
            };
            assert!(description.contains(name));
            assert!(description.contains("ProviderError unavailable: null native error"));
        }
    }

    #[test]
    fn provider_failures_and_unknown_enumeration_status_preserve_diagnostics() {
        for (status, name) in [
            (FindAllWebAccountsStatus::ProviderError, "ProviderError (3)"),
            (FindAllWebAccountsStatus(99), "Unknown (99)"),
        ] {
            let error = check_enumeration_status(status, || {
                "ProviderError.ErrorCode=2147942405 (0x80070005); ProviderError.ErrorMessage=access denied".into()
            }).unwrap_err();
            let MsalError::AuthenticationFailed(description) = error else {
                panic!("provider failures must not be treated as an empty list or Unsupported");
            };
            assert!(description.contains(name));
            assert!(description.contains("2147942405 (0x80070005)"));
            assert!(description.contains("access denied"));
        }
    }

    #[test]
    fn hwnd_encoding_preserves_native_pointer_bits_and_rejects_bad_inputs() {
        for handle in [1isize, 0x123456, isize::MAX, isize::MIN] {
            assert_eq!(decode_window_handle(&handle.to_le_bytes()).unwrap(), handle);
        }
        for bytes in [
            Vec::new(),
            vec![1; std::mem::size_of::<isize>() - 1],
            vec![1; std::mem::size_of::<isize>() + 1],
            0isize.to_le_bytes().to_vec(),
        ] {
            assert!(matches!(
                decode_window_handle(&bytes),
                Err(MsalError::InvalidConfiguration(_))
            ));
        }
        let handle = 0x123456isize;
        let mut request = request();
        request.window_handle = Some(handle.to_le_bytes().to_vec());
        assert!(request_properties(&request, DEFAULT_AUTHORITY).is_ok());
        request.window_handle = Some(vec![1]);
        assert!(request_properties(&request, DEFAULT_AUTHORITY).is_err());
    }

    #[test]
    fn explicit_hwnd_takes_priority_and_never_falls_back() {
        let bytes = 42isize.to_le_bytes();
        assert_eq!(
            resolve_window_handle(
                Some(&bytes),
                || panic!("must not infer a console"),
                |_| panic!("must not replace the caller's HWND"),
                |handle| handle == 42,
            )
            .unwrap(),
            42
        );
        assert!(matches!(
            resolve_window_handle(
                Some(&bytes),
                || panic!("invalid explicit HWND must not fall back"),
                |_| panic!("invalid explicit HWND must not fall back"),
                |_| false,
            ),
            Err(MsalError::InvalidConfiguration(_))
        ));
    }

    #[test]
    fn console_resolution_uses_root_owner_and_errors_without_a_usable_parent() {
        assert_eq!(
            resolve_window_handle(
                None,
                || 10,
                |console| {
                    assert_eq!(console, 10);
                    20
                },
                |root| root == 20
            )
            .unwrap(),
            20
        );
        assert!(matches!(
            resolve_window_handle(
                None,
                || 0,
                |_| panic!("no console must not be passed to GetAncestor"),
                |_| panic!("must not choose an unrelated window"),
            ),
            Err(MsalError::MissingParameter(_))
        ));
        for root in [0, 20] {
            assert!(matches!(
                resolve_window_handle(None, || 10, |_| root, |_| false),
                Err(MsalError::InvalidConfiguration(_))
            ));
        }
    }

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
    fn refresh_is_unsupported_but_native_cancellation_is_accepted() {
        let mut request = request();
        request.force_refresh = true;
        assert!(matches!(
            request_properties(&request, DEFAULT_AUTHORITY),
            Err(MsalError::Unsupported(_))
        ));
        request.force_refresh = false;
        let token = crate::request::CancellationToken::new();
        request.cancellation_token = Some(token.clone());
        assert!(request_properties(&request, DEFAULT_AUTHORITY).is_ok());
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
        request.authority =
            Some("https://login.microsoftonline.com/11111111-1111-4111-8111-111111111111".into());
        assert!(request_properties(&request, DEFAULT_AUTHORITY).is_err());
    }

    fn snapshot() -> WamAccountSnapshot {
        WamAccountSnapshot {
            version: 1,
            client_id: "client".into(),
            authority: DEFAULT_AUTHORITY.into(),
            provider_id: AAD_PROVIDER_ID.into(),
            accounts: vec![WamAccountAssociation {
                native_account_id: "opaque-native-id".into(),
                account: AccountInfo {
                    home_account_id: "home-user.home-tenant".into(),
                    local_account_id: "guest".into(),
                    tenant_id: "resource-tenant".into(),
                    environment: crate::account::AAD_PUBLIC_CLOUD_ENVIRONMENT.into(),
                    username: String::new(),
                    name: None,
                    id_token_claims: None,
                },
            }],
        }
    }

    #[test]
    fn protected_snapshot_round_trip_restores_exact_cold_selection() {
        let snapshot = snapshot();
        let account = snapshot.accounts[0].account.clone();
        let encoded = serde_json::to_vec(&snapshot).unwrap();
        let imported = validate_snapshot(
            "client",
            DEFAULT_AUTHORITY,
            serde_json::from_slice(&encoded).unwrap(),
        )
        .unwrap();
        assert_eq!(
            mapped_account_id(&imported, "client", &account).unwrap(),
            "opaque-native-id"
        );
        assert!(mapped_account_id(&imported, "other-client", &account).is_err());
        for field in ["home", "local", "tenant", "environment"] {
            let mut changed = account.clone();
            match field {
                "home" => changed.home_account_id = "another.home-tenant".into(),
                "local" => changed.local_account_id = "another-object".into(),
                "tenant" => changed.tenant_id = "home-tenant".into(),
                _ => changed.environment = "login.microsoftonline.us".into(),
            }
            assert!(
                mapped_account_id(&imported, "client", &changed).is_err(),
                "{field}"
            );
        }
    }

    #[test]
    fn snapshot_preserves_explicit_resource_tenant_override_without_changing_default_routing() {
        let default_authority =
            "https://login.microsoftonline.com/11111111-1111-4111-8111-111111111111";
        let resource_authority =
            "https://login.microsoftonline.com/22222222-2222-4222-8222-222222222222";
        let mut snapshot = snapshot();
        snapshot.authority = default_authority.into();
        snapshot.accounts[0].account.tenant_id = "22222222-2222-4222-8222-222222222222".into();
        let account = snapshot.accounts[0].account.clone();
        let restored = validate_snapshot("client", default_authority, snapshot).unwrap();
        assert_eq!(
            mapped_account_id(&restored, "client", &account).unwrap(),
            "opaque-native-id"
        );
        let mut request = request();
        request.account = Some(account);
        assert!(request_properties(&request, default_authority).is_err());
        request.authority = Some(resource_authority.into());
        assert_eq!(
            request_properties(&request, default_authority).unwrap()["authority"],
            resource_authority
        );
    }

    #[test]
    fn checked_lookup_rejects_a_native_id_replaced_by_concurrent_import() {
        let snapshot = snapshot();
        let account = snapshot.accounts[0].account.clone();
        let mut known = validate_snapshot("client", DEFAULT_AUTHORITY, snapshot).unwrap();
        assert!(same_account(
            &account_after_native_lookup(&known, "client", &account, "opaque-native-id").unwrap(),
            &account,
        ));
        known
            .get_mut(&("client".into(), account.cache_key()))
            .unwrap()
            .0 = "unchecked-replacement".into();
        assert!(matches!(
            account_after_native_lookup(&known, "client", &account, "opaque-native-id"),
            Err(MsalError::AuthenticationFailed(_)),
        ));
    }

    #[test]
    fn snapshot_and_selection_use_the_same_verified_cloud_aliases() {
        let authority = "https://sts.windows.net/common";
        let mut snapshot = snapshot();
        snapshot.authority = authority.into();
        let account = snapshot.accounts[0].account.clone();
        let restored = validate_snapshot("client", authority, snapshot).unwrap();
        assert_eq!(
            mapped_account_id(&restored, "client", &account).unwrap(),
            "opaque-native-id"
        );
        let mut request = request();
        request.account = Some(account);
        assert_eq!(
            request_properties(&request, authority).unwrap()["authority"],
            "https://sts.windows.net/resource-tenant"
        );
    }

    #[test]
    fn snapshot_rejects_invalid_scope_identity_and_conflicting_entries() {
        for field in [
            "version",
            "client",
            "authority",
            "provider",
            "native",
            "home",
            "local",
            "tenant",
            "environment",
            "duplicate",
        ] {
            let mut value = snapshot();
            match field {
                "version" => value.version = 2,
                "client" => value.client_id = "other".into(),
                "authority" => value.authority = "https://login.microsoftonline.us/common".into(),
                "provider" => value.provider_id = "other".into(),
                "native" => value.accounts[0].native_account_id.clear(),
                "home" => value.accounts[0].account.home_account_id.clear(),
                "local" => value.accounts[0].account.local_account_id.clear(),
                "tenant" => value.accounts[0].account.tenant_id.clear(),
                "environment" => {
                    value.accounts[0].account.environment = "login.microsoftonline.us".into()
                }
                _ => value.accounts.push(value.accounts[0].clone()),
            }
            assert!(
                validate_snapshot("client", DEFAULT_AUTHORITY, value).is_err(),
                "{field}"
            );
        }
    }

    #[test]
    fn enumeration_skips_unassociated_native_accounts() {
        let snapshot = snapshot();
        let account = snapshot.accounts[0].account.clone();
        let known = validate_snapshot("client", DEFAULT_AUTHORITY, snapshot).unwrap();
        let native_ids = vec![
            "unrelated-os-account".to_string(),
            "opaque-native-id".into(),
        ];
        let accounts = associated_accounts(&known, "client", &native_ids);
        assert_eq!(accounts.len(), 1);
        assert!(same_account(&accounts[0], &account));
        assert!(associated_accounts(&known, "other-client", &native_ids).is_empty());
        assert!(associated_accounts(&known, "client", &["unrelated-os-account".into()]).is_empty());
    }

    #[test]
    fn export_leaves_out_accounts_from_another_cloud() {
        let snapshot = snapshot();
        let mut known = validate_snapshot("client", DEFAULT_AUTHORITY, snapshot).unwrap();
        let mut sovereign = known.values().next().unwrap().1.clone();
        sovereign.environment = "login.microsoftonline.us".into();
        known.insert(
            ("client".into(), sovereign.cache_key()),
            ("us-native-id".into(), sovereign),
        );
        let exported = snapshot_for_client(&known, "client", DEFAULT_AUTHORITY).unwrap();
        assert_eq!(exported.accounts.len(), 1);
        assert_eq!(exported.accounts[0].native_account_id, "opaque-native-id");
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
