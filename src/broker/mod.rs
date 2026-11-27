//! Native authentication broker support.
//!
//! Brokered authentication delegates to a platform-native authentication broker
//! (WAM on Windows, Enterprise SSO on macOS) for device-bound tokens, SSO across
//! apps, and conditional access compliance.
//!
//! # Usage
//!
//! ```no_run
//! use msal::{Configuration, PublicClientApplication};
//! use msal::broker::BrokerTokenRequest;
//!
//! # async fn example() -> Result<(), msal::MsalError> {
//! # let config = Configuration::builder("client-id").build();
//! let app = PublicClientApplication::new(config)?;
//!
//! // Enable brokered auth (platform-specific)
//! #[cfg(all(target_os = "windows", feature = "broker-wam"))]
//! app.set_broker(Box::new(msal::broker::wam::WamBroker::new().await?)).await;
//!
//! let request = BrokerTokenRequest {
//!     scopes: vec!["user.read".into()],
//!     account: None,
//!     claims: None,
//!     force_refresh: false,
//!     authority: None,
//!     extra_query_parameters: Default::default(),
//!     cancellation_token: None,
//!     correlation_id: None,
//!     window_handle: None,
//!     authentication_scheme: Default::default(),
//!     pop_params: None,
//! };
//!
//! // Will use broker if available, otherwise falls back to standard flow
//! let result = app.acquire_token_interactive(request).await?;
//! # Ok(())
//! # }
//! ```

#[cfg(all(target_os = "macos", feature = "broker-macos"))]
pub mod macos;
#[cfg(all(target_os = "windows", feature = "broker-wam"))]
pub mod wam;

#[cfg(any(test, all(target_os = "macos", feature = "broker-macos")))]
mod macos_protocol;

use std::future::Future;
use std::pin::Pin;

use crate::account::AccountInfo;
use crate::error::Result;
use crate::response::AuthenticationResult;

/// Authentication scheme for token requests.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum AuthenticationScheme {
    /// Standard Bearer token (default).
    #[default]
    Bearer,
    /// Proof-of-Possession: tokens are bound to the requesting client.
    Pop,
}

/// Parameters for Proof-of-Possession token binding.
#[derive(Debug, Clone)]
pub struct PopParams {
    /// HTTP method for the resource request (GET, POST, etc.).
    pub resource_request_method: String,
    /// URI of the resource being accessed.
    pub resource_request_uri: String,
    /// Server-provided nonce for the signed HTTP request.
    pub shr_nonce: Option<String>,
}

/// Request for broker token acquisition (interactive or silent).
#[derive(Debug, Clone)]
pub struct BrokerTokenRequest {
    /// OAuth 2.0 scopes to request.
    pub scopes: Vec<String>,
    /// Account for silent flow (required for silent, optional for interactive).
    pub account: Option<AccountInfo>,
    /// Additional claims requested.
    pub claims: Option<String>,
    /// Bypass the native token cache. Unsupported adapters must reject this.
    pub force_refresh: bool,
    /// Authority for this request, overriding the broker's configured authority.
    pub authority: Option<String>,
    /// Additional server query parameters, mapped only through supported native APIs.
    pub extra_query_parameters: std::collections::BTreeMap<String, String>,
    /// Requests cancellation of the native operation, not merely the awaiting future.
    /// WAM calls `IAsyncInfo::Cancel` and waits for native completion; this does
    /// not guarantee UI dismissal or revoke already-issued tokens. Adapters
    /// without native cancellation reject an uncancelled token before dispatch.
    pub cancellation_token: Option<crate::request::CancellationToken>,
    /// Correlation ID for request tracing.
    pub correlation_id: Option<String>,
    /// Native window handle for parenting the broker UI (interactive only).
    /// On Windows this is an HWND. Pass `None` for console apps.
    pub window_handle: Option<Vec<u8>>,
    /// Token type: Bearer (default) or PoP.
    pub authentication_scheme: AuthenticationScheme,
    /// Proof-of-Possession parameters (required when scheme is PoP).
    pub pop_params: Option<PopParams>,
}

/// Request for broker sign-out.
#[derive(Debug, Clone)]
pub struct BrokerSignOutRequest {
    /// The account to sign out.
    pub account: AccountInfo,
    /// Correlation ID for request tracing.
    pub correlation_id: Option<String>,
}

/// Trait for native authentication broker plugins.
///
/// Implementors bridge MSAL to platform-specific authentication infrastructure
/// (WAM on Windows, Enterprise SSO on macOS, etc.).
///
/// # Important behavioral notes
///
/// - **No fallback on broker failure**: if the broker returns an error, MSAL does
///   NOT fall back to browser-based auth. The error propagates to the caller.
/// - **Unsupported options fail before dispatch**: an adapter must not silently
///   discard claims, force-refresh, account selection, query parameters or cancellation.
/// - **Tokens are device-bound**: refresh tokens are managed by the OS, not by MSAL's cache.
pub trait NativeBroker: Send + Sync {
    /// Returns `true` if the broker is available on this platform.
    fn is_available(&self) -> bool;

    /// Whether token acquisition accepts and dispatches native cancellation.
    /// False preserves wait-only cancellation for legacy silent adapters.
    /// True does not promise native UI dismissal or server-side rollback, but an
    /// adapter returning true must still return promptly once cancellation is
    /// requested (see `NATIVE_CANCEL_GRACE`), because callers do not add an
    /// outer wait-only bound around it.
    fn supports_native_cancellation(&self) -> bool {
        false
    }

    /// Acquire a token silently (no user prompts).
    ///
    /// The `request.account` field must be `Some`. Returns a cached or refreshed
    /// token without user interaction.
    fn acquire_token_silent<'a>(
        &'a self,
        client_id: &'a str,
        request: &'a BrokerTokenRequest,
    ) -> Pin<Box<dyn Future<Output = Result<AuthenticationResult>> + Send + 'a>>;

    /// Acquire a token interactively (may show system prompts).
    ///
    /// Shows OS-native authentication UI (not a browser window). The window handle
    /// in the request is used to parent the broker dialog.
    fn acquire_token_interactive<'a>(
        &'a self,
        client_id: &'a str,
        request: &'a BrokerTokenRequest,
    ) -> Pin<Box<dyn Future<Output = Result<AuthenticationResult>> + Send + 'a>>;

    /// Sign out a user from the broker.
    fn sign_out<'a>(
        &'a self,
        client_id: &'a str,
        request: &'a BrokerSignOutRequest,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;

    /// Return all accounts known to the broker for this client.
    fn all_accounts<'a>(
        &'a self,
        client_id: &'a str,
        correlation_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<AccountInfo>>> + Send + 'a>>;

    /// Look up a specific account by its home_account_id.
    fn account<'a>(
        &'a self,
        account_id: &'a str,
        correlation_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<AccountInfo>> + Send + 'a>>;
}

/// How long an adapter waits for a native operation to finish after asking it
/// to cancel. Native cancellation is cooperative (an interactive prompt can stay
/// open), so the caller gets `OperationCancelled` after this bound even if the
/// native operation has not finished; its late result is never returned.
#[cfg(any(test, all(target_os = "windows", feature = "broker-wam")))]
pub(crate) const NATIVE_CANCEL_GRACE: std::time::Duration = std::time::Duration::from_secs(5);

/// Await a native operation, dispatching `cancel` when `cancellation` fires.
///
/// After cancelling, waits at most `grace` for the operation's terminal result,
/// then returns `OperationCancelled`. A result racing cancellation is discarded.
/// A failed `cancel` or an unexpected terminal native error is surfaced, but only
/// after the bounded wait, so the operation is not abandoned mid-flight early.
#[cfg(any(test, all(target_os = "windows", feature = "broker-wam")))]
pub(crate) async fn await_with_cancellation<T>(
    future: impl Future<Output = Result<T>>,
    cancel: impl FnOnce() -> Result<()>,
    cancellation: Option<&crate::request::CancellationToken>,
    grace: std::time::Duration,
) -> Result<T> {
    use crate::error::MsalError;
    tokio::pin!(future);
    let Some(token) = cancellation else {
        return future.await;
    };
    tokio::select! {
        biased;
        _ = token.cancelled() => {}
        result = &mut future => {
            token.check_cancelled()?;
            return result;
        }
    }
    let cancel_result = cancel();
    match tokio::time::timeout(grace, &mut future).await {
        // Terminal native failure other than the cancellation we asked for.
        Ok(Err(error)) if !matches!(error, MsalError::OperationCancelled) => {
            cancel_result?;
            Err(error)
        }
        // Completed (result discarded), cancelled, or still running after the
        // grace period: the caller asked to cancel, so report that.
        _ => {
            cancel_result?;
            Err(MsalError::OperationCancelled)
        }
    }
}

/// Shared preflight for adapters that cannot guarantee in-flight native cancellation.
#[cfg(any(test, all(target_os = "macos", feature = "broker-macos")))]
fn validate_request(request: &BrokerTokenRequest) -> Result<()> {
    validate_request_options(request, false)
}

#[cfg(any(
    test,
    all(target_os = "windows", feature = "broker-wam"),
    all(target_os = "macos", feature = "broker-macos")
))]
fn validate_request_options(request: &BrokerTokenRequest, native_cancellation: bool) -> Result<()> {
    if let Some(token) = &request.cancellation_token {
        token.check_cancelled()?;
        if !native_cancellation {
            return Err(crate::error::MsalError::Unsupported(
                "this native adapter cannot cancel an in-flight broker operation; omit cancellation_token"
                    .into(),
            ));
        }
    }
    crate::request::validate_extra_query_parameters(&request.extra_query_parameters)?;
    if request.authentication_scheme != AuthenticationScheme::Bearer || request.pop_params.is_some()
    {
        return Err(crate::error::MsalError::Unsupported(
            "this native adapter does not implement proof-of-possession".into(),
        ));
    }
    if let Some(claims) = &request.claims {
        if !serde_json::from_str::<serde_json::Value>(claims)
            .map(|value| value.is_object())
            .unwrap_or(false)
        {
            return Err(crate::error::MsalError::InvalidConfiguration(
                "broker claims must be a JSON object".into(),
            ));
        }
    }
    if let Some(account) = &request.account {
        validate_account_identity(account)?;
    }
    Ok(())
}

#[cfg(any(
    test,
    all(target_os = "windows", feature = "broker-wam"),
    all(target_os = "macos", feature = "broker-macos")
))]
fn validate_account_identity(account: &AccountInfo) -> Result<()> {
    if [
        &account.home_account_id,
        &account.local_account_id,
        &account.tenant_id,
        &account.environment,
    ]
    .iter()
    .any(|value| value.trim().is_empty())
    {
        return Err(crate::error::MsalError::InvalidConfiguration(
            "native account selection requires home, local, tenant and environment identity".into(),
        ));
    }
    Ok(())
}

#[cfg(any(
    test,
    all(target_os = "windows", feature = "broker-wam"),
    all(target_os = "macos", feature = "broker-macos")
))]
fn same_account(left: &AccountInfo, right: &AccountInfo) -> bool {
    left.same_identity(right)
}

/// Interpret identity metadata only from a trusted, successful native response.
/// The native broker authenticates the response. Public clients do not require
/// blanket ID-token signature verification, but audience and issuer still matter.
#[cfg(any(
    test,
    all(target_os = "windows", feature = "broker-wam"),
    all(target_os = "macos", feature = "broker-macos")
))]
fn account_from_native_response(
    client_id: &str,
    authority: &str,
    id_token: &str,
    client_info: &str,
) -> Result<AccountInfo> {
    use crate::error::MsalError;
    let invalid = || MsalError::AuthenticationFailed("invalid native account identity".into());
    let claims = crate::crypto::decode_jwt_payload(id_token)?;
    let tid = claims["tid"]
        .as_str()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(invalid)?;
    if claims["aud"].as_str() != Some(client_id) || client_id.trim().is_empty() {
        return Err(invalid());
    }
    let local_id = claims["oid"]
        .as_str()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            claims["sub"]
                .as_str()
                .filter(|value| !value.trim().is_empty())
        })
        .ok_or_else(invalid)?;
    let authority = url::Url::parse(authority).map_err(|_| invalid())?;
    let issuer =
        url::Url::parse(claims["iss"].as_str().ok_or_else(invalid)?).map_err(|_| invalid())?;
    let host = authority.host_str().ok_or_else(invalid)?;
    let issuer_host = issuer.host_str().ok_or_else(invalid)?;
    let tenant = authority
        .path_segments()
        .and_then(|mut segments| segments.find(|segment| !segment.is_empty()))
        .ok_or_else(invalid)?;
    // Only established Entra aliases are accepted; arbitrary issuer hosts are not.
    let public_alias = |host: &str| {
        matches!(
            host,
            "login.microsoftonline.com" | "login.windows.net" | "sts.windows.net"
        )
    };
    if authority.scheme() != "https"
        || issuer.scheme() != "https"
        || !authority.username().is_empty()
        || authority.password().is_some()
        || authority.query().is_some()
        || authority.fragment().is_some()
        || authority.port_or_known_default() != Some(443)
        || !issuer.username().is_empty()
        || issuer.password().is_some()
        || issuer.port_or_known_default() != Some(443)
        || issuer.query().is_some()
        || issuer.fragment().is_some()
        || !(host == issuer_host || (public_alias(host) && public_alias(issuer_host)))
        || !matches!(issuer.path(), path if path == format!("/{tid}/") || path == format!("/{tid}/v2.0"))
        || !(matches!(tenant, "common" | "organizations" | "consumers")
            || tenant.eq_ignore_ascii_case(tid)
            // Domain-name tenants (contoso.onmicrosoft.com) name the tenant
            // that issued `tid`; only GUID tenants can be compared directly.
            || uuid::Uuid::parse_str(tenant).is_err())
    {
        return Err(invalid());
    }
    let client_info = crate::account::ClientInfo::from_base64(client_info)?;
    if client_info.uid.trim().is_empty() || client_info.utid.trim().is_empty() {
        return Err(invalid());
    }
    // utid identifies the home tenant, not the resource tenant (tid).
    Ok(AccountInfo {
        home_account_id: client_info.home_account_id(),
        local_account_id: local_id.into(),
        environment: if public_alias(host) {
            crate::account::AAD_PUBLIC_CLOUD_ENVIRONMENT.into()
        } else {
            host.into()
        },
        tenant_id: tid.into(),
        username: claims["preferred_username"]
            .as_str()
            .or_else(|| claims["upn"].as_str())
            .unwrap_or_default()
            .into(),
        name: claims["name"].as_str().map(String::from),
        id_token_claims: Some(claims),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const GRACE: std::time::Duration = NATIVE_CANCEL_GRACE;

    #[tokio::test]
    async fn active_cancellation_dispatches_cancel_and_waits_for_terminal_result() {
        let token = crate::request::CancellationToken::new();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel();
        let (terminal_tx, terminal_rx) = tokio::sync::oneshot::channel();
        let future = async {
            started_tx.send(()).unwrap();
            terminal_rx.await.unwrap();
            Ok(42)
        };
        let acquisition = await_with_cancellation(
            future,
            || {
                cancel_tx.send(()).unwrap();
                Ok(())
            },
            Some(&token),
            GRACE,
        );
        tokio::pin!(acquisition);
        tokio::select! {
            biased;
            result = &mut acquisition => panic!("completed before cancellation: {result:?}"),
            _ = started_rx => {}
        }
        token.cancel();
        tokio::select! {
            biased;
            result = &mut acquisition => panic!("returned without native completion: {result:?}"),
            _ = cancel_rx => {}
        }
        terminal_tx.send(()).unwrap();
        assert!(matches!(
            acquisition.await,
            Err(crate::error::MsalError::OperationCancelled)
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn cancellation_returns_after_grace_when_native_operation_never_finishes() {
        let token = crate::request::CancellationToken::new();
        token.cancel();
        let started = tokio::time::Instant::now();
        let result = await_with_cancellation(
            std::future::pending::<Result<()>>(),
            || Ok(()),
            Some(&token),
            GRACE,
        )
        .await;
        assert!(matches!(
            result,
            Err(crate::error::MsalError::OperationCancelled)
        ));
        assert_eq!(started.elapsed(), GRACE);
    }

    #[tokio::test(start_paused = true)]
    async fn failed_cancel_still_waits_for_the_operation_then_surfaces() {
        let token = crate::request::CancellationToken::new();
        token.cancel();
        let finished = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let operation = {
            let finished = finished.clone();
            async move {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                finished.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(42)
            }
        };
        let result = await_with_cancellation(
            operation,
            || {
                Err(crate::error::MsalError::AuthenticationFailed(
                    "Cancel failed".into(),
                ))
            },
            Some(&token),
            GRACE,
        )
        .await;
        assert!(matches!(
            result,
            Err(crate::error::MsalError::AuthenticationFailed(_))
        ));
        assert!(finished.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[tokio::test]
    async fn cancel_wins_ready_result_race_and_terminal_errors_surface() {
        let token = crate::request::CancellationToken::new();
        token.cancel();
        assert!(matches!(
            await_with_cancellation(async { Ok(42) }, || Ok(()), Some(&token), GRACE).await,
            Err(crate::error::MsalError::OperationCancelled)
        ));
        assert!(matches!(
            await_with_cancellation(
                async {
                    Err::<(), _>(crate::error::MsalError::AuthenticationFailed(
                        "native".into(),
                    ))
                },
                || Ok(()),
                Some(&token),
                GRACE
            )
            .await,
            Err(crate::error::MsalError::AuthenticationFailed(_))
        ));
        assert_eq!(
            await_with_cancellation(async { Ok(7) }, || Ok(()), None, GRACE)
                .await
                .unwrap(),
            7
        );
    }
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    fn native_account(claims: serde_json::Value) -> Result<AccountInfo> {
        let jwt = format!(
            "e30.{}.native",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
        );
        let info = URL_SAFE_NO_PAD.encode(br#"{"uid":"home-user","utid":"home-tenant"}"#);
        account_from_native_response(
            "client",
            "https://login.microsoftonline.com/resource-tenant",
            &jwt,
            &info,
        )
    }

    fn claims() -> serde_json::Value {
        serde_json::json!({
            "aud": "client", "tid": "resource-tenant", "oid": "guest-object",
            "iss": "https://login.microsoftonline.com/resource-tenant/v2.0"
        })
    }

    #[test]
    fn native_guest_keeps_home_and_resource_identity_distinct() {
        let account = native_account(claims()).unwrap();
        assert_eq!(account.home_account_id, "home-user.home-tenant");
        assert_eq!(account.tenant_id, "resource-tenant");
        assert_eq!(account.local_account_id, "guest-object");
    }

    #[test]
    fn native_identity_rejects_missing_tenant_audience_issuer_and_local_id() {
        for field in ["tid", "aud", "iss", "oid"] {
            let mut claims = claims();
            claims.as_object_mut().unwrap().remove(field);
            assert!(native_account(claims).is_err(), "{field}");
        }
        for (field, value) in [
            ("aud", "other-client"),
            ("iss", "https://evil.example/resource-tenant/v2.0"),
            ("iss", "https://login.microsoftonline.com/other-tenant/v2.0"),
            ("oid", ""),
        ] {
            let mut claims = claims();
            claims[field] = value.into();
            assert!(native_account(claims).is_err());
        }
    }

    #[test]
    fn domain_name_tenant_authority_accepts_its_tenant_guid() {
        let tid = "11111111-1111-4111-8111-111111111111";
        let mut value = claims();
        value["tid"] = tid.into();
        value["iss"] = format!("https://login.microsoftonline.com/{tid}/v2.0").into();
        let jwt = format!(
            "e30.{}.native",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&value).unwrap())
        );
        let info = URL_SAFE_NO_PAD.encode(br#"{"uid":"home-user","utid":"home-tenant"}"#);
        let account = account_from_native_response(
            "client",
            "https://login.microsoftonline.com/contoso.onmicrosoft.com",
            &jwt,
            &info,
        )
        .unwrap();
        assert_eq!(account.tenant_id, tid);
        // A different GUID tenant is still rejected.
        assert!(account_from_native_response(
            "client",
            "https://login.microsoftonline.com/22222222-2222-4222-8222-222222222222",
            &jwt,
            &info,
        )
        .is_err());
    }

    #[test]
    fn exact_identity_includes_resource_tenant_and_local_id() {
        let account = native_account(claims()).unwrap();
        let mut other = account.clone();
        other.tenant_id = "home-tenant".into();
        assert!(!same_account(&account, &other));
        other = account.clone();
        other.local_account_id = "different-object".into();
        assert!(!same_account(&account, &other));
    }

    #[test]
    fn preflight_requires_complete_identity_and_honest_cancellation() {
        let mut request = BrokerTokenRequest {
            scopes: vec!["user.read".into()],
            account: Some(native_account(claims()).unwrap()),
            claims: Some(r#"{"access_token":{}}"#.into()),
            force_refresh: false,
            authority: None,
            extra_query_parameters: Default::default(),
            cancellation_token: None,
            correlation_id: None,
            window_handle: None,
            authentication_scheme: Default::default(),
            pop_params: None,
        };
        assert!(validate_request(&request).is_ok());
        request.account.as_mut().unwrap().tenant_id.clear();
        assert!(validate_request(&request).is_err());
        let token = crate::request::CancellationToken::new();
        request.cancellation_token = Some(token.clone());
        assert!(matches!(
            validate_request(&request),
            Err(crate::error::MsalError::Unsupported(_))
        ));
        token.cancel();
        assert!(matches!(
            validate_request(&request),
            Err(crate::error::MsalError::OperationCancelled)
        ));
    }
}
