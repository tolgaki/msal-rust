//! macOS Enterprise SSO broker implementation.
//!
//! This module provides brokered authentication through Apple's
//! `ASAuthorizationSingleSignOnProvider` API and the Microsoft Enterprise SSO
//! plug-in (delivered via Intune Company Portal on macOS).
//!
//! # Requirements
//!
//! - macOS 13.0+ (Ventura)
//! - Microsoft Intune Company Portal installed and MDM-configured
//! - The SSO extension must be deployed via MDM profile
//!
//! # Redirect URI
//!
//! The redirect URI must be registered in your Entra ID app registration
//! under the **iOS/macOS** platform:
//!
//! | App type | Redirect URI | Bundle ID |
//! |----------|-------------|-----------|
//! | `.app` bundle | `msauth.{bundle_id}://auth` | Your bundle ID |
//! | **Unsigned CLI** | `msauth.com.msauth.unsignedapp://auth` | `com.msauth.unsignedapp` |
//!
//! **Important**: Signed-but-not-bundled executables (e.g., `codesign`-ed CLI
//! binaries) are currently **blocked** by the broker. Either ship unsigned
//! or wrap in a `.app` bundle.
//!
//! # CLI usage
//!
//! For CLI tools, use the convenience constructor [`MacOsBroker::new_for_cli`]
//! which sets the correct unsigned-app redirect URI. Interactive broker flows
//! require a running CFRunLoop on the main thread — call
//! [`run_main_loop_until`] to pump AppKit events while waiting for the broker
//! dialog.
//!
//! ```no_run
//! # #[cfg(all(target_os = "macos", feature = "broker-macos"))]
//! # fn example() -> Result<(), msal::MsalError> {
//! use msal::broker::macos::MacOsBroker;
//!
//! let broker = MacOsBroker::new_for_cli(
//!     "https://login.microsoftonline.com/your-tenant-id",
//! )?;
//! # Ok(())
//! # }
//! ```
//!
//! # Feature flag
//!
//! Enable with the `broker-macos` feature:
//! ```toml
//! msal = { version = "0.1", features = ["broker-macos"] }
//! ```
//!
//! # Threading
//!
//! `ASAuthorizationController` must run on the main thread. This broker
//! dispatches to the main thread internally via Grand Central Dispatch and
//! bridges back to async via oneshot channels. Callers can `.await` from
//! any thread. For interactive flows in CLI apps, the main thread must be
//! running a CFRunLoop (see [`run_main_loop_until`]).
//!
//! Construction checks extension availability on the main thread. This adapter
//! maps claims, `force_refresh` and form-encoded `extra_query_param` using
//! Microsoft's `MSIDBrokerOperationTokenRequest` protocol. Enumeration and
//! sign-out currently return `Unsupported`: the extension has typed operations,
//! but this adapter does not yet implement their identity/removal contracts.
//! In-flight cancellation and explicit presentation anchors are also unsupported.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;

use objc2::rc::Retained;
use objc2::runtime::ProtocolObject;
use objc2::{define_class, msg_send, AnyThread, ClassType, DefinedClass, MainThreadOnly};
use objc2_authentication_services::{
    ASAuthorization, ASAuthorizationController, ASAuthorizationControllerDelegate,
    ASAuthorizationError, ASAuthorizationErrorDomain, ASAuthorizationSingleSignOnCredential,
    ASAuthorizationSingleSignOnProvider,
};
use objc2_foundation::{
    MainThreadMarker, NSArray, NSHTTPURLResponse, NSObject, NSObjectProtocol, NSString,
    NSURLQueryItem, NSUnderlyingErrorKey, NSURL,
};

use crate::account::AccountInfo;
use crate::broker::{
    account_from_native_response, same_account, validate_request, BrokerSignOutRequest,
    BrokerTokenRequest, NativeBroker,
};
use crate::error::{MsalError, Result};
use crate::response::AuthenticationResult;

/// The identity provider URL for the Microsoft SSO extension.
const MS_SSO_URL: &str = "https://login.microsoftonline.com/common";

/// Redirect URI for unsigned CLI executables.
///
/// Register this in your Entra ID app registration under the iOS/macOS
/// platform with bundle ID `com.msauth.unsignedapp`.
pub const CLI_REDIRECT_URI: &str = "msauth.com.msauth.unsignedapp://auth";

/// macOS Enterprise SSO broker.
///
/// Uses Apple's `ASAuthorizationSingleSignOnProvider` to communicate with the
/// Microsoft Enterprise SSO plug-in installed via Company Portal.
///
/// All ObjC objects are created on the main thread at request time. Only
/// plain Rust data is stored in the struct.
pub struct MacOsBroker {
    available: bool,
    redirect_uri: String,
    authority: String,
}

impl MacOsBroker {
    /// Create a new macOS SSO broker.
    ///
    /// `redirect_uri` is required by the SSO extension to match the request
    /// to your Azure app registration. Use the format `msauth.{bundle_id}://auth`
    /// for `.app` bundles, or [`CLI_REDIRECT_URI`] for unsigned CLI tools.
    ///
    /// `authority` is the Azure AD authority URL
    /// (e.g. `https://login.microsoftonline.com/common`).
    pub fn new(redirect_uri: impl Into<String>, authority: impl Into<String>) -> Result<Self> {
        let authority = authority.into();
        validate_authority(&authority)?;
        let _mtm = MainThreadMarker::new().ok_or_else(|| {
            MsalError::Unsupported(
                "construct the macOS broker on the main thread to check SSO availability".into(),
            )
        })?;
        let available = {
            let ns_url_str = NSString::from_str(MS_SSO_URL);
            NSURL::URLWithString(&ns_url_str)
                .map(|url| {
                    let provider = unsafe {
                        ASAuthorizationSingleSignOnProvider::authorizationProviderWithIdentityProviderURL(&url)
                    };
                    unsafe { provider.canPerformAuthorization() }
                })
                .unwrap_or(false)
        };

        Ok(Self {
            available,
            redirect_uri: redirect_uri.into(),
            authority,
        })
    }

    /// Create a broker for an unsigned CLI tool.
    ///
    /// Uses the special `msauth.com.msauth.unsignedapp://auth` redirect URI
    /// that the broker accepts for unsigned executables. You must register
    /// this redirect URI in your Entra ID app registration under the
    /// iOS/macOS platform with bundle ID `com.msauth.unsignedapp`.
    ///
    /// **Note**: Code-signed (but not `.app`-bundled) executables are currently
    /// blocked by the broker. Ship the CLI unsigned or use ad-hoc signing only.
    pub fn new_for_cli(authority: impl Into<String>) -> Result<Self> {
        Self::new(CLI_REDIRECT_URI, authority)
    }

    /// Execute an SSO request on the main thread, returning the result via oneshot.
    async fn perform_request(&self, params: SsoRequestParams) -> Result<AuthenticationResult> {
        let (tx, rx) = tokio::sync::oneshot::channel::<Result<AuthenticationResult>>();

        // All ObjC work happens on the main thread.
        dispatch2::DispatchQueue::main().exec_async(move || {
            execute_sso_on_main_thread(params, tx);
        });

        rx.await.map_err(|_| {
            MsalError::AuthenticationFailed("SSO broker delegate channel dropped".into())
        })?
    }
}

/// Plain-data parameters for an SSO request (Send-safe, no ObjC objects).
#[derive(Clone)]
struct SsoRequestParams {
    client_id: String,
    redirect_uri: String,
    authority: String,
    scopes: String,
    operation: String,
    interactive: bool,
    account: Option<AccountInfo>,
    correlation_id: String,
    claims: Option<String>,
    force_refresh: bool,
    extra_query_parameters: BTreeMap<String, String>,
}

fn validate_authority(authority: &str) -> Result<url::Url> {
    let url = url::Url::parse(authority)
        .map_err(|_| MsalError::InvalidConfiguration("invalid broker authority".into()))?;
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
            "invalid broker authority".into(),
        ));
    }
    Ok(url)
}

impl SsoRequestParams {
    fn query_parameters(&self) -> Result<BTreeMap<String, String>> {
        let authority = validate_authority(&self.authority)?;
        crate::request::validate_extra_query_parameters(&self.extra_query_parameters)?;
        let mut query = BTreeMap::from([
            ("client_id".into(), self.client_id.clone()),
            ("redirect_uri".into(), self.redirect_uri.clone()),
            ("authority".into(), self.authority.clone()),
            ("scope".into(), self.scopes.clone()),
            ("correlation_id".into(), self.correlation_id.clone()),
            ("msg_protocol_ver".into(), "4".into()),
            ("provider_type".into(), "provider_aad_v2".into()),
            (
                "force_refresh".into(),
                if self.force_refresh { "1" } else { "0" }.into(),
            ),
        ]);
        if let Some(account) = &self.account {
            crate::broker::validate_account_identity(account)?;
            let host = authority.host_str().unwrap_or_default();
            let public_alias = matches!(host, "login.microsoftonline.com" | "login.windows.net");
            if !host.eq_ignore_ascii_case(&account.environment)
                && !(public_alias
                    && account.environment == crate::account::AAD_PUBLIC_CLOUD_ENVIRONMENT)
            {
                return Err(MsalError::InvalidConfiguration(
                    "selected account environment differs from SSO authority".into(),
                ));
            }
            let tenant = authority.path().trim_matches('/');
            if matches!(tenant, "common" | "organizations" | "consumers") {
                let mut tenanted_authority = authority.clone();
                tenanted_authority.set_path(&format!("/{}", account.tenant_id));
                query.insert("authority".into(), tenanted_authority.into());
            } else if uuid::Uuid::parse_str(tenant).is_ok()
                && !tenant.eq_ignore_ascii_case(&account.tenant_id)
            {
                // A domain-name tenant cannot be compared with the account's
                // tenant GUID here; the client validates the returned tenant.
                return Err(MsalError::InvalidConfiguration(
                    "selected account resource tenant differs from SSO authority".into(),
                ));
            }
            // MSIDAccountIdentifier serializes home_account_id, not account_identifier.
            query.insert("home_account_id".into(), account.home_account_id.clone());
        }
        if let Some(claims) = &self.claims {
            query.insert("claims".into(), claims.clone());
        }
        if !self.extra_query_parameters.is_empty() {
            // MSIDBrokerOperationTokenRequest uses a single WWW-form-encoded value.
            let mut serializer = url::form_urlencoded::Serializer::new(String::new());
            for (key, value) in &self.extra_query_parameters {
                serializer.append_pair(key, value);
            }
            query.insert("extra_query_param".into(), serializer.finish());
        }
        Ok(query)
    }
}

type ActiveSsoRequests =
    BTreeMap<String, (Retained<ASAuthorizationController>, Retained<SsoDelegate>)>;

thread_local! {
    // AuthenticationServices' delegate is weak. Retain both objects until callback,
    // not forever. All access, including callback cleanup, is on the main thread.
    static ACTIVE_REQUESTS: RefCell<ActiveSsoRequests> =
        const { RefCell::new(BTreeMap::new()) };
}

/// Runs entirely on the main thread. Creates all ObjC objects, sets up
/// delegate, and starts the authorization controller.
fn execute_sso_on_main_thread(
    params: SsoRequestParams,
    tx: tokio::sync::oneshot::Sender<Result<AuthenticationResult>>,
) {
    let delegate = SsoDelegate::new(tx, params.clone());
    if let Err(error) = start_sso_on_main_thread(&params, &delegate) {
        delegate.send_result(Err(error));
    }
}

fn start_sso_on_main_thread(
    params: &SsoRequestParams,
    delegate: &Retained<SsoDelegate>,
) -> Result<()> {
    let _mtm = MainThreadMarker::new()
        .ok_or_else(|| MsalError::AuthenticationFailed("SSO must run on main thread".into()))?;

    // Create provider.
    let ns_url_str = NSString::from_str(MS_SSO_URL);
    let url = NSURL::URLWithString(&ns_url_str).ok_or_else(|| {
        MsalError::AuthenticationFailed("failed to create SSO provider URL".into())
    })?;
    let provider = unsafe {
        ASAuthorizationSingleSignOnProvider::authorizationProviderWithIdentityProviderURL(&url)
    };
    if !unsafe { provider.canPerformAuthorization() } {
        return Err(MsalError::Unsupported(
            "Microsoft SSO extension is unavailable".into(),
        ));
    }

    // Create request.
    let request = unsafe { provider.createRequest() };

    let op = NSString::from_str(&params.operation);
    unsafe { request.setRequestedOperation(&op) };
    unsafe { request.setUserInterfaceEnabled(params.interactive) };

    let query_items: Vec<Retained<NSURLQueryItem>> = params
        .query_parameters()?
        .iter()
        .map(|(k, v)| {
            let name = NSString::from_str(k);
            let value = NSString::from_str(v);
            NSURLQueryItem::initWithName_value(NSURLQueryItem::alloc(), &name, Some(&value))
        })
        .collect();

    let options = NSArray::from_retained_slice(&query_items);
    unsafe { request.setAuthorizationOptions(&options) };

    // Upcast to ASAuthorizationRequest.
    let auth_request: Retained<objc2_authentication_services::ASAuthorizationRequest> =
        unsafe { Retained::cast_unchecked(request) };
    let requests = NSArray::from_retained_slice(&[auth_request]);

    // Create controller.
    let controller = unsafe {
        ASAuthorizationController::initWithAuthorizationRequests(
            ASAuthorizationController::alloc(),
            &requests,
        )
    };

    let delegate_proto: &ProtocolObject<dyn ASAuthorizationControllerDelegate> =
        ProtocolObject::from_ref(&**delegate);
    unsafe { controller.setDelegate(Some(delegate_proto)) };

    ACTIVE_REQUESTS.with(|requests| {
        requests.borrow_mut().insert(
            delegate.ivars().request_id.clone(),
            (controller.clone(), delegate.clone()),
        );
    });
    // Start the flow.
    unsafe { controller.performRequests() };

    Ok(())
}

/// Run the main thread's CFRunLoop until `done` returns `true`.
///
/// Interactive broker flows require AppKit event processing. In a CLI app,
/// call this from the main thread after starting the broker request to pump
/// events until the result arrives.
///
/// The 50ms run-loop deadline only rechecks `done`; it is not an authentication
/// timeout. Returning from this helper does not cancel an outstanding native UI
/// request. Normally `done` should become true after the broker result arrives.
///
/// ```no_run
/// # #[cfg(all(target_os = "macos", feature = "broker-macos"))]
/// # fn example() -> Result<(), msal::MsalError> {
/// use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
/// use msal::broker::macos::run_main_loop_until;
///
/// let done = Arc::new(AtomicBool::new(false));
/// let done2 = done.clone();
///
/// // Spawn async work that sets done=true when the broker responds...
/// // Then pump the run loop on the main thread:
/// run_main_loop_until(|| done2.load(Ordering::Relaxed))?;
/// # Ok(())
/// # }
/// ```
pub fn run_main_loop_until(done: impl Fn() -> bool) -> Result<()> {
    let _mtm = MainThreadMarker::new().ok_or_else(|| {
        MsalError::Unsupported("the SSO run loop must be pumped on the main thread".into())
    })?;
    let run_loop = objc2_foundation::NSRunLoop::currentRunLoop();
    while !done() {
        // A finite deadline rechecks completion even when no AppKit event wakes us.
        let deadline = objc2_foundation::NSDate::dateWithTimeIntervalSinceNow(0.05);
        if !run_loop
            .runMode_beforeDate(unsafe { objc2_foundation::NSDefaultRunLoopMode }, &deadline)
        {
            // A mode without sources may return immediately rather than waiting.
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
    Ok(())
}

impl NativeBroker for MacOsBroker {
    fn is_available(&self) -> bool {
        self.available
    }

    fn acquire_token_silent<'a>(
        &'a self,
        client_id: &'a str,
        request: &'a BrokerTokenRequest,
    ) -> Pin<Box<dyn Future<Output = Result<AuthenticationResult>> + Send + 'a>> {
        Box::pin(async move {
            validate_request(request)?;
            if request.window_handle.is_some() {
                return Err(MsalError::Unsupported(
                    "this macOS adapter does not implement a presentation anchor".into(),
                ));
            }
            let account = request.account.as_ref().ok_or_else(|| {
                MsalError::MissingParameter("account is required for silent broker flow".into())
            })?;

            let params = SsoRequestParams {
                client_id: client_id.to_string(),
                redirect_uri: self.redirect_uri.clone(),
                authority: request
                    .authority
                    .clone()
                    .unwrap_or_else(|| self.authority.clone()),
                scopes: crate::request::user_scopes(&request.scopes).join(" "),
                operation: "refresh".to_string(),
                interactive: false,
                account: Some(account.clone()),
                correlation_id: request
                    .correlation_id
                    .clone()
                    .unwrap_or_else(crate::crypto::generate_correlation_id),
                claims: request.claims.clone(),
                force_refresh: request.force_refresh,
                extra_query_parameters: request.extra_query_parameters.clone(),
            };

            params.query_parameters()?;
            self.perform_request(params).await
        })
    }

    fn acquire_token_interactive<'a>(
        &'a self,
        client_id: &'a str,
        request: &'a BrokerTokenRequest,
    ) -> Pin<Box<dyn Future<Output = Result<AuthenticationResult>> + Send + 'a>> {
        Box::pin(async move {
            validate_request(request)?;
            if request.window_handle.is_some() {
                return Err(MsalError::Unsupported(
                    "this macOS adapter does not implement a presentation anchor".into(),
                ));
            }
            let params = SsoRequestParams {
                client_id: client_id.to_string(),
                redirect_uri: self.redirect_uri.clone(),
                authority: request
                    .authority
                    .clone()
                    .unwrap_or_else(|| self.authority.clone()),
                scopes: crate::request::user_scopes(&request.scopes).join(" "),
                operation: "login".to_string(),
                interactive: true,
                account: request.account.clone(),
                correlation_id: request
                    .correlation_id
                    .clone()
                    .unwrap_or_else(crate::crypto::generate_correlation_id),
                claims: request.claims.clone(),
                force_refresh: request.force_refresh,
                extra_query_parameters: request.extra_query_parameters.clone(),
            };

            params.query_parameters()?;
            self.perform_request(params).await
        })
    }

    fn sign_out<'a>(
        &'a self,
        _client_id: &'a str,
        _request: &'a BrokerSignOutRequest,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            Err(MsalError::Unsupported(
                "this macOS adapter does not implement the typed signout_account_operation \
                 contract; local cache removal is not native sign-out"
                    .into(),
            ))
        })
    }

    fn all_accounts<'a>(
        &'a self,
        _client_id: &'a str,
        _correlation_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<AccountInfo>>> + Send + 'a>> {
        Box::pin(async move {
            Err(MsalError::Unsupported(
                "this macOS adapter does not implement typed get_accounts_operation responses; \
                 it cannot report the native account list"
                    .into(),
            ))
        })
    }

    fn account<'a>(
        &'a self,
        _account_id: &'a str,
        _correlation_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<AccountInfo>> + Send + 'a>> {
        Box::pin(async move {
            Err(MsalError::Unsupported(
                "macOS account lookup by home ID alone is ambiguous; \
                 use a complete account from a trusted token response"
                    .into(),
            ))
        })
    }
}

// ── Delegate ────────────────────────────────────────────────────────────

struct SsoDelegateIvars {
    sender: Mutex<Option<tokio::sync::oneshot::Sender<Result<AuthenticationResult>>>>,
    request_id: String,
    params: SsoRequestParams,
}

define_class!(
    // SAFETY: NSObject has no subclassing requirements, we don't impl Drop.
    #[unsafe(super = NSObject)]
    #[thread_kind = MainThreadOnly]
    #[ivars = SsoDelegateIvars]
    struct SsoDelegate;

    unsafe impl NSObjectProtocol for SsoDelegate {}

    // SAFETY: We implement the delegate methods with correct signatures.
    unsafe impl ASAuthorizationControllerDelegate for SsoDelegate {
        #[unsafe(method(authorizationController:didCompleteWithAuthorization:))]
        fn did_complete_with_authorization(
            &self,
            _controller: &ASAuthorizationController,
            authorization: &ASAuthorization,
        ) {
            let _active = ACTIVE_REQUESTS
                .with(|requests| requests.borrow().get(&self.ivars().request_id).cloned());
            let result = parse_authorization(authorization, &self.ivars().params);
            self.send_result(result);
        }

        #[unsafe(method(authorizationController:didCompleteWithError:))]
        fn did_complete_with_error(
            &self,
            _controller: &ASAuthorizationController,
            error: &objc2_foundation::NSError,
        ) {
            let _active = ACTIVE_REQUESTS
                .with(|requests| requests.borrow().get(&self.ivars().request_id).cloned());
            self.send_result(Err(parse_native_error(error, &self.ivars().params, 0)));
        }
    }
);

impl SsoDelegate {
    fn new(
        sender: tokio::sync::oneshot::Sender<Result<AuthenticationResult>>,
        params: SsoRequestParams,
    ) -> Retained<Self> {
        let mtm = MainThreadMarker::new().expect("SsoDelegate must be created on main thread");
        let this = Self::alloc(mtm).set_ivars(SsoDelegateIvars {
            sender: Mutex::new(Some(sender)),
            request_id: crate::crypto::generate_correlation_id(),
            params,
        });
        unsafe { msg_send![super(this), init] }
    }

    fn send_result(&self, result: Result<AuthenticationResult>) {
        // Keep the removed controller/delegate alive through this callback.
        let _retained =
            ACTIVE_REQUESTS.with(|requests| requests.borrow_mut().remove(&self.ivars().request_id));
        if let Some(sender) = self.ivars().sender.lock().unwrap().take() {
            let _ = sender.send(result);
        }
    }
}

// ── Response parsing ────────────────────────────────────────────────────

fn parse_authorization(
    authorization: &ASAuthorization,
    params: &SsoRequestParams,
) -> Result<AuthenticationResult> {
    let raw_credential = unsafe { authorization.credential() };
    let correct_type: bool = unsafe {
        msg_send![&*raw_credential, isKindOfClass: ASAuthorizationSingleSignOnCredential::class()]
    };
    if !correct_type {
        return Err(MsalError::AuthenticationFailed(
            "unexpected SSO credential type".into(),
        ));
    }
    let credential: Retained<ASAuthorizationSingleSignOnCredential> =
        unsafe { Retained::cast_unchecked(raw_credential) };

    let http_response: Retained<NSHTTPURLResponse> = unsafe { credential.authenticatedResponse() }
        .ok_or_else(|| {
            MsalError::AuthenticationFailed("no authenticatedResponse in SSO credential".into())
        })?;

    // Extract headers into a JSON map.
    let headers = http_response.allHeaderFields();
    let mut json_map = serde_json::Map::new();
    for key in headers.allKeys().iter() {
        let key_string = key.downcast_ref::<NSString>().ok_or_else(|| {
            MsalError::AuthenticationFailed("SSO response header name is not a string".into())
        })?;
        let value = headers.objectForKey(&key).ok_or_else(|| {
            MsalError::AuthenticationFailed("missing SSO response header value".into())
        })?;
        let value_string = value.downcast_ref::<NSString>().ok_or_else(|| {
            MsalError::AuthenticationFailed("SSO response header value is not a string".into())
        })?;
        json_map.insert(
            key_string.to_string(),
            serde_json::Value::String(value_string.to_string()),
        );
    }

    parse_token_body(&serde_json::Value::Object(json_map), params)
}

fn oauth_error(error: &str, body: &serde_json::Value, params: &SsoRequestParams) -> MsalError {
    let description = body["error_description"]
        .as_str()
        .unwrap_or("SSO provider error")
        .into();
    let correlation_id = body["correlation_id"]
        .as_str()
        .map(String::from)
        .or_else(|| Some(params.correlation_id.clone()));
    let claims = body["claims"].as_str().map(String::from);
    let suberror = body["suberror"].as_str().map(String::from);
    if matches!(
        error,
        "interaction_required" | "login_required" | "consent_required"
    ) || claims.is_some()
    {
        MsalError::InteractionRequiredWithClaims {
            error: error.into(),
            description,
            correlation_id,
            claims,
            suberror,
        }
    } else {
        MsalError::ServerError {
            error: error.into(),
            description,
            correlation_id,
            claims,
            suberror,
        }
    }
}

fn parse_native_error(
    error: &objc2_foundation::NSError,
    params: &SsoRequestParams,
    depth: usize,
) -> MsalError {
    let info = error.userInfo();
    let apple_error =
        error.domain().to_string() == unsafe { ASAuthorizationErrorDomain }.to_string();
    // Microsoft wraps extension errors (-6000) in NSUnderlyingErrorKey.
    if apple_error && error.code() == -6000 && depth < 8 {
        if let Some(underlying) = info.objectForKey(unsafe { NSUnderlyingErrorKey }) {
            if let Some(underlying) = underlying.downcast_ref::<objc2_foundation::NSError>() {
                return parse_native_error(underlying, params, depth + 1);
            }
        }
    }
    if apple_error && error.code() == ASAuthorizationError::Canceled.0 {
        return MsalError::UserCancelled;
    }
    let string = |key: &str| {
        info.objectForKey(&NSString::from_str(key))
            .and_then(|value| value.downcast_ref::<NSString>().map(ToString::to_string))
    };
    // MSID preserves a (possibly truncated) HTTP JSON response in this official key.
    // Recover challenges when present, but never fabricate claims from the request.
    if let Some(raw) = string("MSIDHTTPResponseStringKey") {
        if let Ok(body) = serde_json::from_str::<serde_json::Value>(&raw) {
            if let Some(error) = body["error"].as_str() {
                return oauth_error(error, &body, params);
            }
        }
    }
    let description = error.localizedDescription().to_string();
    let mut body = serde_json::json!({
        "error_description": description,
        "correlation_id": params.correlation_id,
    });
    if let Some(claims) = string("claims") {
        body["claims"] = claims.into();
    }
    if let Some(suberror) = string("MSIDOAuthSubErrorKey") {
        body["suberror"] = suberror.into();
    }
    if let Some(oauth) = string("MSIDOAuthErrorKey") {
        return oauth_error(&oauth, &body, params);
    }
    if (apple_error && error.code() == ASAuthorizationError::NotInteractive.0)
        || (error.domain().to_string() == "MSIDErrorDomain" && error.code() == -51115)
        || body["claims"].is_string()
    {
        return oauth_error("interaction_required", &body, params);
    }
    MsalError::AuthenticationFailed(format!("SSO error ({}): {description}", error.code()))
}

fn parse_token_body(
    body: &serde_json::Value,
    params: &SsoRequestParams,
) -> Result<AuthenticationResult> {
    if let Some(error) = body["error"].as_str() {
        return Err(oauth_error(error, body, params));
    }
    let access_token = body["access_token"]
        .as_str()
        .unwrap_or_default()
        .to_string();

    if access_token.is_empty() {
        return Err(MsalError::AuthenticationFailed(
            "no access_token in SSO response".into(),
        ));
    }

    let id_token = body["id_token"].as_str().map(String::from);
    let expires_in: i64 = body["expires_in"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .or_else(|| body["expires_in"].as_i64())
        .filter(|seconds| *seconds > 0)
        .ok_or_else(|| {
            // Assuming a lifetime would let the local cache serve an expired token.
            MsalError::AuthenticationFailed("missing or invalid expires_in in SSO response".into())
        })?;

    let scopes: Vec<String> = body["scope"]
        .as_str()
        .unwrap_or_default()
        .split_whitespace()
        .map(String::from)
        .collect();

    let now = chrono::Utc::now().timestamp();
    let account = build_account_from_response(body, params)?;
    if params
        .account
        .as_ref()
        .is_some_and(|selected| !same_account(selected, &account))
    {
        return Err(MsalError::AuthenticationFailed(
            "SSO returned a different account than requested".into(),
        ));
    }

    Ok(AuthenticationResult {
        access_token,
        id_token,
        scopes,
        expires_on: now + expires_in,
        ext_expires_on: None,
        tenant_id: Some(account.tenant_id.clone()),
        account: Some(account),
        correlation_id: body["correlation_id"].as_str().map(String::from),
        token_type: body["token_type"].as_str().unwrap_or("Bearer").to_string(),
        refresh_token: None,
    })
}

fn build_account_from_response(
    body: &serde_json::Value,
    params: &SsoRequestParams,
) -> Result<AccountInfo> {
    let missing = || MsalError::AuthenticationFailed("missing SSO account identity".into());
    account_from_native_response(
        &params.client_id,
        &params.authority,
        body["id_token"].as_str().ok_or_else(missing)?,
        body["client_info"].as_str().ok_or_else(missing)?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> SsoRequestParams {
        SsoRequestParams {
            client_id: "client".into(),
            redirect_uri: CLI_REDIRECT_URI.into(),
            authority: "https://login.microsoftonline.com/resource-tenant".into(),
            scopes: "user.read".into(),
            operation: "refresh".into(),
            interactive: false,
            account: None,
            correlation_id: "correlation".into(),
            claims: None,
            force_refresh: false,
            extra_query_parameters: Default::default(),
        }
    }

    #[test]
    fn native_query_preserves_claims_refresh_and_encoded_eqp() {
        let mut params = params();
        params.force_refresh = true;
        params.claims = Some(r#"{"access_token":{"x":{"essential":true}}}"#.into());
        params
            .extra_query_parameters
            .insert("client_session".into(), "a+b & c".into());
        let query = params.query_parameters().unwrap();
        assert_eq!(query["claims"], params.claims.unwrap());
        assert_eq!(query["force_refresh"], "1");
        let decoded: BTreeMap<_, _> =
            url::form_urlencoded::parse(query["extra_query_param"].as_bytes())
                .into_owned()
                .collect();
        assert_eq!(decoded, params.extra_query_parameters);
        assert!(!query.contains_key("client_session"));
    }

    #[test]
    fn sso_error_preserves_claims_without_requiring_an_access_token() {
        let body = serde_json::json!({
            "error": "interaction_required", "error_description": "MFA",
            "claims": "{\"access_token\":{}}", "suberror": "basic_action"
        });
        match parse_token_body(&body, &params()).unwrap_err() {
            MsalError::InteractionRequiredWithClaims {
                claims, suberror, ..
            } => {
                assert_eq!(claims.as_deref(), Some("{\"access_token\":{}}"));
                assert_eq!(suberror.as_deref(), Some("basic_action"));
            }
            error => panic!("unexpected error: {error}"),
        }
    }

    #[test]
    fn native_guest_selection_uses_home_id_and_resource_authority() {
        let mut params = params();
        params.authority = MS_SSO_URL.into();
        params.account = Some(AccountInfo {
            home_account_id: "home-user.home-tenant".into(),
            local_account_id: "guest-object".into(),
            tenant_id: "resource-tenant".into(),
            environment: crate::account::AAD_PUBLIC_CLOUD_ENVIRONMENT.into(),
            username: String::new(),
            name: None,
            id_token_claims: None,
        });
        let query = params.query_parameters().unwrap();
        assert_eq!(query["home_account_id"], "home-user.home-tenant");
        assert_eq!(
            query["authority"],
            "https://login.microsoftonline.com/resource-tenant"
        );
        assert!(!query.contains_key("account_identifier"));
    }

    #[test]
    fn native_response_rejects_every_selected_account_identity_mismatch() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        let mut params = params();
        let claims = serde_json::json!({
            "aud": "client", "tid": "resource-tenant", "oid": "guest-object",
            "iss": "https://login.microsoftonline.com/resource-tenant/v2.0"
        });
        let body = serde_json::json!({
            "access_token": "native-token",
            "expires_in": 3600,
            "id_token": format!("e30.{}.native", URL_SAFE_NO_PAD.encode(
                serde_json::to_vec(&claims).unwrap(),
            )),
            "client_info": URL_SAFE_NO_PAD.encode(br#"{"uid":"home-user","utid":"home-tenant"}"#),
        });
        let returned = build_account_from_response(&body, &params).unwrap();
        params.account = Some(returned.clone());
        assert!(parse_token_body(&body, &params).is_ok());
        for field in ["home", "local", "tenant", "environment"] {
            let mut other = returned.clone();
            match field {
                "home" => other.home_account_id = "other-user.home-tenant".into(),
                "local" => other.local_account_id = "other-object".into(),
                "tenant" => other.tenant_id = "home-tenant".into(),
                _ => other.environment = "login.microsoftonline.us".into(),
            }
            params.account = Some(other);
            assert!(parse_token_body(&body, &params).is_err(), "{field}");
        }
    }
}
