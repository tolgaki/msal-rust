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

use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;

use objc2::rc::Retained;
use objc2::runtime::ProtocolObject;
use objc2::{define_class, msg_send, AnyThread, DefinedClass, MainThreadOnly};
use objc2_authentication_services::{
    ASAuthorization, ASAuthorizationController, ASAuthorizationControllerDelegate,
    ASAuthorizationSingleSignOnCredential, ASAuthorizationSingleSignOnProvider,
};
use objc2_foundation::{
    MainThreadMarker, NSArray, NSHTTPURLResponse, NSObject, NSObjectProtocol, NSString,
    NSURLQueryItem, NSURL,
};

use crate::account::AccountInfo;
use crate::broker::{BrokerSignOutRequest, BrokerTokenRequest, NativeBroker};
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
        let available = MainThreadMarker::new().map_or(true, |_mtm| {
            let ns_url_str = NSString::from_str(MS_SSO_URL);
            NSURL::URLWithString(&ns_url_str)
                .map(|url| {
                    let provider = unsafe {
                        ASAuthorizationSingleSignOnProvider::authorizationProviderWithIdentityProviderURL(&url)
                    };
                    unsafe { provider.canPerformAuthorization() }
                })
                .unwrap_or(false)
        });

        Ok(Self {
            available,
            redirect_uri: redirect_uri.into(),
            authority: authority.into(),
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
            let result = execute_sso_on_main_thread(params, tx);
            if let Err(e) = result {
                eprintln!("msal: SSO setup error: {e}");
            }
        });

        rx.await.map_err(|_| {
            MsalError::AuthenticationFailed("SSO broker delegate channel dropped".into())
        })?
    }
}

/// Plain-data parameters for an SSO request (Send-safe, no ObjC objects).
struct SsoRequestParams {
    client_id: String,
    redirect_uri: String,
    authority: String,
    scopes: String,
    operation: String,
    interactive: bool,
    account_id: Option<String>,
    correlation_id: String,
}

/// Runs entirely on the main thread. Creates all ObjC objects, sets up
/// delegate, and starts the authorization controller.
fn execute_sso_on_main_thread(
    params: SsoRequestParams,
    tx: tokio::sync::oneshot::Sender<Result<AuthenticationResult>>,
) -> std::result::Result<(), MsalError> {
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

    // Create request.
    let request = unsafe { provider.createRequest() };

    let op = NSString::from_str(&params.operation);
    unsafe { request.setRequestedOperation(&op) };
    unsafe { request.setUserInterfaceEnabled(params.interactive) };

    // Build query items — redirect_uri and authority are required by the
    // SSO extension to match the request to the Azure app registration.
    let mut kv_pairs: Vec<(&str, &str)> = vec![
        ("client_id", &params.client_id),
        ("redirect_uri", &params.redirect_uri),
        ("authority", &params.authority),
        ("scope", &params.scopes),
        ("correlation_id", &params.correlation_id),
        ("msg_protocol_ver", "4"),
        ("provider_type", "provider_aad_v2"),
    ];
    let acct_id_ref;
    if let Some(ref id) = params.account_id {
        acct_id_ref = id.as_str();
        kv_pairs.push(("account_identifier", acct_id_ref));
    }

    let query_items: Vec<Retained<NSURLQueryItem>> = kv_pairs
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

    // Create delegate (must be MainThreadOnly, created here on main thread).
    let delegate = SsoDelegate::new(tx);
    let delegate_proto: &ProtocolObject<dyn ASAuthorizationControllerDelegate> =
        ProtocolObject::from_ref(&*delegate);
    unsafe { controller.setDelegate(Some(delegate_proto)) };

    // Start the flow.
    unsafe { controller.performRequests() };

    // Controller and delegate must survive until callback fires.
    std::mem::forget(controller);
    std::mem::forget(delegate);

    Ok(())
}

/// Run the main thread's CFRunLoop until `done` returns `true`.
///
/// Interactive broker flows require AppKit event processing. In a CLI app,
/// call this from the main thread after starting the broker request to pump
/// events until the result arrives.
///
/// ```no_run
/// # #[cfg(all(target_os = "macos", feature = "broker-macos"))]
/// # fn example() {
/// use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
/// use msal::broker::macos::run_main_loop_until;
///
/// let done = Arc::new(AtomicBool::new(false));
/// let done2 = done.clone();
///
/// // Spawn async work that sets done=true when the broker responds...
/// // Then pump the run loop on the main thread:
/// run_main_loop_until(|| done2.load(Ordering::Relaxed));
/// # }
/// ```
pub fn run_main_loop_until(done: impl Fn() -> bool) {
    let run_loop = objc2_foundation::NSRunLoop::currentRunLoop();
    let distant_future = objc2_foundation::NSDate::distantFuture();
    while !done() {
        run_loop.runMode_beforeDate(
            unsafe { objc2_foundation::NSDefaultRunLoopMode },
            &distant_future,
        );
    }
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
            let account = request.account.as_ref().ok_or_else(|| {
                MsalError::MissingParameter("account is required for silent broker flow".into())
            })?;

            let params = SsoRequestParams {
                client_id: client_id.to_string(),
                redirect_uri: self.redirect_uri.clone(),
                authority: self.authority.clone(),
                scopes: request.scopes.join(" "),
                operation: "refresh".to_string(),
                interactive: false,
                account_id: Some(account.home_account_id.clone()),
                correlation_id: request
                    .correlation_id
                    .clone()
                    .unwrap_or_else(crate::crypto::generate_correlation_id),
            };

            self.perform_request(params).await
        })
    }

    fn acquire_token_interactive<'a>(
        &'a self,
        client_id: &'a str,
        request: &'a BrokerTokenRequest,
    ) -> Pin<Box<dyn Future<Output = Result<AuthenticationResult>> + Send + 'a>> {
        Box::pin(async move {
            let params = SsoRequestParams {
                client_id: client_id.to_string(),
                redirect_uri: self.redirect_uri.clone(),
                authority: self.authority.clone(),
                scopes: request.scopes.join(" "),
                operation: "login".to_string(),
                interactive: true,
                account_id: request.account.as_ref().map(|a| a.home_account_id.clone()),
                correlation_id: request
                    .correlation_id
                    .clone()
                    .unwrap_or_else(crate::crypto::generate_correlation_id),
            };

            self.perform_request(params).await
        })
    }

    fn sign_out<'a>(
        &'a self,
        _client_id: &'a str,
        _request: &'a BrokerSignOutRequest,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            // The macOS SSO extension does not expose a sign-out API.
            // Sign-out is handled by clearing the local cache.
            Ok(())
        })
    }

    fn all_accounts<'a>(
        &'a self,
        _client_id: &'a str,
        _correlation_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<AccountInfo>>> + Send + 'a>> {
        Box::pin(async move { Ok(Vec::new()) })
    }

    fn account<'a>(
        &'a self,
        _account_id: &'a str,
        _correlation_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<AccountInfo>> + Send + 'a>> {
        Box::pin(async move {
            Err(MsalError::AuthenticationFailed(
                "macOS SSO extension does not support account lookup; \
                 use acquire_token_silent with an account from cache"
                    .into(),
            ))
        })
    }
}

// ── Delegate ────────────────────────────────────────────────────────────

struct SsoDelegateIvars {
    sender: Mutex<Option<tokio::sync::oneshot::Sender<Result<AuthenticationResult>>>>,
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
            let result = parse_authorization(authorization);
            self.send_result(result);
        }

        #[unsafe(method(authorizationController:didCompleteWithError:))]
        fn did_complete_with_error(
            &self,
            _controller: &ASAuthorizationController,
            error: &objc2_foundation::NSError,
        ) {
            let code = error.code();
            let description = error.localizedDescription().to_string();

            // ASAuthorizationError codes:
            //   1000 = canceled, 1001 = failed, 1002 = invalidResponse,
            //   1003 = notHandled, 1004 = notInteractive
            // Negative codes (e.g., -6000) come from the SSO extension itself.
            let err = if code == 1000 {
                MsalError::UserCancelled
            } else if code == 1004 {
                MsalError::InteractionRequired(description)
            } else {
                MsalError::AuthenticationFailed(format!("SSO error ({code}): {description}"))
            };

            self.send_result(Err(err));
        }
    }
);

impl SsoDelegate {
    fn new(sender: tokio::sync::oneshot::Sender<Result<AuthenticationResult>>) -> Retained<Self> {
        let mtm = MainThreadMarker::new().expect("SsoDelegate must be created on main thread");
        let this = Self::alloc(mtm).set_ivars(SsoDelegateIvars {
            sender: Mutex::new(Some(sender)),
        });
        unsafe { msg_send![super(this), init] }
    }

    fn send_result(&self, result: Result<AuthenticationResult>) {
        if let Some(sender) = self.ivars().sender.lock().unwrap().take() {
            let _ = sender.send(result);
        }
    }
}

// ── Response parsing ────────────────────────────────────────────────────

fn parse_authorization(authorization: &ASAuthorization) -> Result<AuthenticationResult> {
    let raw_credential = unsafe { authorization.credential() };
    let credential: Retained<ASAuthorizationSingleSignOnCredential> =
        unsafe { Retained::cast_unchecked(raw_credential) };

    let http_response: Retained<NSHTTPURLResponse> = unsafe { credential.authenticatedResponse() }
        .ok_or_else(|| {
            MsalError::AuthenticationFailed("no authenticatedResponse in SSO credential".into())
        })?;

    // Extract headers into a JSON map.
    let headers: Retained<objc2_foundation::NSDictionary> =
        unsafe { msg_send![&http_response, allHeaderFields] };

    let mut json_map = serde_json::Map::new();
    unsafe {
        let keys: Retained<NSArray<NSString>> = msg_send![&headers, allKeys];
        let count = keys.count();
        for i in 0..count {
            let key: &NSString = &keys.objectAtIndex(i);
            let value: Retained<NSString> = msg_send![&headers, objectForKey: key];
            json_map.insert(
                key.to_string(),
                serde_json::Value::String(value.to_string()),
            );
        }
    }

    let body = serde_json::Value::Object(json_map);

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
        .unwrap_or(3600);

    let scopes: Vec<String> = body["scope"]
        .as_str()
        .unwrap_or_default()
        .split_whitespace()
        .map(String::from)
        .collect();

    let now = chrono::Utc::now().timestamp();
    let account = build_account_from_response(&body);

    Ok(AuthenticationResult {
        access_token,
        id_token,
        scopes,
        expires_on: now + expires_in,
        ext_expires_on: None,
        account,
        tenant_id: body["tenant_id"].as_str().map(String::from),
        correlation_id: body["correlation_id"].as_str().map(String::from),
        token_type: body["token_type"].as_str().unwrap_or("Bearer").to_string(),
        refresh_token: None,
    })
}

fn build_account_from_response(body: &serde_json::Value) -> Option<AccountInfo> {
    let client_info_str = body["client_info"].as_str()?;
    let client_info = crate::account::ClientInfo::from_base64(client_info_str).ok()?;
    let id_token = body["id_token"].as_str()?;
    let claims = crate::crypto::decode_jwt_payload(id_token).ok()?;

    Some(AccountInfo {
        home_account_id: client_info.home_account_id(),
        local_account_id: claims["oid"]
            .as_str()
            .or_else(|| claims["sub"].as_str())
            .unwrap_or_default()
            .to_string(),
        environment: crate::account::AAD_PUBLIC_CLOUD_ENVIRONMENT.into(),
        tenant_id: claims["tid"].as_str().unwrap_or_default().to_string(),
        username: claims["preferred_username"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        name: claims["name"].as_str().map(String::from),
        id_token_claims: Some(claims),
    })
}
