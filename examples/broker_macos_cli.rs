type ExampleResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

#[cfg(all(target_os = "macos", feature = "broker-macos"))]
fn main() -> ExampleResult {
    use msal::broker::macos::{run_main_loop_until, MacOsBroker};
    use msal::broker::{BrokerTokenRequest, NativeBroker};
    use msal::{Configuration, PublicClientApplication};

    let client_id = std::env::var("MSAL_CLIENT_ID")
        .map_err(|_| msal::MsalError::MissingParameter("MSAL_CLIENT_ID".into()))?;
    let authority = std::env::var("MSAL_AUTHORITY")
        .map_err(|_| msal::MsalError::MissingParameter("MSAL_AUTHORITY".into()))?;
    // Availability checks must happen on the real main thread, before Tokio.
    let broker = MacOsBroker::new_for_cli(&authority)?;
    if !broker.is_available() {
        return Err(msal::MsalError::Unsupported(
            "Microsoft Enterprise SSO extension is unavailable".into(),
        )
        .into());
    }
    let worker = std::thread::spawn(move || -> ExampleResult {
        let runtime = tokio::runtime::Runtime::new().map_err(|error| {
            msal::MsalError::AuthenticationFailed(format!("Tokio runtime: {error}"))
        })?;
        runtime.block_on(async {
            let application = PublicClientApplication::new(
                Configuration::builder(client_id)
                    .authority(authority)
                    .build(),
            )?;
            application.set_broker(Box::new(broker)).await;
            let result = application
                .acquire_token_interactive(BrokerTokenRequest {
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
                })
                .await?;
            println!("Acquired a broker token; expires at {}.", result.expires_on);
            Ok(())
        })
    });
    // Do not block_on/join on the main thread before pumping native callbacks.
    run_main_loop_until(|| worker.is_finished())?;
    worker
        .join()
        .map_err(|_| msal::MsalError::AuthenticationFailed("broker worker panicked".into()))?
}

#[cfg(not(all(target_os = "macos", feature = "broker-macos")))]
fn main() -> ExampleResult {
    Err(msal::MsalError::Unsupported(
        "run this example on macOS with --features broker-macos".into(),
    )
    .into())
}
