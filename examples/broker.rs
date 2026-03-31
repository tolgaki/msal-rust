use msal::broker::{AuthenticationScheme, BrokerTokenRequest};
use msal::{Configuration, PublicClientApplication};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Configuration::builder("YOUR_CLIENT_ID")
        .authority("https://login.microsoftonline.com/YOUR_TENANT_ID")
        .build();

    let app = PublicClientApplication::new(config)?;

    // Set up the native broker (Windows WAM).
    // On non-Windows platforms, the broker won't be available and
    // acquire_token_interactive will return an error suggesting
    // alternative flows.
    #[cfg(all(target_os = "windows", feature = "broker-wam"))]
    {
        let broker = msal::broker::wam::WamBroker::new().await?;
        app.set_broker(Box::new(broker)).await;
    }

    println!("Broker available: {}", app.is_broker_available().await);

    // Interactive token acquisition via broker.
    let request = BrokerTokenRequest {
        scopes: vec!["user.read".into()],
        account: None,
        claims: None,
        correlation_id: None,
        window_handle: None, // None for console apps; pass HWND bytes for GUI apps.
        authentication_scheme: AuthenticationScheme::Bearer,
        pop_params: None,
    };

    match app.acquire_token_interactive(request).await {
        Ok(result) => {
            println!("Access token: {}...", &result.access_token[..20]);
            if let Some(account) = &result.account {
                println!("Signed in as: {}", account.username);

                // Subsequent calls can use silent flow (broker manages refresh).
                let silent_request = msal::request::SilentFlowRequest {
                    scopes: vec!["user.read".into()],
                    account: account.clone(),
                    force_refresh: false,
                    claims: None,
                    correlation_id: None,
                };
                let silent_result = app.acquire_token_silent(silent_request).await?;
                println!("Silent token: {}...", &silent_result.access_token[..20]);
            }
        }
        Err(e) => {
            eprintln!("Interactive auth failed: {e}");
            eprintln!("Falling back to device code flow...");

            // Manual fallback to device code.
            let dc_request = msal::request::DeviceCodeRequest {
                scopes: vec!["user.read".into()],
                claims: None,
                correlation_id: None,
            };
            let result = app
                .acquire_token_by_device_code(dc_request, |info| {
                    println!("{}", info.message);
                })
                .await?;
            println!("Access token: {}...", &result.access_token[..20]);
        }
    }

    Ok(())
}
