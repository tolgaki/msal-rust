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
        window_handle: None, // Console root owner; GUI: Some((hwnd as isize).to_le_bytes().to_vec()).
        authentication_scheme: AuthenticationScheme::Bearer,
        pop_params: None,
        force_refresh: false,
        authority: None,
        extra_query_parameters: Default::default(),
        cancellation_token: None,
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
                    extra_query_parameters: Default::default(),
                    cancellation_token: None,
                };
                let silent_result = app.acquire_token_silent(silent_request).await?;
                println!("Silent token: {}...", &silent_result.access_token[..20]);
            }
        }
        Err(e) => {
            eprintln!("Interactive auth failed: {e}");
            // Do not silently discard broker-only or claims/session guarantees.
            return Err(e.into());
        }
    }

    Ok(())
}
