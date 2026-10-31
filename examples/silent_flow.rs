//! Demonstrates the silent token acquisition pattern.
//!
//! In most apps, you first authenticate interactively (or via device code),
//! then use `acquire_token_silent` for subsequent calls. This avoids
//! prompting the user every time.
//!
//! Run with: `cargo run --example silent_flow`

use msal::request::{DeviceCodeRequest, SilentFlowRequest};
use msal::{Configuration, PublicClientApplication};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Configuration::builder("YOUR_CLIENT_ID")
        .authority("https://login.microsoftonline.com/common")
        .build();

    let app = PublicClientApplication::new(config)?;
    let scopes = vec!["user.read".into()];

    // Check if we already have a cached account.
    let accounts = app.all_accounts().await?;
    let result = if let Some(account) = accounts.first() {
        // Try silent first.
        let silent_request = SilentFlowRequest::new(scopes.clone(), account.clone());

        match app.acquire_token_silent(silent_request).await {
            Ok(result) => {
                println!("Got token silently (from cache or refresh)");
                result
            }
            Err(error) if error.is_interaction_required() => {
                println!("Silent failed, falling back to device code...");
                acquire_interactively(&app, &scopes, error.claims()).await?
            }
            Err(e) => return Err(e.into()),
        }
    } else {
        println!("No cached accounts, authenticating...");
        acquire_interactively(&app, &scopes, None).await?
    };

    println!(
        "Access token: {}...",
        &result.access_token[..20.min(result.access_token.len())]
    );
    if let Some(ref account) = result.account {
        println!("Account: {} ({})", account.username, account.tenant_id);
    }

    Ok(())
}

async fn acquire_interactively(
    app: &PublicClientApplication,
    scopes: &[String],
    claims: Option<&str>,
) -> Result<msal::AuthenticationResult, Box<dyn std::error::Error>> {
    let request = DeviceCodeRequest {
        scopes: scopes.to_vec(),
        claims: claims.map(String::from),
        correlation_id: None,
        extra_query_parameters: Default::default(),
        cancellation_token: None,
    };

    Ok(app
        .acquire_token_by_device_code(request, |info| {
            println!("\n{}\n", info.message);
        })
        .await?)
}
