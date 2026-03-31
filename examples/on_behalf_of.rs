//! Demonstrates the on-behalf-of (OBO) flow for middle-tier services.
//!
//! In this scenario, a web API receives a token from a frontend client
//! and exchanges it for a new token to call a downstream API.
//!
//! Run with: `cargo run --example on_behalf_of`

use msal::request::OnBehalfOfRequest;
use msal::{ConfidentialClientApplication, Configuration};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Configuration::builder("YOUR_MIDDLE_TIER_CLIENT_ID")
        .authority("https://login.microsoftonline.com/YOUR_TENANT_ID")
        .client_secret("YOUR_MIDDLE_TIER_SECRET")
        .build();

    let app = ConfidentialClientApplication::new(config)?;

    // The incoming access token from the frontend client.
    // In a real app, this comes from the Authorization header.
    let incoming_token = "eyJ...the-token-from-the-frontend...";

    let request = OnBehalfOfRequest::new(
        incoming_token.into(),
        vec!["https://graph.microsoft.com/User.Read".into()],
    );

    let result = app.acquire_token_on_behalf_of(request).await?;
    println!(
        "Downstream token: {}...",
        &result.access_token[..20.min(result.access_token.len())]
    );

    Ok(())
}
