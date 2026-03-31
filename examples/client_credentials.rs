use msal::request::ClientCredentialRequest;
use msal::{ConfidentialClientApplication, Configuration};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Configuration::builder("YOUR_CLIENT_ID")
        .authority("https://login.microsoftonline.com/YOUR_TENANT_ID")
        .client_secret("YOUR_CLIENT_SECRET")
        .build();

    let app = ConfidentialClientApplication::new(config)?;

    let request = ClientCredentialRequest::new(vec!["https://graph.microsoft.com/.default".into()]);

    let result = app.acquire_token_by_client_credential(request).await?;

    println!("Access token: {}...", &result.access_token[..20]);
    println!("Expires on: {}", result.expires_on);

    Ok(())
}
