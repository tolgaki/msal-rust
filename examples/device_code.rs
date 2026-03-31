use msal::request::DeviceCodeRequest;
use msal::{Configuration, PublicClientApplication};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Configuration::builder("YOUR_CLIENT_ID")
        .authority("https://login.microsoftonline.com/common")
        .build();

    let app = PublicClientApplication::new(config)?;

    let request = DeviceCodeRequest {
        scopes: vec!["user.read".into()],
        claims: None,
        correlation_id: None,
    };

    let result = app
        .acquire_token_by_device_code(request, |info| {
            println!("{}", info.message);
            println!("Go to: {}", info.verification_uri);
            println!("Enter code: {}", info.user_code);
        })
        .await?;

    println!("Access token: {}...", &result.access_token[..20]);

    if let Some(account) = &result.account {
        println!("Signed in as: {}", account.username);
    }

    Ok(())
}
