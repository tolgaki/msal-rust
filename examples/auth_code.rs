use msal::request::AuthorizationCodeRequest;
use msal::{Configuration, PublicClientApplication};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Configuration::builder("YOUR_CLIENT_ID")
        .authority("https://login.microsoftonline.com/common")
        .build();

    let app = PublicClientApplication::new(config)?;

    // Step 1: Get the authorization URL (send user to this URL).
    let (auth_url, pkce) = app
        .get_authorization_url(
            vec!["user.read".into()],
            "http://localhost:3000/redirect",
            None,
        )
        .await?;

    println!("Open this URL in a browser:\n{auth_url}\n");

    // Step 2: After the user authenticates, exchange the code.
    // In a real app, you'd extract the code from the redirect callback.
    let code = "PASTE_AUTH_CODE_HERE";

    let request = AuthorizationCodeRequest {
        code: code.into(),
        scopes: vec!["user.read".into()],
        redirect_uri: "http://localhost:3000/redirect".into(),
        code_verifier: Some(pkce.verifier),
        claims: None,
        correlation_id: None,
    };

    let result = app.acquire_token_by_code(request).await?;

    println!("Access token: {}...", &result.access_token[..20]);

    if let Some(account) = &result.account {
        println!("Signed in as: {}", account.username);

        // Step 3: Later, acquire tokens silently.
        let silent_request = msal::request::SilentFlowRequest {
            scopes: vec!["user.read".into()],
            account: account.clone(),
            force_refresh: false,
            claims: None,
            correlation_id: None,
        };

        let cached = app.acquire_token_silent(silent_request).await?;
        println!("Cached token: {}...", &cached.access_token[..20]);
    }

    Ok(())
}
