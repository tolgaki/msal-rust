use msal::request::{AuthorizationCodeRequest, SilentFlowRequest};
use msal::{Configuration, PublicClientApplication};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Configuration::builder("YOUR_CLIENT_ID")
        .authority("https://login.microsoftonline.com/common")
        .build();

    let app = PublicClientApplication::new(config)?;

    // Step 1: Get the authorization URL (send user to this URL).
    let scopes = vec!["user.read".into()];
    let (auth_url, pkce) =
        app.authorization_url(&scopes, "http://localhost:3000/redirect", None)?;

    println!("Open this URL in a browser:\n{auth_url}\n");

    // Step 2: After the user authenticates, exchange the code.
    let code = "PASTE_AUTH_CODE_HERE";
    let mut request = AuthorizationCodeRequest::new(
        code.into(),
        scopes.clone(),
        "http://localhost:3000/redirect".into(),
    );
    request.code_verifier = Some(pkce.verifier);

    let result = app.acquire_token_by_code(request).await?;

    println!("Access token: {}...", &result.access_token[..20]);

    if let Some(account) = &result.account {
        println!("Signed in as: {}", account.username);

        // Step 3: Later, acquire tokens silently.
        let silent = SilentFlowRequest::new(scopes, account.clone());
        let cached = app.acquire_token_silent(silent).await?;
        println!("Cached token: {}...", &cached.access_token[..20]);
    }

    Ok(())
}
