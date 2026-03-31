//! HTTP client and token endpoint communication.
//!
//! This module is internal to the crate. It builds the [`reqwest::Client`]
//! from [`HttpConfig`](crate::config::HttpConfig) and provides a helper
//! for form-encoded POST requests to OAuth 2.0 token endpoints.

use std::time::Duration;

use crate::config::HttpConfig;
use crate::error::{MsalError, Result};

/// Build a [`reqwest::Client`] configured from MSAL HTTP settings.
pub fn build_http_client(config: &HttpConfig) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder().timeout(Duration::from_millis(config.timeout_ms));

    if let Some(ref proxy_url) = config.proxy {
        let proxy = reqwest::Proxy::all(proxy_url)
            .map_err(|e| MsalError::InvalidConfiguration(format!("invalid proxy: {e}")))?;
        builder = builder.proxy(proxy);
    }

    builder
        .build()
        .map_err(|e| MsalError::InvalidConfiguration(format!("failed to build HTTP client: {e}")))
}

/// POST a form-encoded request to a token endpoint and return the JSON body.
///
/// Handles OAuth 2.0 error responses by mapping them to the appropriate
/// [`MsalError`] variant.
pub async fn post_token_request(
    http: &reqwest::Client,
    url: &str,
    params: &[(&str, &str)],
) -> Result<serde_json::Value> {
    let resp = http.post(url).form(params).send().await?;

    let status = resp.status();
    let body: serde_json::Value = resp.json().await?;

    if !status.is_success() {
        let error = body["error"].as_str().unwrap_or("unknown").to_string();
        let description = body["error_description"]
            .as_str()
            .unwrap_or("no description")
            .to_string();
        let correlation_id = body["correlation_id"].as_str().map(String::from);
        let claims = body["claims"].as_str().map(String::from);
        let suberror = body["suberror"].as_str().map(String::from);

        if error == "authorization_pending" {
            return Err(MsalError::AuthorizationPending);
        }
        if error == "expired_token" || description.contains("expired") {
            return Err(MsalError::DeviceCodeExpired);
        }
        if error == "interaction_required"
            || error == "consent_required"
            || error == "login_required"
        {
            return Err(MsalError::InteractionRequired(description));
        }

        return Err(MsalError::ServerError {
            error,
            description,
            correlation_id,
            claims,
            suberror,
        });
    }

    Ok(body)
}
