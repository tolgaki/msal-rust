//! Pure serialization for Microsoft's typed Enterprise SSO account operations.
//! Source revision and transport contracts are documented in README.md.

use std::collections::BTreeMap;

use crate::account::AccountInfo;
use crate::error::{MsalError, Result};

#[cfg(all(target_os = "macos", feature = "broker-macos"))]
pub(super) const GET_ACCOUNTS: &str = "get_accounts_operation";
pub(super) fn get_accounts_query(
    client_id: &str,
    correlation_id: &str,
) -> Result<BTreeMap<String, String>> {
    if client_id.trim().is_empty() {
        return Err(MsalError::InvalidConfiguration(
            "SSO client ID is empty".into(),
        ));
    }
    Ok(BTreeMap::from([
        ("client_id".into(), client_id.into()),
        ("correlation_id".into(), correlation_id.into()),
        ("msg_protocol_ver".into(), "4".into()),
        ("signed_in_accounts_only".into(), "1".into()),
    ]))
}

fn validate_accounts_response(body: &serde_json::Value) -> Result<()> {
    if body["operation_response_type"].as_str() != Some("operation_get_accounts_response") {
        return Err(MsalError::AuthenticationFailed(
            "unexpected SSO operation response type".into(),
        ));
    }
    if !matches!(body["success"].as_str(), Some("1" | "true"))
        && body["success"] != serde_json::Value::Bool(true)
        && body["success"] != serde_json::json!(1)
    {
        return Err(MsalError::AuthenticationFailed(
            "SSO operation did not report success".into(),
        ));
    }
    Ok(())
}

pub(super) fn parse_accounts(body: &serde_json::Value) -> Result<Vec<AccountInfo>> {
    validate_accounts_response(body)?;
    // MSIDBrokerOperationGetAccountsResponse serializes an array *inside* a
    // string header. Missing/corrupt data is not a successful empty account list.
    let raw = body["accounts"]
        .as_str()
        .ok_or_else(|| MsalError::AuthenticationFailed("missing SSO accounts string".into()))?;
    let values: Vec<serde_json::Value> = serde_json::from_str(raw)
        .map_err(|_| MsalError::AuthenticationFailed("invalid SSO accounts array".into()))?;
    let mut accounts = BTreeMap::new();
    for value in values {
        let identity = |key: &str| -> Result<String> {
            value[key]
                .as_str()
                .filter(|value| !value.trim().is_empty())
                .map(String::from)
                .ok_or_else(|| {
                    MsalError::AuthenticationFailed(format!("missing SSO account {key}"))
                })
        };
        let environment = crate::authority::canonical_environment(&identity("environment")?);
        let account = AccountInfo {
            home_account_id: identity("home_account_id")?,
            local_account_id: identity("local_account_id")?,
            tenant_id: identity("realm")?,
            environment,
            username: value["username"].as_str().unwrap_or_default().into(),
            name: value["name"].as_str().map(String::from),
            id_token_claims: value
                .get("id_token_claims")
                .filter(|claims| claims.is_object())
                .cloned(),
        };
        if let Some(info) = value["client_info"].as_str() {
            if crate::account::ClientInfo::from_base64(info)?.home_account_id()
                != account.home_account_id
            {
                return Err(MsalError::AuthenticationFailed(
                    "SSO account client_info mismatch".into(),
                ));
            }
        }
        // The native cache can hold one identity under several environment
        // aliases (login.windows.net, login.microsoftonline.com). After
        // canonicalization these are the same complete identity: keep the first
        // instead of failing the whole enumeration.
        accounts.entry(account.cache_key()).or_insert(account);
    }
    Ok(accounts.into_values().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guest() -> AccountInfo {
        AccountInfo {
            home_account_id: "home-user.home-tenant".into(),
            local_account_id: "guest-object".into(),
            tenant_id: "resource-tenant".into(),
            environment: crate::account::AAD_PUBLIC_CLOUD_ENVIRONMENT.into(),
            username: String::new(),
            name: None,
            id_token_claims: None,
        }
    }

    fn response() -> serde_json::Value {
        serde_json::json!({
            "operation_response_type": "operation_get_accounts_response", "success": "1",
            "accounts": serde_json::json!([{
                "home_account_id": "home-user.home-tenant", "local_account_id": "guest-object",
                "realm": "resource-tenant", "environment": "login.windows.net",
                "username": "display-only"
            }]).to_string(),
        })
    }

    #[test]
    fn typed_queries_do_not_invent_token_or_device_wipe_options() {
        let query = get_accounts_query("client", "correlation").unwrap();
        assert_eq!(query["signed_in_accounts_only"], "1");
        assert!(!query.contains_key("scope"));
        assert!(!query.contains_key("broker_key"));
        for key in [
            "wipe_account",
            "wipe_cache_all_accounts",
            "signout_from_browser",
            "clear_sso_extension_cookies",
        ] {
            assert!(!query.contains_key(key));
        }
        assert!(!query.contains_key("username"));
        assert!(get_accounts_query("", "correlation").is_err());
    }

    #[test]
    fn native_account_metadata_keeps_complete_guest_identity() {
        let accounts = parse_accounts(&response()).unwrap();
        assert!(accounts[0].same_identity(&guest()));
        assert_eq!(accounts[0].username, "display-only");
        let mut body = response();
        body["accounts"] = "[]".into();
        assert!(parse_accounts(&body).unwrap().is_empty());
    }

    #[test]
    fn same_identity_under_environment_aliases_is_listed_once() {
        let mut body = response();
        body["accounts"] = serde_json::json!([
            {
                "home_account_id": "home-user.home-tenant", "local_account_id": "guest-object",
                "realm": "resource-tenant", "environment": "login.windows.net",
                "username": "first"
            },
            {
                "home_account_id": "home-user.home-tenant", "local_account_id": "guest-object",
                "realm": "resource-tenant", "environment": "login.microsoftonline.com",
                "username": "second"
            },
            {
                "home_account_id": "home-user.home-tenant", "local_account_id": "home-object",
                "realm": "home-tenant", "environment": "login.microsoftonline.com"
            }
        ])
        .to_string()
        .into();
        let accounts = parse_accounts(&body).unwrap();
        assert_eq!(accounts.len(), 2);
        assert!(accounts
            .iter()
            .any(|account| account.same_identity(&guest())));
    }

    #[test]
    fn corrupt_partial_wrong_type_and_failed_responses_are_not_empty_success() {
        for (key, value) in [
            ("accounts", serde_json::Value::Null),
            ("accounts", "not json".into()),
            ("accounts", "null".into()),
            ("success", "0".into()),
            (
                "operation_response_type",
                "operation_generic_response".into(),
            ),
        ] {
            let mut body = response();
            body[key] = value;
            assert!(parse_accounts(&body).is_err(), "{key}");
        }
        for key in [
            "home_account_id",
            "local_account_id",
            "realm",
            "environment",
        ] {
            let mut body = response();
            let mut accounts: serde_json::Value =
                serde_json::from_str(body["accounts"].as_str().unwrap()).unwrap();
            accounts[0].as_object_mut().unwrap().remove(key);
            body["accounts"] = accounts.to_string().into();
            assert!(parse_accounts(&body).is_err(), "{key}");
        }
        let mut body = response();
        body["accounts"] = serde_json::json!([{
            "home_account_id": "home-user.home-tenant", "local_account_id": "guest-object",
            "realm": "resource-tenant", "environment": "login.windows.net",
            "client_info": base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD,
                br#"{"uid":"another","utid":"home-tenant"}"#),
        }])
        .to_string()
        .into();
        assert!(parse_accounts(&body).is_err());
    }
}
