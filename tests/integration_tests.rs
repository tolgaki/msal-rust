use msal::account::AccountInfo;
use msal::config::{ClientCredential, Configuration};
use msal::error::MsalError;
use msal::request::*;

// ── Configuration Tests ─────────────────────────────────────────────────

#[test]
fn config_builder_defaults() {
    let config = Configuration::builder("my-app").build();
    assert_eq!(config.auth.client_id, "my-app");
    assert_eq!(
        config.auth.authority,
        "https://login.microsoftonline.com/common"
    );
    assert!(config.auth.client_credential.is_none());
    assert!(config.auth.redirect_uri.is_none());
    assert!(!config.is_confidential());
    assert_eq!(config.http.timeout_ms, 30_000);
    assert!(config.http.proxy.is_none());
    assert!(config.cache.store_in_memory);
}

#[test]
fn config_builder_all_options() {
    let config = Configuration::builder("my-app")
        .authority("https://login.microsoftonline.com/my-tenant")
        .client_secret("my-secret")
        .redirect_uri("http://localhost:3000/redirect")
        .known_authorities(vec!["login.microsoftonline.com".into()])
        .timeout_ms(60_000)
        .proxy("http://proxy:8080")
        .build();

    assert_eq!(config.auth.client_id, "my-app");
    assert!(config.auth.authority.contains("my-tenant"));
    assert!(config.is_confidential());
    assert_eq!(
        config.auth.redirect_uri.as_deref(),
        Some("http://localhost:3000/redirect")
    );
    assert_eq!(config.auth.known_authorities.len(), 1);
    assert_eq!(config.http.timeout_ms, 60_000);
    assert_eq!(config.http.proxy.as_deref(), Some("http://proxy:8080"));
}

#[test]
fn config_builder_certificate_credential() {
    let config = Configuration::builder("my-app")
        .client_certificate(
            "-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----",
            "AABB",
        )
        .build();

    assert!(config.is_confidential());
    match config.auth.client_credential {
        Some(ClientCredential::Certificate { ref thumbprint, .. }) => {
            assert_eq!(thumbprint, "AABB");
        }
        _ => panic!("expected Certificate credential"),
    }
}

#[test]
fn config_builder_assertion_credential() {
    let config = Configuration::builder("my-app")
        .client_assertion("eyJhbGciOiJSUzI1NiJ9.payload.signature")
        .build();

    assert!(config.is_confidential());
    assert!(matches!(
        config.auth.client_credential,
        Some(ClientCredential::Assertion(_))
    ));
}

#[test]
fn config_build_validated_rejects_empty_client_id() {
    let result = Configuration::builder("").build_validated();
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        MsalError::InvalidConfiguration(_)
    ));
}

#[test]
fn config_build_validated_accepts_valid() {
    let result = Configuration::builder("valid-id").build_validated();
    assert!(result.is_ok());
}

// ── Client Construction Tests ───────────────────────────────────────────

#[test]
fn public_client_construction_succeeds() {
    let config = Configuration::builder("app-id").build();
    let app = msal::PublicClientApplication::new(config);
    assert!(app.is_ok());
}

#[test]
fn confidential_client_requires_credential() {
    let config = Configuration::builder("app-id").build();
    let result = msal::ConfidentialClientApplication::new(config);
    assert!(result.is_err());
    let err = result.err().unwrap();
    assert!(matches!(err, MsalError::InvalidConfiguration(_)));
}

#[test]
fn confidential_client_construction_with_secret() {
    let config = Configuration::builder("app-id")
        .client_secret("secret")
        .build();
    let app = msal::ConfidentialClientApplication::new(config);
    assert!(app.is_ok());
}

// ── Account Tests ───────────────────────────────────────────────────────

#[test]
fn account_cache_key() {
    let account = test_account();
    assert_eq!(account.cache_key(), "uid.utid-login.microsoftonline.com");
}

#[test]
fn account_serialization_roundtrip() {
    let account = test_account();
    let json = serde_json::to_string(&account).unwrap();
    let deserialized: AccountInfo = serde_json::from_str(&json).unwrap();
    assert_eq!(account, deserialized);
}

// ── Authority Tests ─────────────────────────────────────────────────────

#[test]
fn authority_aad_single_tenant() {
    let authority = msal::authority::Authority::from_url_no_discovery(
        "https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47",
    )
    .unwrap();

    assert_eq!(
        authority.authority_type,
        msal::authority::AuthorityType::Aad
    );
    assert_eq!(authority.tenant, "72f988bf-86f1-41af-91ab-2d7cd011db47");
    assert!(authority
        .token_endpoint
        .contains("72f988bf-86f1-41af-91ab-2d7cd011db47"));
    assert!(authority.token_endpoint.ends_with("/oauth2/v2.0/token"));
}

#[test]
fn authority_aad_common() {
    let authority = msal::authority::Authority::from_url_no_discovery(
        "https://login.microsoftonline.com/common",
    )
    .unwrap();
    assert_eq!(authority.tenant, "common");
}

#[test]
fn authority_b2c() {
    let authority = msal::authority::Authority::from_url_no_discovery(
        "https://contoso.b2clogin.com/contoso.onmicrosoft.com/B2C_1_signupsignin",
    )
    .unwrap();
    assert_eq!(
        authority.authority_type,
        msal::authority::AuthorityType::AadB2C
    );
}

#[test]
fn authority_adfs() {
    let authority =
        msal::authority::Authority::from_url_no_discovery("https://adfs.contoso.com/adfs").unwrap();
    assert_eq!(
        authority.authority_type,
        msal::authority::AuthorityType::Adfs
    );
}

#[test]
fn authority_ciam() {
    let authority =
        msal::authority::Authority::from_url_no_discovery("https://contoso.ciamlogin.com/contoso")
            .unwrap();
    assert_eq!(
        authority.authority_type,
        msal::authority::AuthorityType::Ciam
    );
}

#[test]
fn authority_invalid_url() {
    let result = msal::authority::Authority::from_url_no_discovery("not a url at all");
    assert!(result.is_err());
}

// ── PKCE Tests ──────────────────────────────────────────────────────────

#[test]
fn pkce_generates_unique_values() {
    let pkce1 = msal::crypto::PkceParams::generate();
    let pkce2 = msal::crypto::PkceParams::generate();

    assert_ne!(pkce1.verifier, pkce2.verifier);
    assert_ne!(pkce1.challenge, pkce2.challenge);
    assert_eq!(pkce1.challenge_method, "S256");
    assert_eq!(pkce2.challenge_method, "S256");
}

#[test]
fn pkce_verifier_length() {
    let pkce = msal::crypto::PkceParams::generate();
    assert_eq!(pkce.verifier.len(), 43);
}

#[test]
fn pkce_challenge_is_base64url() {
    let pkce = msal::crypto::PkceParams::generate();
    // base64url uses - and _ instead of + and /
    assert!(!pkce.challenge.contains('+'));
    assert!(!pkce.challenge.contains('/'));
    assert!(!pkce.challenge.contains('='));
}

// ── JWT Decode Tests ────────────────────────────────────────────────────

#[test]
fn decode_jwt_payload_extracts_claims() {
    let payload = serde_json::json!({
        "sub": "user-123",
        "name": "Test User",
        "tid": "tenant-id",
        "oid": "object-id",
        "preferred_username": "user@example.com"
    });
    let token = build_test_jwt(&payload);
    let claims = msal::crypto::decode_jwt_payload(&token).unwrap();

    assert_eq!(claims["sub"], "user-123");
    assert_eq!(claims["name"], "Test User");
    assert_eq!(claims["tid"], "tenant-id");
    assert_eq!(claims["preferred_username"], "user@example.com");
}

#[test]
fn decode_jwt_payload_rejects_invalid() {
    assert!(msal::crypto::decode_jwt_payload("invalid").is_err());
    assert!(msal::crypto::decode_jwt_payload("a.b").is_err());
    assert!(msal::crypto::decode_jwt_payload("").is_err());
}

// ── Nonce / Correlation ID Tests ────────────────────────────────────────

#[test]
fn nonce_is_uuid_format() {
    let nonce = msal::crypto::generate_nonce();
    assert_eq!(nonce.len(), 36);
    assert_eq!(nonce.chars().filter(|&c| c == '-').count(), 4);
}

#[test]
fn correlation_id_is_unique() {
    let id1 = msal::crypto::generate_correlation_id();
    let id2 = msal::crypto::generate_correlation_id();
    assert_ne!(id1, id2);
}

// ── Token Cache Tests ───────────────────────────────────────────────────

#[test]
fn cache_save_and_lookup() {
    let cache = msal::cache::TokenCache::new();
    let account = test_account();
    let result = test_auth_result(&account);

    cache.save(&result);

    let scopes = vec!["user.read".into()];
    let cached = cache.lookup_access_token(&account, &scopes);
    assert!(cached.is_some());
    assert_eq!(cached.unwrap().access_token, "test-access-token");
}

#[test]
fn cache_scope_normalization() {
    let cache = msal::cache::TokenCache::new();
    let account = test_account();
    let result = test_auth_result(&account);

    cache.save(&result);

    // Lookup with different case should still match.
    let scopes = vec!["User.Read".into()];
    let cached = cache.lookup_access_token(&account, &scopes);
    assert!(cached.is_some());
}

#[test]
fn cache_expired_token_returns_none() {
    let cache = msal::cache::TokenCache::new();
    let account = test_account();
    let mut result = test_auth_result(&account);
    result.expires_on = chrono::Utc::now().timestamp() - 1;

    cache.save(&result);

    let scopes = vec!["user.read".into()];
    assert!(cache.lookup_access_token(&account, &scopes).is_none());
}

#[test]
fn cache_near_expiry_treated_as_expired() {
    let cache = msal::cache::TokenCache::new();
    let account = test_account();
    let mut result = test_auth_result(&account);
    // Expires in 4 minutes — within the 5-minute buffer.
    result.expires_on = chrono::Utc::now().timestamp() + 240;

    cache.save(&result);

    let scopes = vec!["user.read".into()];
    assert!(cache.lookup_access_token(&account, &scopes).is_none());
}

#[test]
fn cache_refresh_token_lookup() {
    let cache = msal::cache::TokenCache::new();
    let account = test_account();
    let result = test_auth_result(&account);

    cache.save(&result);

    let rt = cache.lookup_refresh_token(&account);
    assert_eq!(rt.as_deref(), Some("test-refresh-token"));
}

#[test]
fn cache_no_refresh_token_returns_none() {
    let cache = msal::cache::TokenCache::new();
    let account = test_account();
    let mut result = test_auth_result(&account);
    result.refresh_token = None;

    cache.save(&result);

    assert!(cache.lookup_refresh_token(&account).is_none());
}

#[test]
fn cache_all_accounts() {
    let cache = msal::cache::TokenCache::new();
    let account1 = test_account();
    let mut account2 = test_account();
    account2.home_account_id = "uid2.utid2".into();
    account2.username = "other@example.com".into();

    cache.save(&test_auth_result(&account1));
    cache.save(&test_auth_result(&account2));

    assert_eq!(cache.all_accounts().len(), 2);
}

#[test]
fn cache_remove_account() {
    let cache = msal::cache::TokenCache::new();
    let account = test_account();
    cache.save(&test_auth_result(&account));

    assert_eq!(cache.all_accounts().len(), 1);
    cache.remove_account(&account).unwrap();
    assert!(cache.all_accounts().is_empty());
    assert!(cache.lookup_refresh_token(&account).is_none());
    let scopes = vec!["user.read".into()];
    assert!(cache.lookup_access_token(&account, &scopes).is_none());
}

#[test]
fn cache_clear() {
    let cache = msal::cache::TokenCache::new();
    let account = test_account();
    cache.save(&test_auth_result(&account));

    cache.clear();
    assert!(cache.all_accounts().is_empty());
}

#[test]
fn cache_different_scopes_stored_separately() {
    let cache = msal::cache::TokenCache::new();
    let account = test_account();

    let mut result1 = test_auth_result(&account);
    result1.scopes = vec!["user.read".into()];
    result1.access_token = "token-for-user-read".into();

    let mut result2 = test_auth_result(&account);
    result2.scopes = vec!["mail.read".into()];
    result2.access_token = "token-for-mail-read".into();

    cache.save(&result1);
    cache.save(&result2);

    let cached1 = cache
        .lookup_access_token(&account, &["user.read".into()])
        .unwrap();
    assert_eq!(cached1.access_token, "token-for-user-read");

    let cached2 = cache
        .lookup_access_token(&account, &["mail.read".into()])
        .unwrap();
    assert_eq!(cached2.access_token, "token-for-mail-read");
}

// ── Client Info Tests ───────────────────────────────────────────────────

#[test]
fn client_info_decode() {
    use base64::Engine;
    let json = r#"{"uid":"abc","utid":"def"}"#;
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json);

    let info = msal::account::ClientInfo::from_base64(&encoded).unwrap();
    assert_eq!(info.uid, "abc");
    assert_eq!(info.utid, "def");
    assert_eq!(info.home_account_id(), "abc.def");
}

#[test]
fn client_info_invalid_base64() {
    let result = msal::account::ClientInfo::from_base64("!!!invalid!!!");
    assert!(result.is_err());
}

#[test]
fn client_info_invalid_json() {
    use base64::Engine;
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("not json");
    let result = msal::account::ClientInfo::from_base64(&encoded);
    assert!(result.is_err());
}

// ── Broker Types Tests ──────────────────────────────────────────────────

#[test]
fn broker_auth_scheme_default_is_bearer() {
    let scheme: msal::broker::AuthenticationScheme = Default::default();
    assert_eq!(scheme, msal::broker::AuthenticationScheme::Bearer);
}

#[test]
fn broker_token_request_construction() {
    let request = msal::broker::BrokerTokenRequest {
        scopes: vec!["user.read".into()],
        account: None,
        claims: None,
        correlation_id: None,
        window_handle: None,
        authentication_scheme: msal::broker::AuthenticationScheme::Pop,
        pop_params: Some(msal::broker::PopParams {
            resource_request_method: "GET".into(),
            resource_request_uri: "https://graph.microsoft.com/v1.0/me".into(),
            shr_nonce: None,
        }),
    };

    assert_eq!(request.scopes, vec!["user.read"]);
    assert_eq!(
        request.authentication_scheme,
        msal::broker::AuthenticationScheme::Pop
    );
    assert!(request.pop_params.is_some());
}

// ── Async Client Tests ──────────────────────────────────────────────────

#[tokio::test]
async fn public_client_get_all_accounts_empty() {
    let config = Configuration::builder("test-id").build();
    let app = msal::PublicClientApplication::new(config).unwrap();
    let accounts = app.get_all_accounts().await.unwrap();
    assert!(accounts.is_empty());
}

#[tokio::test]
async fn public_client_broker_not_available_by_default() {
    let config = Configuration::builder("test-id").build();
    let app = msal::PublicClientApplication::new(config).unwrap();
    assert!(!app.is_broker_available().await);
}

#[tokio::test]
async fn public_client_interactive_without_broker_errors() {
    let config = Configuration::builder("test-id").build();
    let app = msal::PublicClientApplication::new(config).unwrap();

    let request = msal::broker::BrokerTokenRequest {
        scopes: vec!["user.read".into()],
        account: None,
        claims: None,
        correlation_id: None,
        window_handle: None,
        authentication_scheme: Default::default(),
        pop_params: None,
    };

    let result = app.acquire_token_interactive(request).await;
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        MsalError::AuthenticationFailed(_)
    ));
}

#[tokio::test]
async fn public_client_silent_without_cache_errors() {
    let config = Configuration::builder("test-id").build();
    let app = msal::PublicClientApplication::new(config).unwrap();

    let request = SilentFlowRequest {
        scopes: vec!["user.read".into()],
        account: test_account(),
        force_refresh: false,
        claims: None,
        correlation_id: None,
    };

    let result = app.acquire_token_silent(request).await;
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        MsalError::InteractionRequired(_)
    ));
}

#[tokio::test]
async fn public_client_sign_out_without_broker_clears_cache() {
    let config = Configuration::builder("test-id").build();
    let app = msal::PublicClientApplication::new(config).unwrap();
    let account = test_account();

    // sign_out without broker should succeed (clears cache only).
    let result = app.sign_out(&account).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn public_client_authorization_url() {
    let config = Configuration::builder("test-client-id")
        .authority("https://login.microsoftonline.com/common")
        .build();
    let app = msal::PublicClientApplication::new(config).unwrap();

    let (url, pkce) = app
        .get_authorization_url(
            vec!["user.read".into(), "mail.read".into()],
            "http://localhost:3000/redirect",
            Some("my-state"),
        )
        .await
        .unwrap();

    assert!(url.contains("client_id=test-client-id"));
    assert!(url.contains("response_type=code"));
    assert!(url.contains("redirect_uri="));
    assert!(url.contains("code_challenge="));
    assert!(url.contains("code_challenge_method=S256"));
    assert!(url.contains("state=my-state"));
    assert!(url.contains("user.read"));
    assert!(!pkce.verifier.is_empty());
    assert!(!pkce.challenge.is_empty());
}

#[tokio::test]
async fn public_client_authorization_url_without_state() {
    let config = Configuration::builder("test-id").build();
    let app = msal::PublicClientApplication::new(config).unwrap();

    let (url, _) = app
        .get_authorization_url(vec!["user.read".into()], "http://localhost", None)
        .await
        .unwrap();

    assert!(!url.contains("state="));
}

// ── Error Display Tests ─────────────────────────────────────────────────

#[test]
fn error_display_authentication_failed() {
    let err = MsalError::AuthenticationFailed("bad token".into());
    assert_eq!(err.to_string(), "authentication failed: bad token");
}

#[test]
fn error_display_server_error() {
    let err = MsalError::ServerError {
        error: "invalid_grant".into(),
        description: "token expired".into(),
        correlation_id: Some("abc-123".into()),
        claims: None,
        suberror: None,
    };
    assert_eq!(
        err.to_string(),
        "server error [invalid_grant]: token expired"
    );
}

#[test]
fn error_display_interaction_required() {
    let err = MsalError::InteractionRequired("consent needed".into());
    assert_eq!(err.to_string(), "interaction required: consent needed");
}

#[test]
fn error_display_device_code_expired() {
    let err = MsalError::DeviceCodeExpired;
    assert_eq!(err.to_string(), "device code expired");
}

// ── Request Type Tests ──────────────────────────────────────────────────

#[test]
fn request_types_are_clone_and_debug() {
    let req = AuthorizationCodeRequest {
        code: "code".into(),
        scopes: vec!["scope".into()],
        redirect_uri: "http://localhost".into(),
        code_verifier: Some("verifier".into()),
        claims: None,
        correlation_id: None,
    };
    let cloned = req.clone();
    assert_eq!(format!("{:?}", req), format!("{:?}", cloned));
}

#[test]
fn device_code_info_fields() {
    let info = DeviceCodeInfo {
        user_code: "ABCD-EFGH".into(),
        device_code: "device123".into(),
        verification_uri: "https://microsoft.com/devicelogin".into(),
        message: "Visit https://microsoft.com/devicelogin and enter ABCD-EFGH".into(),
        expires_in: 900,
        interval: 5,
    };
    assert_eq!(info.user_code, "ABCD-EFGH");
    assert_eq!(info.expires_in, 900);
    assert_eq!(info.interval, 5);
}

// ── Helpers ─────────────────────────────────────────────────────────────

fn test_account() -> AccountInfo {
    AccountInfo {
        home_account_id: "uid.utid".into(),
        local_account_id: "oid".into(),
        environment: "login.microsoftonline.com".into(),
        tenant_id: "tenant-id".into(),
        username: "user@example.com".into(),
        name: Some("Test User".into()),
        id_token_claims: None,
    }
}

fn test_auth_result(account: &AccountInfo) -> msal::AuthenticationResult {
    msal::AuthenticationResult {
        access_token: "test-access-token".into(),
        id_token: None,
        scopes: vec!["user.read".into()],
        expires_on: chrono::Utc::now().timestamp() + 3600,
        ext_expires_on: None,
        account: Some(account.clone()),
        tenant_id: Some("tenant-id".into()),
        correlation_id: None,
        token_type: "Bearer".into(),
        refresh_token: Some("test-refresh-token".into()),
    }
}

fn build_test_jwt(payload: &serde_json::Value) -> String {
    use base64::Engine;
    let header =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","typ":"JWT"}"#);
    let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.to_string());
    format!("{header}.{payload_b64}.fakesignature")
}
