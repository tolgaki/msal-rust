use std::collections::BTreeMap;

use base64::Engine;
use msal::account::AccountInfo;
use msal::cache::TokenCache;
use msal::request::{CancellationToken, DeviceCodeRequest, RefreshTokenRequest, SilentFlowRequest};
use msal::{AuthenticationResult, Configuration, MsalError, PublicClientApplication};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const TENANT: &str = "11111111-1111-4111-8111-111111111111";
const OTHER_TENANT: &str = "22222222-2222-4222-8222-222222222222";
const CLAIMS: &str = r#"{"access_token":{"xms_cc":{"values":["cp1"]}}}"#;

fn account(environment: &str) -> AccountInfo {
    AccountInfo {
        home_account_id: "user.home-tenant".into(),
        local_account_id: "local-user".into(),
        environment: environment.into(),
        tenant_id: TENANT.into(),
        username: "display@example.test".into(),
        name: None,
        id_token_claims: None,
    }
}

fn result(account: &AccountInfo) -> AuthenticationResult {
    AuthenticationResult {
        access_token: "access".into(),
        id_token: None,
        scopes: vec!["user.read".into()],
        expires_on: chrono::Utc::now().timestamp() + 3600,
        ext_expires_on: None,
        account: Some(account.clone()),
        tenant_id: Some(account.tenant_id.clone()),
        correlation_id: None,
        token_type: "Bearer".into(),
        refresh_token: Some("refresh".into()),
    }
}

fn form_field(key: &'static str, value: &str) -> impl wiremock::Match {
    let value = value.to_owned();
    move |request: &Request| {
        url::form_urlencoded::parse(&request.body)
            .any(|(name, actual)| name == key && actual == value)
    }
}

fn token_path() -> String {
    format!("/{TENANT}/oauth2/v2.0/token")
}

fn app(server: &MockServer) -> PublicClientApplication {
    PublicClientApplication::new(
        Configuration::builder("client")
            .authority(format!("{}/{TENANT}", server.uri()))
            .build(),
    )
    .unwrap()
}

fn jwt(claims: &serde_json::Value, alg: &str) -> String {
    let encoder = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header = encoder.encode(serde_json::json!({"alg": alg, "typ": "JWT"}).to_string());
    let payload = encoder.encode(claims.to_string());
    // Mock TLS-endpoint consistency tests, not signature-authenticity tests.
    format!("{header}.{payload}.testsignature")
}

fn id_claims() -> serde_json::Value {
    serde_json::json!({
        "aud": "client", "iss": format!("https://127.0.0.1/{TENANT}/v2.0"),
        "tid": TENANT, "oid": "local-user", "sub": "subject",
        "exp": chrono::Utc::now().timestamp() + 3600,
        "preferred_username": "display@example.test"
    })
}

fn user_response(claims: serde_json::Value) -> serde_json::Value {
    let client_info = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(r#"{"uid":"user","utid":"home-tenant"}"#);
    serde_json::json!({
        "access_token": "access", "refresh_token": "refresh",
        "expires_in": 3600, "scope": "user.read",
        "id_token": jwt(&claims, "RS256"), "client_info": client_info
    })
}

#[test]
fn cache_isolates_guest_tenants_environments_and_removal() {
    let cache = TokenCache::new();
    let first = account("login.microsoftonline.com");
    let mut guest = first.clone();
    guest.tenant_id = OTHER_TENANT.into();
    guest.local_account_id = "guest-local".into();
    let mut sovereign = first.clone();
    sovereign.environment = "login.microsoftonline.us".into();
    for (identity, token) in [
        (&first, "first"),
        (&guest, "guest"),
        (&sovereign, "sovereign"),
    ] {
        let mut value = result(identity);
        value.refresh_token = Some(token.into());
        value.access_token = token.into();
        cache.save(&value).unwrap();
    }
    assert_eq!(cache.all_accounts().len(), 3);
    cache.remove_account(&first).unwrap();
    assert!(cache.lookup_refresh_token(&first).is_none());
    assert_eq!(cache.lookup_refresh_token(&guest).as_deref(), Some("guest"));
    assert_eq!(
        cache.lookup_refresh_token(&sovereign).as_deref(),
        Some("sovereign")
    );
    assert_eq!(
        cache
            .lookup_access_token(&guest, &["user.read".into()])
            .unwrap()
            .access_token,
        "guest"
    );
    assert_eq!(cache.all_accounts().len(), 2);
}

#[test]
fn snapshot_roundtrip_and_failed_import_are_atomic() {
    let cache = TokenCache::new();
    let identity = account("login.microsoftonline.com");
    cache.save(&result(&identity)).unwrap();
    let snapshot = serde_json::to_value(cache.export().unwrap()).unwrap();
    let restored = TokenCache::new();
    restored
        .import(serde_json::from_value(snapshot.clone()).unwrap())
        .unwrap();
    assert_eq!(
        restored.lookup_refresh_token(&identity).as_deref(),
        Some("refresh")
    );
    let mut bad = snapshot;
    bad["tokens"][0]["result"]["account"]["tenant_id"] = "".into();
    assert!(restored
        .import(serde_json::from_value(bad).unwrap())
        .is_err());
    assert_eq!(
        restored.lookup_refresh_token(&identity).as_deref(),
        Some("refresh")
    );
}

#[test]
fn application_snapshots_are_client_bound() {
    let first = PublicClientApplication::new(Configuration::builder("first").build()).unwrap();
    let second = PublicClientApplication::new(Configuration::builder("second").build()).unwrap();
    assert!(matches!(
        second.import_cache(first.export_cache().unwrap()),
        Err(MsalError::CacheError(_))
    ));
}

#[test]
fn cache_does_not_reuse_pop_as_bearer_and_rejects_incomplete_identity() {
    let cache = TokenCache::new();
    let identity = account("login.microsoftonline.com");
    let mut value = result(&identity);
    value.token_type = "pop".into();
    cache.save(&value).unwrap();
    assert!(cache
        .lookup_access_token(&identity, &value.scopes)
        .is_none());
    value.token_type = "Bearer".into();
    value.account.as_mut().unwrap().tenant_id.clear();
    assert!(cache.save(&value).is_err());
}

#[test]
fn cache_matches_resource_scopes_when_login_added_oidc_scopes() {
    let cache = TokenCache::new();
    let identity = account("login.microsoftonline.com");
    let mut value = result(&identity);
    value
        .scopes
        .extend(["openid".into(), "profile".into(), "offline_access".into()]);
    cache.save(&value).unwrap();
    assert!(cache
        .try_lookup_access_token(&identity, &["user.read".into()])
        .unwrap()
        .is_some());
}

#[test]
fn extra_parameters_reject_oauth_override_and_allow_client_session() {
    for key in [
        "client_id",
        "CLIENT_ID",
        "claims",
        "grant_type",
        "code_verifier",
        "nonce",
        "client_info",
        "state",
    ] {
        assert!(
            msal::request::validate_extra_query_parameters(&BTreeMap::from([(
                key.into(),
                "bad".into()
            )]))
            .is_err()
        );
    }
    assert!(
        msal::request::validate_extra_query_parameters(&BTreeMap::from([(
            "client_session".into(),
            "session".into()
        )]))
        .is_ok()
    );
}

#[tokio::test]
async fn device_initiation_and_polling_preserve_claims_session_and_client_info() {
    let server = MockServer::start().await;
    Mock::given(method("POST")).and(path(format!("/{TENANT}/oauth2/v2.0/devicecode")))
        .and(form_field("claims", CLAIMS)).and(form_field("client_session", "session"))
        .and(form_field("client_info", "1"))
        .and(|request: &Request| url::form_urlencoded::parse(&request.body).any(|(key, value)| key == "scope" && value.split_whitespace().any(|scope| scope == "openid")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "device_code":"device", "user_code":"ABCD", "verification_uri":"https://microsoft.com/devicelogin",
            "expires_in":60, "interval":1, "message":"Sign in"
        }))).expect(1).mount(&server).await;
    Mock::given(method("POST"))
        .and(path(token_path()))
        .and(form_field("client_info", "1"))
        .and(form_field("claims", CLAIMS))
        .and(form_field("client_session", "session"))
        .respond_with(ResponseTemplate::new(200).set_body_json(user_response(id_claims())))
        .expect(1)
        .mount(&server)
        .await;
    let mut request = DeviceCodeRequest::new(vec!["user.read".into()]);
    request.claims = Some(CLAIMS.into());
    request
        .extra_query_parameters
        .insert("client_session".into(), "session".into());
    let application = app(&server);
    let value = application
        .acquire_token_by_device_code(request, |info| assert_eq!(info.user_code, "ABCD"))
        .await
        .unwrap();
    let identity = value.account.unwrap();
    assert_eq!(identity.tenant_id, TENANT);
    assert_eq!(identity.home_account_id, "user.home-tenant");
    assert_eq!(identity.environment, "127.0.0.1");
    assert_eq!(value.tenant_id.as_deref(), Some(TENANT));
    let mut silent = SilentFlowRequest::new(vec!["user.read".into()], identity.clone());
    silent.claims = Some(CLAIMS.into());
    silent
        .extra_query_parameters
        .insert("client_session".into(), "session".into());
    assert_eq!(
        application
            .acquire_token_silent(silent)
            .await
            .unwrap()
            .access_token,
        "access"
    );
    let unchallenged = SilentFlowRequest::new(vec!["user.read".into()], identity);
    assert!(application
        .acquire_token_silent(unchallenged)
        .await
        .unwrap_err()
        .is_interaction_required());
}

#[tokio::test]
async fn refresh_without_id_token_preserves_trusted_identity_scopes_and_rotation() {
    let server = MockServer::start().await;
    let application = app(&server);
    let identity = account("127.0.0.1");
    Mock::given(method("POST"))
        .and(path(token_path()))
        .and(form_field("client_info", "1"))
        .and(form_field("claims", CLAIMS))
        .and(form_field("client_session", "session"))
        .and(form_field("refresh_token", "old"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token":"fresh", "expires_in":3600, "refresh_token":"rotated"
        })))
        .expect(1)
        .mount(&server)
        .await;
    let mut request = RefreshTokenRequest::new("old".into(), vec!["user.read".into()]);
    request.account = Some(identity.clone());
    request.claims = Some(CLAIMS.into());
    request
        .extra_query_parameters
        .insert("client_session".into(), "session".into());
    let value = application
        .acquire_token_by_refresh_token(request)
        .await
        .unwrap();
    assert_eq!(value.account, Some(identity.clone()));
    assert_eq!(value.scopes, vec!["user.read"]);
    assert_eq!(value.refresh_token.as_deref(), Some("rotated"));
    Mock::given(method("POST"))
        .and(path(token_path()))
        .and(form_field("refresh_token", "rotated"))
        .and(form_field("claims", CLAIMS))
        .and(form_field("client_session", "session"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token":"forced", "expires_in":3600
        })))
        .expect(1)
        .mount(&server)
        .await;
    let mut silent = SilentFlowRequest::new(vec!["user.read".into()], identity);
    silent.force_refresh = true;
    silent.claims = Some(CLAIMS.into());
    silent
        .extra_query_parameters
        .insert("client_session".into(), "session".into());
    let value = application.acquire_token_silent(silent).await.unwrap();
    assert_eq!(value.access_token, "forced");
    assert_eq!(value.refresh_token.as_deref(), Some("rotated"));
}

#[tokio::test]
async fn bare_refresh_does_not_fabricate_account_from_client_info() {
    let server = MockServer::start().await;
    let client_info =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"uid":"user","utid":"home"}"#);
    Mock::given(method("POST"))
        .and(path(token_path()))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token":"access", "expires_in":3600, "client_info":client_info
        })))
        .expect(1)
        .mount(&server)
        .await;
    let application = app(&server);
    let value = application
        .acquire_token_by_refresh_token(RefreshTokenRequest::new(
            "refresh".into(),
            vec!["user.read".into()],
        ))
        .await
        .unwrap();
    assert!(value.account.is_none());
    assert!(application.all_accounts().await.unwrap().is_empty());
}

#[tokio::test]
async fn confidential_credentials_and_refresh_preserve_challenge_parameters() {
    let server = MockServer::start().await;
    let application = msal::ConfidentialClientApplication::new(
        Configuration::builder("client")
            .authority(format!("{}/{TENANT}", server.uri()))
            .client_secret("test-secret")
            .build(),
    )
    .unwrap();
    for grant in ["client_credentials", "refresh_token"] {
        Mock::given(method("POST"))
            .and(path(token_path()))
            .and(form_field("grant_type", grant))
            .and(form_field("client_secret", "test-secret"))
            .and(form_field("claims", CLAIMS))
            .and(form_field("client_session", "session"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token":"access", "expires_in":3600
            })))
            .expect(1)
            .mount(&server)
            .await;
    }
    let mut credentials =
        msal::request::ClientCredentialRequest::new(vec!["resource/.default".into()]);
    credentials.claims = Some(CLAIMS.into());
    credentials
        .extra_query_parameters
        .insert("client_session".into(), "session".into());
    assert!(application
        .acquire_token_by_client_credential(credentials)
        .await
        .unwrap()
        .account
        .is_none());
    let mut refresh = RefreshTokenRequest::new("refresh".into(), vec!["user.read".into()]);
    refresh.claims = Some(CLAIMS.into());
    refresh
        .extra_query_parameters
        .insert("client_session".into(), "session".into());
    refresh.account = Some(account("127.0.0.1"));
    assert_eq!(
        application
            .acquire_token_by_refresh_token(refresh)
            .await
            .unwrap()
            .account
            .unwrap()
            .tenant_id,
        TENANT
    );
}

#[tokio::test]
async fn claims_challenges_preserve_metadata_and_are_never_retried() {
    for error in [
        "interaction_required",
        "consent_required",
        "login_required",
        "invalid_grant",
    ] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(token_path()))
            .and(form_field("claims", CLAIMS))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error":error, "error_description":"interaction needed", "claims":CLAIMS,
                "correlation_id":"correlation", "suberror":"additional_action"
            })))
            .expect(1)
            .mount(&server)
            .await;
        let mut request = RefreshTokenRequest::new("refresh".into(), vec!["user.read".into()]);
        request.claims = Some(CLAIMS.into());
        let error = app(&server)
            .acquire_token_by_refresh_token(request)
            .await
            .unwrap_err();
        assert!(error.is_interaction_required());
        assert_eq!(error.claims(), Some(CLAIMS));
        assert!(
            matches!(error, MsalError::InteractionRequiredWithClaims { correlation_id: Some(id), .. } if id == "correlation")
        );
    }
}

#[tokio::test]
async fn expired_refresh_is_not_misclassified_as_device_expiration() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(token_path()))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "error":"invalid_grant", "error_description":"refresh token expired"
        })))
        .expect(1)
        .mount(&server)
        .await;
    assert!(matches!(
        app(&server)
            .acquire_token_by_refresh_token(RefreshTokenRequest::new(
                "refresh".into(),
                vec!["user.read".into()]
            ))
            .await,
        Err(MsalError::ServerError { .. })
    ));
}

#[tokio::test]
async fn mismatched_id_tokens_fail_without_cache_writes() {
    let mut wrong_audience = id_claims();
    wrong_audience["aud"] = "attacker".into();
    let mut wrong_issuer = id_claims();
    wrong_issuer["iss"] = "https://attacker.test/issuer".into();
    let mut wrong_tenant = id_claims();
    wrong_tenant["tid"] = OTHER_TENANT.into();
    let mut wrong_account = id_claims();
    wrong_account["oid"] = "other-account".into();
    let mut expired = id_claims();
    expired["exp"] = (chrono::Utc::now().timestamp() - 1).into();
    let mut missing_tenant = id_claims();
    missing_tenant.as_object_mut().unwrap().remove("tid");
    for claims in [
        wrong_audience,
        wrong_issuer,
        wrong_tenant,
        wrong_account,
        expired,
        missing_tenant,
    ] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(token_path()))
            .respond_with(ResponseTemplate::new(200).set_body_json(user_response(claims)))
            .expect(1)
            .mount(&server)
            .await;
        let application = app(&server);
        let mut request = RefreshTokenRequest::new("refresh".into(), vec!["user.read".into()]);
        request.account = Some(account("127.0.0.1"));
        assert!(application
            .acquire_token_by_refresh_token(request)
            .await
            .is_err());
        assert!(application.all_accounts().await.unwrap().is_empty());
    }
}

#[tokio::test]
async fn unsigned_token_and_malformed_client_info_are_rejected() {
    for response in [
        {
            let mut response = user_response(id_claims());
            response["id_token"] = jwt(&id_claims(), "none").into();
            response
        },
        {
            let mut response = user_response(id_claims());
            response["client_info"] = "invalid".into();
            response
        },
    ] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(token_path()))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .expect(1)
            .mount(&server)
            .await;
        assert!(app(&server)
            .acquire_token_by_refresh_token(RefreshTokenRequest::new(
                "refresh".into(),
                vec!["user.read".into()]
            ))
            .await
            .is_err());
    }
}

#[tokio::test]
async fn pre_cancelled_http_and_polling_do_not_continue() {
    let server = MockServer::start().await;
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    let mut request = RefreshTokenRequest::new("refresh".into(), vec!["user.read".into()]);
    request.cancellation_token = Some(cancellation);
    assert!(matches!(
        app(&server).acquire_token_by_refresh_token(request).await,
        Err(MsalError::OperationCancelled)
    ));
    assert!(server.received_requests().await.unwrap().is_empty());

    Mock::given(method("POST")).and(path(format!("/{TENANT}/oauth2/v2.0/devicecode")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "device_code":"device", "user_code":"ABCD", "verification_uri":"https://microsoft.com/devicelogin",
            "expires_in":60, "interval":5
        }))).expect(1).mount(&server).await;
    let cancellation = CancellationToken::new();
    let mut request = DeviceCodeRequest::new(vec!["user.read".into()]);
    request.cancellation_token = Some(cancellation.clone());
    let value = app(&server)
        .acquire_token_by_device_code(request, |_| cancellation.cancel())
        .await;
    assert!(matches!(value, Err(MsalError::OperationCancelled)));
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn in_flight_http_cancellation_drops_wait_without_caching() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(token_path()))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(std::time::Duration::from_secs(2))
                .set_body_json(serde_json::json!({"access_token":"access","expires_in":3600})),
        )
        .mount(&server)
        .await;
    let cancellation = CancellationToken::new();
    let mut request = RefreshTokenRequest::new("refresh".into(), vec!["user.read".into()]);
    request.cancellation_token = Some(cancellation.clone());
    let application = app(&server);
    let acquire = application.acquire_token_by_refresh_token(request);
    let cancel = async {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        cancellation.cancel();
    };
    let (value, _) = tokio::join!(acquire, cancel);
    assert!(matches!(value, Err(MsalError::OperationCancelled)));
    assert!(application.all_accounts().await.unwrap().is_empty());
}

#[test]
fn authorization_url_exposes_nonce_claims_and_session_without_oauth_overrides() {
    let application =
        PublicClientApplication::new(Configuration::builder("client").build()).unwrap();
    let extra = BTreeMap::from([("client_session".into(), "session".into())]);
    let (url, pkce) = application
        .authorization_url_with_options(
            &["user.read".into()],
            "http://localhost",
            Some("state"),
            Some(CLAIMS),
            &extra,
        )
        .unwrap();
    let pairs: BTreeMap<_, _> = url::Url::parse(&url)
        .unwrap()
        .query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();
    assert_eq!(pairs["nonce"], pkce.nonce);
    assert_eq!(pairs["claims"], CLAIMS);
    assert_eq!(pairs["client_session"], "session");
    assert_eq!(pairs["client_info"], "1");
}

#[tokio::test]
async fn code_exchange_checks_nonce_and_pkce() {
    let server = MockServer::start().await;
    let application = app(&server);
    let mut claims = id_claims();
    claims["nonce"] = "wrong".into();
    Mock::given(method("POST"))
        .and(path(token_path()))
        .and(form_field("code_verifier", "verifier"))
        .respond_with(ResponseTemplate::new(200).set_body_json(user_response(claims)))
        .expect(1)
        .mount(&server)
        .await;
    let mut request = msal::request::AuthorizationCodeRequest::new(
        "code".into(),
        vec!["user.read".into()],
        "http://localhost".into(),
    );
    assert!(matches!(
        application.acquire_token_by_code(request.clone()).await,
        Err(MsalError::MissingParameter(_))
    ));
    request.code_verifier = Some("verifier".into());
    request.nonce = Some("expected".into());
    assert!(matches!(
        application.acquire_token_by_code(request).await,
        Err(MsalError::InvalidToken(_))
    ));
}
