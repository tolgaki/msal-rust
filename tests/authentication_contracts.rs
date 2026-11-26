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
    // An expired refresh token needs interactive sign-in, not a device-code
    // expiration and not an opaque server error.
    let error = app(&server)
        .acquire_token_by_refresh_token(RefreshTokenRequest::new(
            "refresh".into(),
            vec!["user.read".into()],
        ))
        .await
        .unwrap_err();
    assert!(error.is_interaction_required(), "{error:?}");
}

#[tokio::test]
async fn invalid_grant_suberrors_without_ui_remedy_stay_server_errors() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(token_path()))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "error":"invalid_grant", "error_description":"wrong client",
            "suberror":"client_mismatch"
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
    // Beyond the ID token clock-skew allowance.
    expired["exp"] = (chrono::Utc::now().timestamp() - 3600).into();
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

fn refresh_app(server: &MockServer, authority_path: &str) -> PublicClientApplication {
    PublicClientApplication::new(
        Configuration::builder("client")
            .authority(format!("{}/{authority_path}", server.uri()))
            .build(),
    )
    .unwrap()
}

#[tokio::test]
async fn b2c_id_token_issuer_omits_policy_and_is_accepted() {
    let server = MockServer::start().await;
    let mut claims = id_claims();
    claims["iss"] = format!("https://127.0.0.1/{TENANT}/v2.0/").into();
    Mock::given(method("POST"))
        .and(path(format!(
            "/tfp/{TENANT}/B2C_1_signin/oauth2/v2.0/token"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(user_response(claims)))
        .expect(1)
        .mount(&server)
        .await;
    let value = refresh_app(&server, &format!("tfp/{TENANT}/B2C_1_signin"))
        .acquire_token_by_refresh_token(RefreshTokenRequest::new(
            "refresh".into(),
            vec!["user.read".into()],
        ))
        .await
        .unwrap();
    assert_eq!(value.account.unwrap().tenant_id, TENANT);
}

#[tokio::test]
async fn adfs_id_token_without_tid_or_client_info_establishes_account() {
    let server = MockServer::start().await;
    let mut claims = id_claims();
    claims["iss"] = "https://127.0.0.1/adfs".into();
    let object = claims.as_object_mut().unwrap();
    object.remove("tid");
    object.remove("oid");
    let mut response = user_response(claims);
    response.as_object_mut().unwrap().remove("client_info");
    Mock::given(method("POST"))
        .and(path("/adfs/oauth2/v2.0/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(response))
        .expect(1)
        .mount(&server)
        .await;
    let application = refresh_app(&server, "adfs");
    let value = application
        .acquire_token_by_refresh_token(RefreshTokenRequest::new(
            "refresh".into(),
            vec!["user.read".into()],
        ))
        .await
        .unwrap();
    let identity = value.account.unwrap();
    assert_eq!(identity.local_account_id, "subject");
    assert_eq!(identity.home_account_id, "subject");
    assert_eq!(identity.tenant_id, "adfs");
    assert_eq!(application.all_accounts().await.unwrap().len(), 1);
}

#[tokio::test]
async fn silent_claims_challenge_redeems_refresh_token_from_unchallenged_login() {
    let server = MockServer::start().await;
    let application = app(&server);
    let identity = account("127.0.0.1");
    Mock::given(method("POST"))
        .and(path(token_path()))
        .and(form_field("refresh_token", "initial"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token":"plain", "expires_in":3600, "refresh_token":"cached"
        })))
        .expect(1)
        .mount(&server)
        .await;
    let mut request = RefreshTokenRequest::new("initial".into(), vec!["user.read".into()]);
    request.account = Some(identity.clone());
    application
        .acquire_token_by_refresh_token(request)
        .await
        .unwrap();
    Mock::given(method("POST"))
        .and(path(token_path()))
        .and(form_field("refresh_token", "cached"))
        .and(form_field("claims", CLAIMS))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token":"challenged", "expires_in":3600
        })))
        .expect(1)
        .mount(&server)
        .await;
    let mut silent = SilentFlowRequest::new(vec!["user.read".into()], identity.clone());
    silent.claims = Some(CLAIMS.into());
    // The claims challenge must not be satisfied by the unchallenged access token.
    assert_eq!(
        application
            .acquire_token_silent(silent)
            .await
            .unwrap()
            .access_token,
        "challenged"
    );
    // And the unchallenged token is still served from cache afterwards.
    assert_eq!(
        application
            .acquire_token_silent(SilentFlowRequest::new(vec!["user.read".into()], identity))
            .await
            .unwrap()
            .access_token,
        "plain"
    );
}

#[test]
fn cached_token_satisfies_subset_of_server_granted_scopes() {
    let cache = TokenCache::new();
    let identity = account("login.microsoftonline.com");
    let mut value = result(&identity);
    value.scopes = ["User.Read", "Mail.Read", "openid", "profile", "email"]
        .map(String::from)
        .to_vec();
    cache.save(&value).unwrap();
    for hit in [vec!["user.read"], vec!["mail.read", "User.Read"]] {
        let scopes: Vec<String> = hit.into_iter().map(String::from).collect();
        assert!(cache.lookup_access_token(&identity, &scopes).is_some());
    }
    assert!(cache
        .lookup_access_token(&identity, &["mail.send".into()])
        .is_none());
}

#[test]
fn cache_treats_public_cloud_aliases_as_one_environment() {
    let cache = TokenCache::new();
    cache.save(&result(&account("login.windows.net"))).unwrap();
    assert!(cache
        .lookup_access_token(&account("login.microsoftonline.com"), &["user.read".into()])
        .is_some());
}

/// Broker double that, like the WAM and macOS adapters, rejects any request
/// carrying a cancellation token.
struct StrictBroker;

impl msal::broker::NativeBroker for StrictBroker {
    fn is_available(&self) -> bool {
        true
    }

    fn acquire_token_silent<'a>(
        &'a self,
        _client_id: &'a str,
        request: &'a msal::broker::BrokerTokenRequest,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = msal::error::Result<AuthenticationResult>> + Send + 'a,
        >,
    > {
        Box::pin(async move {
            if request.cancellation_token.is_some() {
                return Err(MsalError::Unsupported("native cancellation".into()));
            }
            let mut value = result(request.account.as_ref().unwrap());
            value.access_token = "brokered".into();
            value.refresh_token = None;
            Ok(value)
        })
    }

    fn acquire_token_interactive<'a>(
        &'a self,
        _client_id: &'a str,
        request: &'a msal::broker::BrokerTokenRequest,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = msal::error::Result<AuthenticationResult>> + Send + 'a,
        >,
    > {
        Box::pin(async move {
            let mut value = result(&account("login.microsoftonline.com"));
            value.access_token = request.authority.clone().unwrap();
            value.refresh_token = None;
            Ok(value)
        })
    }

    fn sign_out<'a>(
        &'a self,
        _client_id: &'a str,
        _request: &'a msal::broker::BrokerSignOutRequest,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = msal::error::Result<()>> + Send + 'a>>
    {
        Box::pin(async { Ok(()) })
    }

    fn all_accounts<'a>(
        &'a self,
        _client_id: &'a str,
        _correlation_id: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = msal::error::Result<Vec<AccountInfo>>> + Send + 'a>,
    > {
        Box::pin(async { Ok(Vec::new()) })
    }

    fn account<'a>(
        &'a self,
        _account_id: &'a str,
        _correlation_id: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = msal::error::Result<AccountInfo>> + Send + 'a>,
    > {
        Box::pin(async { Err(MsalError::Unsupported("lookup".into())) })
    }
}

async fn brokered_app() -> PublicClientApplication {
    let application = PublicClientApplication::new(
        Configuration::builder("client")
            .authority(format!("https://login.microsoftonline.com/{TENANT}"))
            .build(),
    )
    .unwrap();
    application.set_broker(Box::new(StrictBroker)).await;
    application
}

#[tokio::test]
async fn silent_broker_call_honors_cancellation_without_forwarding_it() {
    let application = brokered_app().await;
    let mut silent = SilentFlowRequest::new(
        vec!["user.read".into()],
        account("login.microsoftonline.com"),
    );
    let cancellation = CancellationToken::new();
    silent.cancellation_token = Some(cancellation.clone());
    assert_eq!(
        application
            .acquire_token_silent(silent.clone())
            .await
            .unwrap()
            .access_token,
        "brokered"
    );
    cancellation.cancel();
    silent.force_refresh = true;
    assert!(matches!(
        application.acquire_token_silent(silent).await,
        Err(MsalError::OperationCancelled)
    ));
}

#[tokio::test]
async fn interactive_broker_accepts_equivalent_authority_spelling() {
    let application = brokered_app().await;
    for authority in [
        format!("https://login.microsoftonline.com/{TENANT}/"),
        format!(
            "https://LOGIN.microsoftonline.com/{}",
            TENANT.to_uppercase()
        ),
    ] {
        let request = msal::broker::BrokerTokenRequest {
            scopes: vec!["user.read".into()],
            account: None,
            claims: None,
            force_refresh: false,
            authority: Some(authority),
            extra_query_parameters: Default::default(),
            cancellation_token: None,
            correlation_id: None,
            window_handle: None,
            authentication_scheme: Default::default(),
            pop_params: None,
        };
        application
            .acquire_token_interactive(request)
            .await
            .unwrap();
    }
    let request = msal::broker::BrokerTokenRequest {
        scopes: vec!["user.read".into()],
        account: None,
        claims: None,
        force_refresh: false,
        authority: Some(format!("https://login.microsoftonline.com/{OTHER_TENANT}")),
        extra_query_parameters: Default::default(),
        cancellation_token: None,
        correlation_id: None,
        window_handle: None,
        authentication_scheme: Default::default(),
        pop_params: None,
    };
    assert!(matches!(
        application.acquire_token_interactive(request).await,
        Err(MsalError::InvalidConfiguration(_))
    ));
}

#[tokio::test]
async fn sign_out_removes_accounts_that_no_longer_match_the_authority() {
    let application = brokered_app().await;
    let mut foreign = account("login.microsoftonline.us");
    foreign.tenant_id = OTHER_TENANT.into();
    application.sign_out(&foreign).await.unwrap();
}

#[tokio::test]
async fn login_with_domain_hint_is_reusable_by_plain_silent_call() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(token_path()))
        .and(form_field("domain_hint", "contoso.com"))
        .respond_with(ResponseTemplate::new(200).set_body_json(user_response(id_claims())))
        .expect(1)
        .mount(&server)
        .await;
    let application = app(&server);
    let mut request = RefreshTokenRequest::new("refresh".into(), vec!["user.read".into()]);
    request
        .extra_query_parameters
        .insert("domain_hint".into(), "contoso.com".into());
    let identity = application
        .acquire_token_by_refresh_token(request)
        .await
        .unwrap()
        .account
        .unwrap();
    assert_eq!(
        application
            .acquire_token_silent(SilentFlowRequest::new(vec!["user.read".into()], identity))
            .await
            .unwrap()
            .access_token,
        "access"
    );
}

#[test]
fn remove_account_ignores_local_id_spelling_but_keeps_guest_tenants() {
    let cache = TokenCache::new();
    let home = account("login.microsoftonline.com");
    let mut guest = home.clone();
    guest.tenant_id = OTHER_TENANT.into();
    cache.save(&result(&home)).unwrap();
    cache.save(&result(&guest)).unwrap();
    let mut by_subject = home.clone();
    by_subject.local_account_id = "subject-instead-of-oid".into();
    by_subject.environment = "login.windows.net".into();
    cache.remove_account(&by_subject).unwrap();
    assert!(cache.lookup_refresh_token(&home).is_none());
    assert_eq!(cache.all_accounts(), vec![guest]);
}

#[test]
fn snapshot_access_entries_do_not_carry_refresh_tokens() {
    let cache = TokenCache::new();
    cache
        .save(&result(&account("login.microsoftonline.com")))
        .unwrap();
    let snapshot = serde_json::to_value(cache.export().unwrap()).unwrap();
    assert!(snapshot["tokens"][0]["result"]["refresh_token"].is_null());
    assert_eq!(snapshot["refresh_tokens"][0]["token"], "refresh");
}

#[tokio::test]
async fn sign_out_clears_local_cache_even_when_broker_sign_out_fails() {
    struct FailingSignOut;
    impl msal::broker::NativeBroker for FailingSignOut {
        fn is_available(&self) -> bool {
            true
        }
        fn acquire_token_silent<'a>(
            &'a self,
            client_id: &'a str,
            request: &'a msal::broker::BrokerTokenRequest,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = msal::error::Result<AuthenticationResult>>
                    + Send
                    + 'a,
            >,
        > {
            StrictBroker.acquire_token_silent(client_id, request)
        }
        fn acquire_token_interactive<'a>(
            &'a self,
            client_id: &'a str,
            request: &'a msal::broker::BrokerTokenRequest,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = msal::error::Result<AuthenticationResult>>
                    + Send
                    + 'a,
            >,
        > {
            StrictBroker.acquire_token_interactive(client_id, request)
        }
        fn sign_out<'a>(
            &'a self,
            _client_id: &'a str,
            _request: &'a msal::broker::BrokerSignOutRequest,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = msal::error::Result<()>> + Send + 'a>>
        {
            Box::pin(async { Err(MsalError::Unsupported("sign-out".into())) })
        }
        fn all_accounts<'a>(
            &'a self,
            client_id: &'a str,
            correlation_id: &'a str,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = msal::error::Result<Vec<AccountInfo>>> + Send + 'a,
            >,
        > {
            StrictBroker.all_accounts(client_id, correlation_id)
        }
        fn account<'a>(
            &'a self,
            account_id: &'a str,
            correlation_id: &'a str,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = msal::error::Result<AccountInfo>> + Send + 'a>,
        > {
            StrictBroker.account(account_id, correlation_id)
        }
    }
    let application = PublicClientApplication::new(
        Configuration::builder("client")
            .authority(format!("https://login.microsoftonline.com/{TENANT}"))
            .build(),
    )
    .unwrap();
    let identity = account("login.microsoftonline.com");
    let mut snapshot = serde_json::to_value(application.export_cache().unwrap()).unwrap();
    let mut saved = result(&identity);
    saved.refresh_token = None;
    snapshot["tokens"] = serde_json::json!([{ "result": saved, "context": "" }]);
    application
        .import_cache(serde_json::from_value(snapshot).unwrap())
        .unwrap();
    application.set_broker(Box::new(FailingSignOut)).await;
    assert!(application.sign_out(&identity).await.is_err());
    let remaining = serde_json::to_value(application.export_cache().unwrap()).unwrap();
    assert_eq!(remaining["tokens"], serde_json::json!([]));
}

#[tokio::test]
async fn silent_falls_back_to_refresh_token_when_broker_cannot_serve_account() {
    let server = MockServer::start().await;
    let application = app(&server);
    let identity = account("127.0.0.1");
    let mut request = RefreshTokenRequest::new("initial".into(), vec!["user.read".into()]);
    request.account = Some(identity.clone());
    Mock::given(method("POST"))
        .and(path(token_path()))
        .and(form_field("refresh_token", "initial"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token":"first", "expires_in":3600, "refresh_token":"cached"
        })))
        .expect(1)
        .mount(&server)
        .await;
    application
        .acquire_token_by_refresh_token(request)
        .await
        .unwrap();
    Mock::given(method("POST"))
        .and(path(token_path()))
        .and(form_field("refresh_token", "cached"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token":"refreshed", "expires_in":3600
        })))
        .expect(1)
        .mount(&server)
        .await;
    // A broker that cannot serve this account (no native mapping) reports
    // Unsupported; silent must continue with the cached refresh token.
    struct UnsupportedSilent;
    impl msal::broker::NativeBroker for UnsupportedSilent {
        fn is_available(&self) -> bool {
            true
        }
        fn acquire_token_silent<'a>(
            &'a self,
            _client_id: &'a str,
            _request: &'a msal::broker::BrokerTokenRequest,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = msal::error::Result<AuthenticationResult>>
                    + Send
                    + 'a,
            >,
        > {
            Box::pin(async { Err(MsalError::Unsupported("no native mapping".into())) })
        }
        fn acquire_token_interactive<'a>(
            &'a self,
            client_id: &'a str,
            request: &'a msal::broker::BrokerTokenRequest,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = msal::error::Result<AuthenticationResult>>
                    + Send
                    + 'a,
            >,
        > {
            StrictBroker.acquire_token_interactive(client_id, request)
        }
        fn sign_out<'a>(
            &'a self,
            client_id: &'a str,
            request: &'a msal::broker::BrokerSignOutRequest,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = msal::error::Result<()>> + Send + 'a>>
        {
            StrictBroker.sign_out(client_id, request)
        }
        fn all_accounts<'a>(
            &'a self,
            client_id: &'a str,
            correlation_id: &'a str,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = msal::error::Result<Vec<AccountInfo>>> + Send + 'a,
            >,
        > {
            StrictBroker.all_accounts(client_id, correlation_id)
        }
        fn account<'a>(
            &'a self,
            account_id: &'a str,
            correlation_id: &'a str,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = msal::error::Result<AccountInfo>> + Send + 'a>,
        > {
            StrictBroker.account(account_id, correlation_id)
        }
    }
    application.set_broker(Box::new(UnsupportedSilent)).await;
    let mut silent = SilentFlowRequest::new(vec!["user.read".into()], identity);
    silent.force_refresh = true;
    assert_eq!(
        application
            .acquire_token_silent(silent)
            .await
            .unwrap()
            .access_token,
        "refreshed"
    );
}

const DOMAIN: &str = "contoso.onmicrosoft.com";

async fn mount_discovery(server: &MockServer, issuer: String, times: u64) {
    Mock::given(method("GET"))
        .and(path(format!(
            "/{DOMAIN}/v2.0/.well-known/openid-configuration"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "authorization_endpoint": format!("{}/{DOMAIN}/oauth2/v2.0/authorize", server.uri()),
            "token_endpoint": format!("{}/{DOMAIN}/oauth2/v2.0/token", server.uri()),
            "issuer": issuer,
        })))
        .expect(times)
        .mount(server)
        .await;
}

fn domain_app(server: &MockServer) -> PublicClientApplication {
    refresh_app(server, DOMAIN)
}

fn import_tokens(application: &PublicClientApplication, identities: &[&AccountInfo]) {
    let mut snapshot = serde_json::to_value(application.export_cache().unwrap()).unwrap();
    snapshot["tokens"] = identities
        .iter()
        .map(|identity| serde_json::json!({ "result": result(identity), "context": "" }))
        .collect();
    application
        .import_cache(serde_json::from_value(snapshot).unwrap())
        .unwrap();
}

#[tokio::test]
async fn domain_tenant_authority_rejects_cached_accounts_from_other_tenants() {
    let server = MockServer::start().await;
    // Discovery runs once per application, not once per request.
    mount_discovery(&server, format!("https://127.0.0.1/{TENANT}/v2.0"), 1).await;
    let application = domain_app(&server);
    let own = account("127.0.0.1");
    let mut foreign = own.clone();
    foreign.tenant_id = OTHER_TENANT.into();
    import_tokens(&application, &[&own, &foreign]);

    let error = application
        .acquire_token_silent(SilentFlowRequest::new(
            vec!["user.read".into()],
            foreign.clone(),
        ))
        .await
        .unwrap_err();
    assert!(matches!(error, MsalError::InvalidToken(_)), "{error:?}");
    for _ in 0..2 {
        assert_eq!(
            application
                .acquire_token_silent(SilentFlowRequest::new(
                    vec!["user.read".into()],
                    own.clone()
                ))
                .await
                .unwrap()
                .access_token,
            "access"
        );
    }
    // No token endpoint call was made for either account.
    assert!(server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .all(|request| request.method.as_str() == "GET"));
}

#[tokio::test]
async fn domain_tenant_authority_rejects_id_tokens_from_other_tenants() {
    for (tid, accepted) in [(TENANT, true), (OTHER_TENANT, false)] {
        let server = MockServer::start().await;
        mount_discovery(&server, format!("https://127.0.0.1/{TENANT}/v2.0"), 1).await;
        let mut claims = id_claims();
        claims["tid"] = tid.into();
        claims["iss"] = format!("https://127.0.0.1/{tid}/v2.0").into();
        Mock::given(method("POST"))
            .and(path(format!("/{DOMAIN}/oauth2/v2.0/token")))
            .respond_with(ResponseTemplate::new(200).set_body_json(user_response(claims)))
            .expect(1)
            .mount(&server)
            .await;
        let application = domain_app(&server);
        let value = application
            .acquire_token_by_refresh_token(RefreshTokenRequest::new(
                "refresh".into(),
                vec!["user.read".into()],
            ))
            .await;
        assert_eq!(value.is_ok(), accepted, "{tid}: {value:?}");
        assert_eq!(
            application.all_accounts().await.unwrap().len(),
            usize::from(accepted)
        );
    }
}

#[tokio::test]
async fn domain_tenant_discovery_must_name_a_tenant_guid_on_the_same_host() {
    for issuer in [
        format!("https://127.0.0.1/{DOMAIN}/v2.0"),
        format!("https://attacker.example/{TENANT}/v2.0"),
        "https://127.0.0.1/common/v2.0".to_string(),
    ] {
        let server = MockServer::start().await;
        mount_discovery(&server, issuer.clone(), 1).await;
        let application = domain_app(&server);
        let error = application
            .acquire_token_silent(SilentFlowRequest::new(
                vec!["user.read".into()],
                account("127.0.0.1"),
            ))
            .await
            .unwrap_err();
        assert!(
            matches!(error, MsalError::AuthorityMetadataNotFound(_)),
            "{issuer}: {error:?}"
        );
    }
    // A failed discovery is an error, never a silent pass.
    let server = MockServer::start().await;
    let error = domain_app(&server)
        .acquire_token_silent(SilentFlowRequest::new(
            vec!["user.read".into()],
            account("127.0.0.1"),
        ))
        .await
        .unwrap_err();
    assert!(
        matches!(error, MsalError::AuthorityMetadataNotFound(_)),
        "{error:?}"
    );
}

#[tokio::test]
async fn guid_and_multi_tenant_authorities_skip_discovery() {
    let server = MockServer::start().await;
    let application = app(&server);
    let own = account("127.0.0.1");
    import_tokens(&application, &[&own]);
    application
        .acquire_token_silent(SilentFlowRequest::new(vec!["user.read".into()], own))
        .await
        .unwrap();
    assert!(server.received_requests().await.unwrap().is_empty());
}
