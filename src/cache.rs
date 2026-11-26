//! In-memory, client/account/tenant/environment/request-context isolated cache.
//!
//! Snapshots are plaintext secret-bearing values. The caller owns protected
//! persistence, integrity, concurrency and deletion; this crate writes no files.

use std::collections::HashMap;
use std::sync::RwLock;

use crate::account::AccountInfo;
use crate::error::{MsalError, Result};
use crate::response::AuthenticationResult;

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct AccessTokenKey {
    account: String,
    scopes: String,
    context: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct CachedToken {
    result: AuthenticationResult,
    context: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct CachedRefreshToken {
    account: AccountInfo,
    token: String,
    context: String,
}

/// Serializable in-memory snapshot, not a secret-file or keychain format.
///
/// Import only integrity-protected snapshots belonging to this client. Tokens
/// and account metadata in a snapshot are trusted caller state, not revalidated
/// against the server. No native broker refresh tokens are exported.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TokenCacheSnapshot {
    client_id: String,
    tokens: Vec<CachedToken>,
    refresh_tokens: Vec<CachedRefreshToken>,
}

#[derive(Debug, Default)]
struct CacheState {
    access_tokens: HashMap<AccessTokenKey, CachedToken>,
    refresh_tokens: HashMap<(String, String), CachedRefreshToken>,
    accounts: HashMap<String, AccountInfo>,
}

/// A single lock makes save, import, export and removal atomic in this process.
#[derive(Debug)]
pub struct TokenCache {
    client_id: String,
    state: RwLock<CacheState>,
}

fn lock_error() -> MsalError {
    MsalError::CacheError("lock poisoned".into())
}

/// OIDC scopes the server adds to login responses; they never select a resource token.
fn is_oidc_scope(scope: &str) -> bool {
    matches!(scope, "openid" | "profile" | "offline_access" | "email")
}

fn normalized_scopes(scopes: &[String]) -> std::collections::BTreeSet<String> {
    scopes
        .iter()
        .map(|s| s.to_lowercase())
        .filter(|scope| !is_oidc_scope(scope))
        .collect()
}

fn scope_key(scopes: &[String]) -> String {
    normalized_scopes(scopes)
        .into_iter()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Whether a cached token granted for `cached` scopes satisfies `requested`.
///
/// The server may return more scopes than were requested (for example, other
/// consented scopes of the same resource), so a superset satisfies the request.
fn scopes_satisfy(
    cached: &std::collections::BTreeSet<String>,
    requested: &std::collections::BTreeSet<String>,
) -> bool {
    if requested.is_empty() {
        cached.is_empty()
    } else {
        requested.is_subset(cached)
    }
}

/// Cache partition for a request.
///
/// Access tokens are partitioned by claims and opaque extra parameters, so a
/// claims challenge never reuses a token issued without it. Refresh tokens are
/// partitioned only by the extra parameters (e.g. `client_session`): claims are a
/// per-request challenge that must be redeemable with the account's existing
/// refresh token. Neither partition proves server-side session enforcement.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct CacheContext {
    access: String,
    refresh: String,
}

pub(crate) fn request_context(
    claims: &Option<String>,
    extra: &std::collections::BTreeMap<String, String>,
) -> CacheContext {
    let encode = |claims: &Option<String>| {
        if claims.is_none() && extra.is_empty() {
            String::new()
        } else {
            serde_json::json!([claims, extra]).to_string()
        }
    };
    CacheContext {
        access: encode(claims),
        refresh: encode(&None),
    }
}

fn validate_result(result: &AuthenticationResult) -> Result<&AccountInfo> {
    let account = result
        .account
        .as_ref()
        .ok_or_else(|| MsalError::CacheError("cached user token requires an account".into()))?;
    account.validate()?;
    if result
        .tenant_id
        .as_deref()
        .is_some_and(|tenant| !tenant.eq_ignore_ascii_case(&account.tenant_id))
        || result.access_token.is_empty()
    {
        return Err(MsalError::CacheError(
            "invalid cached token/account identity".into(),
        ));
    }
    Ok(account)
}

/// Insert an access token under `context`, and its refresh token under
/// `refresh_context` when one is given.
fn insert_result(
    state: &mut CacheState,
    result: &AuthenticationResult,
    context: &str,
    refresh_context: Option<&str>,
) -> Result<()> {
    let Some(account) = result.account.as_ref() else {
        return Ok(());
    };
    validate_result(result)?;
    // PoP acquisition must not satisfy a later bearer-cache lookup.
    if !result.token_type.eq_ignore_ascii_case("Bearer") {
        return Ok(());
    }
    let account_key = account.cache_key();
    state.access_tokens.insert(
        AccessTokenKey {
            account: account_key.clone(),
            scopes: scope_key(&result.scopes),
            context: context.into(),
        },
        CachedToken {
            result: result.clone(),
            context: context.into(),
        },
    );
    if let (Some(token), Some(refresh_context)) = (&result.refresh_token, refresh_context) {
        state.refresh_tokens.insert(
            (account_key.clone(), refresh_context.into()),
            CachedRefreshToken {
                account: account.clone(),
                token: token.clone(),
                context: refresh_context.into(),
            },
        );
    }
    state.accounts.insert(account_key, account.clone());
    Ok(())
}

impl TokenCache {
    pub fn new() -> Self {
        Self::for_client(String::new())
    }

    pub(crate) fn for_client(client_id: String) -> Self {
        Self {
            client_id,
            state: RwLock::new(CacheState::default()),
        }
    }

    pub fn save(&self, result: &AuthenticationResult) -> Result<()> {
        self.save_with_context(result, &CacheContext::default())
    }

    pub(crate) fn save_with_context(
        &self,
        result: &AuthenticationResult,
        context: &CacheContext,
    ) -> Result<()> {
        insert_result(
            &mut *self.state.write().map_err(|_| lock_error())?,
            result,
            &context.access,
            Some(&context.refresh),
        )
    }

    /// Fallible lookup used by acquisition methods; lock errors are not cache misses.
    pub fn try_lookup_access_token(
        &self,
        account: &AccountInfo,
        scopes: &[String],
    ) -> Result<Option<AuthenticationResult>> {
        self.lookup_with_context(account, scopes, &CacheContext::default())
    }

    pub(crate) fn lookup_with_context(
        &self,
        account: &AccountInfo,
        scopes: &[String],
        context: &CacheContext,
    ) -> Result<Option<AuthenticationResult>> {
        account.validate()?;
        let state = self.state.read().map_err(|_| lock_error())?;
        let account_key = account.cache_key();
        let requested = normalized_scopes(scopes);
        let fresh_after = chrono::Utc::now().timestamp() + 300;
        Ok(state
            .access_tokens
            .iter()
            .filter(|(key, entry)| {
                key.account == account_key
                    && key.context == context.access
                    && entry.result.expires_on > fresh_after
                    && scopes_satisfy(&normalized_scopes(&entry.result.scopes), &requested)
            })
            .map(|(_, entry)| entry)
            .max_by_key(|entry| entry.result.expires_on)
            .map(|entry| {
                let mut result = entry.result.clone();
                result.refresh_token = None;
                result
            }))
    }

    /// Legacy convenience lookup. Prefer the fallible `try_` API.
    pub fn lookup_access_token(
        &self,
        account: &AccountInfo,
        scopes: &[String],
    ) -> Option<AuthenticationResult> {
        self.try_lookup_access_token(account, scopes).ok().flatten()
    }

    pub fn try_lookup_refresh_token(&self, account: &AccountInfo) -> Result<Option<String>> {
        self.refresh_with_context(account, &CacheContext::default())
    }

    pub(crate) fn refresh_with_context(
        &self,
        account: &AccountInfo,
        context: &CacheContext,
    ) -> Result<Option<String>> {
        account.validate()?;
        Ok(self
            .state
            .read()
            .map_err(|_| lock_error())?
            .refresh_tokens
            .get(&(account.cache_key(), context.refresh.clone()))
            .map(|entry| entry.token.clone()))
    }

    /// Legacy convenience lookup. Prefer the fallible `try_` API.
    pub fn lookup_refresh_token(&self, account: &AccountInfo) -> Option<String> {
        self.try_lookup_refresh_token(account).ok().flatten()
    }

    pub fn try_all_accounts(&self) -> Result<Vec<AccountInfo>> {
        Ok(self
            .state
            .read()
            .map_err(|_| lock_error())?
            .accounts
            .values()
            .cloned()
            .collect())
    }

    /// Legacy convenience enumeration. Prefer the fallible `try_` API.
    pub fn all_accounts(&self) -> Vec<AccountInfo> {
        self.try_all_accounts().unwrap_or_default()
    }

    /// Atomically remove only this complete identity, not other guest tenants.
    pub fn remove_account(&self, account: &AccountInfo) -> Result<()> {
        let key = account.cache_key();
        let mut state = self.state.write().map_err(|_| lock_error())?;
        state.accounts.remove(&key);
        state.access_tokens.retain(|entry, _| entry.account != key);
        state
            .refresh_tokens
            .retain(|(account, _), _| account != &key);
        Ok(())
    }

    pub fn clear(&self) -> Result<()> {
        *self.state.write().map_err(|_| lock_error())? = CacheState::default();
        Ok(())
    }

    pub fn export(&self) -> Result<TokenCacheSnapshot> {
        let state = self.state.read().map_err(|_| lock_error())?;
        Ok(TokenCacheSnapshot {
            client_id: self.client_id.clone(),
            tokens: state.access_tokens.values().cloned().collect(),
            refresh_tokens: state.refresh_tokens.values().cloned().collect(),
        })
    }

    /// Atomically replace cache state, rejecting wrong-client or malformed data.
    pub fn import(&self, snapshot: TokenCacheSnapshot) -> Result<()> {
        if snapshot.client_id != self.client_id {
            return Err(MsalError::CacheError(
                "snapshot belongs to a different client".into(),
            ));
        }
        let mut state = CacheState::default();
        for entry in snapshot.tokens {
            validate_result(&entry.result)?;
            // Refresh tokens come only from the snapshot's own refresh list,
            // which holds the newest token for each partition.
            insert_result(&mut state, &entry.result, &entry.context, None)?;
        }
        for entry in snapshot.refresh_tokens {
            entry.account.validate()?;
            if entry.token.is_empty() {
                return Err(MsalError::CacheError(
                    "empty refresh token in snapshot".into(),
                ));
            }
            state
                .accounts
                .insert(entry.account.cache_key(), entry.account.clone());
            state
                .refresh_tokens
                .insert((entry.account.cache_key(), entry.context.clone()), entry);
        }
        *self.state.write().map_err(|_| lock_error())? = state;
        Ok(())
    }
}

impl Default for TokenCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_account() -> AccountInfo {
        AccountInfo {
            home_account_id: "uid.utid".into(),
            local_account_id: "oid".into(),
            environment: "login.microsoftonline.com".into(),
            tenant_id: "tenant".into(),
            username: "user@example.com".into(),
            name: None,
            id_token_claims: None,
        }
    }

    fn test_result(account: &AccountInfo) -> AuthenticationResult {
        AuthenticationResult {
            access_token: "access-token-value".into(),
            id_token: None,
            scopes: vec!["user.read".into()],
            expires_on: chrono::Utc::now().timestamp() + 3600,
            ext_expires_on: None,
            account: Some(account.clone()),
            tenant_id: Some("tenant".into()),
            correlation_id: None,
            token_type: "Bearer".into(),
            refresh_token: Some("refresh-token-value".into()),
        }
    }

    #[test]
    fn save_and_lookup_access_token() {
        let cache = TokenCache::new();
        let account = test_account();
        cache.save(&test_result(&account)).unwrap();
        assert_eq!(
            cache
                .lookup_access_token(&account, &["user.read".into()])
                .unwrap()
                .access_token,
            "access-token-value"
        );
    }

    #[test]
    fn lookup_returns_none_for_expired_token() {
        let cache = TokenCache::new();
        let account = test_account();
        let mut result = test_result(&account);
        result.expires_on = chrono::Utc::now().timestamp() - 1;
        cache.save(&result).unwrap();
        assert!(cache
            .lookup_access_token(&account, &result.scopes)
            .is_none());
    }

    #[test]
    fn lookup_refresh_token() {
        let cache = TokenCache::new();
        let account = test_account();
        cache.save(&test_result(&account)).unwrap();
        assert_eq!(
            cache.lookup_refresh_token(&account).as_deref(),
            Some("refresh-token-value")
        );
    }

    #[test]
    fn remove_account_clears_tokens() {
        let cache = TokenCache::new();
        let account = test_account();
        cache.save(&test_result(&account)).unwrap();
        assert_eq!(cache.all_accounts().len(), 1);
        cache.remove_account(&account).unwrap();
        assert!(cache.all_accounts().is_empty());
        assert!(cache.lookup_refresh_token(&account).is_none());
    }

    #[test]
    fn clear_empties_everything() {
        let cache = TokenCache::new();
        cache.save(&test_result(&test_account())).unwrap();
        cache.clear().unwrap();
        assert!(cache.all_accounts().is_empty());
    }

    #[test]
    fn poisoned_lock_is_an_error_not_a_miss_for_fallible_api() {
        let cache = TokenCache::new();
        let _ = std::panic::catch_unwind(|| {
            let _guard = cache.state.write().unwrap();
            panic!("poison test");
        });
        assert!(matches!(
            cache.try_all_accounts(),
            Err(MsalError::CacheError(_))
        ));
        assert!(matches!(
            cache.try_lookup_refresh_token(&test_account()),
            Err(MsalError::CacheError(_))
        ));
    }
}
