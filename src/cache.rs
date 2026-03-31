//! In-memory token cache.
//!
//! The [`TokenCache`] stores access tokens, refresh tokens, and account
//! information in memory. It is used automatically by
//! [`PublicClientApplication`](crate::PublicClientApplication) and
//! [`ConfidentialClientApplication`](crate::ConfidentialClientApplication)
//! to avoid unnecessary token endpoint calls.
//!
//! Access tokens are considered expired 5 minutes before their actual
//! expiration to account for clock skew.

use std::collections::HashMap;
use std::sync::RwLock;

use crate::account::AccountInfo;
use crate::error::{MsalError, Result};
use crate::response::AuthenticationResult;

/// Cache key for access token lookups.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct AccessTokenKey {
    home_account_id: String,
    environment: String,
    scope_set: String,
    tenant_id: String,
}

/// Cached access token entry.
#[derive(Debug, Clone)]
struct AccessTokenEntry {
    access_token: String,
    expires_on: i64,
    ext_expires_on: Option<i64>,
    scopes: Vec<String>,
    token_type: String,
}

/// Cached refresh token entry.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields used for debugging and future serialization.
struct RefreshTokenEntry {
    refresh_token: String,
    home_account_id: String,
    environment: String,
}

/// Thread-safe in-memory token cache.
///
/// All methods acquire the internal lock for the shortest possible duration.
/// The cache is safe to share across threads via `Arc`.
#[derive(Debug)]
pub struct TokenCache {
    access_tokens: RwLock<HashMap<AccessTokenKey, AccessTokenEntry>>,
    refresh_tokens: RwLock<HashMap<String, RefreshTokenEntry>>,
    accounts: RwLock<HashMap<String, AccountInfo>>,
}

impl TokenCache {
    /// Create an empty token cache.
    pub fn new() -> Self {
        Self {
            access_tokens: RwLock::new(HashMap::new()),
            refresh_tokens: RwLock::new(HashMap::new()),
            accounts: RwLock::new(HashMap::new()),
        }
    }

    /// Store tokens and account from an [`AuthenticationResult`].
    pub fn save(&self, result: &AuthenticationResult) {
        if let Some(ref account) = result.account {
            let mut normalized_scopes: Vec<String> =
                result.scopes.iter().map(|s| s.to_lowercase()).collect();
            normalized_scopes.sort();

            let key = AccessTokenKey {
                home_account_id: account.home_account_id.clone(),
                environment: account.environment.clone(),
                scope_set: normalized_scopes.join(" "),
                tenant_id: account.tenant_id.clone(),
            };

            if let Ok(mut tokens) = self.access_tokens.write() {
                tokens.insert(
                    key,
                    AccessTokenEntry {
                        access_token: result.access_token.clone(),
                        expires_on: result.expires_on,
                        ext_expires_on: result.ext_expires_on,
                        scopes: result.scopes.clone(),
                        token_type: result.token_type.clone(),
                    },
                );
            }

            if let Some(ref rt) = result.refresh_token {
                if let Ok(mut rts) = self.refresh_tokens.write() {
                    rts.insert(
                        account.home_account_id.clone(),
                        RefreshTokenEntry {
                            refresh_token: rt.clone(),
                            home_account_id: account.home_account_id.clone(),
                            environment: account.environment.clone(),
                        },
                    );
                }
            }

            if let Ok(mut accts) = self.accounts.write() {
                accts.insert(account.cache_key(), account.clone());
            }
        }
    }

    /// Look up a cached access token for the given account and scopes.
    ///
    /// Returns `None` if no matching token is found or if the token has
    /// expired (with a 5-minute buffer).
    pub fn lookup_access_token(
        &self,
        account: &AccountInfo,
        scopes: &[String],
    ) -> Option<AuthenticationResult> {
        let mut normalized: Vec<String> = scopes.iter().map(|s| s.to_lowercase()).collect();
        normalized.sort();

        let key = AccessTokenKey {
            home_account_id: account.home_account_id.clone(),
            environment: account.environment.clone(),
            scope_set: normalized.join(" "),
            tenant_id: account.tenant_id.clone(),
        };

        let tokens = self.access_tokens.read().ok()?;
        let entry = tokens.get(&key)?;

        let now = chrono::Utc::now().timestamp();
        // 5-minute buffer for clock skew.
        if entry.expires_on <= now + 300 {
            return None;
        }

        Some(AuthenticationResult {
            access_token: entry.access_token.clone(),
            id_token: None,
            scopes: entry.scopes.clone(),
            expires_on: entry.expires_on,
            ext_expires_on: entry.ext_expires_on,
            account: Some(account.clone()),
            tenant_id: Some(account.tenant_id.clone()),
            correlation_id: None,
            token_type: entry.token_type.clone(),
            refresh_token: None,
        })
    }

    /// Look up a cached refresh token for the given account.
    pub fn lookup_refresh_token(&self, account: &AccountInfo) -> Option<String> {
        let rts = self.refresh_tokens.read().ok()?;
        rts.get(&account.home_account_id)
            .map(|e| e.refresh_token.clone())
    }

    /// Return all cached accounts.
    pub fn all_accounts(&self) -> Vec<AccountInfo> {
        self.accounts
            .read()
            .map(|a| a.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Remove an account and all associated tokens from the cache.
    pub fn remove_account(&self, account: &AccountInfo) -> Result<()> {
        let cache_key = account.cache_key();

        self.accounts
            .write()
            .map_err(|_| MsalError::CacheError("lock poisoned".into()))?
            .remove(&cache_key);

        self.access_tokens
            .write()
            .map_err(|_| MsalError::CacheError("lock poisoned".into()))?
            .retain(|k, _| k.home_account_id != account.home_account_id);

        self.refresh_tokens
            .write()
            .map_err(|_| MsalError::CacheError("lock poisoned".into()))?
            .remove(&account.home_account_id);

        Ok(())
    }

    /// Remove all tokens and accounts from the cache.
    pub fn clear(&self) {
        if let Ok(mut t) = self.access_tokens.write() {
            t.clear();
        }
        if let Ok(mut r) = self.refresh_tokens.write() {
            r.clear();
        }
        if let Ok(mut a) = self.accounts.write() {
            a.clear();
        }
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
        let result = test_result(&account);

        cache.save(&result);

        let scopes = vec!["user.read".into()];
        let cached = cache.lookup_access_token(&account, &scopes);
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().access_token, "access-token-value");
    }

    #[test]
    fn lookup_returns_none_for_expired_token() {
        let cache = TokenCache::new();
        let account = test_account();
        let mut result = test_result(&account);
        result.expires_on = chrono::Utc::now().timestamp() - 1; // Already expired.

        cache.save(&result);

        let scopes = vec!["user.read".into()];
        assert!(cache.lookup_access_token(&account, &scopes).is_none());
    }

    #[test]
    fn lookup_refresh_token() {
        let cache = TokenCache::new();
        let account = test_account();
        let result = test_result(&account);

        cache.save(&result);

        let rt = cache.lookup_refresh_token(&account);
        assert_eq!(rt.as_deref(), Some("refresh-token-value"));
    }

    #[test]
    fn remove_account_clears_tokens() {
        let cache = TokenCache::new();
        let account = test_account();
        let result = test_result(&account);

        cache.save(&result);
        assert_eq!(cache.all_accounts().len(), 1);

        cache.remove_account(&account).unwrap();
        assert!(cache.all_accounts().is_empty());
        assert!(cache.lookup_refresh_token(&account).is_none());
    }

    #[test]
    fn clear_empties_everything() {
        let cache = TokenCache::new();
        let account = test_account();
        let result = test_result(&account);

        cache.save(&result);
        cache.clear();

        assert!(cache.all_accounts().is_empty());
    }
}
