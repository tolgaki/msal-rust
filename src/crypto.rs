//! Cryptographic utilities for OAuth 2.0 and OpenID Connect.
//!
//! Provides PKCE code challenge generation, nonce/correlation-ID helpers,
//! and a lightweight JWT payload decoder.

use base64::Engine;
use sha2::{Digest, Sha256};

use crate::error::Result;

/// PKCE (Proof Key for Code Exchange) parameters.
///
/// Used with the authorization code flow to prevent authorization code
/// interception attacks. See [RFC 7636](https://tools.ietf.org/html/rfc7636).
///
/// ```
/// use msal::crypto::PkceParams;
///
/// let pkce = PkceParams::generate();
/// assert!(!pkce.verifier.is_empty());
/// assert!(!pkce.challenge.is_empty());
/// assert_eq!(pkce.challenge_method, "S256");
/// ```
#[derive(Debug, Clone)]
pub struct PkceParams {
    /// The code verifier (high-entropy random string).
    pub verifier: String,
    /// The code challenge (base64url-encoded SHA-256 of the verifier).
    pub challenge: String,
    /// The challenge method (always `"S256"`).
    pub challenge_method: &'static str,
}

impl PkceParams {
    /// Generate a new PKCE verifier and S256 challenge.
    pub fn generate() -> Self {
        let verifier = generate_random_string(43);
        let challenge = base64_url_encode_sha256(verifier.as_bytes());
        PkceParams {
            verifier,
            challenge,
            challenge_method: "S256",
        }
    }
}

/// Generate a UUID v4 nonce for use in OpenID Connect requests.
pub fn generate_nonce() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Generate a UUID v4 correlation ID for request tracing.
pub fn generate_correlation_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Generate a random string of the given length from the unreserved character set.
fn generate_random_string(len: usize) -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

/// Compute SHA-256 and return the base64url-encoded (no padding) result.
fn base64_url_encode_sha256(input: &[u8]) -> String {
    let hash = Sha256::digest(input);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash)
}

/// Decode a JWT payload without signature verification.
///
/// This is used internally to extract claims from ID tokens returned by the
/// token endpoint. Signature verification is not performed because the token
/// was received over a direct HTTPS channel from the authority.
pub fn decode_jwt_payload(token: &str) -> Result<serde_json::Value> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(crate::error::MsalError::InvalidToken(
            "JWT must have 3 parts".into(),
        ));
    }
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| crate::error::MsalError::InvalidToken(format!("invalid JWT base64: {e}")))?;
    serde_json::from_slice(&payload).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_generates_valid_params() {
        let pkce = PkceParams::generate();
        assert_eq!(pkce.verifier.len(), 43);
        assert_eq!(pkce.challenge_method, "S256");
        // Challenge should be a valid base64url string.
        assert!(!pkce.challenge.is_empty());
        assert!(!pkce.challenge.contains('+'));
        assert!(!pkce.challenge.contains('/'));
    }

    #[test]
    fn nonce_is_uuid() {
        let nonce = generate_nonce();
        assert_eq!(nonce.len(), 36); // UUID v4 with hyphens.
    }

    #[test]
    fn decode_jwt_payload_valid() {
        // Build a minimal JWT: header.payload.signature
        let payload = serde_json::json!({"sub": "user123", "name": "Test"});
        let encoded_payload =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.to_string());
        let token = format!("eyJhbGciOiJSUzI1NiJ9.{encoded_payload}.fakesig");

        let claims = decode_jwt_payload(&token).unwrap();
        assert_eq!(claims["sub"], "user123");
        assert_eq!(claims["name"], "Test");
    }

    #[test]
    fn decode_jwt_payload_invalid_parts() {
        let result = decode_jwt_payload("not.a-jwt");
        assert!(result.is_err());
    }
}
