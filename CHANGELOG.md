# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- All OAuth requests accept validated extra server parameters and cooperative
  cancellation. `client_session` is transmitted without claiming live server
  enforcement; claims and challenge metadata are preserved without silent retry.
- Device/login requests obtain `client_info` and OIDC scopes. Refresh preserves
  trusted prior identity when realistic responses omit ID tokens or rotation.
  Account, resource tenant, environment, audience, issuer and nonce mismatches
  fail explicitly instead of silently yielding incomplete cached identities.
- Public authorization-code requests require the original PKCE verifier and
  nonce. `PkceParams` now retains the generated nonce.
- Cache keys include the complete account, tenant, environment and claims/EQP
  context. Atomic, client-bound serde snapshots support caller-owned protected
  persistence without creating secret files.
- Broker requests expose authority, force-refresh, EQP and cancellation.
  Unsupported native guarantees fail explicitly; macOS enumeration/sign-out no
  longer report false success. Native runtime behavior remains platform-specific.
- ID-token parsing documents the direct TLS/native provenance boundary, not a
  blanket public-client local-signature requirement or arbitrary-JWT validator.

These request-field additions and complete-identity cache keys are source/API
changes; prefer constructors and update explicit struct literals. No main-branch
or consumer integration changes are included.

## [0.1.0] - 2026-03-30

### Added

- `PublicClientApplication` with support for:
  - Authorization code flow with PKCE
  - Device code flow with polling
  - Refresh token flow
  - Silent token acquisition (cache + broker + refresh)
  - Username/password (ROPC) flow
  - Interactive authentication via native broker
  - Broker-aware sign-out and account enumeration
- `ConfidentialClientApplication` with support for:
  - Client credentials flow (app-only)
  - Authorization code flow with client credential
  - On-behalf-of flow (OBO)
  - Refresh token flow
  - Silent token acquisition
- Native broker support via `NativeBroker` trait
  - Windows WAM broker implementation (`broker-wam` feature)
  - macOS Enterprise SSO broker via `ASAuthorizationSingleSignOnProvider`
    (`broker-macos` feature) with GCD main-thread dispatch
- In-memory token cache with 5-minute expiration buffer
- Authority resolution via OpenID Connect discovery
- Support for AAD, Azure AD B2C, ADFS, and CIAM authorities
- PKCE code challenge/verifier generation (S256)
- Proof-of-Possession (PoP) token support in broker flows
- Configuration builder with validation
- Convenience constructors for all request types (`::new()`)
- Comprehensive error types with `thiserror`
- 85 tests (unit, integration, doc-tests, Send/Sync assertions)
- CI via GitHub Actions (check, test, clippy, fmt, doc, MSRV)
- MIT license, SECURITY.md, CONTRIBUTING.md

[Unreleased]: https://github.com/tolgaki/msal-rust/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/tolgaki/msal-rust/releases/tag/v0.1.0
