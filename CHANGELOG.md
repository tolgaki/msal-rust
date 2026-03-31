# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-03-30

### Added

- `PublicClientApplication` with support for:
  - Authorization code flow with PKCE
  - Device code flow
  - Refresh token flow
  - Silent token acquisition (cache + refresh)
  - Username/password (ROPC) flow
  - Interactive authentication via native broker
- `ConfidentialClientApplication` with support for:
  - Client credentials flow
  - Authorization code flow
  - On-behalf-of flow
  - Refresh token flow
  - Silent token acquisition
- Native broker support via `NativeBroker` trait
- Windows WAM broker implementation (`broker-wam` feature)
- In-memory token cache with expiration handling
- Authority resolution via OpenID Connect discovery
- Support for AAD, Azure AD B2C, ADFS, and CIAM authorities
- PKCE code challenge/verifier generation
- Proof-of-Possession (PoP) token support in broker
- Configuration builder with validation

[Unreleased]: https://github.com/tolgaki/msal-rust/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/tolgaki/msal-rust/releases/tag/v0.1.0
