# Contributing to MSAL for Rust

Thank you for your interest in contributing to the Microsoft Authentication
Library for Rust! This document provides guidelines and information for
contributors.

## Code of Conduct

This project has adopted the
[Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information, see the
[Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com).

## Getting Started

1. Fork and clone the repository
2. Install Rust 1.75+ via [rustup](https://rustup.rs/)
3. Run `cargo build` to verify setup
4. Run `cargo test` to run the test suite

## Development

### Building

```sh
# Default build
cargo build

# With WAM broker support (Windows only)
cargo build --features broker-wam

# With macOS Enterprise SSO broker support
cargo build --features broker-macos

# Run all checks
cargo clippy
cargo fmt --check
cargo test
cargo doc --no-deps
```

### Testing

```sh
# Run all tests
cargo test

# Run a specific test
cargo test test_name

# Run tests with output
cargo test -- --nocapture
```

### Code Style

- Run `cargo fmt` before committing
- Run `cargo clippy --all-features` and address warnings
- Follow standard Rust naming conventions
- Add doc comments (`///`) to all public items
- Keep error messages lowercase (Rust convention)

## Pull Requests

1. Create a feature branch from `main`
2. Make focused, atomic commits
3. Add tests for new functionality
4. Ensure `cargo test`, `cargo clippy`, and `cargo fmt --check` pass
5. Update documentation if the public API changes
6. Open a pull request with a clear description

### PR Checklist

- [ ] Code compiles without warnings (`cargo clippy --all-features`)
- [ ] All tests pass (`cargo test`)
- [ ] Code is formatted (`cargo fmt --check`)
- [ ] Documentation builds (`cargo doc --no-deps`)
- [ ] Public API changes are documented
- [ ] New features have tests
- [ ] CHANGELOG.md is updated (for user-facing changes)

## Reporting Issues

Use [GitHub Issues](https://github.com/tolgaki/msal-rust/issues)
to report bugs or request features. Include:

- Rust version (`rustc --version`)
- OS and version
- Steps to reproduce
- Expected vs actual behavior
- Relevant error messages or logs

## Security Issues

**Do not report security vulnerabilities through public issues.** See
[SECURITY.md](SECURITY.md) for instructions.

## License

By contributing, you agree that your contributions will be licensed under the
[MIT License](LICENSE).
