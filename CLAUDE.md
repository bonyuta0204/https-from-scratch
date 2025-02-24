# HTTPS From Scratch

## Build Commands
- Build: `cargo build`
- Run: `cargo run`
- Test: `cargo test`
- Run single test: `cargo test test_name`
- Run example: `cargo run --example http2_client`
- Lint: `cargo clippy`
- Format: `cargo fmt`

## Code Style Guidelines
- **Naming**: Use snake_case for variables/functions, CamelCase for types/structs
- **Imports**: Group imports logically, sort alphabetically within groups
- **Error Handling**: Use Result with Error enum, include proper context
- **Comments**: Document public interfaces with doc comments (`//!` for modules, `///` for items)
- **Formatting**: Max line length 100 chars, 4-space indentation
- **Logging**: Use println! for now (will eventually be replaced by proper logging)
- **Types**: Use strong typing, prefer owned types over references when possible
- **HTTP/2**: Follow RFC 7540 specification for HTTP/2 implementation
- **TLS**: Use rustls for TLS with proper ALPN negotiation