# Void Rooms

Privacy-first group chat with end-to-end encryption and explicit defenses against traffic analysis. The product aims for a familiar room-and-invite experience without requiring a centralized identity account.

> **Status:** early research and implementation. Cryptographic and metadata-privacy guarantees are **not production-validated**.

## Architecture

- **Core:** Rust workspace; shared types and versioned envelopes.
- **Group encryption:** OpenMLS candidate, evaluated through a native integration spike and a browser/WASM feasibility laboratory.
- **Client (planned):** web UI with a Rust/WASM security core.
- **Relay (planned):** untrusted Rust service for opaque envelope delivery.
- **Metadata privacy (planned):** padding, scheduled transmission, cover traffic, identifier minimization and origin-protecting transport options.

The relay must not possess room secrets or authority to admit participants. E2EE does not by itself hide IP addresses, timing, traffic volume or communication relationships.

## Security scope

Void Rooms is designed against untrusted relays and network observers, including active interference and traffic correlation. Stronger anonymity properties depend on transport choice, endpoint integrity and measurable defenses; they must not be inferred from encryption alone.

**Do not use this prototype for sensitive communications.**
