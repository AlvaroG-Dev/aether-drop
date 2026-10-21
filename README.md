# AetherDrop

**Move files between your devices. Keep the handoff simple.**

AetherDrop is an early-stage, Rust + Tauri desktop app for moving files between a computer and a phone on the same local network. The desktop dashboard shows a QR code for the mobile web interface and a visual device-bridge concept.

> **Development status: prototype. Do not treat this version as production-ready for sensitive files.** The local HTTP transport is not encrypted yet, and this branch has not been compiled or penetration-tested in a real environment. Do not advertise end-to-end encryption.

## Current prototype

- Tauri 2 desktop shell with a Rust backend.
- Axum server for the local-network mobile web interface.
- QR code and local address for pairing.
- Six-digit pairing PIN, bearer session tokens, session checks, and a basic failed-attempt cooldown.
- Trusted-device list and revocation checks for active session tokens.
- Multiple-file upload UI with progress reporting.
- Filename validation and no-overwrite file creation on upload.
- Animated desktop and mobile device-bridge bubbles; mobile packets animate during an actual upload.
- Reduced-motion support for the bridge animation.

## Planned product

1. **Security and reliability:** encrypted transport, robust authentication, strict upload limits, safe file handling, test coverage, and review of every endpoint.
2. **Desktop MVP:** polished Windows and Linux packages, clear transfer state, drag-and-drop, cancel/retry, and reliable error reporting.
3. **Android:** native app experience alongside QR/browser handoff.
4. **macOS and iOS:** build, test, sign, and distribute when Apple tooling and hardware are available.
5. **Growth:** public documentation, demo videos, feedback loops, and privacy-respecting metrics.

## Security notes

- The mobile server currently listens on port 8080 on all network interfaces so devices on the LAN can reach it.
- The transport uses HTTP. Bearer tokens and uploaded content can therefore be exposed to an attacker able to observe or interfere with the local network. **Pairing tokens do not replace transport encryption.**
- The PIN attempt cooldown is a basic in-process guard, not a substitute for a reviewed rate-limiting and threat model.
- The upload handler rejects path-like names and avoids silently overwriting existing files, but the whole upload lifecycle still needs adversarial testing.
- Do not expose port 8080 to the public Internet or use this prototype for confidential data.
- Only claim encrypted or end-to-end encrypted transfer after the transport and key-verification design has been implemented and independently tested.

## Development

Install the prerequisites for [Tauri 2](https://v2.tauri.app/start/prerequisites/), Rust, and Node.js.

```bash
npm install
npm run tauri dev
```

Rust checks:

```bash
cargo fmt --manifest-path src-tauri/Cargo.toml --all -- --check
cargo check --manifest-path src-tauri/Cargo.toml
```

## Contributing

Bug reports and practical feedback are welcome. Please include your operating system, the device pair tested, file size, and steps to reproduce. Never attach private files or secrets to an issue.
