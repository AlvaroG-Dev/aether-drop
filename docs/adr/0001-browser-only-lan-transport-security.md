# ADR: Browser-only LAN transport security

- Status: accepted as the implementation direction; handshake probe works, real transfer transport remains pending
- Date: 2026-10-22

## Requirements

- File data travels directly between the desktop and phone over the LAN.
- No relay, tunnel, account, or cloud storage.
- No certificate-warning bypass, user-installed CA, or insecure HTTP fallback for transfers.
- The phone UI remains browser-based; a native app is out of scope for now.
- If the browser cannot authenticate the desktop connection, transfer must fail closed.

## Findings

The current mobile URL is `http://<LAN-IP>:8080`. This is not a secure context, and normal browser fetch/WebSocket APIs do not provide a way for JavaScript to override TLS certificate validation.

WebTransport is a possible transport for a future browser implementation because its `serverCertificateHashes` option can authenticate an ephemeral server certificate by SHA-256 hash instead of ordinary Web PKI. This is not a general-purpose certificate-warning bypass: the client must know the expected leaf-certificate hash through a trusted pairing channel, and the server must prove possession of the corresponding private key.

Important constraints:

1. WebTransport is only available in secure contexts. Serving the page from the current plain-HTTP LAN origin does not satisfy this prerequisite.
2. WebTransport requires an HTTP/3-capable server. The current Axum HTTP/1.1/HTTP/2 server on port 8080 cannot be reused as-is; this requires a separate QUIC/HTTP/3 transport implementation.
3. The WebTransport certificate-hash mechanism has strict certificate requirements, including a short validity period (at most 14 days) and an interoperable ECDSA P-256 key. Certificate rotation and overlapping pins need a designed protocol.
4. Browser support is version-dependent. Current compatibility data lists Safari and Safari on iOS support from version 26.4, so older phones cannot be assumed to support it.
5. A secure HTTPS origin is still required to deliver the browser UI. A static HTTPS-hosted UI could connect directly to the PC over the LAN without relaying file data, but the initial page load would depend on internet access and the UI's origin. This conflicts with a fully offline, self-contained LAN-only setup.

References:
- W3C WebTransport specification: https://www.w3.org/TR/webtransport/
- MDN WebTransport API: https://developer.mozilla.org/en-US/docs/Web/API/WebTransport_API
- Browser compatibility: https://caniuse.com/webtransport

## Decision

Do not try to make the existing HTTP endpoint look secure, and do not silently fall back to HTTP for transfers.

The most promising browser-only experiment is:

1. Serve a minimal mobile UI from a trusted HTTPS static origin (no file data is sent to that origin).
2. Add a separate local HTTP/3/WebTransport server in the desktop app.
3. Generate an ephemeral ECDSA P-256 certificate with validity no longer than 14 days and publish its leaf-certificate SHA-256 hash through the desktop-generated pairing QR.
4. Require explicit pairing confirmation and bind the resulting session to the device, then authenticate all application messages and enforce size, rate, expiry, and cancellation limits.
5. Test current Chrome Android and Safari iOS versions, including local-network permission behavior, certificate rotation, malformed messages, reconnects, and unsupported-browser failure.
6. If either the secure-context requirement or browser support prevents the requested experience, fail closed and report the incompatibility; do not downgrade to plain HTTP.

## Non-goals

- Installing a root CA or asking the user to trust a certificate manually.
- Disabling TLS validation or hiding browser security warnings.
- Sending file contents through a public relay.
- Claiming end-to-end encryption before the protocol and implementation have been reviewed and tested.

## Transfer protocol plan

The framing, pairing/session requirements, required operations, migration sequence, and acceptance criteria are tracked in [the WebTransport file-transfer protocol](../webtransport-file-transfer-protocol.md). This is a specification, not an implementation; the existing probe endpoint still does not transfer files.

## Current security status

The existing transfer endpoint still uses plain HTTP. This ADR does not change that code and does not make the current build safe for confidential transfers. Until the new transport is implemented and tested, treat the current build as a development prototype only.
