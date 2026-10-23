# WebTransport file-transfer protocol

Status: implementation plan; **not implemented**. The existing `webtransport.rs` endpoint is a pairing probe only. Do not treat this document or the probe as evidence that real transfers use WebTransport.

## Security invariants

- File contents, filenames, clipboard data, session credentials, and transfer metadata must travel only inside the authenticated WebTransport connection.
- The client must validate the pinned certificate hash before sending the PIN or any application data.
- A missing WebTransport API, rejected certificate pin, wrong Origin, wrong PIN, expired session, malformed frame, timeout, or dropped connection must fail closed. There is no HTTP transfer fallback.
- GitHub Pages serves only the static browser UI. It must never receive file bytes or clipboard contents.
- The current HTTP/8080 API is legacy and must not be called by the browser client after migration. Do not remove its server-side protections until the WebTransport handlers have equivalent or stronger protections and tests.

## Connection and pairing

1. The desktop generates a short-lived ECDSA P-256 certificate supported by WebTransport certificate-hash authentication and exposes its SHA-256 leaf hash in a QR code alongside the LAN address.
2. The browser loads the static UI from the fixed HTTPS origin, validates all URL parameters, verifies WebTransport support, and connects directly to the desktop over UDP/HTTP/3.
3. Before sending the PIN, the browser supplies the expected SHA-256 certificate hash through `serverCertificateHashes`. If the browser cannot perform this validation, it stops.
4. The browser opens a bidirectional stream and sends one bounded UTF-8 JSON line:
   `{"type":"pair","version":1,"pin":"000000","device_id":"dev_..."}\n`
5. The server checks the Origin, exact path, input size, rate limit, PIN in constant time, and device identifier. On success it returns a bounded JSON line with an opaque random session credential and expiry. The credential is valid only for this server process and is bound to the paired device. The server must not return a reusable credential before validating the PIN.
6. The browser keeps the WebTransport session alive and stores credentials only for the lifetime needed by the app. A reconnect must re-authenticate or prove possession of a current session credential over the newly pinned connection.

## Framing

Use one bidirectional stream per request/response operation. The first frame is a 4-byte unsigned big-endian header length followed by UTF-8 JSON. Reject header lengths of zero or above 64 KiB before allocation. For operations with a binary body, the header declares its exact byte length and the server enforces the operation-specific cap. Responses use the same framing, with a JSON header followed by the declared binary payload. A stream must be closed after one operation; never parse unbounded newline-delimited data or allocate based on untrusted lengths.

Common request fields:
- `version`: protocol version, initially `1`
- `request_id`: random per-request identifier
- `session`: opaque session credential, except for pairing
- `op`: allow-listed operation name
- operation-specific fields validated with strict schemas that reject unknown fields

Common response fields:
- `version`, `request_id`, `ok`
- successful operation result, or a stable non-sensitive error code
- no filesystem paths, stack traces, PIN values, or secrets in errors

## Required operations

- `session.check`: verify that the session exists, is unexpired, and has not been revoked.
- `files.list`: list the explicitly shared PC files using opaque IDs and display names only.
- `upload.start`, `upload.status`, `upload.chunk`, `upload.finish`, `upload.cancel`: preserve current bounded chunking, per-device quotas, disk-space reserve, cancellation, revalidation, hash checks, atomic no-overwrite publication, and resumability. Binary chunks must be streamed and capped; do not buffer whole files in memory.
- `download.start` and `download.read`: authorize a one-use ticket against device/session/file, stream bounded chunks, and expire/cancel on revocation.
- `clipboard.get`, `clipboard.set`: enforce the existing 1 MiB text cap and reject malformed input.
- `session.revoke` remains a desktop-local operation; a paired browser must not be able to revoke other devices.

## Transfer correctness and abuse resistance

- Reuse the existing server-side transfer implementation where possible, but factor business logic into transport-independent functions rather than bypassing it or calling HTTP handlers with fabricated requests.
- Preserve the 2 GiB file limit, 8 MiB upload chunks, maximum three concurrent uploads/downloads, 24 pending uploads overall, four per device, and current cleanup/expiry semantics unless tests justify a stricter limit.
- Validate filenames as leaf names only; never accept a client-supplied destination path.
- Check session validity and cancellation between chunks and during long transfers.
- Enforce global and per-device limits on concurrent streams, message sizes, and operation rates.
- Use SHA-256 for integrity checks, not as a substitute for authenticated transport.
- On interruption, keep resumable state only while its owning session remains valid and the configured TTL has not elapsed.

## Migration and acceptance criteria

1. Add protocol parsing/framing unit tests for short/oversized headers, truncated frames, invalid UTF-8/JSON, unknown operations, wrong protocol versions, length overflow, and unknown fields.
2. Factor existing transfer logic out of Axum handlers into shared application services and add direct unit tests for authorization, revocation, quotas, cancellation, disk-full errors, duplicate filenames, and cleanup.
3. Implement WebTransport dispatch against those shared services; do not expose the old HTTP endpoints to the browser.
4. Move the full mobile UI to the HTTPS static origin and replace every API `fetch`/XHR with the WebTransport client. The only permitted requests to the public host are static assets; no transfer data is relayed.
5. Add browser tests for pairing, invalid PIN, pin mismatch, reconnect, lost responses, resumed upload, cancellation, download integrity, clipboard limits, and unsupported WebTransport.
6. Verify on current Chrome for Android and Safari for iOS, including local-network permissions and firewall behavior. Unsupported browsers must display a clear error and must not attempt HTTP.
7. Update README security claims only after end-to-end tests pass. Until then, this remains a development prototype and must not be used for confidential files.
