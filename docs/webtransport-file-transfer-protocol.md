# WebTransport file-transfer protocol

Status: **partial implementation; not ready for real transfers**. The endpoint supports PIN pairing, authenticated metadata operations, chunked upload/download, and clipboard access over framed WebTransport streams. The browser UI exposes those operations. It uses the File System Access API to stream downloads to disk where supported; browsers without that API are limited to files of 64 MiB or less to avoid buffering large files in memory. End-to-end browser/desktop testing remains pending. The browser probe remains a handshake diagnostic, not a file-transfer client.

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

Use one bidirectional stream per request/response operation. The first frame is a 4-byte unsigned big-endian header length followed by UTF-8 JSON. Reject header lengths of zero or above 64 KiB before allocation. For requests with a binary body (`upload.chunk`, `clipboard.set`), the request header declares its exact body length; cap each body at 8 MiB and stream it without buffering a whole file. `download.read` has no request body; the response header declares its binary body length. `clipboard.get` returns UTF-8 text as a bounded binary response body. Every declared length must match bytes received or sent exactly. A stream must be closed after one operation; never parse unbounded newline-delimited data or allocate based on untrusted lengths.

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

## Implementation status

- [x] Bounded length-prefixed JSON header framing and request validation.
- [x] Pairing checks the PIN, validates an optional device ID, registers trusted devices within the existing device cap, and issues an expiring server-side session.
- [x] Authenticated `session.check` and `files.list` dispatch over separate bidirectional streams.
- [x] `upload.start`, `upload.status`, `upload.chunk`, `upload.finish`, and `upload.cancel`, routed through the existing hardened upload handlers.
- [x] `download.start` and bounded binary `download.read` responses, with session/device-bound expiring tickets and the shared concurrent-download limit.
- [x] `clipboard.get` and `clipboard.set`, with a 1 MiB cap and binary UTF-8 payloads.
- [x] Browser UI for pairing, file listing, chunked upload/download, and clipboard over this transport; no HTTP transfer fallback.
- [ ] End-to-end automated tests with a real browser and desktop server, including disconnect/revocation and large-file cases.

Unsupported operations return a stable error and must not be routed to the legacy HTTP endpoints as a fallback. Until end-to-end browser/desktop tests pass, this branch is development work and must not be presented as verified secure end-to-end file transfer.

### Browser client module

`docs/aetherdrop-webtransport.js` exposes `connectAetherDrop({ host, hash, pin, deviceId })`. It opens WebTransport with SHA-256 certificate pinning, pairs over the existing bounded newline handshake, and returns a session-bound client whose `request()` currently permits only `session.check` and `files.list`. It rejects unsupported operations locally and never falls back to HTTP. This module is a transport building block, not yet the complete mobile UI.

## Required operations

- `session.check`: verify that the session exists, is unexpired, and has not been revoked.
- `files.list`: list the explicitly shared PC files using opaque IDs and display names only.
- `upload.start`, `upload.status`, `upload.chunk`, `upload.finish`, `upload.cancel`: preserve current bounded chunking, per-device quotas, disk-space reserve, cancellation, revalidation, hash checks, atomic no-overwrite publication, and resumability. Binary chunks must be streamed and capped; do not buffer whole files in memory.
- `download.start` and `download.read`: authorize a session/device-bound expiring ticket against the shared file, stream bounded chunks, and refresh the short expiry while active; the session must remain valid for every request.
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
