/**
 * Browser WebTransport client for the currently implemented AetherDrop operations.
 * This module intentionally has no HTTP fallback.
 */
const PROTOCOL_VERSION = 1;
const MAX_HEADER_BYTES = 64 * 1024;
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

function withTimeout(promise, milliseconds, message) {
  let timer;
  return Promise.race([
    promise,
    new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(message)), milliseconds);
    }),
  ]).finally(() => clearTimeout(timer));
}

function isLanIpv4(host) {
  const parts = host.split(".");
  if (parts.length !== 4 || parts.some(part => !/^(0|[1-9][0-9]{0,2})$/.test(part))) return false;
  const octets = parts.map(Number);
  if (octets.some(part => part > 255)) return false;
  const [a, b] = octets;
  return a === 10 ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 169 && b === 254) ||
    a === 127;
}

function hexBytes(hex) {
  if (!/^[a-fA-F0-9]{64}$/.test(hex)) throw new Error("Invalid SHA-256 certificate hash");
  return Uint8Array.from(hex.match(/../g), byte => Number.parseInt(byte, 16));
}

function encodeFrame(value) {
  const json = encoder.encode(JSON.stringify(value));
  if (!json.length || json.length > MAX_HEADER_BYTES) throw new Error("Protocol header is out of bounds");
  const frame = new Uint8Array(4 + json.length);
  new DataView(frame.buffer).setUint32(0, json.length, false);
  frame.set(json, 4);
  return frame;
}

function createByteReader(reader) {
  let pending = new Uint8Array(0);
  return {
    async readExact(length) {
      const result = new Uint8Array(length);
      let offset = 0;
      while (offset < length) {
        if (pending.length === 0) {
          const { value, done } = await reader.read();
          if (done || !value || value.length === 0) throw new Error("Truncated WebTransport response");
          pending = value;
        }
        const take = Math.min(pending.length, length - offset);
        result.set(pending.subarray(0, take), offset);
        offset += take;
        pending = pending.subarray(take);
      }
      return result;
    },
    async cancel() { return reader.cancel(); },
  };
}

async function readJsonLine(reader, limit = 512) {
  let bytes = new Uint8Array(0);
  while (bytes.length < limit) {
    const { value, done } = await reader.read();
    if (done) break;
    if (!value) continue;
    const newline = value.indexOf(10);
    const part = newline < 0 ? value : value.subarray(0, newline);
    if (bytes.length + part.length > limit) throw new Error("Pairing response exceeds limit");
    const combined = new Uint8Array(bytes.length + part.length);
    combined.set(bytes);
    combined.set(part, bytes.length);
    bytes = combined;
    if (newline >= 0) return JSON.parse(decoder.decode(bytes));
  }
  throw new Error("Incomplete pairing response");
}

export async function connectAetherDrop({ host, hash, pin, deviceId, port = 8443 }) {
  if (!/^[0-9]{6}$/.test(pin)) throw new Error("PIN must contain six digits");
  if (!/^dev_[A-Za-z0-9_-]{1,60}$/.test(deviceId)) throw new Error("Invalid device identifier");
  if (!isLanIpv4(host)) throw new Error("The PC address must be a private IPv4 address on your LAN");
  if (!("WebTransport" in globalThis) || !globalThis.isSecureContext) {
    throw new Error("This browser does not support WebTransport in a secure context");
  }

  const transport = new WebTransport(`https://${host}:${port}/aetherdrop-wt-probe-v1`, {
    allowPooling: false,
    requireUnreliable: true,
    serverCertificateHashes: [{ algorithm: "sha-256", value: hexBytes(hash) }],
  });
  try {
    await withTimeout(transport.ready, 10000, 'Timed out connecting to the PC');
    const stream = await transport.createBidirectionalStream();
    const writer = stream.writable.getWriter();
    const reader = stream.readable.getReader();
    await writer.write(encoder.encode(JSON.stringify({ type: "pair", pin, device_id: deviceId }) + "\n"));
    await writer.close();
    const paired = await withTimeout(readJsonLine(reader), 10000, 'Timed out waiting for the pairing response');
    if (!paired.ok || paired.protocol !== "aetherdrop-webtransport-v1" ||
        typeof paired.token !== "string" || !/^[A-Za-z0-9]+$/.test(paired.token)) {
      throw new Error("Pairing was rejected or no session was issued");
    }
    await reader.cancel().catch(() => {});
    return {
      transport,
      session: paired.token,
      expiresIn: paired.expires_in,
      async request(op, data, body = null) {
        if (!["session.check", "files.list", "download.start", "download.read", "upload.start", "upload.status", "upload.chunk", "upload.finish", "upload.cancel", "clipboard.get", "clipboard.set"].includes(op)) {
          throw new Error("This WebTransport operation is not implemented yet");
        }
        const requestId = crypto.randomUUID().replace(/-/g, "");
        const requestStream = await transport.createBidirectionalStream();
        const requestWriter = requestStream.writable.getWriter();
        const responseReader = createByteReader(requestStream.readable.getReader());
        if (body !== null && (!(body instanceof Uint8Array) || body.byteLength > 8 * 1024 * 1024)) {
          throw new Error("Request body exceeds the allowed chunk size");
        }
        await requestWriter.write(encodeFrame({
          version: PROTOCOL_VERSION,
          request_id: requestId,
          op,
          session: paired.token,
          ...(data === undefined ? {} : { data }),
          ...(body === null ? {} : { payload_bytes: body.byteLength }),
        }));
        if (body !== null) await requestWriter.write(body);
        await requestWriter.close();
        const prefix = await withTimeout(responseReader.readExact(4), 30000, 'Timed out waiting for the response');
        const length = new DataView(prefix.buffer, prefix.byteOffset, 4).getUint32(0, false);
        if (!length || length > MAX_HEADER_BYTES) throw new Error("Invalid response header length");
        const payload = await withTimeout(responseReader.readExact(length), 30000, 'Timed out reading the response header');
        const response = JSON.parse(decoder.decode(payload));
        if (response.request_id !== requestId || response.version !== PROTOCOL_VERSION) {
          throw new Error("Response does not match the request");
        }
        if (!response.ok) throw new Error(response.error || "WebTransport request failed");
        let binary = null;
        if (response.payload_bytes !== undefined && response.payload_bytes !== null) {
          if (!Number.isSafeInteger(response.payload_bytes) || response.payload_bytes < 0 ||
              response.payload_bytes > 8 * 1024 * 1024) {
            throw new Error("Response body exceeds the allowed chunk size");
          }
          binary = await withTimeout(responseReader.readExact(response.payload_bytes), 60000, 'Timed out reading the response body');
        }
        await responseReader.cancel().catch(() => {});
        return binary === null ? response.result : { result: response.result, payload: binary };
      },
      close() { transport.close({ closeCode: 0, reason: "Client closed" }); },
    };
  } catch (error) {
    transport.close({ closeCode: 1, reason: "Connection or pairing failed" });
    throw error;
  }
}
