'use strict';

const assert = require('node:assert/strict');
const { webcrypto } = require('node:crypto');
globalThis.crypto ||= webcrypto;
globalThis.isSecureContext = true;

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const state = { instances: [], streamsOpened: 0, pairRequest: null, extraResponseBytes: null, extraPairBytes: null, truncateResponse: false };

class ByteQueue {
  constructor() { this.items = []; this.waiters = []; this.closed = false; }
  push(value) {
    const item = { value: new Uint8Array(value), done: false };
    const waiter = this.waiters.shift();
    if (waiter) waiter(item); else this.items.push(item);
  }
  end() {
    this.closed = true;
    while (this.waiters.length) this.waiters.shift()({ value: undefined, done: true });
  }
  reader() {
    return {
      read: () => {
        if (this.items.length) return Promise.resolve(this.items.shift());
        if (this.closed) return Promise.resolve({ value: undefined, done: true });
        return new Promise(resolve => this.waiters.push(resolve));
      },
      cancel: async () => this.end(),
    };
  }
}

function join(parts) {
  const length = parts.reduce((sum, part) => sum + part.length, 0);
  const result = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) { result.set(part, offset); offset += part.length; }
  return result;
}

function frame(value, payload = null) {
  const json = encoder.encode(JSON.stringify(value));
  const header = new Uint8Array(4 + json.length);
  new DataView(header.buffer).setUint32(0, json.length, false);
  header.set(json, 4);
  return payload === null ? header : join([header, payload]);
}

class FakeWebTransport {
  constructor(url, options) {
    this.url = url;
    this.options = options;
    this.closed = false;
    this.ready = Promise.resolve();
    state.instances.push(this);
  }
  async createBidirectionalStream() {
    state.streamsOpened += 1;
    const queue = new ByteQueue();
    const writes = [];
    let handled = false;
    const readable = { getReader: () => queue.reader() };
    const writable = {
      getWriter: () => ({
        write: async value => { writes.push(new Uint8Array(value)); },
        close: async () => {
          if (handled) return;
          handled = true;
          const bytes = join(writes);
          if (bytes[0] === 123) {
            state.pairRequest = JSON.parse(decoder.decode(bytes).trim());
            queue.push(encoder.encode(JSON.stringify({
              ok: true,
              protocol: 'aetherdrop-webtransport-v1',
              token: 'a'.repeat(64),
              expires_in: 43200,
            }) + '\n'));
            if (state.extraPairBytes) queue.push(state.extraPairBytes);
            queue.end();
            return;
          }
          const headerLength = new DataView(bytes.buffer, bytes.byteOffset, 4).getUint32(0, false);
          const request = JSON.parse(decoder.decode(bytes.subarray(4, 4 + headerLength)));
          let result = { accepted: true };
          let payload = null;
          if (request.op === 'session.check') result = { valid: true, expires_in: 43200 };
          if (request.op === 'files.list') result = [];
          if (request.op === 'clipboard.get') {
            payload = encoder.encode('hello clipboard');
            result = { encoding: 'utf-8', bytes: payload.length };
          }
          if (request.op === 'download.read') {
            const length = request.data.length;
            payload = new Uint8Array(length).fill(7);
            result = {
              offset: request.data.offset,
              bytes: length,
              sha256: require('node:crypto').createHash('sha256').update(payload).digest('hex'),
            };
          }
          const response = {
            version: 1,
            request_id: request.request_id,
            ok: true,
            result,
            ...(payload === null ? {} : { payload_bytes: payload.length }),
          };
          const responseFrame = frame(response, payload);
          queue.push(state.truncateResponse ? responseFrame.subarray(0, 3) : responseFrame);
          if (state.extraResponseBytes) queue.push(state.extraResponseBytes);
          queue.end();
        },
        abort: async () => queue.end(),
      }),
    };
    return { readable, writable };
  }
  close() { this.closed = true; }
}

globalThis.WebTransport = FakeWebTransport;
(async () => {
  const source = require('node:fs').readFileSync('docs/aetherdrop-webtransport.js', 'utf8');
  const moduleUrl = 'data:text/javascript;base64,' + Buffer.from(source).toString('base64');
  const { connectAetherDrop } = await import(moduleUrl);
  const client = await connectAetherDrop({
    host: '192.168.1.20',
    hash: 'ab'.repeat(32),
    pin: '123456',
    deviceId: 'dev_test123',
  });

  const transport = state.instances.at(-1);
  assert.match(transport.url, /^https:\/\/192\.168\.1\.20:8443\//);
  assert.equal(transport.options.serverCertificateHashes[0].algorithm, 'sha-256');
  assert.equal(transport.options.serverCertificateHashes[0].value.length, 32);
  assert.equal(state.pairRequest.version, 1);
  assert.equal(state.pairRequest.device_id, 'dev_test123');

  state.extraPairBytes = encoder.encode('unexpected');
  await assert.rejects(connectAetherDrop({
    host: '192.168.1.20',
    hash: 'ab'.repeat(32),
    pin: '123456',
    deviceId: 'dev_test123',
  }), /trailing pairing response bytes/);
  state.extraPairBytes = null;

  assert.deepEqual(await client.request('session.check'), { valid: true, expires_in: 43200 });
  assert.deepEqual(await client.request('files.list'), []);
  const clipboard = await client.request('clipboard.get');
  assert.equal(decoder.decode(clipboard.payload), 'hello clipboard');
  assert.equal(clipboard.result.encoding, 'utf-8');

  const part = await client.request('download.read', { ticket: 'wt_test', offset: 4, length: 5 });
  assert.equal(part.result.offset, 4);
  assert.deepEqual([...part.payload], [7, 7, 7, 7, 7]);

  state.extraResponseBytes = new Uint8Array([0xde, 0xad]);
  await assert.rejects(client.request('session.check'), /trailing WebTransport response bytes/);
  state.extraResponseBytes = null;
  state.truncateResponse = true;
  await assert.rejects(client.request('session.check'), /Truncated WebTransport response/);
  state.truncateResponse = false;

  await client.request('upload.chunk', { transfer_id: 't', chunk_index: 0, sha256: '0'.repeat(64) }, new Uint8Array([1, 2, 3]));
  const openedBeforeInvalid = state.streamsOpened;
  await assert.rejects(client.request('session.check', undefined, new Uint8Array([1])), /binary body only/);
  await assert.rejects(client.request('clipboard.set'), /requires a binary body/);
  await assert.rejects(client.request('clipboard.set', undefined, new Uint8Array(1024 * 1024 + 1)), /allowed size/);
  assert.equal(state.streamsOpened, openedBeforeInvalid, 'invalid bodies must be rejected before opening a stream');

  client.close();
  assert.equal(transport.closed, true);
  console.log('WebTransport browser client: pairing, framing, binary payloads, and fail-closed body validation passed.');
})().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
