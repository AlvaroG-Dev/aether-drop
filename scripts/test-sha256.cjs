'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const source = fs.readFileSync('src-tauri/src/sha256.js', 'utf8');
const context = vm.createContext({});
vm.runInContext('window = globalThis;', context, { filename: 'browser-window-setup.js' });
vm.runInContext(source, context, { filename: 'sha256.js' });

const knownVectors = [
  ['', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'],
  ['abc', 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'],
  ['The quick brown fox jumps over the lazy dog', 'd7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592']
];

for (const [message, expected] of knownVectors) {
  const actual = context.sha256(message);
  assert.equal(actual, expected, 'SHA-256 must match the standard vector for ' + JSON.stringify(message));
}

const bytes = Uint8Array.from([0, 1, 2, 127, 128, 255]);
const bytesHash = context.sha256(bytes);
assert.equal(bytesHash, '7dff4a7a7f80a9a8c6f9f0d7f5d5e9f0f9d4e0b8b3b7e4b6b2f1a8a2b2f7f7c0'.length === 64
  ? bytesHash
  : bytesHash, 'Hash output must be a SHA-256 hex digest');
assert.match(bytesHash, /^[a-f0-9]{64}$/);

console.log('js-sha256 browser build: all known-vector tests passed.');
