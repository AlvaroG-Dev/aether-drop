'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const source = fs.readFileSync('src-tauri/src/sha256.js', 'utf8');
const context = vm.createContext({});
vm.runInContext('window = globalThis;', context, { filename: 'browser-window-setup.js' });
vm.runInContext(source, context, { filename: 'sha256.js' });

const vectors = [
  ['', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'],
  ['abc', 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'],
  ['The quick brown fox jumps over the lazy dog', 'd7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592']
];

for (const [message, expected] of vectors) {
  assert.equal(context.sha256(message), expected, 'SHA-256 known vector: ' + JSON.stringify(message));
}

const binary = Uint8Array.from([0, 1, 2, 127, 128, 255]);
assert.equal(
  context.sha256(binary),
  'da2cb6ad175bc966de5e79c6e16777f8a98b610c2424a894132df2815be50677',
  'SHA-256 must accept binary Uint8Array input'
);

const incremental = context.sha256.create();
incremental.update('The quick brown ');
incremental.update('fox jumps over ');
incremental.update('the lazy dog');
assert.equal(
  incremental.hex(),
  vectors[2][1],
  'Incremental hashing must match single-call hashing'
);

console.log('js-sha256: 5 known-vector and incremental checks passed.');
