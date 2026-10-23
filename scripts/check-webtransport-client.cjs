const fs = require('node:fs');
const { spawnSync } = require('node:child_process');

const html = fs.readFileSync('docs/aetherdrop-client.html', 'utf8');
const match = html.match(/<script\s+type="module">([\s\S]*?)<\/script>/i);
if (!match) {
  console.error('WebTransport client HTML has no inline module script');
  process.exit(1);
}
if (!html.includes('src="./sha256.js"')) {
  console.error('WebTransport client is missing the incremental SHA-256 helper');
  process.exit(1);
}
const transportClient = fs.readFileSync('docs/aetherdrop-webtransport.js', 'utf8');
if (!transportClient.includes('serverCertificateHashes') || !transportClient.includes('new WebTransport')) {
  console.error('WebTransport client must pin the certificate before pairing');
  process.exit(1);
}
if (/\bfetch\s*\(|XMLHttpRequest/.test(transportClient + match[1])) {
  console.error('WebTransport client must not contain an HTTP transfer fallback');
  process.exit(1);
}
const result = spawnSync(process.execPath, ['--input-type=module', '--check'], {
  input: match[1],
  encoding: 'utf8',
});
if (result.status !== 0) {
  process.stderr.write(result.stderr || result.stdout);
  process.exit(result.status || 1);
}
console.log('WebTransport browser UI module syntax is valid');
