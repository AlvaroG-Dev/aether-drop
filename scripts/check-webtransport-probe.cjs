const fs = require('node:fs');

const html = fs.readFileSync('docs/webtransport-probe.html', 'utf8');
const match = html.match(/<script type="module">([\s\S]*?)<\/script>/);
if (!match) {
  throw new Error('No se encontró el módulo JavaScript de la prueba WebTransport.');
}

// Compile only; browser APIs are exercised by a real browser integration test.
new Function(match[1]);
console.log('WebTransport probe JavaScript syntax: OK');
