// Boots web3270's mock IBM i HTTP Server Administration GUI for test.sh.
// Usage: node mock-servers.cjs <Bridge_server dir> <key> <cert> <unpatched|patched|other>
//   unpatched / patched: the admin GUI on 2001 (plain) and 2010 (TLS)
//   other: a plain non-IBM i web server on 2001
const path = require('path');
const http = require('http');
const https = require('https');
const fs = require('fs');
const [, , bridge, key, cert, mode] = process.argv;
if (mode === 'real401') {
  // What a real IBM i (pub400.com) sends: Apache banner, "HTTP Admin" realm.
  http.createServer((q, r) => {
    r.writeHead(401, { Server: 'Apache', 'WWW-Authenticate': 'Basic realm="HTTP Admin"', 'Content-Type': 'text/html' });
    r.end('<H1>Authorization Required</H1>');
  }).listen(2001, '127.0.0.1', () => console.log('ready'));
} else if (mode === 'other') {
  http.createServer((q, r) => { r.writeHead(200, { Server: 'nginx' }); r.end('hi'); }).listen(2001, '127.0.0.1', () => console.log('ready'));
} else {
  const ha = require(path.join(bridge, 'mock-lpar', 'mock-as400-httpadmin.js'));
  const usrprfs = [{ name: 'JSMITH', status: '*ENABLED', pwdNone: false, text: 'Accounting', specialAuth: [], pwdChg: '07/02/26' }];
  const env = { MOCK_AS400_OSLEVEL: 'V7R4M0', ...(mode === 'patched' ? { MOCK_AS400_HTTPADMIN_PATCHED: '1' } : {}) };
  const ctx = ha.makeContext({ sysname: 'T', usrprfs, credentials: { JSMITH: 'Summer2026' }, log: () => {}, env });
  http.createServer(ha.listener(ctx)).listen(2001, '127.0.0.1');
  https.createServer({ key: fs.readFileSync(key), cert: fs.readFileSync(cert) }, ha.listener(ctx))
    .listen(2010, '127.0.0.1', () => console.log('ready'));
}
