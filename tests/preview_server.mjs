/**
 * Dev preview server: exposes a sealed build over real HTTP using php-wasm.
 *
 *   node preview_server.mjs /tmp/gvh-out/demo 8080
 *
 * This is *not* part of the shipped tool (production uses PHP-FPM / Apache);
 * it exists so the whole flow can be exercised in a real browser without
 * installing PHP.
 */
import http from 'node:http';
import { startServer } from './php_server.mjs';

const dir = process.argv[2];
const port = Number(process.argv[3] || 8080);
if (!dir) {
  console.error('usage: node preview_server.mjs <sealed-folder> [port]');
  process.exit(2);
}

const srv = await startServer(dir + '/index.php', { base: 'https://preview.local' });

function parseCookies(header) {
  const out = {};
  for (const part of String(header || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}

function readBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
  });
}

let chain = Promise.resolve();

const server = http.createServer((req, res) => {
  chain = chain.then(async () => {
    try {
      const u = new URL(req.url, 'https://preview.local');
      const headers = {};
      for (const [k, v] of Object.entries(req.headers)) {
        if (typeof v !== 'string') continue;
        if (['host', 'connection', 'content-length', 'transfer-encoding'].includes(k)) continue;
        headers[k] = v;
      }
      let post = {};
      if (req.method === 'POST') {
        const body = await readBody(req);
        if (/application\/x-www-form-urlencoded/.test(req.headers['content-type'] || '')) {
          for (const [k, v] of new URLSearchParams(body.toString('utf8'))) post[k] = v;
        }
      }
      const r = await srv.request({
        path: u.pathname + u.search,
        method: req.method,
        headers,
        cookies: parseCookies(req.headers.cookie),
        referer: req.headers.referer,
        range: req.headers.range,
        ua: req.headers['user-agent'],
        ip: (req.socket.remoteAddress || '127.0.0.1').replace(/^::ffff:/, ''),
      });
      const out = {};
      for (const [k, v] of Object.entries(r.headers)) {
        if (k === 'content-length' || k === 'connection' || k === 'transfer-encoding') continue;
        out[k] = v.length === 1 ? v[0] : v;
      }
      res.writeHead(r.status, out);
      if (req.method === 'HEAD') res.end();
      else res.end(r.body);
    } catch (err) {
      res.writeHead(500, { 'content-type': 'text/plain; charset=utf-8' });
      res.end('preview error: ' + (err && err.message || err));
    }
  });
});

server.listen(port, '0.0.0.0', () => {
  console.log('GVH preview listening on http://0.0.0.0:' + port);
  console.log('serving ' + dir);
});
