/**
 * Server-side acceptance suite for a sealed build.
 *
 *   node api_suite.mjs /tmp/gvh-out/simple [source-site-dir]
 *
 * Every check prints `ok   name` / `FAIL name  detail` and the process exits
 * non-zero when anything failed.
 */
import { startServer } from './php_server.mjs';
import { webcrypto, createHash } from 'node:crypto';
import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';

const dir = process.argv[2];
const srcFile = process.argv[3];
const srcDir = srcFile ? dirname(srcFile) : null;
const results = [];
function check(name, ok, detail = '') {
  results.push({ name, ok: !!ok, detail: String(detail).slice(0, 300) });
  console.log((ok ? 'ok   ' : 'FAIL ') + name + (ok || !detail ? '' : '  [' + String(detail).slice(0, 300) + ']'));
}

const sha = (b) => createHash('sha256').update(b).digest('hex');
const b64d = (s) => Uint8Array.from(Buffer.from(s, 'base64'));
const cat = (a, b) => { const o = new Uint8Array(a.length + b.length); o.set(a); o.set(b, a.length); return o; };
const rd32le = (b, o) => (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;

async function digest(x) { return new Uint8Array(await webcrypto.subtle.digest('SHA-256', x)); }
async function gcm(k, iv, ctAndTag) {
  const key = await webcrypto.subtle.importKey('raw', k, { name: 'AES-GCM' }, false, ['decrypt']);
  return new Uint8Array(await webcrypto.subtle.decrypt({ name: 'AES-GCM', iv, tagLength: 128 }, key, ctAndTag));
}
async function hmac(k, msg) {
  const key = await webcrypto.subtle.importKey('raw', k, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await webcrypto.subtle.sign('HMAC', key, msg));
}

function sourceHashes(root) {
  const map = new Map();
  if (!root || !existsSync(root)) return map;
  const walk = (d) => {
    for (const name of readdirSync(d)) {
      const p = join(d, name);
      const st = statSync(p);
      if (st.isDirectory()) { if (name !== 'node_modules') walk(p); }
      else if (st.size < 30 * 1024 * 1024) {
        const buf = readFileSync(p);
        map.set(sha(buf), { name, size: buf.length });
      }
    }
  };
  walk(root);
  return map;
}

const srv = await startServer(join(dir, 'index.php'));
const shell = await srv.request({ path: '/index.php', ip: '198.51.100.1' });
const html = shell.text();

check('shell 200', shell.status === 200, shell.status);
check('x-frame-options DENY', shell.header('x-frame-options') === 'DENY', shell.header('x-frame-options'));
check('CSP frame-ancestors none', /frame-ancestors 'none'/.test(shell.header('content-security-policy') || ''));
check('cache no-store', /no-store/.test(shell.header('cache-control') || ''));
check('nosniff', shell.header('x-content-type-options') === 'nosniff');
check('session cookie set', /^gv_[a-z0-9]{6}=/.test((shell.setCookies[0] || '')), shell.setCookies[0]);
check('shell has no raw page markup', !/<h1[^>]*id="headline"/.test(html) && !html.includes('class="hero"'));
check('shell has credit', html.includes('@SHACKER_ENCRYPTION_bot') && html.includes('@Haki_xmw'));
check('shell has splash', html.includes('Decrypting secure layers'));
check('shell has sealed manifest', /var MAN_B64 = "[A-Za-z0-9+/=]{40,}"/.test(html) && /var MX = \[/.test(html));
check('shell has engine blob', /var BLOB = "[A-Za-z0-9+/=]{1000,}"/.test(html));
check('shell has no asset file names', !/logo-small\.png|site\.css|movie\.mp4/.test(html));

const cookieHeader = shell.setCookies[0] || '';
const cookieName = cookieHeader.split('=')[0];
const cookieVal = cookieHeader.slice(cookieName.length + 1);

const mxm = html.match(/var MX = (\[[^\]]+\])/);
const manm = html.match(/var MAN_B64 = "([^"]+)"/);
let MAN = null;
if (mxm && manm) {
  const mx = JSON.parse(mxm[1]);
  const raw = Buffer.from(manm[1], 'base64');
  const plain = Buffer.from(raw.map((b, i) => b ^ mx[i % mx.length]));
  try { MAN = JSON.parse(plain.toString('utf8')); } catch (e) { }
}
check('manifest decodes', !!MAN);
check('manifest session token', MAN && MAN.sess && MAN.sess.t && MAN.sess.k);
check('manifest 50-char engine keys', MAN && MAN.chunks.every((c) => Buffer.from(c.k, 'base64').toString().length === 50));
check('manifest decoys >= 16', MAN && MAN.fakes && MAN.fakes.length >= 16, MAN && MAN.fakes && MAN.fakes.length);
check('manifest one api per content chunk', MAN && MAN.content && MAN.content.apis.length === MAN.content.n);

const KEY = MAN ? Buffer.from(MAN.sess.k, 'base64') : Buffer.alloc(32);

async function apiRequest(api, opts = {}) {
  const nonce = opts.nonce || 'abcdef' + String(Math.floor(Math.random() * 1e6)).padStart(6, '0') + '0011';
  const sig = opts.sig || Buffer.from(await hmac(KEY, Buffer.from(api + '|' + nonce))).toString('hex');
  const path = `/index.php?${MAN.gw}=${api}&${MAN.pn}=${nonce}&${MAN.ps}=${sig}&${MAN.pt}=${encodeURIComponent(MAN.sess.t)}`;
  const res = await srv.request({ path, ip: opts.ip || '198.51.100.2', headers: opts.headers || { 'Sec-Fetch-Site': 'same-origin' } });
  res.nonce = nonce;
  return res;
}
async function unseal(text, api, nonce) {
  const stream = await digest(cat(KEY, Buffer.from('|' + api + '|' + nonce + '|r')));
  const enc = Buffer.from(JSON.parse(text).p, 'base64');
  return JSON.parse(Buffer.from(enc.map((b, i) => b ^ stream[i % 32])).toString('utf8'));
}
async function chunk(api, nonce) {
  const res = await apiRequest(api, { nonce });
  if (res.status !== 200) throw new Error('chunk http ' + res.status);
  return unseal(res.text(), api, nonce);
}

let content = '';
if (MAN) {
  let okAll = true;
  let out = '';
  for (let i = 0; i < MAN.content.n; i++) {
    const api = MAN.content.apis[i];
    const nonce = 'f00d' + String(i).padStart(4, '0') + 'beefcafe';
    let obj;
    try { obj = await chunk(api, nonce); } catch (e) { okAll = false; check('chunk ' + i, false, e.message); break; }
    if (obj.n !== i) { okAll = false; check('chunk order ' + i, false, obj.n); break; }
    if (Buffer.from(obj.k, 'base64').toString().length !== 50) { okAll = false; check('chunk key length ' + i, false); break; }
    const aesKey = await digest(b64d(obj.k));
    const piece = Buffer.from(await gcm(aesKey, b64d(obj.iv), Buffer.concat([b64d(obj.ct), b64d(obj.tg)]))).toString('utf8');
    out += piece;
  }
  check('all content chunk APIs decrypt', okAll);
  content = Buffer.from(out, 'base64').toString('utf8');
  check('content decoded', content.length > 100, content.length);
  check('content carries the html credit', content.includes('@SHACKER_ENCRYPTION_bot'));
  const placeholders = [...new Set([...content.matchAll(/__GVH_A_([a-f0-9]{40})__/g)].map((m) => m[1]))];
  check('content has well-formed asset placeholders', !/__GVH_A_(?![a-f0-9]{40}__)/.test(content), placeholders.length);

  if (srcFile) {
    const src = readFileSync(srcFile, 'utf8');
    const title = ((src.match(/<title[^>]*>([\s\S]*?)<\/title>/i) || [])[1] || '').trim();
    const h1 = ((src.match(/<h1[^>]*>([\s\S]*?)<\/h1>/i) || [])[1] || '')
      .replace(/<[^>]+>/g, ' ').replace(/&[a-z#0-9]+;/gi, ' ').replace(/\s+/g, ' ').trim();
    const textOnly = content.replace(/<script[\s\S]*?<\/script>/gi, ' ').replace(/<style[\s\S]*?<\/style>/gi, ' ')
      .replace(/<[^>]+>/g, ' ').replace(/&[a-z#0-9]+;/gi, ' ').replace(/\s+/g, ' ');
    if (title) check('content title matches source', content.includes(title.split('—')[0].trim()), title);
    if (h1) check('content headline matches source', textOnly.includes(h1.slice(0, 18)), h1);
  }

  // negative paths
  const good = await apiRequest(MAN.content.apis[0]);
  check('valid signed chunk 200', good.status === 200, good.status);
  const badSig = await apiRequest(MAN.content.apis[0], { sig: 'a'.repeat(64) });
  check('bad signature 403', badSig.status === 403, badSig.status);
  const noTok = await srv.request({ path: `/index.php?${MAN.gw}=${MAN.content.apis[0]}&${MAN.pn}=abcdef0123456789&${MAN.ps}=${'a'.repeat(64)}`, ip: '198.51.100.3' });
  check('missing session 403', noTok.status === 403, noTok.status);
  const badTok = await srv.request({
    path: `/index.php?${MAN.gw}=${MAN.content.apis[0]}&${MAN.pn}=abcdef0123456789&${MAN.ps}=${'a'.repeat(64)}`,
    ip: '198.51.100.4', headers: { 'X-GVH-S': MAN.sess.t.slice(0, -2) + 'ff' },
  });
  check('tampered token 403', badTok.status === 403, badTok.status);
  const shortNonce = await apiRequest(MAN.content.apis[0], { nonce: 'abc' });
  check('bad nonce 403', shortNonce.status === 403, shortNonce.status);
  const unknown = await apiRequest('f'.repeat(32));
  if (unknown.status === 200) {
    const fake = await unseal(unknown.text(), 'f'.repeat(32), unknown.nonce);
    check('unknown api returns decoy', fake.n === -1, fake.n);
  } else {
    check('unknown api returns decoy', unknown.status === 403 || unknown.status === 404, unknown.status);
  }
  const decoy = await apiRequest(MAN.fakes[0]);
  check('fake key api answers 200', decoy.status === 200, decoy.status);
  if (decoy.status === 200) {
    // nonce is random inside apiRequest; recompute by re-requesting with fixed nonce
    const nonce = 'aaaaaaaaaaaaaaaa';
    const r2 = await apiRequest(MAN.fakes[0], { nonce });
    const obj = await unseal(r2.text(), MAN.fakes[0], nonce);
    check('fake key api returns an unusable decoy', obj.n === -1 && Buffer.from(obj.k, 'base64').toString().length === 50, obj.n);
  }

  // bots
  const bot = await srv.request({ path: '/index.php', ua: 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)', ip: '198.51.100.5' });
  check('crawler blocked', bot.status === 403 && bot.text().includes('NOOB'), bot.status);
  const curl = await srv.request({ path: '/index.php', ua: 'curl/8.5.0', ip: '198.51.100.6' });
  check('curl UA blocked', curl.status === 403, curl.status);
  const hl = await srv.request({ path: '/index.php', ua: 'Mozilla/5.0 HeadlessChrome/120.0.0.0', ip: '198.51.100.7' });
  check('headless UA blocked', hl.status === 403, hl.status);
  const empty = await srv.request({ path: '/index.php', ua: '', ip: '198.51.100.8' });
  check('empty UA blocked', empty.status === 403, empty.status);

  // assets
  const ids = placeholders;
  const expectsAssets = srcFile ? /<(img|video|audio|source|link|image|object|embed)[^>]*(src|href|data|poster)=/i.test(readFileSync(srcFile, 'utf8')) : false;
  check('assets referenced', expectsAssets ? ids.length > 0 : true, ids.length);
  const hashes = sourceHashes(srcDir);
  for (const id of ids.slice(0, 12)) {
    const res = await srv.request({
      path: `/index.php?${MAN.ap}=${id}&${MAN.pt}=${encodeURIComponent(MAN.sess.t)}`,
      ip: '198.51.100.' + (20 + ids.indexOf(id) % 50),
      headers: { 'Sec-Fetch-Site': 'same-origin' },
    });
    if (res.status !== 200) { check('asset ' + id.slice(0, 8), false, res.status); continue; }
    const mime = res.header('content-type') || '';
    const known = hashes.get(sha(res.body));
    const textual = /^text\/|javascript|json|svg/.test(mime);
    check('asset ' + id.slice(0, 8) + ' ' + mime.split(';')[0], textual ? res.body.length > 0 : !!known,
      res.body.length + 'B ' + (known ? known.name : 'rewritten-or-unknown'));
    if (res.body.length > 256) {
      const range = await srv.request({
        path: `/index.php?${MAN.ap}=${id}&${MAN.pt}=${encodeURIComponent(MAN.sess.t)}`,
        ip: '198.51.100.90', range: 'bytes=100-227', headers: { 'Sec-Fetch-Site': 'same-origin' },
      });
      check('range 206 on ' + id.slice(0, 8), range.status === 206 && Buffer.compare(range.body, res.body.subarray(100, 228)) === 0, range.status + ' ' + range.header('content-range'));
      const tail = await srv.request({
        path: `/index.php?${MAN.ap}=${id}&${MAN.pt}=${encodeURIComponent(MAN.sess.t)}`,
        ip: '198.51.100.91', range: 'bytes=-64', headers: { 'Sec-Fetch-Site': 'same-origin' },
      });
      check('suffix range on ' + id.slice(0, 8), tail.status === 206 && tail.body.length === 64, tail.status + ' ' + tail.body.length);
      const bad = await srv.request({
        path: `/index.php?${MAN.ap}=${id}&${MAN.pt}=${encodeURIComponent(MAN.sess.t)}`,
        ip: '198.51.100.92', range: `bytes=${res.body.length + 10}-`, headers: { 'Sec-Fetch-Site': 'same-origin' },
      });
      check('unsatisfiable range 416', bad.status === 416, bad.status);
      const etag = res.header('etag');
      const nm = await srv.request({
        path: `/index.php?${MAN.ap}=${id}&${MAN.pt}=${encodeURIComponent(MAN.sess.t)}`,
        ip: '198.51.100.93', headers: { 'If-None-Match': etag, 'Sec-Fetch-Site': 'same-origin' },
      });
      check('etag 304', nm.status === 304, nm.status);
      const head = await srv.request({
        path: `/index.php?${MAN.ap}=${id}&${MAN.pt}=${encodeURIComponent(MAN.sess.t)}`,
        ip: '198.51.100.94', method: 'HEAD', headers: { 'Sec-Fetch-Site': 'same-origin' },
      });
      check('asset HEAD', head.status === 200 && head.body.length === 0, head.status + '/' + head.body.length);
    }
    const hot = await srv.request({
      path: `/index.php?${MAN.ap}=${id}&${MAN.pt}=${encodeURIComponent(MAN.sess.t)}`,
      ip: '198.51.100.95', referer: 'https://evil.example/steal', headers: { 'Sec-Fetch-Site': 'cross-site' },
    });
    check('hotlink blocked', hot.status === 403, hot.status);
    const bare = await srv.request({ path: `/index.php?${MAN.ap}=${id}`, ip: '198.51.100.96' });
    check('asset without credentials blocked', bare.status === 403, bare.status);
  }
  const missing = await srv.request({ path: `/index.php?${MAN.ap}=${'a'.repeat(40)}`, ip: '198.51.100.97', headers: { 'Sec-Fetch-Site': 'same-origin' } });
  check('unknown asset 404', missing.status === 404, missing.status);

  // files mode
  const reportPath = dir.replace(/\/+$/, '') + '.report.json';
  if (existsSync(reportPath)) {
    const report = JSON.parse(readFileSync(reportPath, 'utf8'));
    if (report.output.files_mode) {
      const vdir = join(dir, report.vault || '');
      const vaultDir = readdirSync(dir).find((n) => n.startsWith('vault_'));
      check('vault folder exists', !!vaultDir, vaultDir);
      if (vaultDir) {
        const files = readdirSync(join(dir, vaultDir)).filter((f) => f.endsWith('.gvh'));
        check('vault has encrypted media', files.length > 0, files.length);
        const hd = readFileSync(join(dir, vaultDir, '.htaccess'), 'utf8');
        check('vault htaccess denies', /deny/i.test(hd));
        const sample = readFileSync(join(dir, vaultDir, files[0]));
        check('vault bytes are ciphertext', !/ftyp|ID3|PNG|RIFF/.test(sample.subarray(0, 64).toString('latin1')));
        check('index.php has no media payload', !html.includes('ftyp') && html.length < 2_000_000, html.length);
      }
    }
  }

  // rate limit
  const rlIp = '203.0.113.250';
  let last = null;
  for (let i = 0; i < 720; i++) {
    last = await apiRequest(MAN.content.apis[0], { ip: rlIp });
    if (last.status === 429) break;
  }
  check('rate limit kicks in', last && last.status === 429, last && last.status);
}

const failed = results.filter((r) => !r.ok);
console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
process.exit(failed.length ? 1 : 0);
