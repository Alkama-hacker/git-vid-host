/**
 * Codec round-trip test: PHP helper (build/runtime) -> browser algorithms.
 *
 *   node codec_test.mjs
 *
 * Produces a bundle, content chunks and an asset with the real PHP helper, then
 * decodes all three with the exact algorithms used by src/assets/js/boot.js and
 * src/assets/template.php.
 */
import { readFileSync, writeFileSync, mkdtempSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { webcrypto, createDecipheriv } from 'node:crypto';

const SC = webcrypto.subtle;
const here = dirname(fileURLToPath(import.meta.url));
const dir = mkdtempSync(join(tmpdir(), 'gvh-codec-'));
const BANNER = '/*! test banner */';
const CORE = 'GVHCORE::TEST::SIG';
const SITE = 'gvh_codec_test';
const SOURCE = 'console.log("hello from the sealed engine");\n// ' + 'x'.repeat(4000) + '\n';

const assetBytes = Buffer.from(Array.from({ length: 5000 }, (_, i) => (i * 37 + 11) & 255));

const inp = {
  op: 'batch',
  ops: [
    { op: 'asset', data_b64: assetBytes.toString('base64') },
    { op: 'content', data_b64: Buffer.from('<h1>hi</h1>'.repeat(600)).toString('base64'), chunk_size: 1024 },
    {
      op: 'bundle', source_b64: Buffer.from(SOURCE).toString('base64'),
      core: CORE, site: SITE, banner: BANNER, chunks: 50, iter: 120000, vmRounds: 2, vmProg: 96,
    },
    { op: 'cfg', cfg: { hello: 'world', n: [1, 2, 3] } },
  ],
};
writeFileSync(join(dir, 'in.json'), JSON.stringify(inp));
execFileSync(process.execPath, [join(here, 'phpwasm_cli.mjs'), '--script', join(here, '..', 'src', 'lib', 'crypt_build.php'),
  '--in', join(dir, 'in.json'), '--out', join(dir, 'out.json')], { stdio: 'inherit' });
const out = JSON.parse(readFileSync(join(dir, 'out.json'), 'utf8'));

const results = [];
const check = (name, ok, detail = '') => {
  results.push(ok);
  console.log((ok ? 'ok   ' : 'FAIL ') + name + (ok || !detail ? '' : '  [' + detail + ']'));
};
const b64d = (s) => Uint8Array.from(Buffer.from(s, 'base64'));
const cat = (a, b) => { const o = new Uint8Array(a.length + b.length); o.set(a); o.set(b, a.length); return o; };
const rev = (a) => { const o = new Uint8Array(a.length); for (let i = 0; i < a.length; i++) o[i] = a[a.length - 1 - i]; return o; };
const hexOf = (b) => Buffer.from(b).toString('hex');
const rd16 = (b, o) => (b[o] | (b[o + 1] << 8)) >>> 0;
const rd32le = (b, o) => (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;
const mul32 = (a, b) => Math.imul(a, b) >>> 0;
const rotl32 = (x, r) => { r &= 31; return r ? (((x << r) | (x >>> (32 - r))) >>> 0) : (x >>> 0); };
const digest = async (x) => new Uint8Array(await SC.digest('SHA-256', x));

function vmX(data, seed, prog, rounds) {
  const s = new Array(8);
  for (let i = 0; i < 8; i++) s[i] = rd32le(seed, i * 4);
  const plen = prog.length >> 1, out = new Uint8Array(data.length);
  const nBlocks = Math.ceil(data.length / 32), word = new Uint8Array(32);
  for (let n = 0; n < nBlocks; n++) {
    s[0] = (s[0] ^ n) >>> 0; s[6] = (s[6] + n) >>> 0;
    for (let r = 0; r < rounds; r++) for (let p = 0; p < plen; p++) {
      const ins = prog[p * 2] | (prog[p * 2 + 1] << 8), op = ins & 7, a = (ins >> 3) & 7, b = (ins >> 6) & 7;
      if (op === 0) s[a] = (s[a] + s[b]) >>> 0;
      else if (op === 1) s[a] = (s[a] ^ s[b]) >>> 0;
      else if (op === 2) s[a] = rotl32(s[a], 1 + (b % 31));
      else if (op === 3) s[a] = mul32(s[a], (2 * s[b] + 1) >>> 0);
      else if (op === 4) { const t = s[a]; s[a] = s[b]; s[b] = t; }
      else if (op === 5) s[a] = (s[a] + 0x9E3779B9 + n) >>> 0;
      else if (op === 6) s[a] = (s[a] ^ mul32(n, 0x85EBCA6B)) >>> 0;
      else s[a] = (s[a] + (s[(a + 1) & 7] ^ n)) >>> 0;
    }
    for (let i = 0; i < 8; i++) {
      const w = s[i];
      word[i * 4] = w & 255; word[i * 4 + 1] = (w >>> 8) & 255;
      word[i * 4 + 2] = (w >>> 16) & 255; word[i * 4 + 3] = (w >>> 24) & 255;
    }
    for (let i = 0; i < 32; i++) { const pos = n * 32 + i; if (pos < data.length) out[pos] = data[pos] ^ word[i]; }
  }
  return out;
}
async function gcm(k, iv, ct) {
  const kk = await SC.importKey('raw', k, { name: 'AES-GCM' }, false, ['decrypt']);
  return new Uint8Array(await SC.decrypt({ name: 'AES-GCM', iv, tagLength: 128 }, kk, ct));
}

check('helper ok', out.ok === true, JSON.stringify(out).slice(0, 120));

/* ---------- 1. defence-engine envelope ---------- */
const B = out.results[2].bundle, M = B.manifest;
check('50 engine chunks', M.chunks.length === 50, M.chunks.length);
check('50-char engine keys', M.chunks.every((c) => Buffer.from(c.k, 'base64').toString().length === 50));
const outer = vmX(b64d(B.blob), await digest(cat(b64d(M.vm.k), b64d(M.vm.n))), b64d(M.vm.p), M.vm.r);
const salt = outer.subarray(0, 16), iv = outer.subarray(16, 28), tag = outer.subarray(28, 44), body = outer.subarray(44);
const pass = await digest(new TextEncoder().encode(CORE + '|' + SITE + '|' + M.pbkdf2.salt + '|' + BANNER));
const pk = await SC.importKey('raw', pass, { name: 'PBKDF2' }, false, ['deriveKey']);
const key = await SC.deriveKey({ name: 'PBKDF2', salt, iterations: M.pbkdf2.iter, hash: 'SHA-256' }, pk,
  { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
const inner = rev(new Uint8Array(await SC.decrypt({ name: 'AES-GCM', iv, tagLength: 128 }, key, cat(body, tag))));
const magic = String.fromCharCode(...inner.slice(0, 4));
check('engine magic', magic === 'GVH1', magic);
check('engine chunk count', rd16(inner, 4) === 50, rd16(inner, 4));
const b64len = rd32le(inner, 6);
let o = 10, pieces = [];
for (let i = 0; i < 50; i++) {
  const plen = rd32le(inner, o), clen = rd32le(inner, o + 4);
  const civ = inner.subarray(o + 8, o + 20), ctag = inner.subarray(o + 20, o + 36), ct = inner.subarray(o + 36, o + 36 + clen);
  const p = await gcm(await digest(b64d(M.chunks[i].k)), civ, cat(ct, ctag));
  const s = Buffer.from(p).toString('utf8');
  if (s.length !== plen) throw new Error('chunk length mismatch at ' + i);
  pieces.push(s);
  o += 36 + clen;
}
const src = Buffer.from(pieces.join(''), 'base64').toString('utf8');
check('engine source round-trip', src === SOURCE, src.length + ' vs ' + SOURCE.length);
check('engine base64 length header', pieces.join('').length === b64len, pieces.join('').length + '/' + b64len);
check('engine sha256', hexOf(await digest(new TextEncoder().encode(src))) === M.srcHash);

/* ---------- 2. content chunks ---------- */
const CH = out.results[1].chunks;
check('content chunks split', CH.length >= 2, CH.length);
check('content keys are 50 chars', CH.every((c) => Buffer.from(c.k, 'base64').toString().length === 50));
let content = '';
for (const c of CH) {
  const p = await gcm(await digest(b64d(c.k)), b64d(c.iv), cat(b64d(c.ct), b64d(c.tg)));
  content += Buffer.from(p).toString('utf8');
}
check('content base64 round-trip',
  Buffer.from(content, 'base64').toString('utf8') === '<h1>hi</h1>'.repeat(600));
check('content chunk lengths are base64 quartets', CH.every((c) => c.len % 4 === 0 || c === CH[CH.length - 1]));

/* ---------- 3. asset stream (AES-256-CTR + Range) ---------- */
const A = out.results[0].asset;
const decipher = createDecipheriv('aes-256-ctr', Buffer.from(A.k, 'base64'), Buffer.from(A.iv, 'base64'));
const plain = Buffer.concat([decipher.update(Buffer.from(A.ct_b64, 'base64')), decipher.final()]);
check('asset CTR round-trip', Buffer.compare(plain, assetBytes) === 0, plain.length + ' vs ' + assetBytes.length);
// seek: decrypt from block boundary like the PHP runtime
const start = 1234, block = start - (start % 16);
const ctr = Buffer.from(A.iv, 'base64');
let carry = block / 16;
for (let i = 15; i >= 0 && carry > 0; i--) {
  const v = ctr[i] + (carry & 0xff);
  carry = (carry >> 8) + (v >> 8);
  ctr[i] = v & 0xff;
}
const d3 = createDecipheriv('aes-256-ctr', Buffer.from(A.k, 'base64'), ctr);
const slice = Buffer.concat([d3.update(Buffer.from(A.ct_b64, 'base64').subarray(block, block + 200))]).subarray(start - block, start - block + 64);
check('asset Range seek', Buffer.compare(slice, assetBytes.subarray(start, start + 64)) === 0);

/* ---------- 4. config blob ---------- */
check('cfg blob is gzip base64', typeof out.results[3].cfg === 'string' && out.results[3].cfg.startsWith('G1.'), out.results[3].cfg?.slice(0, 3));

console.log(`\n${results.filter(Boolean).length}/${results.length} checks passed`);
process.exit(results.every(Boolean) ? 0 : 1);
