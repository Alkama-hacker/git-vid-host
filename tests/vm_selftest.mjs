/**
 * VM layer self-test: the PHP generator and the browser decoder must produce
 * identical bytes, otherwise every sealed page would fail to unlock.
 *
 *   node tests/vm_selftest.mjs
 *
 * The fixture is generated on the fly by src/lib/crypt_build.php (`vm_selftest`
 * op) through the php-wasm bridge, so this test is self-contained.
 */
import { readFileSync, writeFileSync, mkdtempSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { webcrypto } from 'node:crypto';

const here = dirname(fileURLToPath(import.meta.url));
const dir = mkdtempSync(join(tmpdir(), 'gvh-vm-'));
const inp = join(dir, 'in.json');
const outPath = join(dir, 'out.json');

writeFileSync(inp, JSON.stringify({
  op: 'batch',
  ops: [{ op: 'vm_selftest' }, { op: 'vm_selftest' }],
}));
execFileSync(process.execPath, [
  join(here, 'phpwasm_cli.mjs'),
  '--script', join(here, '..', 'src', 'lib', 'crypt_build.php'),
  '--in', inp, '--out', outPath,
], { stdio: 'inherit' });

const out = JSON.parse(readFileSync(outPath, 'utf8'));
const v = out.results[0].vm;

const b64d = (s) => Uint8Array.from(Buffer.from(s, 'base64'));
const rd32le = (b, o) => (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;
const mul32 = (a, b) => Math.imul(a, b) >>> 0;
const rotl32 = (x, r) => { r &= 31; return r ? (((x << r) | (x >>> (32 - r))) >>> 0) : (x >>> 0); };

/** Exact copy of vmX() in src/assets/js/boot.js. */
function vmX(data, seed, prog, rounds) {
  const s = new Array(8);
  for (let i = 0; i < 8; i++) s[i] = rd32le(seed, i * 4);
  const plen = prog.length >> 1;
  const out = new Uint8Array(data.length);
  const nBlocks = Math.ceil(data.length / 32);
  const word = new Uint8Array(32);
  for (let n = 0; n < nBlocks; n++) {
    s[0] = (s[0] ^ n) >>> 0;
    s[6] = (s[6] + n) >>> 0;
    for (let r = 0; r < rounds; r++) {
      for (let p = 0; p < plen; p++) {
        const ins = prog[p * 2] | (prog[p * 2 + 1] << 8);
        const op = ins & 7, a = (ins >> 3) & 7, b = (ins >> 6) & 7;
        if (op === 0) s[a] = (s[a] + s[b]) >>> 0;
        else if (op === 1) s[a] = (s[a] ^ s[b]) >>> 0;
        else if (op === 2) s[a] = rotl32(s[a], 1 + (b % 31));
        else if (op === 3) s[a] = mul32(s[a], (2 * s[b] + 1) >>> 0);
        else if (op === 4) { const t = s[a]; s[a] = s[b]; s[b] = t; }
        else if (op === 5) s[a] = (s[a] + 0x9E3779B9 + n) >>> 0;
        else if (op === 6) s[a] = (s[a] ^ mul32(n, 0x85EBCA6B)) >>> 0;
        else s[a] = (s[a] + (s[(a + 1) & 7] ^ n)) >>> 0;
      }
    }
    for (let i = 0; i < 8; i++) {
      const w = s[i];
      word[i * 4] = w & 255; word[i * 4 + 1] = (w >>> 8) & 255;
      word[i * 4 + 2] = (w >>> 16) & 255; word[i * 4 + 3] = (w >>> 24) & 255;
    }
    for (let i = 0; i < 32; i++) {
      const pos = n * 32 + i;
      if (pos < data.length) out[pos] = data[pos] ^ word[i];
    }
  }
  return out;
}

const results = [];
const check = (name, ok, detail = '') => {
  results.push(ok);
  console.log((ok ? 'ok   ' : 'FAIL ') + name + (ok || !detail ? '' : '  [' + detail + ']'));
};

const key = b64d(v.key), nonce = b64d(v.nonce), prog = b64d(v.prog), data = b64d(v.data);
const seed = new Uint8Array(await webcrypto.subtle.digest('SHA-256', Buffer.concat([Buffer.from(key), Buffer.from(nonce)])));
const enc = vmX(data, seed, prog, 2);
const got = Buffer.from(enc).toString('base64');

check('PHP and JS produce identical VM bytes', got === v.enc, v.enc.slice(0, 24) + ' != ' + got.slice(0, 24));
check('VM output keeps the input length', enc.length === data.length, enc.length + ' vs ' + data.length);
check('VM output actually transforms the data', got !== v.data);

// XOR keystream means the same routine decrypts: run it twice and get the input back.
const back = vmX(enc, seed, prog, 2);
check('VM round-trip restores the plaintext', Buffer.from(back).toString('base64') === v.data);

// The fixture is deterministic on purpose: two runs must agree byte for byte,
// so the check above is a real regression test and not luck.
const v2 = out.results[1].vm;
check('self-test fixture is deterministic', v2.enc === v.enc && v2.key === v.key && v2.prog === v.prog);

const bad = results.filter((r) => !r).length;
console.log('\n' + (results.length - bad) + '/' + results.length + ' checks passed');
process.exit(bad ? 1 : 0);
