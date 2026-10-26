/**
 * Software crypto fallback: every primitive must match Node's reference
 * implementation bit for bit, otherwise a browser with a broken
 * crypto.subtle would decrypt to garbage (or accept a bad tag).
 *
 *   node tests/softcrypto_test.mjs
 */
import { createHash, createHmac, pbkdf2Sync, createCipheriv, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const sandbox = {};
new Function('window', readFileSync(join(here, '..', 'src', 'assets', 'js', 'soft.js'), 'utf8'))(sandbox);
const S = sandbox.GVH_SOFT;
const hex = (b) => Buffer.from(b).toString('hex');
let checks = 0, fails = 0;
const ok = (name, cond, detail = '') => {
  checks++;
  if (!cond) fails++;
  console.log(`${cond ? '  ok  ' : '  FAIL'} ${name}${cond ? '' : ' — ' + detail}`);
};

for (const len of [0, 1, 3, 55, 56, 63, 64, 65, 119, 120, 1000]) {
  const m = randomBytes(len);
  ok('sha256 len=' + len, hex(S.sha256(m)) === createHash('sha256').update(m).digest('hex'));
}
for (const [kl, ml] of [[32, 0], [32, 16], [64, 100], [100, 50]]) {
  const k = randomBytes(kl), m = randomBytes(ml);
  ok(`hmac k${kl} m${ml}`, hex(S.hmac(k, m)) === createHmac('sha256', k).update(m).digest('hex'));
}
for (const [iter, saltLen, dk] of [[1, 16, 32], [1000, 16, 32], [120000, 16, 32], [10, 8, 64]]) {
  const p = randomBytes(16), s = randomBytes(saltLen);
  const mine = hex(S.pbkdf2(p, s, iter, dk));
  const ref = pbkdf2Sync(p, s, iter, dk, 'sha256').toString('hex');
  ok(`pbkdf2 iter=${iter} dk=${dk}`, mine === ref, mine.slice(0, 16) + ' vs ' + ref.slice(0, 16));
}
for (const len of [0, 1, 15, 16, 17, 63, 64, 65, 1000, 9780]) {
  const key = randomBytes(32), iv = randomBytes(12), pt = randomBytes(len);
  const c = createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([c.update(pt), c.final(), c.getAuthTag()]);
  let out, err;
  try { out = Buffer.from(S.gcmOpen(key, iv, ct)); } catch (e) { err = e.message; }
  ok('aes-256-gcm len=' + len, !err && out.equals(pt), err || 'mismatch');
}
{
  const key = randomBytes(32), iv = randomBytes(12), pt = randomBytes(100);
  const c = createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([c.update(pt), c.final(), c.getAuthTag()]);
  ct[40] ^= 1;
  let threw = false;
  try { S.gcmOpen(key, iv, ct); } catch (e) { threw = true; }
  ok('aes-256-gcm rejects a flipped byte', threw);
}
console.log(`\n${fails ? 'SOFT CRYPTO FAILED' : 'SOFT CRYPTO PASSED'} — ${checks - fails}/${checks} checks`);
process.exit(fails ? 1 : 0);
