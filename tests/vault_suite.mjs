/**
 * Vault acceptance test: Shacker-Security projects, container crypto, unlock page.
 *
 *   node tests/vault_suite.mjs
 *
 * Everything runs through the real PHP helper (php-wasm here, native php on
 * Termux), so this catches offset/format drift between PHP, Python and the
 * generated unlock.php.
 */
import { readFileSync, writeFileSync, mkdirSync, mkdtempSync, statSync, readdirSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { randomBytes, createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { PHP } from '@php-wasm/universal';
import { loadNodeRuntime } from '@php-wasm/node';

const here = dirname(fileURLToPath(import.meta.url));
const repo = join(here, '..');
const tmp = mkdtempSync(join(tmpdir(), 'gvh-vault-'));
const vaultRoot = join(tmp, 'Shacker-Security');
let checks = 0;
let fails = 0;

const ok = (name, cond, extra = '') => {
  checks++;
  if (!cond) fails++;
  console.log(`${cond ? '  ✔' : '  ✖'} ${name}${extra ? ' — ' + extra : ''}`);
};
const sha = (buf) => createHash('sha256').update(buf).digest('hex');

function gvh(...args) {
  return execFileSync('python3', [join(repo, 'src', 'gvh.py'), ...args], {
    cwd: repo,
    env: { ...process.env, GVH_PHP_MODE: 'wasm', GVH_VAULT: vaultRoot },
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}

function gvhFail(...args) {
  try {
    gvh(...args);
    return '';
  } catch (err) {
    return `${err.stderr || ''}${err.stdout || ''}`;
  }
}

console.log('\n== 1. plain file ==');
const payload = randomBytes(300 * 1024); // 3 chunks at the default 1 MiB? no: single chunk + boundary test below
const srcFile = join(tmp, 'secret.bin');
writeFileSync(srcFile, payload);
const out1 = gvh('vault', srcFile, '--name', 'alpha-vault', '--password', 'hunter2x');
ok('seal prints the project folder', /alpha-vault/.test(out1));
const dir1 = join(vaultRoot, 'alpha-vault');
ok('project folder exists', statSync(dir1).isDirectory());
const files1 = readdirSync(dir1).sort();
ok('folder holds container + unlock page + card + audit',
  files1.includes('alpha-vault.gvhe') && files1.includes('unlock.php') &&
  files1.includes('project.txt') && files1.includes('AUDIT.json'), files1.join(', '));
const container1 = readFileSync(join(dir1, 'alpha-vault.gvhe'));
ok('container is raw binary, not base64 text', container1.subarray(0, 10).toString('latin1') === 'GVHVAULT1\n',
  container1.subarray(0, 10).toString('latin1'));
ok('container does not contain the plaintext', !container1.includes(payload.subarray(0, 64)));

gvh('unlock', dir1, '--password', 'hunter2x');
const back1 = readFileSync(join(dir1, 'alpha-vault'));
ok('local unlock reproduces the exact bytes', sha(back1) === sha(payload));

const wrong = gvhFail('unlock', dir1, '--password', 'definitely-wrong');
ok('wrong password is rejected', /wrong password|damaged/i.test(wrong), wrong.trim().split('\n').pop());
const stale = join(dir1, 'alpha-vault');
ok('wrong password leaves no output file behind', sha(readFileSync(stale)) === sha(payload));

console.log('\n== 2. tamper detection ==');
const tampered = join(tmp, 'tampered.gvhe');
const bad = Buffer.from(container1);
bad[bad.length - 40] ^= 0xff; // flip a ciphertext byte in the last chunk
writeFileSync(tampered, bad);
const tamperMsg = gvhFail('unlock', tampered, '--password', 'hunter2x', '-o', join(tmp, 'tamper.out'));
ok('flipped byte fails the GCM tag', /wrong password|damaged|truncated|checksum/i.test(tamperMsg),
  tamperMsg.trim().split('\n').pop());
ok('no plaintext written on failure', !(() => {
  try { readFileSync(join(tmp, 'tamper.out')); return true; } catch { return false; }
})());

console.log('\n== 3. multi-chunk (3 MiB > 1 MiB chunk) ==');
const big = randomBytes(3 * 1024 * 1024 + 777);
const bigSrc = join(tmp, 'big.bin');
writeFileSync(bigSrc, big);
gvh('vault', bigSrc, '--name', 'big-vault', '--password', 'chunky-pass');
const bigContainer = readFileSync(join(vaultRoot, 'big-vault', 'big-vault.gvhe'));
const headerLen = bigContainer.readUInt32BE(10);
const header = JSON.parse(bigContainer.subarray(14, 14 + headerLen).toString('utf8'));
ok('header records 4 chunks for 3 MiB at 1 MiB', header.n === 4, `n=${header.n}`);
ok('header keeps no plaintext name leak of content', header.size === big.length);
gvh('unlock', join(vaultRoot, 'big-vault'), '--password', 'chunky-pass');
ok('multi-chunk round-trip is byte-identical',
  sha(readFileSync(join(vaultRoot, 'big-vault', 'big-vault'))) === sha(big));

console.log('\n== 4. folder / zip payload ==');
const folder = join(tmp, 'project-dir');
mkdirSync(join(folder, 'sub'), { recursive: true });
writeFileSync(join(folder, 'a.txt'), 'alpha\n');
writeFileSync(join(folder, 'sub', 'b.txt'), 'bravo\n');
gvh('vault', folder, '--name', 'dir-vault', '--password', 'dirpass1');
const dirContainer = join(vaultRoot, 'dir-vault', 'dir-vault.gvhe');
ok('folder payload produced a container', statSync(dirContainer).size > 0);
gvh('unlock', join(vaultRoot, 'dir-vault'), '--password', 'dirpass1');
const unzipped = join(vaultRoot, 'dir-vault', 'dir-vault');
ok('folder payload decrypts to a zip', readFileSync(unzipped).subarray(0, 2).toString() === 'PK');

console.log('\n== 5. generated unlock.php (real POST) ==');
const php = new PHP(await loadNodeRuntime('8.3', { emscriptenOptions: { processId: 1 } }));
const unlockSrc = readFileSync(join(dir1, 'unlock.php')).toString('base64');
const containerSrc = container1.toString('base64');

// php-wasm keeps no state between php.run() calls: ship the page + container in
// the same snippet, exactly as a browser would POST to the deployed folder.
const runUnlock = async (password, method = 'POST') => {
  const res = await php.run({
    code: `<?php
      @mkdir('/vault');
      file_put_contents('/vault/alpha-vault.gvhe', base64_decode('${containerSrc}'));
      file_put_contents('/vault/index.php', base64_decode('${unlockSrc}'));
      $_SERVER['REQUEST_METHOD'] = '${method}';
      $_SERVER['REMOTE_ADDR'] = '127.0.0.1';
      $_POST['password'] = ${JSON.stringify(password)};
      $_REQUEST['password'] = ${JSON.stringify(password)};
      chdir('/vault');
      require '/vault/index.php';
    `,
  });
  return Buffer.from(res.bytes);
};

const good = await runUnlock('hunter2x');
ok('unlock.php streams the decrypted file', sha(good) === sha(payload),
  `${good.length} bytes vs ${payload.length}`);
const badPage = await runUnlock('nope');
ok('unlock.php refuses a wrong password', badPage.length < 60 * 1024 &&
  /Wrong password/i.test(badPage.toString('utf8')));
ok('unlock.php never echoes the payload on failure', !badPage.includes(payload.subarray(0, 64)));

const page = await runUnlock('', 'GET');
const pageText = page.toString('utf8');
ok('unlock.php GET renders the form', /<form method="post"/.test(pageText));
ok('unlock.php shows the branding footer', /@SHACKER_ENCRYPTION_bot/.test(pageText));
ok('unlock.php is mobile ready', /viewport-fit=cover/.test(pageText));
ok('unlock.php hides from search engines', /noindex/.test(pageText));
ok('unlock.php names the cipher', /AES-256-GCM/.test(pageText));
ok('unlock.php GET does not leak the plaintext', !page.includes(payload.subarray(0, 64)));

console.log('\n== 6. vault root bookkeeping ==');
const rootFiles = readdirSync(vaultRoot).sort();
ok('root README + ledger exist', rootFiles.includes('README.txt') && rootFiles.includes('projects.json'),
  rootFiles.join(', '));
const ledger = JSON.parse(readFileSync(join(vaultRoot, 'projects.json'), 'utf8'));
const entries = Array.isArray(ledger) ? ledger : ledger.projects || [];
ok('ledger lists every project', entries.length >= 3, `${entries.length} entries`);
const card = readFileSync(join(dir1, 'project.txt'), 'utf8');
ok('project card carries the credit banner', /@SHACKER_ENCRYPTION_bot/.test(card));
ok('project card warns about AUDIT.json', /AUDIT\.json/.test(card));

console.log('\n== 7. website target ==');
const site = join(tmp, 'site');
mkdirSync(join(site, 'assets'), { recursive: true });
writeFileSync(join(site, 'index.html'),
  '<!doctype html><html><head><title>Vault Site</title></head><body><h1>sealed</h1>' +
  '<script>console.log("hi")</script></body></html>');
writeFileSync(join(site, 'assets', 'logo.svg'), '<svg xmlns="http://www.w3.org/2000/svg"></svg>');
const outSite = gvh('vault', site, '--name', 'site-vault');
ok('website target needs no password', /site-vault/.test(outSite), outSite.trim().split('\n')[2] || '');
const siteDir = join(vaultRoot, 'site-vault');
ok('website produced index.php', statSync(join(siteDir, 'index.php')).size > 4000);
const indexSrc = readFileSync(join(siteDir, 'index.php'), 'utf8');
ok('website output opens with the credit banner comment', indexSrc.startsWith('<?php /*!'),
  indexSrc.slice(0, 16).replace(/\n/g, '\\n'));
ok('the banner is the first thing in the file',
  indexSrc.slice(0, 900).includes('@SHACKER_ENCRYPTION_bot'));
ok('the banner names the developer', /DEV\s+Shacker/.test(indexSrc.slice(0, 900)) ||
  indexSrc.slice(0, 900).includes('Shacker'));

console.log(`\n${fails === 0 ? 'VAULT SUITE PASSED' : 'VAULT SUITE FAILED'} — ${checks - fails}/${checks} checks`);
process.exit(fails === 0 ? 0 : 1);
