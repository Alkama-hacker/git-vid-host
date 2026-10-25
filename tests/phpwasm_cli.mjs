/**
 * GVH test bridge: run a PHP CLI script inside php-wasm.
 *
 *   node phpwasm_cli.mjs --script /path/script.php --in /path/in.json --out /path/out.json
 *
 * Used by the test-suite (and by Arena) because no native PHP binary exists in
 * this sandbox. On Termux the real `php` binary is used instead.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { PHP } from '@php-wasm/universal';
import { loadNodeRuntime } from '@php-wasm/node';

const args = process.argv.slice(2);
const get = (name, dflt) => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : dflt;
};
const script = get('--script');
const inp = get('--in');
const out = get('--out');

const php = new PHP(await loadNodeRuntime('8.3', { emscriptenOptions: { processId: 1 } }));

const code = readFileSync(script, 'utf8');
php.writeFile('/tool.php', code);
if (inp) php.writeFile('/in.json', readFileSync(inp));
if (out) php.writeFile('/out.json', '');

let result;
try {
  result = await php.run({
    code: `<?php $GLOBALS['GVH_IN'] = '/in.json'; $GLOBALS['GVH_OUT'] = '/out.json'; require '/tool.php';`,
  });
} catch (err) {
  // PHP exited (gvh_fail): the JSON it wrote still explains why
  result = { exitCode: (err && err.response && err.response.exitCode) || 2, errors: '', text: '' };
}
if (out) {
  try {
    writeFileSync(out, php.readFileAsBuffer('/out.json'));
  } catch (e) {
    console.error('bridge: could not read out file:', e.message);
  }
}
if (result.errors) console.error(result.errors);
if (result.exitCode !== 0) {
  // gvh_fail() writes {ok:false,error:...} before exiting: surface it
  let why = result.text || '';
  try {
    const doc = JSON.parse(readFileSync(out, 'utf8'));
    if (doc && doc.error) why = doc.error;
  } catch (e) { /* no output file */ }
  console.error('PHP exit code', result.exitCode, why);
  process.exit(result.exitCode || 1);
}
if (!out && result.text) process.stdout.write(result.text);
process.exit(0);
