/**
 * Minimal PHP "web server" harness on top of php-wasm.
 *
 *   const srv = await startServer('/path/index.php');
 *   const res = await srv.request({ path: '/index.php', headers: {...}, cookies: {...} });
 *   // -> { status, headers: {name: [values]}, body: Buffer, cookies: {..} }
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { PHP } from '@php-wasm/universal';
import { loadNodeRuntime } from '@php-wasm/node';

const WRAPPER = `<?php
$R = json_decode(file_get_contents('/req.json'), true);
$_SERVER = $R['server'];
$_GET = $R['get'] ? $R['get'] : array();
$_POST = $R['post'] ? $R['post'] : array();
$_COOKIE = $R['cookies'] ? $R['cookies'] : array();
$_REQUEST = array_merge($_GET, $_POST);
$GLOBALS['GVH_HDR'] = array();
$GLOBALS['GVH_STATUS'] = 200;
register_shutdown_function(function () {
  $body = '';
  while (ob_get_level() > 0) { $body = ob_get_clean() . $body; }
  $hdrs = isset($GLOBALS['GVH_HDR']) && is_array($GLOBALS['GVH_HDR']) ? $GLOBALS['GVH_HDR'] : array();
  if (!$hdrs && function_exists('headers_list')) { $hdrs = headers_list(); }
  $status = isset($GLOBALS['GVH_STATUS']) ? $GLOBALS['GVH_STATUS'] : 200;
  file_put_contents('/res.json', json_encode(array(
    'status' => $status,
    'headers' => $hdrs,
    'body_b64' => base64_encode($body),
  )));
});
ob_start();
require '/app/index.php';
`;

export async function startServer(indexPath, opts = {}) {
  const root = join(indexPath, '..');
  const php = new PHP(await loadNodeRuntime('8.3', { emscriptenOptions: { processId: 1 } }));
  try { php.mkdir('/app'); } catch (e) { }
  try { php.mkdir('/app/data'); } catch (e) { }
  const walk = (dir) => {
    for (const name of readdirSync(dir)) {
      const full = join(dir, name);
      const st = statSync(full);
      const rel = relative(root, full).replace(/\\/g, '/');
      if (st.isDirectory()) {
        try { php.mkdir('/app/' + rel); } catch (e) { }
        walk(full);
      } else {
        php.writeFile('/app/' + rel, readFileSync(full));
      }
    }
  };
  walk(root);
  php.writeFile('/wrapper.php', WRAPPER);
  const base = opts.base || 'https://example.com';

  async function request(spec = {}) {
    const url = new URL(spec.path || '/index.php', base);
    const get = {};
    for (const [k, v] of url.searchParams.entries()) get[k] = v;
    const cookies = {};
    if (spec.cookieHeader) {
      for (const part of spec.cookieHeader.split(';')) {
        const i = part.indexOf('=');
        if (i > 0) cookies[part.slice(0, i).trim()] = part.slice(i + 1).trim();
      }
    }
    Object.assign(cookies, spec.cookies || {});
    const headers = {};
    for (const [k, v] of Object.entries(spec.headers || {})) headers[k.toUpperCase().replace(/-/g, '_')] = v;
    const ua = typeof spec.ua === 'string' ? spec.ua
      : (headers['USER_AGENT'] || 'Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36');
    headers['USER_AGENT'] = ua;
    const server = {
      REQUEST_METHOD: spec.method || 'GET',
      REQUEST_URI: url.pathname + url.search,
      QUERY_STRING: url.search.replace(/^\?/, ''),
      HTTP_HOST: url.host,
      SERVER_NAME: url.hostname,
      SERVER_PORT: url.port || (url.protocol === 'https:' ? '443' : '80'),
      HTTPS: url.protocol === 'https:' ? 'on' : '',
      REMOTE_ADDR: spec.ip || '203.0.113.9',
      HTTP_USER_AGENT: ua,
      SCRIPT_NAME: url.pathname,
      SCRIPT_FILENAME: '/app/index.php',
      DOCUMENT_ROOT: '/app',
      HTTP_ACCEPT_ENCODING: 'identity',
    };
    for (const [k, v] of Object.entries(headers)) server['HTTP_' + k] = v;
    if (spec.referer) server.HTTP_REFERER = spec.referer;
    if (spec.range) server.HTTP_RANGE = spec.range;
    if (spec.token) server.HTTP_X_GVH_S = spec.token;
    const req = { server, get, post: spec.post || {}, cookies };
    php.writeFile('/req.json', JSON.stringify(req));
    php.writeFile('/res.json', '');
    const out = await php.run({ code: `<?php require '/wrapper.php';` });
    let doc;
    try {
      doc = JSON.parse(php.readFileAsText('/res.json'));
    } catch (e) {
      throw new Error('PHP harness: no response (' + (out.errors || out.text || '') + ')');
    }
    const hdrs = {};
    for (const line of doc.headers || []) {
      const i = line.indexOf(':');
      if (i < 0) continue;
      const k = line.slice(0, i).trim().toLowerCase();
      (hdrs[k] = hdrs[k] || []).push(line.slice(i + 1).trim());
    }
    const setCookies = (hdrs['set-cookie'] || []).map((c) => c.split(';')[0]);
    return {
      status: doc.status,
      headers: hdrs,
      header: (k) => (hdrs[String(k).toLowerCase()] || [])[0],
      setCookies,
      body: Buffer.from(doc.body_b64 || '', 'base64'),
      text: () => Buffer.from(doc.body_b64 || '', 'base64').toString('utf8'),
    };
  }
  return { php, request };
}
