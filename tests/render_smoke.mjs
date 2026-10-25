import { startServer, boot, render } from './client_test.mjs';
const dir = process.argv[2] || '/tmp/gvh-out/simple';
const srv = await startServer(dir + '/index.php');
const b = await boot(srv, { globals: { __GVH_DEBUG: 1 } });
const r = render(b.finalHtml, srv, {});
await new Promise((res) => setTimeout(res, 700));
const w = r.win, d = r.doc;
console.log('title', d.title);
console.log('headline', d.getElementById('headline') && d.getElementById('headline').textContent);
console.log('data-ready', d.body && d.body.getAttribute('data-ready'));
const btn = d.getElementById('btn');
if (btn) {
  btn.dispatchEvent(new w.MouseEvent('click', { bubbles: true }));
  console.log('after click', d.getElementById('sub') && d.getElementById('sub').textContent);
}
const ev = new w.MouseEvent('contextmenu', { bubbles: true, cancelable: true });
const allowed = d.dispatchEvent(ev);
console.log('contextmenu prevented', !allowed, ev.defaultPrevented);
await new Promise((res) => setTimeout(res, 3200));
console.log('writes after 3.9s', r.writes.length, r.writes[0] ? r.writes[0].slice(0, 80) : '');
console.log('errors', r.errors.filter((e) => !/Not implemented/.test(e)).slice(0, 3));
r.close();
process.exit(0);
