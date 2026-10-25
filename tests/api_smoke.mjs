import { startServer } from './php_server.mjs';
import { webcrypto } from 'node:crypto';
const dir = process.argv[2] || '/tmp/gvh-out/simple';
const srv = await startServer(dir + '/index.php');
const r = await srv.request({ path: '/index.php' });
const html = r.text();
console.log('leaks: SECRET SAUCE?', html.includes('SECRET SAUCE'), '| internal note?', html.includes('internal note'), '| hero?', html.includes('hero'));
const cookie = r.setCookies[0].split(';')[0];
const m = html.match(/var MAN_B64 = "([^"]+)"/);
console.log('manifest found', !!m, m && m[1].slice(0,20));
// decode manifest: base64 xor with MX
const mxm = html.match(/var MX = (\[[^\]]+\])/);
const MX = JSON.parse(mxm[1]);
const raw = Buffer.from(m[1], 'base64');
const dec = Buffer.from(raw.map((b,i)=>b ^ MX[i%MX.length]));
const MAN = JSON.parse(dec.toString('utf8'));
console.log('manifest keys', Object.keys(MAN).join(','));
console.log('apis', MAN.content.apis.length, 'fakes', MAN.fakes.length, 'sess', MAN.sess.t.slice(0,20));
const key = Buffer.from(MAN.sess.k,'base64');
const api = MAN.content.apis[0];
const nonce = 'a1b2c3d4e5f6a7b8';
const sig = Buffer.from(await webcrypto.subtle.sign('HMAC', await webcrypto.subtle.importKey('raw', key, {name:'HMAC',hash:'SHA-256'}, false, ['sign']), Buffer.from(api+'|'+nonce))).toString('hex');
const url = `/index.php?${MAN.gw}=${api}&${MAN.pn}=${nonce}&${MAN.ps}=${sig}&${MAN.pt}=${encodeURIComponent(MAN.sess.t)}`;
const ar = await srv.request({ path: url, cookies: { [cookie.split('=')[0]]: cookie.split('=')[1] } });
console.log('api status', ar.status, 'body', ar.text().slice(0,60));
// unseal
const stream = Buffer.from(await webcrypto.subtle.digest('SHA-256', Buffer.from(key.toString('binary')+'|'+api+'|'+nonce+'|r','binary')));
const enc = Buffer.from(JSON.parse(ar.text()).p, 'base64');
const plain = Buffer.from(enc.map((b,i)=>b ^ stream[i%32])).toString('utf8');
console.log('unsealed', plain.slice(0,120));
// wrong sig
const bad = await srv.request({ path: url.replace(sig, 'f'.repeat(64)) });
console.log('bad sig status', bad.status);
// no cookie/token
const noc = await srv.request({ path: `/index.php?${MAN.gw}=${api}&${MAN.pn}=${nonce}&${MAN.ps}=${sig}` });
console.log('no session status', noc.status);
// bot UA
const bot = await srv.request({ path: '/index.php', ua: 'curl/8.0' });
console.log('bot status', bot.status, bot.text().includes('NICE TRY'));
process.exit(0);
