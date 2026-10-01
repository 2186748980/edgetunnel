// 本地功能测试：直接调用 Worker 的 fetch handler（不部署、不联网到真实 Worker）
// 用法: node test-flyclash.mjs
import { copyFileSync, unlinkSync } from 'node:fs';
import http from 'node:http';
import crypto from 'node:crypto';

// _worker.js 是 ESM 但扩展名为 .js，复制为 .mjs 供 Node 以 ESM 加载
copyFileSync('_worker.js', '.tmp-worker.mjs');

// Node webcrypto 不支持 MD5（Cloudflare Workers 专有扩展），这里用 node crypto 补齐
const 原始digest = crypto.subtle.digest.bind(crypto.subtle);
crypto.subtle.digest = async (algorithm, data) => {
	const name = typeof algorithm === 'string' ? algorithm : algorithm?.name;
	if (String(name).toUpperCase() === 'MD5') {
		const buf = crypto.createHash('md5').update(new Uint8Array(data)).digest();
		return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
	}
	return 原始digest(algorithm, data);
};

const { default: worker } = await import('./.tmp-worker.mjs');

const md5hex = (s) => crypto.createHash('md5').update(Buffer.from(s, 'utf8')).digest('hex');
const MD5MD5 = async (text) => md5hex(md5hex(text).slice(7, 27));

// ---------- 本地 mock 静态页服务器（替代 edt-pages.github.io） ----------
const mockServer = http.createServer((req, res) => {
	res.writeHead(200, { 'Content-Type': 'text/html; charset=UTF-8' });
	res.end('<!DOCTYPE html><html><head><title>mock-page:' + req.url + '</title></head><body>MOCK STATIC PAGE</body></html>');
});
await new Promise(r => mockServer.listen(18081, '127.0.0.1', r));

// ---------- env / ctx stub ----------
const UUID = 'a1b2c3d4-0000-4000-8000-00000000dead';
const ADMIN_PASSWORD = 'test-admin-password';
const store = new Map();
const env = {
	UUID,
	admin: ADMIN_PASSWORD, // 只提供 env.admin（验证 ADMIN||admin 逻辑）
	UI_URL: 'http://127.0.0.1:18081',
	KV: {
		get: async (k) => store.has(k) ? store.get(k) : null,
		put: async (k, v) => { store.set(k, v); },
		delete: async (k) => { store.delete(k); },
	},
};
const ctx = { waitUntil() { } };
const HOST = 'worker.local';
const userID = UUID.toLowerCase();
const 订阅TOKEN = await MD5MD5(HOST + userID);

const makeRequest = (path, headers = {}) => {
	const req = new Request(`https://${HOST}${path}`, { headers: { 'User-Agent': 'test-agent', ...headers } });
	Object.defineProperty(req, 'cf', { value: { colo: 'LAX', country: 'US', asn: 13335, asOrganization: 'CLOUDFLARENET' } });
	return req;
};
const call = async (path, headers = {}) => {
	try { return await worker.fetch(makeRequest(path, headers), env, ctx); }
	catch (e) { console.log(`  [worker threw] ${path}: ${e && e.stack ? e.stack.split('\n').slice(0, 4).join(' | ') : e}`); return { __error: e.message }; };
};

let pass = 0, fail = 0;
const check = (name, cond, detail = '') => {
	if (cond) { pass++; console.log(`  PASS  ${name}`); }
	else { fail++; console.log(`  FAIL  ${name}  ${detail}`); }
};

// ---------- 1. GET / 伪装页 ----------
{
	const res = await call('/');
	const text = await res.text();
	check('GET / 状态 200', res.status === 200, `status=${res.status}`);
	check('GET / 伪装页内容', text.includes('Welcome to nginx!'), `head=${text.slice(0, 80)}`);
}

// ---------- 2. GET /login 登录页 ----------
{
	const res = await call('/login');
	const text = await res.text();
	check('GET /login 状态 200', res.status === 200, `status=${res.status}`);
	check('GET /login 静态页 fallback', text.includes('mock-page:/login'), '');
}

// ---------- 3. GET /admin 未登录 → 302 /login ----------
{
	const res = await call('/admin');
	check('GET /admin 未登录 302', res.status === 302 && res.headers.get('location') === '/login', `status=${res.status} loc=${res.headers.get('location')}`);
}

// ---------- 4. /sub + FlyClash UA → Clash YAML ----------
{
	const res = await call(`/sub?token=${订阅TOKEN}`, { 'User-Agent': 'FlyClash/1.2.3 (clash-meta)' });
	const text = await res.text();
	const ct = res.headers.get('content-type') || '';
	check('/sub FlyClash UA 状态 200', res.status === 200, `status=${res.status}`);
	check('/sub FlyClash UA Content-Type x-yaml', ct.includes('yaml'), `ct=${ct}`);
	check('/sub FlyClash UA 不是 base64', !/^[A-Za-z0-9+/=\s]+$/.test(text) || text.includes('proxies:'), `head=${text.slice(0, 60)}`);
	check('/sub FlyClash UA 含 proxies:', text.includes('proxies:'), '');
	check('/sub FlyClash UA 含 vless 节点', /type:\s*"?vless"?/.test(text), '');
	check('/sub FlyClash UA 含真实 UUID', text.includes(UUID), '');
	check('/sub FlyClash UA 含 ws-opts', text.includes('ws-opts:'), '');
	check('/sub FlyClash UA 含 MATCH 规则', text.includes('MATCH,PROXY'), '');
	if (process.env.DUMP_YAML) console.log('---- YAML sample ----\n' + text.split('\n').slice(0, 40).join('\n'));
}

// ---------- 5. /sub?target=clash 显式参数 ----------
{
	const res = await call(`/sub?token=${订阅TOKEN}&target=clash`, { 'User-Agent': 'curl/8.0' });
	const text = await res.text();
	check('/sub target=clash 状态 200', res.status === 200, `status=${res.status}`);
	check('/sub target=clash Content-Type x-yaml', (res.headers.get('content-type') || '').includes('yaml'), `ct=${res.headers.get('content-type')}`);
	check('/sub target=clash 含 proxies:', text.includes('proxies:'), `head=${text.slice(0, 60)}`);
}

// ---------- 6. /sub?target=clash 交给 YAML parser 校验 ----------
{
	const res = await call(`/sub?token=${订阅TOKEN}&target=clash`, { 'User-Agent': 'curl/8.0' });
	const text = await res.text();
	const { writeFileSync } = await import('node:fs');
	writeFileSync('.tmp-clash-output.yaml', text);
	// 内置严格校验：缩进/键值结构自检（最终 mihomo 解析由 FlyClash 实测）
	const lines = text.split('\n');
	let 结构ok = true;
	for (const [i, line] of lines.entries()) {
		if (/^\t/.test(line)) { 结构ok = false; console.log(`    行 ${i + 1} 含 tab 缩进`); break; }
	}
	const proxiesStart = lines.indexOf('proxies:');
	const groupsStart = lines.indexOf('proxy-groups:');
	const rulesStart = lines.indexOf('rules:');
	结构ok = 结构ok && proxiesStart > -1 && groupsStart > proxiesStart && rulesStart > groupsStart;
	check('/sub target=clash YAML 结构自检', 结构ok, `proxies=${proxiesStart} groups=${groupsStart} rules=${rulesStart}`);
}

// ---------- 7. /sub + Mozilla UA（原 mixed 明文行为） ----------
{
	const res = await call(`/sub?token=${订阅TOKEN}`, { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0) v2rayN/7.0' });
	const text = await res.text();
	check('/sub Mozilla UA 状态 200', res.status === 200, `status=${res.status}`);
	check('/sub Mozilla UA text/plain', (res.headers.get('content-type') || '').includes('text/plain'), `ct=${res.headers.get('content-type')}`);
	check('/sub Mozilla UA 明文 VLESS URI', text.startsWith('vless://'), `head=${text.slice(0, 60)}`);
	check('/sub Mozilla UA 非 base64', !text.includes('dmxlc3M'), '');
}

// ---------- 8. /sub + 非 Mozilla 非 clash UA（原 base64 行为保持） ----------
{
	const res = await call(`/sub?token=${订阅TOKEN}`, { 'User-Agent': 'okhttp/4.9' });
	const text = await res.text();
	check('/sub 非浏览器 UA 状态 200', res.status === 200, `status=${res.status}`);
	let decoded = '';
	try { decoded = atob(text.trim()); } catch (e) { }
	check('/sub 非浏览器 UA 返回 base64', decoded.startsWith('vless://'), `decoded=${decoded.slice(0, 40)}`);
}

// ---------- 9. /sub 错误 token → 伪装页 ----------
{
	const res = await call('/sub?token=wrong-token', { 'User-Agent': 'FlyClash/1.0' });
	const text = await res.text();
	check('/sub 错误 token 拒绝', res.status === 200 && text.includes('Welcome to nginx!'), `status=${res.status} head=${text.slice(0, 40)}`);
}

// ---------- 10. /sub?b64&target=clash 组合（subconverter 语义不破坏） ----------
{
	const res = await call(`/sub?token=${订阅TOKEN}&b64`, { 'User-Agent': 'subconverter/0.9.0' });
	const text = await res.text();
	check('/sub b64 subconverter 仍为 mixed', (res.headers.get('content-type') || '').includes('text/plain'), `ct=${res.headers.get('content-type')}`);
	let decoded = '';
	try { decoded = atob(text.trim()); } catch (e) { }
	check('/sub b64 subconverter 内容为 URI 列表', decoded.startsWith('vless://') || decoded.startsWith('ss://'), `decoded=${decoded.slice(0, 40)}`);
}

// ---------- 11. 登录流程：POST /login 正确密码 → cookie → /admin 可访问 ----------
{
	const res = await call('/login', { 'User-Agent': 'admin-ua', });
	const post = await worker.fetch(makeRequest('/login', { 'User-Agent': 'admin-ua' }), env, ctx); // 预热
	const body = new URLSearchParams({ password: ADMIN_PASSWORD }).toString();
	const resPost = await worker.fetch(new Request(`https://${HOST}/login`, { method: 'POST', body, headers: { 'User-Agent': 'admin-ua', 'Content-Type': 'application/x-www-form-urlencoded' } }), env, ctx);
	const json = await resPost.json();
	check('POST /login 正确密码 success', resPost.status === 200 && json.success === true, `status=${resPost.status}`);
	const setCookie = resPost.headers.get('set-cookie') || '';
	const authCookie = (setCookie.match(/auth=([0-9a-f]+)/) || [])[1];
	check('POST /login 下发 auth cookie', Boolean(authCookie), `cookie=${setCookie.slice(0, 40)}`);
	if (authCookie) {
		const resAdmin = await worker.fetch(makeRequest('/admin', { 'User-Agent': 'admin-ua', 'Cookie': `auth=${authCookie}` }), env, ctx);
		check('带 cookie 访问 /admin 200', resAdmin.status === 200, `status=${resAdmin.status}`);
	}
}

// ---------- 12. 安全回归：无 ADMIN 时 / 返回 noADMIN 404 ----------
{
	const noAdminEnv = { ...env, admin: undefined, ADMIN: undefined };
	const req = new Request(`https://${HOST}/`);
	Object.defineProperty(req, 'cf', { value: { colo: 'LAX', country: 'US' } });
	const res = await worker.fetch(req, noAdminEnv, ctx);
	check('无 ADMIN 时 / 返回 404 noADMIN', res.status === 404, `status=${res.status}`);
}

// ---------- 13. ALLOW_DEFAULT_PROXY 未开启时不启用作者预设代理 ----------
{
	const req = makeRequest('/sub?token=' + 订阅TOKEN, { 'User-Agent': 'FlyClash/1.0' });
	const res = await worker.fetch(req, env, ctx);
	const text = await res.text();
	// 特征码字典[0] = PROXYIP 大写变形，作者代理域名包含 ".tp1."（字典0+tp1+字典1）
	check('订阅输出不含作者预设代理域名', !/\btp1\b/i.test(text), '');
}

mockServer.close();
unlinkSync('.tmp-worker.mjs');
console.log(`\n结果: ${pass} passed, ${fail} failed`);
process.exit(fail > 0 ? 1 : 0);
