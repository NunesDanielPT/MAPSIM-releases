// MapSim — servidor de licenças (sem dependências; Node 18+)
// Endpoints públicos: POST /api/activate, /api/check, /api/release · Painel: /admin (Basic Auth)
'use strict';
const http = require('http'), crypto = require('crypto'), fs = require('fs'), path = require('path');

const DATA = process.env.DATA_DIR || '/data';
const PORT = +process.env.PORT || 8080;
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
if (!ADMIN_PASSWORD || ADMIN_PASSWORD.length < 10) { console.error('Define ADMIN_PASSWORD (mínimo 10 caracteres).'); process.exit(1); }
fs.mkdirSync(DATA, { recursive: true });

/* ---------- chaves de assinatura (Ed25519) — geradas uma vez, ficam em /data ---------- */
const PRIV = path.join(DATA, 'signing-private.pem'), PUB = path.join(DATA, 'signing-public.pem');
if (!fs.existsSync(PRIV)) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  fs.writeFileSync(PRIV, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
  fs.writeFileSync(PUB, publicKey.export({ type: 'spki', format: 'pem' }));
  console.log('Novo par de chaves de assinatura criado em', DATA);
}
const privateKey = crypto.createPrivateKey(fs.readFileSync(PRIV));
const publicPem = fs.readFileSync(PUB, 'utf8');
const publicRaw = crypto.createPublicKey(publicPem).export({ type: 'spki', format: 'der' }).toString('base64');

/* ---------- base de dados (JSON) ---------- */
const DBF = path.join(DATA, 'keys.json');
let db = fs.existsSync(DBF) ? JSON.parse(fs.readFileSync(DBF, 'utf8')) : { keys: [], log: [] };
const save = () => { const t = DBF + '.tmp'; fs.writeFileSync(t, JSON.stringify(db, null, 1)); fs.renameSync(t, DBF); };
const log = (ev, k, ip, extra = '') => { db.log.unshift({ t: Date.now(), ev, key: k, ip, extra }); db.log = db.log.slice(0, 500); };
const newKey = () => 'MAPS-' + Array.from({ length: 4 }, () => crypto.randomBytes(3).toString('hex').toUpperCase().slice(0, 5)).join('-');
const b64u = b => Buffer.from(b).toString('base64url');

function sign(k) {
  const payload = { v: 1, k: k.key, o: k.owner, m: k.machine, iat: Date.now(), exp: k.expires || null };
  const body = b64u(JSON.stringify(payload));
  return body + '.' + b64u(crypto.sign(null, Buffer.from(body), privateKey));
}
function status(k) {
  if (!k) return 'Chave desconhecida.';
  if (k.revoked) return 'Esta chave foi revogada. Contacta o Daniel Nunes.';
  if (k.expires && Date.now() > k.expires) return 'Esta chave expirou. Contacta o Daniel Nunes.';
  return null;
}

/* ---------- limite de tentativas por IP ---------- */
const hits = new Map();
const limited = ip => { const now = Date.now(), a = (hits.get(ip) || []).filter(t => now - t < 3600e3); a.push(now); hits.set(ip, a); return a.length > 30; };

/* ---------- HTTP ---------- */
const send = (res, code, obj, type = 'application/json; charset=utf-8') => { res.writeHead(code, { 'Content-Type': type, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' }); res.end(typeof obj === 'string' ? obj : JSON.stringify(obj)); };
const body = req => new Promise((ok, ko) => { let s = ''; req.on('data', c => { s += c; if (s.length > 1e5) req.destroy(); }); req.on('end', () => ok(s)); req.on('error', ko); });
const ipOf = req => (req.headers['cf-connecting-ip'] || req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
function authed(req) {
  const h = req.headers.authorization || '';
  if (!h.startsWith('Basic ')) return false;
  const [u, p] = Buffer.from(h.slice(6), 'base64').toString().split(':');
  const a = Buffer.from(`${u}:${p ?? ''}`), b = Buffer.from(`${ADMIN_USER}:${ADMIN_PASSWORD}`);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

async function api(req, res, route, ip) {
  if (limited(ip)) return send(res, 429, { ok: false, error: 'Demasiadas tentativas. Tenta daqui a uma hora.' });
  let q; try { q = JSON.parse(await body(req) || '{}'); } catch { return send(res, 400, { ok: false, error: 'Pedido inválido.' }); }
  const key = String(q.key || '').trim().toUpperCase(), machine = String(q.machine || '').slice(0, 64);
  if (!/^[0-9a-f]{32}$/.test(machine)) return send(res, 400, { ok: false, error: 'Identificador do PC inválido.' });
  const k = db.keys.find(x => x.key === key), st = status(k);
  if (st) { log(route + '-fail', key, ip, st); save(); return send(res, 403, { ok: false, error: st }); }
  if (route === 'release') {
    if (k.machine === machine) { k.machine = null; log('release', key, ip); save(); }
    return send(res, 200, { ok: true });
  }
  if (k.machine && k.machine !== machine) {
    log(route + '-fail', key, ip, 'outro PC'); save();
    return send(res, 403, { ok: false, error: 'Esta chave já está ativada noutro computador. Desativa-a lá (Definições → Licença) ou pede ao Daniel Nunes para a libertar.' });
  }
  if (route === 'check' && !k.machine) return send(res, 403, { ok: false, error: 'Licença libertada para este PC. Ativa de novo.' });
  if (!k.machine) { k.machine = machine; k.activatedAt = Date.now(); k.pcName = String(q.pcName || '').slice(0, 60); }
  k.lastCheck = Date.now(); k.lastVersion = String(q.appVersion || '').slice(0, 20); k.lastIp = ip;
  log(route, key, ip, k.lastVersion); save();
  send(res, 200, { ok: true, license: sign(k) });
}

function adminPage(msg = '') {
  const fmt = t => t ? new Date(t).toLocaleString('pt-PT') : '—';
  const rows = db.keys.map(k => {
    const st = k.revoked ? '<b class="bad">revogada</b>' : k.expires && Date.now() > k.expires ? '<b class="bad">expirada</b>' : '<b class="ok">ativa</b>';
    return `<tr><td><code>${esc(k.key)}</code></td><td>${esc(k.owner)}<br><small>${esc(k.note)}</small></td><td>${st}</td><td>${k.expires ? fmt(k.expires).split(',')[0] : 'permanente'}</td>
    <td>${k.machine ? `<small>${esc(k.pcName || '')}<br><code>${esc(k.machine.slice(0, 12))}…</code></small>` : '<small>livre</small>'}</td><td><small>${fmt(k.lastCheck)}<br>${esc(k.lastVersion || '')}</small></td>
    <td><form method="post" action="/admin/act"><input type="hidden" name="key" value="${esc(k.key)}">
      ${k.machine ? '<button name="do" value="free">Libertar PC</button>' : ''}
      ${k.revoked ? '<button name="do" value="unrevoke">Reativar</button>' : '<button name="do" value="revoke" class="danger">Revogar</button>'}
      <input type="date" name="exp"><button name="do" value="setexp">Validade</button><button name="do" value="perm">Permanente</button></form></td></tr>`;
  }).join('');
  return `<!doctype html><html lang="pt"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>MapSim — Licenças</title>
<style>body{font:14px system-ui,sans-serif;background:#0b0e12;color:#d8e0ea;margin:24px}h1{font-weight:500}h1 b{color:#14c4ef}table{border-collapse:collapse;width:100%;margin-top:16px}td,th{border-bottom:1px solid #232b35;padding:8px;text-align:left;vertical-align:top}th{color:#7f8b99;font-weight:500;font-size:12px;text-transform:uppercase}
input,button{background:#151a21;color:#d8e0ea;border:1px solid #2b3540;border-radius:5px;padding:6px 9px;font:inherit}button{cursor:pointer}button:hover{border-color:#14c4ef}.danger{color:#ff7a7a}.ok{color:#3ddc97}.bad{color:#ff5d5d}
.card{background:#0e1217;border:1px solid #232b35;border-radius:8px;padding:14px;margin:14px 0}code{font-family:Consolas,monospace;color:#9fd8ee}textarea{width:100%;height:110px;background:#151a21;color:#9fd8ee;border:1px solid #2b3540;font:12px Consolas,monospace}.msg{background:#04222c;border:1px solid #14c4ef;padding:10px;border-radius:6px}small{color:#7f8b99}</style>
<h1><b>MapSim</b> — licenças</h1>${msg ? `<p class="msg">${msg}</p>` : ''}
<div class="card"><form method="post" action="/admin/new"><b>Nova chave</b>&nbsp; <input name="owner" placeholder="Nome / empresa" required> <input name="note" placeholder="Nota (opcional)"> Validade <input type="date" name="exp"> <small>(vazio = permanente)</small> <button>Criar chave</button></form></div>
<table><tr><th>Chave</th><th>Cliente</th><th>Estado</th><th>Validade</th><th>PC</th><th>Última verificação</th><th>Acções</th></tr>${rows || '<tr><td colspan="7"><small>Ainda não há chaves.</small></td></tr>'}</table>
<div class="card"><b>Chave pública de assinatura</b> — envia isto para meter na app (não é secreta):<textarea readonly>${esc(publicRaw)}</textarea></div>
<div class="card"><b>Registo</b><br><small>${db.log.slice(0, 40).map(l => `${fmt(l.t)} · ${esc(l.ev)} · ${esc(l.key)} · ${esc(l.ip)} ${esc(l.extra)}`).join('<br>')}</small></div></html>`;
}

async function admin(req, res, url) {
  if (!authed(req)) { res.writeHead(401, { 'WWW-Authenticate': 'Basic realm="MapSim"' }); return res.end('Autenticação necessária'); }
  if (req.method === 'GET') return send(res, 200, adminPage(), 'text/html; charset=utf-8');
  // proteção CSRF: o POST tem de vir da própria página do painel
  const origin = req.headers.origin || req.headers.referer || '';
  try { if (new URL(origin).host !== req.headers.host) return send(res, 403, 'Origem inválida', 'text/plain'); } catch { return send(res, 403, 'Origem inválida', 'text/plain'); }
  const f = new URLSearchParams(await body(req)), dateMs = s => s ? new Date(s + 'T23:59:59').getTime() : null;
  let msg = '';
  if (url === '/admin/new') {
    const k = { key: newKey(), owner: f.get('owner')?.slice(0, 80) || '—', note: f.get('note')?.slice(0, 120) || '', created: Date.now(), expires: dateMs(f.get('exp')), revoked: false, machine: null };
    db.keys.unshift(k); log('create', k.key, 'admin', k.owner); save(); msg = `Chave criada para <b>${esc(k.owner)}</b>: <code>${k.key}</code>`;
  } else if (url === '/admin/act') {
    const k = db.keys.find(x => x.key === f.get('key')); const d = f.get('do');
    if (k) {
      if (d === 'revoke') k.revoked = true; if (d === 'unrevoke') k.revoked = false; if (d === 'free') k.machine = null;
      if (d === 'setexp' && f.get('exp')) k.expires = dateMs(f.get('exp')); if (d === 'perm') k.expires = null;
      log('admin-' + d, k.key, 'admin'); save(); msg = `${esc(k.key)}: feito (${esc(d)}).`;
    }
  }
  send(res, 200, adminPage(msg), 'text/html; charset=utf-8');
}

http.createServer(async (req, res) => {
  try {
    const url = req.url.split('?')[0], ip = ipOf(req);
    if (url === '/health') return send(res, 200, { ok: true });
    if (req.method === 'POST' && ['/api/activate', '/api/check', '/api/release'].includes(url)) return await api(req, res, url.slice(5), ip);
    if (url === '/admin' || url.startsWith('/admin/')) return await admin(req, res, url);
    send(res, 404, { ok: false, error: 'Não encontrado' });
  } catch (e) { console.error(e); send(res, 500, { ok: false, error: 'Erro interno' }); }
}).listen(PORT, () => console.log(`MapSim licenças a ouvir em :${PORT}`));
