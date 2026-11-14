// MapSim — servidor de licenças (sem dependências; Node 18+)
// Endpoints públicos: POST /api/activate, /api/check, /api/release · Painel: /admin (Basic Auth)
'use strict';
const SERVER_VERSION = '0.9.0';
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
db.changelog ||= []; // [{version,date,title,items[],hidden,edited}]
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

/* ---------- novidades (changelog): base no GitHub, editável no painel ---------- */
const CHANGELOG_URL = process.env.CHANGELOG_URL || 'https://raw.githubusercontent.com/NunesDanielPT/MAPSIM-releases/main/data/changelog.json';
const vnum = v => String(v).split('.').map(n => +n || 0), vcmp = (a, b) => { const x = vnum(a), y = vnum(b); for (let i = 0; i < 3; i++) if ((x[i] || 0) !== (y[i] || 0)) return (x[i] || 0) - (y[i] || 0); return 0; };
const lines = a => (Array.isArray(a) ? a : []).map(x => String(x).slice(0, 400)).filter(Boolean).slice(0, 30);
const cleanEntry = e => ({ version: String(e.version || '').slice(0, 20), date: String(e.date || '').slice(0, 10), title: String(e.title || '').slice(0, 120), items: lines(e.items), title_en: String(e.title_en || '').slice(0, 120), items_en: lines(e.items_en) });
let lastSync = 0;
async function syncChangelog(force) {
  if (!force && Date.now() - lastSync < 10 * 60e3) return;
  lastSync = Date.now();
  try {
    const r = await fetch(CHANGELOG_URL, { signal: AbortSignal.timeout(8000) }); if (!r.ok) return;
    const j = await r.json(); let changed = false;
    for (const e of (j.versions || []).map(cleanEntry)) {
      if (!/^\d+\.\d+\.\d+$/.test(e.version)) continue;
      const cur = db.changelog.find(x => x.version === e.version);
      if (!cur) { db.changelog.push({ ...e, hidden: false, edited: false }); changed = true; }
      else if (!cur.edited && JSON.stringify([cur.date, cur.title, cur.items, cur.title_en, cur.items_en]) !== JSON.stringify([e.date, e.title, e.items, e.title_en, e.items_en])) { Object.assign(cur, e); changed = true; }
      else if (cur.edited && !cur.title_en && e.title_en) { cur.title_en = e.title_en; cur.items_en = e.items_en; changed = true; }
    }
    if (changed) { db.changelog.sort((a, b) => vcmp(b.version, a.version)); save(); }
  } catch (e) { console.error('changelog:', e.message); }
}
syncChangelog(true); setInterval(() => syncChangelog(true), 30 * 60e3);

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

const fmtT = t => t ? new Date(t).toLocaleString('pt-PT', { timeZone: process.env.TZ || 'Europe/Lisbon' }) : '—';
const EV = { create: 'chave criada', activate: 'ativação', check: 'verificação', release: 'PC libertado pelo cliente', 'activate-fail': 'ativação recusada', 'check-fail': 'verificação recusada', 'release-fail': 'libertação recusada',
  'admin-revoke': 'revogada', 'admin-unrevoke': 'reativada', 'admin-free': 'PC libertado', 'admin-setexp': 'validade alterada', 'admin-perm': 'validade permanente', 'admin-delete': 'chave apagada' };
const layout = (section, title, inner, msg) => `<!doctype html><html lang="pt"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>MapSim — ${esc(title)}</title>
<style>*{box-sizing:border-box}body{font:14px system-ui,sans-serif;background:#0b0e12;color:#d8e0ea;margin:0;display:flex;min-height:100vh}
nav{width:220px;background:#0e1217;border-right:1px solid #232b35;padding:22px 14px;flex:0 0 auto}nav h1{font-size:19px;font-weight:500;margin:0 0 2px}nav h1 b{color:#14c4ef}nav .v{color:#7f8b99;font-size:11px;margin-bottom:22px;display:block}
nav a{display:flex;justify-content:space-between;color:#c4ccd6;text-decoration:none;padding:9px 12px;border-radius:7px;margin:2px 0}nav a:hover{background:#151a21}nav a.on{background:#04222c;color:#14c4ef}nav a em{font-style:normal;color:#7f8b99;font-size:12px}
main{flex:1;padding:26px 30px;min-width:0}h2{font-weight:500;margin:0 0 16px}table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid #232b35;padding:8px;text-align:left;vertical-align:top}th{color:#7f8b99;font-weight:500;font-size:12px;text-transform:uppercase}
input,button,select{background:#151a21;color:#d8e0ea;border:1px solid #2b3540;border-radius:5px;padding:6px 9px;font:inherit}button{cursor:pointer}button:hover{border-color:#14c4ef}.danger{color:#ff7a7a}.ok{color:#3ddc97}.bad{color:#ff5d5d}.warn{color:#f5a524}
.card{background:#0e1217;border:1px solid #232b35;border-radius:8px;padding:14px;margin:0 0 16px}code{font-family:Consolas,monospace;color:#9fd8ee}textarea{width:100%;background:#151a21;color:#d8e0ea;border:1px solid #2b3540;border-radius:5px;padding:8px;font:13px system-ui}
.msg{background:#04222c;border:1px solid #14c4ef;padding:10px;border-radius:6px;margin-bottom:16px}small,.muted{color:#7f8b99}.news{border-top:1px solid #232b35;padding:12px 0}.news textarea{height:70px;margin:6px 0}.row{display:flex;gap:6px;flex-wrap:wrap;align-items:center}</style>
<nav><h1><b>MapSim</b> licenças</h1><span class="v">servidor v${SERVER_VERSION}</span>
${[['keys', '/admin', 'Chaves', db.keys.length], ['news', '/admin/news', 'Novidades', db.changelog.length], ['log', '/admin/log', 'Registo', db.log.length], ['config', '/admin/config', 'Configuração', '']]
  .map(([k, u, t, n]) => `<a href="${u}" class="${k === section ? 'on' : ''}">${t}<em>${n}</em></a>`).join('')}</nav>
<main><h2>${esc(title)}</h2>${msg ? `<div class="msg">${msg}</div>` : ''}${inner}</main></html>`;

function pageKeys(msg, q) {
  const f = (q.get('q') || '').toLowerCase(), list = db.keys.filter(k => !f || `${k.key} ${k.owner} ${k.note} ${k.pcName || ''}`.toLowerCase().includes(f));
  const rows = list.map(k => {
    const st = k.revoked ? '<b class="bad">revogada</b>' : k.expires && Date.now() > k.expires ? '<b class="bad">expirada</b>' : '<b class="ok">ativa</b>';
    return `<tr><td><code>${esc(k.key)}</code><br><small>criada ${fmtT(k.created).split(',')[0]}</small></td><td>${esc(k.owner)}<br><small>${esc(k.note)}</small></td><td>${st}</td><td>${k.expires ? fmtT(k.expires).split(',')[0] : 'permanente'}</td>
    <td>${k.machine ? `<small>${esc(k.pcName || '')}<br><code>${esc(k.machine.slice(0, 12))}…</code></small>` : '<small>livre</small>'}</td><td><small>${fmtT(k.lastCheck)}<br>${esc(k.lastVersion || '')}</small><br><a href="/admin/log?q=${encodeURIComponent(k.key)}" style="color:#14c4ef;font-size:12px">ver registo</a></td>
    <td><form method="post" action="/admin/act" class="row"><input type="hidden" name="key" value="${esc(k.key)}">
      ${k.machine ? '<button name="do" value="free">Libertar PC</button>' : ''}
      ${k.revoked ? '<button name="do" value="unrevoke">Reativar</button>' : '<button name="do" value="revoke" class="danger">Revogar</button>'}
      <input type="date" name="exp"><button name="do" value="setexp">Validade</button><button name="do" value="perm">Permanente</button>
      <button name="do" value="delete" class="danger" onclick="return confirm('Apagar definitivamente a chave ${esc(k.key)} (${esc(k.owner)})? Quem a usa perde o acesso na próxima verificação.')">Apagar</button></form></td></tr>`;
  }).join('');
  return layout('keys', 'Chaves', `<div class="card"><form method="post" action="/admin/new" class="row"><b>Nova chave</b> <input name="owner" placeholder="Nome / empresa" required> <input name="note" placeholder="Nota (opcional)"> Validade <input type="date" name="exp"> <small>(vazio = permanente)</small> <button>Criar chave</button></form></div>
<form method="get" action="/admin" class="row" style="margin-bottom:10px"><input name="q" value="${esc(q.get('q') || '')}" placeholder="Procurar chave, cliente, PC…" style="width:280px"><button>Procurar</button>${f ? ' <a href="/admin" style="color:#14c4ef">limpar</a>' : ''}</form>
<table><tr><th>Chave</th><th>Cliente</th><th>Estado</th><th>Validade</th><th>PC</th><th>Última verificação</th><th>Acções</th></tr>${rows || '<tr><td colspan="7"><small>Sem chaves.</small></td></tr>'}</table>`, msg);
}
function pageNews(msg) {
  const forms = [{ version: '', date: new Date().toISOString().slice(0, 10), title: '', items: [], hidden: false, isNew: true }, ...db.changelog].map(e => `<form method="post" action="/admin/news" class="news">
<div class="row"><input name="version" value="${esc(e.version)}" placeholder="0.9.0" ${e.isNew ? '' : 'readonly'} style="width:84px"> <input type="date" name="date" value="${esc(e.date)}"> <input name="title" value="${esc(e.title)}" placeholder="Título curto" style="width:340px">
<label><input type="checkbox" name="hidden" ${e.hidden ? 'checked' : ''}> esconder</label> ${e.isNew ? '<b>nova versão</b>' : e.edited ? '<small class="ok">editado por ti</small>' : '<small>do GitHub</small>'}</div>
<div class="row" style="align-items:flex-start"><div style="flex:1"><small>Português</small><textarea name="items" placeholder="Uma novidade por linha">${esc((e.items || []).join('\n'))}</textarea></div>
<div style="flex:1"><small>English</small> <input name="title_en" value="${esc(e.title_en || '')}" placeholder="Title (English)" style="width:100%;margin:2px 0 0"><textarea name="items_en" placeholder="One item per line (English)">${esc((e.items_en || []).join('\n'))}</textarea></div></div>
<div class="row"><button name="do" value="save">Guardar</button>${e.isNew ? '' : ` ${e.edited ? '<button name="do" value="reset">Repor texto do GitHub</button>' : ''} <button name="do" value="delete" class="danger" onclick="return confirm('Remover a versão ${esc(e.version)} das novidades?')">Remover</button>`}</div></form>`).join('');
  return layout('news', 'Novidades', `<div class="card row"><form method="post" action="/admin/news"><button name="do" value="sync">Sincronizar com o GitHub</button></form>
<small>Aparecem na app ao actualizar e em Definições → Updates · uma linha por novidade · as versões editadas aqui não são substituídas pelo GitHub</small></div><div class="card">${forms}</div>`, msg);
}
function pageLog(q) {
  const f = (q.get('q') || '').toLowerCase(), ev = q.get('ev') || '';
  const list = db.log.filter(l => (!f || `${l.key} ${l.ip} ${l.extra}`.toLowerCase().includes(f)) && (!ev || l.ev === ev));
  const opts = [...new Set(db.log.map(l => l.ev))].map(e => `<option value="${esc(e)}" ${e === ev ? 'selected' : ''}>${esc(EV[e] || e)}</option>`).join('');
  return layout('log', 'Registo', `<form method="get" action="/admin/log" class="row" style="margin-bottom:10px"><input name="q" value="${esc(q.get('q') || '')}" placeholder="Chave, IP…" style="width:260px"><select name="ev"><option value="">Todos os eventos</option>${opts}</select><button>Filtrar</button>${f || ev ? ' <a href="/admin/log" style="color:#14c4ef">limpar</a>' : ''}</form>
<table><tr><th>Data</th><th>Evento</th><th>Chave</th><th>Cliente</th><th>IP</th><th>Detalhe</th></tr>${list.slice(0, 300).map(l => { const k = db.keys.find(x => x.key === l.key);
  return `<tr><td><small>${fmtT(l.t)}</small></td><td class="${/fail/.test(l.ev) ? 'warn' : ''}">${esc(EV[l.ev] || l.ev)}</td><td><code>${esc(l.key)}</code></td><td>${esc(k?.owner || '')}</td><td><small>${esc(l.ip)}</small></td><td><small>${esc(l.extra)}</small></td></tr>`; }).join('') || '<tr><td colspan="6"><small>Sem registos.</small></td></tr>'}</table>
<p class="muted">Mostra os últimos ${Math.min(list.length, 300)} de ${list.length} eventos (o servidor guarda os 500 mais recentes).</p>`, '');
}
function pageConfig() {
  return layout('config', 'Configuração', `<div class="card"><b>Chave pública de assinatura</b><p class="muted">Está dentro da app (license-config.json). Não é secreta. Se a chave privada do servidor mudar, as licenças existentes deixam de ser válidas.</p><textarea readonly style="height:60px;font-family:Consolas,monospace;color:#9fd8ee">${esc(publicRaw)}</textarea></div>
<div class="card"><b>Servidor</b><table><tr><td>Versão</td><td>${SERVER_VERSION}</td></tr><tr><td>Chaves</td><td>${db.keys.length} (${db.keys.filter(k => !k.revoked && !(k.expires && Date.now() > k.expires)).length} ativas, ${db.keys.filter(k => k.machine).length} com PC)</td></tr>
<tr><td>Novidades — origem</td><td><code>${esc(CHANGELOG_URL)}</code></td></tr><tr><td>Dados</td><td><code>${esc(DATA)}</code></td></tr></table>
<p class="muted">Para actualizar o servidor basta reiniciar o contentor no Portainer.</p></div>`, '');
}

async function admin(req, res, url) {
  if (!authed(req)) { res.writeHead(401, { 'WWW-Authenticate': 'Basic realm="MapSim"' }); return res.end('Autenticação necessária'); }
  const q = new URLSearchParams(req.url.split('?')[1] || ''), html = h => send(res, 200, h, 'text/html; charset=utf-8');
  if (req.method === 'GET') return html(url === '/admin/news' ? pageNews('') : url === '/admin/log' ? pageLog(q) : url === '/admin/config' ? pageConfig() : pageKeys('', q));
  // proteção CSRF: o POST tem de vir da própria página do painel
  const origin = req.headers.origin || req.headers.referer || '';
  try { if (new URL(origin).host !== req.headers.host) return send(res, 403, 'Origem inválida', 'text/plain'); } catch { return send(res, 403, 'Origem inválida', 'text/plain'); }
  const f = new URLSearchParams(await body(req)), dateMs = s => s ? new Date(s + 'T23:59:59').getTime() : null;
  let msg = '';
  if (url === '/admin/new') {
    const k = { key: newKey(), owner: f.get('owner')?.slice(0, 80) || '—', note: f.get('note')?.slice(0, 120) || '', created: Date.now(), expires: dateMs(f.get('exp')), revoked: false, machine: null };
    db.keys.unshift(k); log('create', k.key, 'admin', k.owner); save(); msg = `Chave criada para <b>${esc(k.owner)}</b>: <code>${k.key}</code>`;
  } else if (url === '/admin/news') {
    const d = f.get('do'), v = String(f.get('version') || '').trim();
    if (d === 'sync') { await syncChangelog(true); msg = 'Novidades sincronizadas com o GitHub.'; }
    else if (/^\d+\.\d+\.\d+$/.test(v)) {
      let e = db.changelog.find(x => x.version === v);
      if (d === 'reset' && e) { e.edited = false; save(); await syncChangelog(true); msg = `Versão ${esc(v)}: texto original reposto.`; }
      else if (d === 'delete' && e) { db.changelog = db.changelog.filter(x => x !== e); save(); msg = `Versão ${esc(v)} removida.`; }
      else if (d === 'save') {
        const split = k => String(f.get(k) || '').split(/\r?\n/).map(x => x.replace(/^[-•*]\s*/, '').trim());
        const ne = cleanEntry({ version: v, date: f.get('date'), title: f.get('title'), items: split('items'), title_en: f.get('title_en'), items_en: split('items_en') });
        if (!e) { e = { hidden: false }; db.changelog.push(e); }
        Object.assign(e, ne, { hidden: f.get('hidden') === 'on', edited: true });
        db.changelog.sort((a, b) => vcmp(b.version, a.version)); save(); msg = `Versão ${esc(v)} guardada.`;
      }
    } else msg = 'Versão inválida (usa o formato 0.7.0).';
  } else if (url === '/admin/act') {
    const k = db.keys.find(x => x.key === f.get('key')); const d = f.get('do');
    if (k) {
      if (d === 'revoke') k.revoked = true; if (d === 'unrevoke') k.revoked = false; if (d === 'free') k.machine = null;
      if (d === 'setexp' && f.get('exp')) k.expires = dateMs(f.get('exp')); if (d === 'perm') k.expires = null;
      if (d === 'delete') { db.keys = db.keys.filter(x => x !== k); log('admin-delete', k.key, 'admin', k.owner); save(); msg = `Chave ${esc(k.key)} (${esc(k.owner)}) apagada.`; }
      else { log('admin-' + d, k.key, 'admin'); save(); msg = `${esc(k.key)}: feito (${esc(d)}).`; }
    }
  }
  html(url === '/admin/news' ? pageNews(msg) : pageKeys(msg, new URLSearchParams()));
}

http.createServer(async (req, res) => {
  try {
    const url = req.url.split('?')[0], ip = ipOf(req);
    if (url === '/health') return send(res, 200, { ok: true, version: SERVER_VERSION });
    if (url === '/api/changelog' && req.method === 'GET') { await syncChangelog(false); return send(res, 200, { ok: true, versions: db.changelog.filter(e => !e.hidden).map(cleanEntry) }); }
    if (req.method === 'POST' && ['/api/activate', '/api/check', '/api/release'].includes(url)) return await api(req, res, url.slice(5), ip);
    if (url === '/admin' || url.startsWith('/admin/')) return await admin(req, res, url);
    send(res, 404, { ok: false, error: 'Não encontrado' });
  } catch (e) { console.error(e); send(res, 500, { ok: false, error: 'Erro interno' }); }
}).listen(PORT, () => console.log(`MapSim licenças v${SERVER_VERSION} a ouvir em :${PORT}`));
