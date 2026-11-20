// MapSim — servidor de licenças (sem dependências; Node 18+)
// Endpoints públicos: POST /api/activate, /api/check, /api/release · Painel: /admin (Basic Auth)
'use strict';
const SERVER_VERSION = '0.11.0';
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
db.tickets ||= [];   // suporte: [{id, token, machine, key, owner, name, email, type, subject, status:'open'|'answered'|'closed', created, updated, closedAt, appVersion, msgs:[{from:'user'|'admin', t, text}]}]
db.catalog ||= { leds: [], procs: [], boards: [], version: 0 };   // base de dados acrescentada à mão no painel (LED, processadores, quadros) — a app junta-a à sua
db.settings ||= {};  // { newsMax: N (só as últimas N versões visíveis na app; 0 = todas), newHidden: bool (versões novas chegam escondidas) }
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
      if (!cur) { db.changelog.push({ ...e, hidden: !!db.settings.newHidden, edited: false }); changed = true; }
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

/* ---------- suporte: mensagens da app (bug, base de dados, funcionalidades) ---------- */
const TTYPE = { bug: 'Reportar bug', db: 'Pedido para a base de dados', feature: 'Pedido de nova funcionalidade' };
const shits = new Map(); const slimited = ip => { const now = Date.now(), a = (shits.get(ip) || []).filter(t => now - t < 3600e3); a.push(now); shits.set(ip, a); return a.length > 240; };
const tView = t => ({ id: t.id, type: t.type, subject: t.subject, status: t.status, created: t.created, updated: t.updated, closedAt: t.closedAt || null, msgs: t.msgs });
async function supportApi(req, res, op, ip) {
  if (slimited(ip)) return send(res, 429, { ok: false, error: 'Demasiados pedidos. Tenta mais tarde.' });
  let q; try { q = JSON.parse(await body(req) || '{}'); } catch { return send(res, 400, { ok: false, error: 'Pedido inválido.' }); }
  const machine = String(q.machine || '').slice(0, 64); if (!/^[0-9a-f]{32}$/.test(machine)) return send(res, 400, { ok: false, error: 'Identificador do PC inválido.' });
  const txt = (v, n) => String(v || '').replace(/\r/g, '').trim().slice(0, n);
  if (op === 'new') {
    const name = txt(q.name, 80), email = txt(q.email, 120), type = TTYPE[q.type] ? q.type : 'bug', subject = txt(q.subject, 140), text = txt(q.message, 5000);
    if (!name || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email) || !text) return send(res, 400, { ok: false, error: 'Preenche o nome, um email válido e a mensagem.' });
    if (db.tickets.filter(t => t.machine === machine && t.status !== 'closed').length >= 20) return send(res, 429, { ok: false, error: 'Tens demasiados pedidos em aberto.' });
    const k = db.keys.find(x => x.key === String(q.key || '').toUpperCase());
    const t = { id: 'T' + Date.now().toString(36).toUpperCase() + crypto.randomBytes(2).toString('hex').toUpperCase(), token: crypto.randomBytes(16).toString('hex'), machine, key: k?.key || '', owner: k?.owner || '',
      name, email, type, subject: subject || TTYPE[type], status: 'open', created: Date.now(), updated: Date.now(), appVersion: txt(q.appVersion, 20), system: txt(q.system, 400), unread: true, msgs: [{ from: 'user', t: Date.now(), text }] };
    db.tickets.unshift(t); save(); return send(res, 200, { ok: true, id: t.id, token: t.token, ticket: tView(t) });
  }
  const list = Array.isArray(q.tickets) ? q.tickets.slice(0, 100) : [];
  const mine = list.map(x => db.tickets.find(t => t.id === x?.id && t.token === x?.token && t.machine === machine)).filter(Boolean);
  if (op === 'list') return send(res, 200, { ok: true, tickets: mine.map(tView) });
  if (op === 'reply') { const t = mine[0], text = txt(q.message, 5000); if (!t || !text) return send(res, 400, { ok: false, error: 'Pedido inválido.' }); if (t.status === 'closed') return send(res, 400, { ok: false, error: 'Este caso já foi encerrado.' });
    t.msgs.push({ from: 'user', t: Date.now(), text }); t.status = 'open'; t.updated = Date.now(); t.unread = true; save(); return send(res, 200, { ok: true, ticket: tView(t) }); }
  send(res, 404, { ok: false, error: 'Não encontrado' });
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
.msg{background:#04222c;border:1px solid #14c4ef;padding:10px;border-radius:6px;margin-bottom:16px}small,.muted{color:#7f8b99}.news{border-top:1px solid #232b35;padding:12px 0}.news textarea{height:70px;margin:6px 0}.row{display:flex;gap:6px;flex-wrap:wrap;align-items:center}
details.t{border:1px solid #232b35;border-radius:8px;margin:0 0 8px;background:#0e1217}details.t>summary{cursor:pointer;padding:10px 12px;display:grid;grid-template-columns:110px 190px 1fr 170px 90px;gap:10px;align-items:center;list-style:none}details.t>summary::-webkit-details-marker{display:none}
details.t[open]>summary{border-bottom:1px solid #232b35}.tb{padding:12px}.bub{max-width:80%;padding:9px 12px;border-radius:10px;margin:6px 0;white-space:pre-wrap}.bub.u{background:#151a21;border:1px solid #2b3540}.bub.a{background:#04222c;border:1px solid #14c4ef;margin-left:auto}
.pill{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;border:1px solid #2b3540}.pill.open{color:#f5a524;border-color:#f5a524}.pill.answered{color:#14c4ef;border-color:#14c4ef}.pill.closed{color:#7f8b99}.dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:#ff5d5d;margin-right:6px}
.tabs a{color:#c4ccd6;text-decoration:none;padding:7px 12px;border-radius:6px;border:1px solid #232b35;margin-right:6px}.tabs a.on{background:#04222c;color:#14c4ef;border-color:#14c4ef}
table.news td{padding:6px 8px}tr.hid td{opacity:.5}</style>
<nav><h1><b>MapSim</b> licenças</h1><span class="v">servidor v${SERVER_VERSION}</span>
${[['keys', '/admin', 'Chaves', db.keys.length], ['support', '/admin/support', 'Suporte', db.tickets.filter(t => t.status !== 'closed').length || ''], ['catalog', '/admin/catalog', 'Base de dados', db.catalog.leds.length + db.catalog.procs.length + db.catalog.boards.length], ['news', '/admin/news', 'Novidades', db.changelog.length], ['log', '/admin/log', 'Registo', db.log.length], ['config', '/admin/config', 'Configuração', '']]
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
function pageNews(msg, q = new URLSearchParams()) {
  // lista compacta: escolhe várias de uma vez e esconde/mostra em bloco; editar abre só a versão escolhida
  const f = (q.get('q') || '').toLowerCase(), show = q.get('show') || 'all', page = Math.max(1, +q.get('p') || 1), per = 50;
  const all = db.changelog.filter(e => (!f || `${e.version} ${e.title}`.toLowerCase().includes(f)) && (show === 'all' || (show === 'hidden' ? e.hidden : !e.hidden)));
  const list = all.slice((page - 1) * per, page * per), pages = Math.max(1, Math.ceil(all.length / per)), vis = db.changelog.filter(e => !e.hidden).length;
  const edit = q.get('edit'), e0 = edit === 'new' ? { version: '', date: new Date().toISOString().slice(0, 10), title: '', items: [], isNew: true } : db.changelog.find(x => x.version === edit);
  const form = e0 ? `<div class="card"><form method="post" action="/admin/news" class="news">
<div class="row"><b>${e0.isNew ? 'Nova versão' : 'Editar ' + esc(e0.version)}</b> <input name="version" value="${esc(e0.version)}" placeholder="0.9.0" ${e0.isNew ? '' : 'readonly'} style="width:84px"> <input type="date" name="date" value="${esc(e0.date)}"> <input name="title" value="${esc(e0.title)}" placeholder="Título curto" style="width:340px">
<label><input type="checkbox" name="hidden" ${e0.hidden ? 'checked' : ''}> esconder</label></div>
<div class="row" style="align-items:flex-start"><div style="flex:1"><small>Português</small><textarea name="items" style="height:120px">${esc((e0.items || []).join('\n'))}</textarea></div>
<div style="flex:1"><small>English</small> <input name="title_en" value="${esc(e0.title_en || '')}" placeholder="Title (English)" style="width:100%;margin:2px 0 0"><textarea name="items_en" style="height:120px">${esc((e0.items_en || []).join('\n'))}</textarea></div></div>
<div class="row"><button name="do" value="save">Guardar</button>${!e0.isNew && e0.edited ? '<button name="do" value="reset">Repor texto do GitHub</button>' : ''} <a href="/admin/news" style="color:#14c4ef">fechar</a></div></form></div>` : '';
  const qs = o => '/admin/news?' + new URLSearchParams({ q: q.get('q') || '', show, p: page, ...o }).toString();
  const rows = list.map(e => `<tr class="${e.hidden ? 'hid' : ''}"><td><input type="checkbox" name="v" value="${esc(e.version)}" form="bulk"></td><td><b>${esc(e.version)}</b></td><td><small>${esc(e.date)}</small></td><td>${esc(e.title)}</td>
  <td>${e.hidden ? '<span class="pill closed">escondida</span>' : '<span class="pill answered">visível</span>'} ${e.edited ? '<small class="ok">editada</small>' : ''}</td>
  <td class="row"><form method="post" action="/admin/news"><input type="hidden" name="v" value="${esc(e.version)}"><button name="do" value="${e.hidden ? 'show' : 'hide'}">${e.hidden ? 'Mostrar' : 'Esconder'}</button></form><a href="${qs({ edit: e.version })}" style="color:#14c4ef">Editar</a></td></tr>`).join('');
  return layout('news', 'Novidades', `<div class="card"><form method="post" action="/admin/news" class="row"><b>Na app:</b> mostrar só as últimas <input type="number" name="newsMax" min="0" max="200" value="${+db.settings.newsMax || 0}" style="width:70px"> versões visíveis <small>(0 = todas)</small>
  <label><input type="checkbox" name="newHidden" ${db.settings.newHidden ? 'checked' : ''}> versões novas do GitHub chegam escondidas</label><button name="do" value="settings">Guardar</button></form>
  <form method="post" action="/admin/news" class="row" style="margin-top:8px"><b>Limpeza rápida:</b> esconder tudo excepto as últimas <input type="number" name="keep" min="0" value="5" style="width:60px"> <button name="do" value="keep">Aplicar</button> <button name="do" value="hideall">Esconder todas</button> <button name="do" value="showall">Mostrar todas</button> <button name="do" value="sync">Sincronizar com o GitHub</button></form>
  <small>${db.changelog.length} versões · ${vis} visíveis${+db.settings.newsMax > 0 ? ` · a app mostra as ${Math.min(vis, +db.settings.newsMax)} mais recentes` : ''}</small></div>
  ${form}
  <form method="get" action="/admin/news" class="row" style="margin-bottom:10px"><input name="q" value="${esc(q.get('q') || '')}" placeholder="Procurar versão ou título" style="width:240px"><select name="show"><option value="all">Todas</option><option value="visible" ${show === 'visible' ? 'selected' : ''}>Visíveis</option><option value="hidden" ${show === 'hidden' ? 'selected' : ''}>Escondidas</option></select><button>Filtrar</button> <a href="${qs({ edit: 'new' })}" style="color:#14c4ef">+ nova versão manual</a></form>
  <form method="post" action="/admin/news" id="bulk" class="row" style="margin-bottom:8px"><label><input type="checkbox" onclick="document.querySelectorAll('input[name=v][form=bulk]').forEach(c=>c.checked=this.checked)"> seleccionar todas desta página</label>
  <button name="do" value="bulkhide">Esconder seleccionadas</button><button name="do" value="bulkshow">Mostrar seleccionadas</button><button name="do" value="bulkdel" class="danger" onclick="return confirm('Remover as versões seleccionadas das novidades?')">Remover seleccionadas</button></form>
  <table class="news"><tr><th></th><th>Versão</th><th>Data</th><th>Título</th><th>Estado</th><th></th></tr>${rows || '<tr><td colspan="6"><small>Sem versões.</small></td></tr>'}</table>
  ${pages > 1 ? `<div class="row" style="margin-top:10px">${Array.from({ length: pages }, (_, i) => `<a href="${qs({ p: i + 1 })}" style="color:${i + 1 === page ? '#14c4ef' : '#c4ccd6'}">${i + 1}</a>`).join(' ')}</div>` : ''}`, msg);
}
function pageSupport(msg, q = new URLSearchParams()) {
  const tab = q.get('tab') === 'closed' ? 'closed' : 'open', f = (q.get('q') || '').toLowerCase();
  const list = db.tickets.filter(t => (tab === 'closed' ? t.status === 'closed' : t.status !== 'closed') && (!f || `${t.id} ${t.name} ${t.email} ${t.subject} ${t.owner}`.toLowerCase().includes(f)));
  const openN = db.tickets.filter(t => t.status !== 'closed').length, closedN = db.tickets.length - openN, ST = { open: 'aberto', answered: 'respondido', closed: 'encerrado' };
  const item = t => `<details class="t" ${q.get('id') === t.id ? 'open' : ''}><summary><span>${t.unread && t.status !== 'closed' ? '<span class="dot"></span>' : ''}<code>${esc(t.id)}</code></span><span>${esc(TTYPE[t.type] || t.type)}</span><span><b>${esc(t.subject)}</b><br><small>${esc(t.name)} · ${esc(t.email)}${t.owner ? ' · ' + esc(t.owner) : ''}</small></span><span><small>${fmtT(t.updated)}</small></span><span class="pill ${t.status}">${ST[t.status]}</span></summary>
  <div class="tb"><small class="muted">Versão ${esc(t.appVersion || '—')} · ${esc(t.system || '')} · criado ${fmtT(t.created)}${t.closedAt ? ' · encerrado ' + fmtT(t.closedAt) : ''}</small>
  ${t.msgs.map(m => `<div class="bub ${m.from === 'admin' ? 'a' : 'u'}"><small class="muted">${m.from === 'admin' ? 'Tu (MapSim)' : esc(t.name)} · ${fmtT(m.t)}</small><br>${esc(m.text)}</div>`).join('')}
  ${t.status !== 'closed' ? `<form method="post" action="/admin/support"><input type="hidden" name="id" value="${esc(t.id)}"><textarea name="text" style="height:90px" placeholder="Resposta para ${esc(t.name)}…"></textarea>
  <div class="row"><button name="do" value="reply">Responder</button><button name="do" value="replyclose">Responder e encerrar</button><button name="do" value="close" onclick="return confirm('Encerrar este caso?')">Encerrar caso</button><button name="do" value="read">Marcar como lido</button></div></form>`
    : `<form method="post" action="/admin/support" class="row"><input type="hidden" name="id" value="${esc(t.id)}"><button name="do" value="reopen">Reabrir</button><button name="do" value="delete" class="danger" onclick="return confirm('Apagar definitivamente o caso ${esc(t.id)}?')">Apagar do arquivo</button></form>`}</div></details>`;
  return layout('support', 'Suporte', `<div class="row tabs" style="margin-bottom:12px"><a href="/admin/support" class="${tab === 'open' ? 'on' : ''}">Abertos (${openN})</a><a href="/admin/support?tab=closed" class="${tab === 'closed' ? 'on' : ''}">Arquivo — encerrados (${closedN})</a>
  <form method="get" action="/admin/support" class="row" style="margin-left:auto"><input type="hidden" name="tab" value="${tab}"><input name="q" value="${esc(q.get('q') || '')}" placeholder="Procurar nome, email, assunto…" style="width:240px"><button>Procurar</button></form></div>
  ${tab === 'closed' ? '<p class="muted">Casos encerrados ficam aqui guardados; clica para ler. Na app do cliente o caso encerrado fica visível 30 dias e depois desaparece.</p>' : ''}
  ${list.map(item).join('') || '<p class="muted">Sem mensagens.</p>'}`, msg);
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

/* ---------- base de dados acrescentada no painel: LED, processadores, quadros ---------- */
const CAT_FIELDS = {
  leds: [['brand', 'Marca', 't'], ['model', 'Modelo', 't'], ['series', 'Série', 't'], ['w', 'Largura (mm)', 'n'], ['h', 'Altura (mm)', 'n'], ['d', 'Profundidade (mm)', 'n'], ['pxW', 'Píxeis H', 'n'], ['pxH', 'Píxeis V', 'n'],
    ['kg', 'Peso (kg)', 'n'], ['wMax', 'Consumo máx. (W)', 'n'], ['wTyp', 'Consumo típico (W)', 'n'], ['nits', 'Brilho (nits)', 'n'], ['hangMax', 'Máx. suspensos', 'n'], ['stackMax', 'Máx. empilhados', 'n'],
    ['curveMin', 'Curva mín. (°, − convexo)', 'n'], ['curveMax', 'Curva máx. (°, + côncavo)', 'n'], ['curveStep', 'Passo da curva (°)', 'n'], ['rx', 'Receiving card', 't'], ['note', 'Nota', 't'], ['srcT', 'Fonte — título', 't'], ['srcU', 'Fonte — link', 't']],
  procs: [['brand', 'Marca', 't'], ['model', 'Modelo', 't'], ['series', 'Série', 't'], ['ports', 'Portas de rede', 'n'], ['total', 'Capacidade total (px)', 'n'], ['port8', 'Píxeis por porta (8 bit)', 'n'], ['port10', 'Píxeis por porta (10 bit)', 'n'],
    ['maxW', 'Largura máx. (px)', 'n'], ['maxH', 'Altura máx. (px)', 'n'], ['opt', 'Fibra / saídas extra', 't'], ['note', 'Nota', 't'], ['srcT', 'Fonte — título', 't'], ['srcU', 'Fonte — link', 't']],
  boards: [['name', 'Nome', 't'], ['feed', 'Entrada (ex.: CEE 63 A 5P)', 't'], ['ph', 'Fases (1 ou 3)', 'n'], ['A', 'Corrente (A)', 'n'], ['dw', 'Largura (mm)', 'n'], ['dh', 'Altura (mm)', 'n'], ['dd', 'Profundidade (mm)', 'n'], ['kg', 'Peso (kg)', 'n'],
    ['o_schuko', 'Saídas Schuko 16 A', 'n'], ['o_cee16', 'Saídas CEE 16 A 3P', 'n'], ['o_cee16_5', 'Saídas CEE 16 A 5P', 'n'], ['o_soca', 'Saídas Socapex', 'n'], ['o_cee32', 'Saídas CEE 32 A', 'n'], ['o_cee63', 'Saídas CEE 63 A', 'n'], ['o_cee125', 'Saídas CEE 125 A', 'n'], ['note', 'Nota', 't']],
};
const CAT_NAME = { leds: 'Painéis LED', procs: 'Processadores LED', boards: 'Quadros eléctricos' };
const CAT_REQ = { leds: ['brand', 'model', 'w', 'h', 'pxW', 'pxH'], procs: ['brand', 'model', 'ports', 'total', 'port8'], boards: ['name', 'A'] };
function catClean(kind, f) {
  const o = {};
  for (const [k, , t] of CAT_FIELDS[kind]) { const v = String(f.get(k) ?? '').trim(); if (v === '') continue; if (t === 'n') { const n = +v.replace(',', '.'); if (Number.isFinite(n)) o[k] = n; } else o[k] = v.slice(0, k === 'srcU' ? 400 : 200); }
  if (o.srcU && !/^https?:\/\//i.test(o.srcU)) delete o.srcU;
  const miss = CAT_REQ[kind].filter(k => o[k] == null);
  return miss.length ? { err: 'Falta: ' + miss.map(k => CAT_FIELDS[kind].find(x => x[0] === k)[1]).join(', ') } : { o };
}
function pageCatalog(msg, q = new URLSearchParams()) {
  const kind = CAT_FIELDS[q.get('k')] ? q.get('k') : 'leds', list = db.catalog[kind], ed = q.get('edit'), e0 = ed ? list.find(x => x.id === ed) || {} : {};
  const label = x => kind === 'boards' ? x.name : `${x.brand} ${x.model}`;
  const sum = x => kind === 'leds' ? `${x.w}×${x.h}${x.d ? '×' + x.d : ''} mm · ${x.pxW}×${x.pxH} px${x.kg ? ' · ' + x.kg + ' kg' : ''}${x.wMax ? ' · ' + x.wMax + ' W' : ''}${x.curveMax != null || x.curveMin != null ? ` · curva ${x.curveMin ?? 0}°…${x.curveMax ?? 0}°` : ''}`
    : kind === 'procs' ? `${x.ports} portas · ${(x.total / 1e6).toFixed(2)} Mpx · ${x.port8} px/porta` : `${x.A} A · ${x.ph === 1 ? '1F' : '3F'} · ${x.feed || ''}`;
  const form = `<div class="card"><form method="post" action="/admin/catalog"><input type="hidden" name="k" value="${kind}"><input type="hidden" name="id" value="${esc(e0.id || '')}">
<b>${e0.id ? 'Editar' : 'Adicionar'} — ${CAT_NAME[kind]}</b><div class="catgrid">${CAT_FIELDS[kind].map(([k, l, t]) => `<label><small>${esc(l)}${CAT_REQ[kind].includes(k) ? ' *' : ''}</small><input name="${k}" ${t === 'n' ? 'inputmode="decimal"' : ''} value="${esc(e0[k] ?? '')}"></label>`).join('')}</div>
<div class="row"><button name="do" value="save">${e0.id ? 'Guardar alterações' : 'Adicionar à base de dados'}</button>${e0.id ? `<a href="/admin/catalog?k=${kind}" style="color:#14c4ef">cancelar</a>` : ''}</div></form></div>`;
  const rows = list.map(x => `<tr class="${x.hidden ? 'hid' : ''}"><td><b>${esc(label(x))}</b><br><small>${esc(sum(x))}</small></td><td>${x.hidden ? '<span class="pill closed">escondido</span>' : '<span class="pill answered">na app</span>'}</td>
<td class="row"><a href="/admin/catalog?k=${kind}&edit=${x.id}" style="color:#14c4ef">Editar</a><form method="post" action="/admin/catalog"><input type="hidden" name="k" value="${kind}"><input type="hidden" name="id" value="${x.id}"><button name="do" value="${x.hidden ? 'show' : 'hide'}">${x.hidden ? 'Mostrar' : 'Esconder'}</button><button name="do" value="delete" class="danger" onclick="return confirm('Apagar ${esc(label(x)).replace(/'/g, '')} da base de dados? Os projectos que já o usam ficam com uma cópia.')">Apagar</button></form></td></tr>`).join('');
  return layout('catalog', 'Base de dados', `<div class="tabs" style="margin-bottom:14px">${Object.keys(CAT_FIELDS).map(k => `<a href="/admin/catalog?k=${k}" class="${k === kind ? 'on' : ''}">${CAT_NAME[k]} (${db.catalog[k].length})</a>`).join('')}</div>
<p class="muted">O que adicionares aqui aparece na app de todos os utilizadores (na próxima vez que abrirem o MapSim com internet), junto com a base de dados incluída. Versão da base de dados do painel: <b>${db.catalog.version}</b>.</p>
${form}<table class="news"><tr><th>${CAT_NAME[kind]}</th><th>Estado</th><th></th></tr>${rows || '<tr><td colspan="3"><small>Ainda nada adicionado.</small></td></tr>'}</table>
<style>.catgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:8px;margin:10px 0}.catgrid label{display:flex;flex-direction:column;gap:2px}.catgrid input{width:100%}</style>`, msg);
}
const catalogPublic = () => ({ ok: true, version: db.catalog.version, leds: db.catalog.leds.filter(x => !x.hidden), procs: db.catalog.procs.filter(x => !x.hidden), boards: db.catalog.boards.filter(x => !x.hidden) });

function pageConfig() {
  return layout('config', 'Configuração', `<div class="card"><b>Chave pública de assinatura</b><p class="muted">Está dentro da app (license-config.json). Não é secreta. Se a chave privada do servidor mudar, as licenças existentes deixam de ser válidas.</p><textarea readonly style="height:60px;font-family:Consolas,monospace;color:#9fd8ee">${esc(publicRaw)}</textarea></div>
<div class="card"><b>Servidor</b><table><tr><td>Versão</td><td>${SERVER_VERSION}</td></tr><tr><td>Chaves</td><td>${db.keys.length} (${db.keys.filter(k => !k.revoked && !(k.expires && Date.now() > k.expires)).length} ativas, ${db.keys.filter(k => k.machine).length} com PC)</td></tr>
<tr><td>Novidades — origem</td><td><code>${esc(CHANGELOG_URL)}</code></td></tr><tr><td>Dados</td><td><code>${esc(DATA)}</code></td></tr></table>
<p class="muted">Para actualizar o servidor basta reiniciar o contentor no Portainer.</p></div>`, '');
}

async function admin(req, res, url) {
  if (!authed(req)) { res.writeHead(401, { 'WWW-Authenticate': 'Basic realm="MapSim"' }); return res.end('Autenticação necessária'); }
  const q = new URLSearchParams(req.url.split('?')[1] || ''), html = h => send(res, 200, h, 'text/html; charset=utf-8');
  if (req.method === 'GET') return html(url === '/admin/catalog' ? pageCatalog('', q) : url === '/admin/news' ? pageNews('', q) : url === '/admin/support' ? pageSupport('', q) : url === '/admin/log' ? pageLog(q) : url === '/admin/config' ? pageConfig() : pageKeys('', q));
  // proteção CSRF: o POST tem de vir da própria página do painel
  const origin = req.headers.origin || req.headers.referer || '';
  try { if (new URL(origin).host !== req.headers.host) return send(res, 403, 'Origem inválida', 'text/plain'); } catch { return send(res, 403, 'Origem inválida', 'text/plain'); }
  const f = new URLSearchParams(await body(req)), dateMs = s => s ? new Date(s + 'T23:59:59').getTime() : null;
  let msg = '';
  if (url === '/admin/new') {
    const k = { key: newKey(), owner: f.get('owner')?.slice(0, 80) || '—', note: f.get('note')?.slice(0, 120) || '', created: Date.now(), expires: dateMs(f.get('exp')), revoked: false, machine: null };
    db.keys.unshift(k); log('create', k.key, 'admin', k.owner); save(); msg = `Chave criada para <b>${esc(k.owner)}</b>: <code>${k.key}</code>`;
  } else if (url === '/admin/news') {
    const d = f.get('do'), v = String(f.get('version') || '').trim(), vs = new Set(f.getAll('v'));
    if (d === 'sync') { await syncChangelog(true); msg = 'Novidades sincronizadas com o GitHub.'; }
    else if (d === 'settings') { db.settings.newsMax = Math.max(0, Math.min(200, +f.get('newsMax') || 0)); db.settings.newHidden = f.get('newHidden') === 'on'; save(); msg = 'Preferências das novidades guardadas.'; }
    else if (d === 'keep') { const n = Math.max(0, +f.get('keep') || 0); db.changelog.forEach((e, i) => { e.hidden = i >= n; }); save(); msg = `Ficam visíveis as ${n} versões mais recentes; as outras foram escondidas.`; }
    else if (d === 'hideall' || d === 'showall') { db.changelog.forEach(e => { e.hidden = d === 'hideall'; }); save(); msg = d === 'hideall' ? 'Todas as versões escondidas.' : 'Todas as versões visíveis.'; }
    else if (d === 'hide' || d === 'show' || d === 'bulkhide' || d === 'bulkshow') { let n = 0; db.changelog.forEach(e => { if (vs.has(e.version)) { e.hidden = d.endsWith('hide'); n++; } }); save(); msg = `${n} versão(ões) ${d.endsWith('hide') ? 'escondida(s)' : 'visível(eis)'}.`; }
    else if (d === 'bulkdel') { const n0 = db.changelog.length; db.changelog = db.changelog.filter(e => !vs.has(e.version)); save(); msg = `${n0 - db.changelog.length} versão(ões) removida(s).`; }
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
  } else if (url === '/admin/catalog') {
    const kind = CAT_FIELDS[f.get('k')] ? f.get('k') : 'leds', list = db.catalog[kind], d = f.get('do'), id = f.get('id') || '', x = list.find(y => y.id === id);
    if (d === 'save') { const r = catClean(kind, f);
      if (r.err) return html(pageCatalog(r.err, new URLSearchParams(`k=${kind}${x ? '&edit=' + x.id : ''}`)));
      if (x) Object.keys(x).forEach(k => { if (!['id', 'hidden', 'created'].includes(k)) delete x[k]; });
      const it = x || { id: 'srv-' + crypto.randomBytes(4).toString('hex'), hidden: false, created: Date.now() }; Object.assign(it, r.o, { updated: Date.now() }); if (!x) list.push(it);
      msg = `${x ? 'Alterado' : 'Adicionado'}: <b>${esc(kind === 'boards' ? it.name : it.brand + ' ' + it.model)}</b>`; }
    else if (x && (d === 'hide' || d === 'show')) { x.hidden = d === 'hide'; msg = 'Feito.'; }
    else if (x && d === 'delete') { db.catalog[kind] = list.filter(y => y !== x); msg = 'Apagado.'; }
    db.catalog.version = (+db.catalog.version || 0) + 1; save();
    return html(pageCatalog(msg, new URLSearchParams(`k=${kind}`)));
  } else if (url === '/admin/support') {
    const t = db.tickets.find(x => x.id === f.get('id')), d = f.get('do'), text = String(f.get('text') || '').trim().slice(0, 5000);
    if (t) {
      if ((d === 'reply' || d === 'replyclose') && text) { t.msgs.push({ from: 'admin', t: Date.now(), text }); t.status = 'answered'; t.updated = Date.now(); t.unread = false; msg = `Resposta enviada (${esc(t.id)}).`; }
      if (d === 'close' || d === 'replyclose') { t.status = 'closed'; t.closedAt = Date.now(); t.updated = Date.now(); t.unread = false; msg = `Caso ${esc(t.id)} encerrado e arquivado.`; }
      if (d === 'read') { t.unread = false; msg = 'Marcado como lido.'; }
      if (d === 'reopen') { t.status = 'answered'; t.closedAt = null; t.updated = Date.now(); msg = `Caso ${esc(t.id)} reaberto.`; }
      if (d === 'delete') { db.tickets = db.tickets.filter(x => x !== t); msg = `Caso ${esc(t.id)} apagado.`; }
      save();
    }
    return html(pageSupport(msg, new URLSearchParams(d === 'close' || d === 'replyclose' || d === 'delete' ? '' : `id=${t?.id || ''}`)));
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
    if (url === '/api/catalog' && req.method === 'GET') return send(res, 200, catalogPublic());
    if (url === '/api/changelog' && req.method === 'GET') { await syncChangelog(false); return send(res, 200, { ok: true, versions: db.changelog.filter(e => !e.hidden).slice(0, +db.settings.newsMax > 0 ? +db.settings.newsMax : 9999).map(cleanEntry) }); }
    if (req.method === 'POST' && ['/api/activate', '/api/check', '/api/release'].includes(url)) return await api(req, res, url.slice(5), ip);
    if (req.method === 'POST' && ['/api/support/new', '/api/support/list', '/api/support/reply'].includes(url)) return await supportApi(req, res, url.slice(13), ip);
    if (url === '/admin' || url.startsWith('/admin/')) return await admin(req, res, url);
    send(res, 404, { ok: false, error: 'Não encontrado' });
  } catch (e) { console.error(e); send(res, 500, { ok: false, error: 'Erro interno' }); }
}).listen(PORT, () => console.log(`MapSim licenças v${SERVER_VERSION} a ouvir em :${PORT}`));
