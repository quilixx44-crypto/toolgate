'use strict';
/* =====================================================================
   ToolGate server: zero-trust gateway for AI agent tool calls.
   No npm dependencies. Needs Node.js 22.13 or newer (built-in SQLite).

   Agent API    POST /v1/inspect          (Authorization: Bearer <agent key>)
   Admin API    POST /v1/login            -> session token
                POST /v1/lab/inspect      test any tool call from the dashboard
                GET  /v1/audit            decrypted audit log
                GET  /v1/audit/verify     check the tamper-evident hash chain
                GET  /v1/approvals        human approval queue (?status=pending)
                POST /v1/approvals/:id/approve | /reject
   Agent API    GET  /v1/requests/:id     agent checks if its held request was approved
                GET  /v1/stats            counts, latency, top rules
                GET  /v1/policy           current policy
                PUT  /v1/policy           save a new policy version
                POST /v1/eval             run the labelled attack test suite
   Public       GET  /v1/health, and the dashboard at /
   ===================================================================== */
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');
const E = require('./public/engine.js');

const PORT = +process.env.PORT || 3000;
const DATA = process.env.DATA_DIR || path.join(__dirname, 'data');
const PUBLIC = path.join(__dirname, 'public');
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'toolgate-admin';
const VERSION = '1.0.0';
fs.mkdirSync(DATA, { recursive: true });

/* ---------------- keys and crypto ---------------- */
const secretFile = path.join(DATA, 'secret.key');
const MASTER = process.env.TOOLGATE_SECRET
  ? crypto.createHash('sha256').update(process.env.TOOLGATE_SECRET).digest()
  : fs.existsSync(secretFile)
    ? Buffer.from(fs.readFileSync(secretFile, 'utf8').trim(), 'hex')
    : (() => { const k = crypto.randomBytes(32); fs.writeFileSync(secretFile, k.toString('hex'), { mode: 0o600 }); return k; })();
const derive = info => Buffer.from(crypto.hkdfSync('sha256', MASTER, Buffer.alloc(0), info, 32));
const ENC_KEY = derive('toolgate-audit-encryption');
const SIGN_KEY = derive('toolgate-session-signing');
const sha256 = s => crypto.createHash('sha256').update(s).digest('hex');
const safeEqual = (a, b) => { const x = Buffer.from(sha256(a)), y = Buffer.from(sha256(b)); return crypto.timingSafeEqual(x, y); };

function encrypt(text) { // AES-256-GCM
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', ENC_KEY, iv);
  const ct = Buffer.concat([c.update(text, 'utf8'), c.final()]);
  return ['v1', iv.toString('base64'), c.getAuthTag().toString('base64'), ct.toString('base64')].join(':');
}
function decrypt(blob) {
  try {
    const [, iv, tag, ct] = blob.split(':');
    const d = crypto.createDecipheriv('aes-256-gcm', ENC_KEY, Buffer.from(iv, 'base64'));
    d.setAuthTag(Buffer.from(tag, 'base64'));
    return Buffer.concat([d.update(Buffer.from(ct, 'base64')), d.final()]).toString('utf8');
  } catch (e) { return null; }
}
const b64u = b => Buffer.from(b).toString('base64url');
function signToken(sub, ttlSec = 8 * 3600) {
  const body = b64u(JSON.stringify({ sub, exp: Date.now() + ttlSec * 1000 }));
  return body + '.' + crypto.createHmac('sha256', SIGN_KEY).update(body).digest('base64url');
}
function verifyToken(tok) {
  if (!tok || !tok.includes('.')) return null;
  const [body, sig] = tok.split('.');
  const good = crypto.createHmac('sha256', SIGN_KEY).update(body).digest('base64url');
  if (sig.length !== good.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(good))) return null;
  try { const p = JSON.parse(Buffer.from(body, 'base64url').toString()); return p.exp > Date.now() ? p : null; } catch (e) { return null; }
}

/* ---------------- database ---------------- */
const db = new DatabaseSync(path.join(DATA, 'toolgate.db'));
db.exec(`
  PRAGMA journal_mode = WAL;
  CREATE TABLE IF NOT EXISTS agents (
    name TEXT PRIMARY KEY, key_hash TEXT NOT NULL, key_prefix TEXT NOT NULL, created_at TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, source TEXT NOT NULL,
    agent TEXT, tool TEXT, decision TEXT NOT NULL, risk INTEGER NOT NULL, reason TEXT NOT NULL,
    latency_ms REAL NOT NULL, payload_enc TEXT NOT NULL, findings_json TEXT NOT NULL,
    prev_hash TEXT NOT NULL, row_hash TEXT NOT NULL);
  CREATE INDEX IF NOT EXISTS idx_audit_decision ON audit_log(decision);
  CREATE TABLE IF NOT EXISTS policy_versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, author TEXT NOT NULL, policy_json TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS approvals (
    id INTEGER PRIMARY KEY AUTOINCREMENT, audit_id INTEGER NOT NULL, ts TEXT NOT NULL,
    agent TEXT, tool TEXT, reason TEXT NOT NULL, payload_enc TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending', decided_at TEXT, decided_by TEXT, result TEXT);
  CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(status);
  CREATE TABLE IF NOT EXISTS eval_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, total INTEGER, accuracy REAL,
    recall REAL, fpr REAL, avg_ms REAL, p95_ms REAL);
`);

let policy;
{
  const row = db.prepare('SELECT policy_json FROM policy_versions ORDER BY id DESC LIMIT 1').get();
  if (row) policy = JSON.parse(row.policy_json);
  else {
    policy = JSON.parse(JSON.stringify(E.DEFAULT_POLICY));
    db.prepare('INSERT INTO policy_versions (ts, author, policy_json) VALUES (?, ?, ?)').run(new Date().toISOString(), 'system', JSON.stringify(policy));
  }
}

function ensureAgentKeys() {
  const created = [];
  for (const name of Object.keys(policy.agents)) {
    if (db.prepare('SELECT 1 FROM agents WHERE name = ?').get(name)) continue;
    const key = `tg_${name.replace(/[^a-z0-9]/gi, '')}_${crypto.randomBytes(18).toString('base64url')}`;
    db.prepare('INSERT INTO agents (name, key_hash, key_prefix, created_at) VALUES (?, ?, ?, ?)').run(name, sha256(key), key.slice(0, 14), new Date().toISOString());
    created.push({ name, key });
  }
  if (created.length) {
    const file = path.join(DATA, 'agent-keys.txt');
    fs.appendFileSync(file, created.map(c => `${c.name}=${c.key}`).join('\n') + '\n', { mode: 0o600 });
    console.log(`\nNew agent API keys (saved to ${path.relative(process.cwd(), file)}; shown once):`);
    created.forEach(c => console.log(`  ${c.name.padEnd(12)} ${c.key}`));
  }
  return created;
}
function agentForKey(key) {
  if (!key) return null;
  const row = db.prepare('SELECT name, key_hash FROM agents WHERE key_hash = ?').get(sha256(key));
  return row ? row.name : null;
}

function lastHash() { const r = db.prepare('SELECT row_hash FROM audit_log ORDER BY id DESC LIMIT 1').get(); return r ? r.row_hash : 'GENESIS'; }
function writeAudit(rec) {
  const prev = lastHash();
  const payload_enc = encrypt(rec.raw);
  const findings_json = JSON.stringify(rec.findings);
  const row_hash = sha256([prev, rec.ts, rec.source, rec.agent, rec.tool, rec.decision, rec.risk, rec.reason, payload_enc, findings_json].join('|'));
  const r = db.prepare(`INSERT INTO audit_log (ts, source, agent, tool, decision, risk, reason, latency_ms, payload_enc, findings_json, prev_hash, row_hash)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(rec.ts, rec.source, rec.agent, rec.tool, rec.decision, rec.risk, rec.reason, rec.latency, payload_enc, findings_json, prev, row_hash);
  return Number(r.lastInsertRowid);
}
function verifyChain() {
  let prev = 'GENESIS', n = 0;
  for (const r of db.prepare('SELECT * FROM audit_log ORDER BY id').iterate()) {
    const h = sha256([prev, r.ts, r.source, r.agent, r.tool, r.decision, r.risk, r.reason, r.payload_enc, r.findings_json].join('|'));
    if (r.prev_hash !== prev || r.row_hash !== h) return { ok: false, checked: n, broken_at: r.id };
    prev = r.row_hash; n++;
  }
  return { ok: true, checked: n };
}

/* ---------------- gateway core ---------------- */
const rateState = { calls: {} };
function gateway(raw, source, boundAgent) {
  const t0 = process.hrtime.bigint();
  let call = null, result;
  try { call = JSON.parse(raw); } catch (e) { call = null; }
  if (!call) {
    result = { decision: 'BLOCK', risk: 100, reason: 'Malformed request: body is not valid JSON', findings: [{ stage: 'identity', severity: 'block', rule: 'Malformed request', msg: 'Body is not valid JSON' }], stages: [] };
  } else {
    result = E.inspect(call, { policy, raw, state: rateState });
    if (boundAgent && call.agent !== boundAgent) {
      result.findings.unshift({ stage: 'identity', severity: 'block', rule: 'Identity mismatch', msg: `API key belongs to ${boundAgent}, but the call claims to be ${call.agent}` });
      result.decision = 'BLOCK'; result.risk = Math.min(100, result.risk + 45);
      result.reason = `Identity mismatch: API key belongs to ${boundAgent}, but the call claims to be ${call.agent}`;
      const st = result.stages.find(s => s.id === 'identity'); if (st) { st.status = 'block'; st.findings = result.findings.filter(f => f.stage === 'identity'); }
    }
  }
  const latency = Number(process.hrtime.bigint() - t0) / 1e6;
  const out = { decision: result.decision, risk: result.risk, reason: result.reason, latency_ms: +latency.toFixed(3), stages: result.stages, deobf: result.deobf };
  if (result.decision === 'ALLOW') out.result = E.simulate(call);
  out.audit_id = writeAudit({ ts: new Date().toISOString(), source, agent: call && call.agent, tool: call && call.tool, decision: result.decision, risk: result.risk, reason: result.reason, latency, raw, findings: result.findings });
  if (result.decision === 'REVIEW') {
    const r = db.prepare('INSERT INTO approvals (audit_id, ts, agent, tool, reason, payload_enc) VALUES (?, ?, ?, ?, ?, ?)')
      .run(out.audit_id, new Date().toISOString(), call.agent, call.tool, result.reason, encrypt(raw));
    out.approval_id = Number(r.lastInsertRowid);
  }
  return out;
}

/* ---------------- human approval queue ---------------- */
function approvalView(a) {
  return { id: a.id, audit_id: a.audit_id, ts: a.ts, agent: a.agent, tool: a.tool, reason: a.reason, status: a.status, decided_at: a.decided_at, decided_by: a.decided_by, result: a.result, payload: decrypt(a.payload_enc) };
}
function decide(id, approve) {
  const a = db.prepare('SELECT * FROM approvals WHERE id = ?').get(id);
  if (!a) return { status: 404, body: { error: 'No such approval request' } };
  if (a.status !== 'pending') return { status: 409, body: { error: `Already ${a.status}` } };
  const raw = decrypt(a.payload_enc);
  const now = new Date().toISOString();
  const result = approve ? E.simulate(JSON.parse(raw)) : null;
  db.prepare('UPDATE approvals SET status = ?, decided_at = ?, decided_by = ?, result = ? WHERE id = ?').run(approve ? 'approved' : 'rejected', now, 'admin', result, id);
  writeAudit({ ts: now, source: 'approval', agent: a.agent, tool: a.tool, decision: approve ? 'ALLOW' : 'BLOCK', risk: 0,
    reason: approve ? `Approved by admin (review #${id})` : `Rejected by admin (review #${id})`, latency: 0, raw,
    findings: [{ stage: 'runtime', severity: 'info', rule: approve ? 'Human approval' : 'Human rejection', msg: `Decision on review #${id}: ${a.reason}` }] });
  return { status: 200, body: approvalView(db.prepare('SELECT * FROM approvals WHERE id = ?').get(id)) };
}

function validatePolicy(p) {
  if (!p || typeof p !== 'object') return 'Policy must be a JSON object';
  if (!p.agents || typeof p.agents !== 'object') return 'Policy needs an "agents" object';
  if (!p.tools || typeof p.tools !== 'object') return 'Policy needs a "tools" object';
  if (!p.global || typeof p.global !== 'object') return 'Policy needs a "global" object';
  for (const [name, a] of Object.entries(p.agents)) {
    if (!/^[a-z0-9-]{2,40}$/.test(name)) return `Agent name "${name}" must be 2-40 lowercase letters, digits or dashes`;
    if (!Array.isArray(a.tools)) return `Agent "${name}" needs a "tools" list`;
    for (const t of a.tools) if (!p.tools[t]) return `Agent "${name}" uses unknown tool "${t}"`;
  }
  for (const [name, t] of Object.entries(p.tools)) {
    if (!t.params || !Array.isArray(t.required)) return `Tool "${name}" needs "params" and "required"`;
    for (const spec of Object.values(t.params)) if (spec.pattern) { try { new RegExp(spec.pattern); } catch (e) { return `Tool "${name}" has an invalid pattern`; } }
  }
  return null;
}

/* ---------------- http plumbing ---------------- */
const SEC_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; connect-src 'self'; frame-ancestors 'none'"
};
function send(res, status, obj) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...SEC_HEADERS });
  res.end(JSON.stringify(obj));
}
function readBody(req, limit = 64 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', c => { size += c.length; if (size > limit) { reject(Object.assign(new Error('Request body too large'), { status: 413 })); req.destroy(); } else chunks.push(c); });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}
const bearer = req => { const h = req.headers.authorization || ''; return h.startsWith('Bearer ') ? h.slice(7).trim() : (req.headers['x-agent-key'] || ''); };
const isAdmin = req => { const p = verifyToken(bearer(req)); return p && p.sub === 'admin'; };

const loginAttempts = new Map();
function loginAllowed(ip) {
  const now = Date.now();
  const list = (loginAttempts.get(ip) || []).filter(t => now - t < 60000);
  list.push(now); loginAttempts.set(ip, list);
  return list.length <= 5;
}

const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon' };
function serveStatic(req, res, urlPath) {
  const rel = urlPath === '/' ? 'index.html' : decodeURIComponent(urlPath).replace(/^\/+/, '');
  const file = path.resolve(PUBLIC, rel);
  if (!file.startsWith(PUBLIC + path.sep)) return send(res, 403, { error: 'Forbidden' });
  fs.readFile(file, (err, buf) => {
    if (err) return send(res, 404, { error: 'Not found' });
    res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream', ...SEC_HEADERS });
    res.end(buf);
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  const p = url.pathname, m = req.method;
  try {
    if (m === 'GET' && p === '/v1/health') return send(res, 200, { ok: true, service: 'toolgate', version: VERSION, uptime_s: Math.round(process.uptime()) });

    if (m === 'POST' && p === '/v1/inspect') {
      const agent = agentForKey(bearer(req));
      if (!agent) return send(res, 401, { decision: 'BLOCK', reason: 'Missing or invalid agent API key' });
      const out = gateway(await readBody(req), 'agent', agent);
      return send(res, out.decision === 'ALLOW' ? 200 : out.decision === 'REVIEW' ? 202 : 403, out);
    }

    const reqMatch = p.match(/^\/v1\/requests\/(\d+)$/);
    if (m === 'GET' && reqMatch) {
      const agent = agentForKey(bearer(req));
      if (!agent) return send(res, 401, { error: 'Missing or invalid agent API key' });
      const a = db.prepare('SELECT * FROM approvals WHERE id = ? AND agent = ?').get(+reqMatch[1], agent);
      if (!a) return send(res, 404, { error: 'No such request for this agent' });
      return send(res, 200, { id: a.id, status: a.status, decided_at: a.decided_at, result: a.result });
    }

    if (m === 'POST' && p === '/v1/login') {
      if (!loginAllowed(req.socket.remoteAddress)) return send(res, 429, { error: 'Too many login attempts. Wait a minute and try again.' });
      let body = {}; try { body = JSON.parse(await readBody(req, 4096)); } catch (e) {}
      if (typeof body.password !== 'string' || !safeEqual(body.password, ADMIN_PASSWORD)) return send(res, 401, { error: 'Wrong password' });
      return send(res, 200, { token: signToken('admin'), expires_in: 8 * 3600 });
    }

    if (p.startsWith('/v1/')) {
      if (!isAdmin(req)) return send(res, 401, { error: 'Sign in as admin first' });

      if (m === 'POST' && p === '/v1/lab/inspect') return send(res, 200, gateway(await readBody(req), 'lab', null));

      if (m === 'GET' && p === '/v1/audit') {
        const dec = url.searchParams.get('decision');
        const limit = Math.min(500, +url.searchParams.get('limit') || 100);
        const rows = dec
          ? db.prepare('SELECT * FROM audit_log WHERE decision = ? ORDER BY id DESC LIMIT ?').all(dec, limit)
          : db.prepare('SELECT * FROM audit_log ORDER BY id DESC LIMIT ?').all(limit);
        return send(res, 200, rows.map(r => ({ id: r.id, ts: r.ts, source: r.source, agent: r.agent, tool: r.tool, decision: r.decision, risk: r.risk, reason: r.reason, latency_ms: r.latency_ms, payload: decrypt(r.payload_enc), findings: JSON.parse(r.findings_json), row_hash: r.row_hash })));
      }
      if (m === 'GET' && p === '/v1/approvals') {
        const st = url.searchParams.get('status');
        const rows = st
          ? db.prepare('SELECT * FROM approvals WHERE status = ? ORDER BY id DESC LIMIT 100').all(st)
          : db.prepare('SELECT * FROM approvals ORDER BY id DESC LIMIT 100').all();
        return send(res, 200, rows.map(approvalView));
      }
      const dec = p.match(/^\/v1\/approvals\/(\d+)\/(approve|reject)$/);
      if (m === 'POST' && dec) { const r = decide(+dec[1], dec[2] === 'approve'); return send(res, r.status, r.body); }

      if (m === 'GET' && p === '/v1/audit/verify') return send(res, 200, verifyChain());
      if (m === 'DELETE' && p === '/v1/audit') { db.exec('DELETE FROM audit_log'); db.exec('DELETE FROM approvals'); return send(res, 200, { ok: true }); }

      if (m === 'GET' && p === '/v1/stats') {
        const by = Object.fromEntries(db.prepare('SELECT decision, COUNT(*) n FROM audit_log GROUP BY decision').all().map(r => [r.decision, r.n]));
        const lat = db.prepare('SELECT AVG(latency_ms) avg FROM audit_log').get();
        const rules = {};
        for (const r of db.prepare("SELECT findings_json FROM audit_log WHERE decision != 'ALLOW' ORDER BY id DESC LIMIT 1000").iterate())
          for (const f of JSON.parse(r.findings_json)) if (f.severity !== 'info') rules[f.rule] = (rules[f.rule] || 0) + 1;
        const lastEval = db.prepare('SELECT * FROM eval_runs ORDER BY id DESC LIMIT 1').get() || null;
        const pending = db.prepare("SELECT COUNT(*) n FROM approvals WHERE status = 'pending'").get().n;
        return send(res, 200, { total: (by.ALLOW || 0) + (by.BLOCK || 0) + (by.REVIEW || 0), allow: by.ALLOW || 0, block: by.BLOCK || 0, review: by.REVIEW || 0, avg_latency_ms: lat.avg || 0, top_rules: Object.entries(rules).sort((a, b) => b[1] - a[1]).slice(0, 6), last_eval: lastEval, pending });
      }

      if (m === 'GET' && p === '/v1/policy') {
        const v = db.prepare('SELECT id, ts, author FROM policy_versions ORDER BY id DESC LIMIT 1').get();
        const agents = db.prepare('SELECT name, key_prefix, created_at FROM agents').all();
        return send(res, 200, { version: v, policy, agents });
      }
      if (m === 'PUT' && p === '/v1/policy') {
        let next; try { next = JSON.parse(await readBody(req)); } catch (e) { return send(res, 400, { error: 'Policy is not valid JSON' }); }
        const err = validatePolicy(next); if (err) return send(res, 400, { error: err });
        policy = next;
        db.prepare('INSERT INTO policy_versions (ts, author, policy_json) VALUES (?, ?, ?)').run(new Date().toISOString(), 'admin', JSON.stringify(policy));
        return send(res, 200, { ok: true, new_agent_keys: ensureAgentKeys() });
      }

      if (m === 'POST' && p === '/v1/eval') {
        const r = E.runSuite(policy);
        db.prepare('INSERT INTO eval_runs (ts, total, accuracy, recall, fpr, avg_ms, p95_ms) VALUES (?, ?, ?, ?, ?, ?, ?)').run(new Date().toISOString(), r.total, r.accuracy, r.recall, r.fpr, r.avg, r.p95);
        return send(res, 200, r);
      }
      return send(res, 404, { error: 'Unknown API route' });
    }

    if (m === 'GET') return serveStatic(req, res, p);
    return send(res, 405, { error: 'Method not allowed' });
  } catch (e) {
    return send(res, e.status || 500, { error: e.status ? e.message : 'Internal error' });
  }
});

if (require.main === module) {
  ensureAgentKeys();
  server.listen(PORT, () => {
    console.log(`\nToolGate ${VERSION} running at http://localhost:${PORT}`);
    if (!process.env.ADMIN_PASSWORD) console.log('Admin password: toolgate-admin  (set ADMIN_PASSWORD to change it)');
  });
}
module.exports = { server, ensureAgentKeys };
