'use strict';
/* Automated tests: run with `npm test`. Used by the CI pipeline too. */
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

let failed = 0;
async function test(name, fn) {
  try { await fn(); console.log('  ✔ ' + name); }
  catch (e) { failed++; console.log('  ✘ ' + name + '\n    ' + e.message); }
}

(async () => {
  console.log('\nEngine');
  const E = require('./public/engine.js');
  const r = E.runSuite();
  await test(`detects attacks (recall ${(r.recall * 100).toFixed(1)}%)`, () => assert.ok(r.recall >= 0.95));
  await test(`few false alarms (false-positive rate ${(r.fpr * 100).toFixed(1)}%)`, () => assert.ok(r.fpr <= 0.05));
  await test(`fast (p95 latency ${r.p95.toFixed(2)} ms)`, () => assert.ok(r.p95 < 20));
  await test('decodes base64-hidden commands', () => assert.match(E.deobfuscate('echo cm0gLXJmIC8= | base64 -d').text, /rm -rf \//));
  await test('finds duplicate JSON keys', () => assert.deepStrictEqual(E.findDuplicateKeys('{"a":1,"b":{"c":1},"a":2}'), ['a']));

  console.log('\nServer');
  process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'toolgate-'));
  process.env.ADMIN_PASSWORD = 'test-pass';
  const { server, ensureAgentKeys } = require('./server.js');
  const keys = Object.fromEntries(ensureAgentKeys().map(k => [k.name, k.key]));
  await new Promise(res => server.listen(0, res));
  const base = `http://127.0.0.1:${server.address().port}`;
  const call = (p, opts = {}) => fetch(base + p, opts).then(async x => ({ status: x.status, body: await x.json() }));
  const post = (p, body, token) => call(p, { method: 'POST', headers: token ? { Authorization: 'Bearer ' + token } : {}, body: typeof body === 'string' ? body : JSON.stringify(body) });

  await test('health check responds', async () => assert.strictEqual((await call('/v1/health')).body.ok, true));
  await test('rejects calls without an agent key', async () => assert.strictEqual((await post('/v1/inspect', {})).status, 401));
  await test('allows a safe call with a valid key', async () => {
    const x = await post('/v1/inspect', { agent: 'devops-bot', tool: 'run_shell', params: { command: 'uptime' } }, keys['devops-bot']);
    assert.strictEqual(x.status, 200); assert.strictEqual(x.body.decision, 'ALLOW');
  });
  await test('blocks rm -rf with 403', async () => {
    const x = await post('/v1/inspect', { agent: 'devops-bot', tool: 'run_shell', params: { command: 'rm -rf /' } }, keys['devops-bot']);
    assert.strictEqual(x.status, 403); assert.strictEqual(x.body.decision, 'BLOCK');
  });
  await test('blocks an agent impersonating another agent', async () => {
    const x = await post('/v1/inspect', { agent: 'devops-bot', tool: 'run_shell', params: { command: 'uptime' } }, keys['support-bot']);
    assert.strictEqual(x.body.decision, 'BLOCK'); assert.match(x.body.reason, /Identity mismatch/);
  });
  await test('admin API needs login', async () => assert.strictEqual((await call('/v1/audit')).status, 401));
  await test('wrong admin password is rejected', async () => assert.strictEqual((await post('/v1/login', { password: 'nope' })).status, 401));
  const token = (await post('/v1/login', { password: 'test-pass' })).body.token;
  await test('admin can log in', async () => assert.ok(token));
  await test('audit log is stored encrypted and decrypts for admin', async () => {
    const x = await call('/v1/audit', { headers: { Authorization: 'Bearer ' + token } });
    assert.ok(x.body.length >= 3); assert.match(x.body[0].payload, /devops-bot/);
  });
  await test('audit hash chain verifies', async () => assert.strictEqual((await call('/v1/audit/verify', { headers: { Authorization: 'Bearer ' + token } })).body.ok, true));
  const auth = { Authorization: 'Bearer ' + token };
  let approvalId;
  await test('large payment is held for review (HTTP 202)', async () => {
    const x = await post('/v1/inspect', { agent: 'finance-bot', tool: 'transfer_funds', params: { vendor_id: 'V-1003', amount: 32000, currency: 'INR' } }, keys['finance-bot']);
    assert.strictEqual(x.status, 202); assert.ok(x.body.approval_id); approvalId = x.body.approval_id;
  });
  await test('held request appears in the approval queue', async () => {
    const x = await call('/v1/approvals?status=pending', { headers: auth });
    assert.ok(x.body.some(a => a.id === approvalId && /V-1003/.test(a.payload)));
  });
  await test('agent sees its request as pending', async () => {
    const x = await call('/v1/requests/' + approvalId, { headers: { Authorization: 'Bearer ' + keys['finance-bot'] } });
    assert.strictEqual(x.body.status, 'pending');
  });
  await test('another agent cannot read that request', async () => {
    const x = await call('/v1/requests/' + approvalId, { headers: { Authorization: 'Bearer ' + keys['support-bot'] } });
    assert.strictEqual(x.status, 404);
  });
  await test('admin approval runs the tool and is logged', async () => {
    const x = await post(`/v1/approvals/${approvalId}/approve`, '', token);
    assert.strictEqual(x.body.status, 'approved'); assert.match(x.body.result, /32,000/);
    const again = await post(`/v1/approvals/${approvalId}/approve`, '', token);
    assert.strictEqual(again.status, 409);
  });
  await test('audit chain still verifies after approvals', async () => assert.strictEqual((await call('/v1/audit/verify', { headers: auth })).body.ok, true));
  await test('invalid policy is refused', async () => {
    const x = await call('/v1/policy', { method: 'PUT', headers: { Authorization: 'Bearer ' + token }, body: '{"agents":{}}' });
    assert.strictEqual(x.status, 400);
  });
  await test('static files cannot escape the public folder', async () => assert.notStrictEqual((await fetch(base + '/..%2fserver.js')).status, 200));

  server.close();
  console.log(failed ? `\n${failed} test(s) failed\n` : '\nAll tests passed\n');
  process.exit(failed ? 1 : 0);
})();
