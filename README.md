# ToolGate

A zero-trust security gateway for AI agent tool calls (problem statement PNC3).

Every tool call an AI agent wants to make (run a shell command, send an email, call an API, query a database, move money) goes through ToolGate first. ToolGate checks it in seven stages and returns **ALLOW**, **REVIEW** (held in an approval queue until an admin approves or rejects it) or **BLOCK**, with the reason. Every decision is written to an encrypted, tamper-evident audit log.

## Run it (Windows, Mac or Linux)

You need **Node.js 22.13 or newer** (https://nodejs.org, pick LTS). No `npm install` is needed: there are no third-party packages.

```bash
cd toolgate
npm start
```

Open **http://localhost:3000** and sign in with the admin password **toolgate-admin**.

The first start prints three agent API keys and saves them to `data/agent-keys.txt`.

To watch simulated AI agents call the gateway, open a **second terminal** and run:

```bash
npm run agent
```

To run the automated tests:

```bash
npm test
```

To change the admin password (Windows PowerShell: `$env:ADMIN_PASSWORD="..."; npm start`):

```bash
ADMIN_PASSWORD="your-password" npm start
```

## The seven inspection stages

1. **Identity and permission**: the agent's API key must match the agent it claims to be, and the agent must be allowed to use this tool (least privilege).
2. **Parameter schema**: types, required fields, formats and lengths; unknown or duplicate parameters are blocked as parameter smuggling.
3. **Deobfuscation**: decodes base64, URL encoding, `\x` escapes, HTML entities, zero-width characters, look-alike Unicode letters and shell quote tricks before anything else is checked.
4. **Command, file and SQL guard**: destructive shell commands, command chaining, command and subcommand allowlists, path traversal, secret files, write queries for read-only agents, stacked queries, `OR 1=1`, table allowlists.
5. **Destination and data-leak guard**: email and web destinations must be on the agent's allowlist; blocks SSRF (cloud metadata, internal IPs), `user@host` URL tricks, email header injection, and secrets or card or Aadhaar numbers leaving the company.
6. **Prompt-injection scan**: scores instruction overrides, role hijacks, fake chat tokens, secret extraction and concealment instructions, in both the tool parameters and any retrieved web, email or document content.
7. **Runtime context**: actions triggered by untrusted content need approval; payment limits and approved vendors; per-agent rate limits.

## API

| Method | Path | Who | What |
|---|---|---|---|
| POST | `/v1/inspect` | Agent (`Authorization: Bearer <agent key>`) | Inspect a tool call. HTTP 200 = allow, 202 = review, 403 = block |
| POST | `/v1/login` | Admin | Returns a signed session token |
| POST | `/v1/lab/inspect` | Admin | Test any tool call from the dashboard |
| GET | `/v1/audit` | Admin | Decrypted audit log (`?decision=BLOCK`) |
| GET | `/v1/audit/verify` | Admin | Check the hash chain for tampering |
| GET | `/v1/approvals` | Admin | Human approval queue (`?status=pending`) |
| POST | `/v1/approvals/:id/approve` or `/reject` | Admin | Approve (the tool runs) or reject a held call |
| GET | `/v1/requests/:id` | Agent | Check whether its own held request was approved |
| GET | `/v1/stats` | Admin | Totals, latency, top rules |
| GET / PUT | `/v1/policy` | Admin | Read or save a new policy version |
| POST | `/v1/eval` | Admin | Run the labelled test suite |
| GET | `/v1/health` | Anyone | Health check |

Example agent call:

```bash
curl -X POST http://localhost:3000/v1/inspect \
  -H "Authorization: Bearer <devops-bot key>" \
  -d '{"agent":"devops-bot","tool":"run_shell","params":{"command":"rm -rf /"}}'
```

## Security

- Agent API keys are stored only as SHA-256 hashes.
- Admin sessions use HMAC-SHA256 signed tokens that expire after 8 hours; login is rate limited.
- Audit payloads are encrypted at rest with AES-256-GCM. Keys are derived from a master secret (`data/secret.key`, or the `TOOLGATE_SECRET` environment variable).
- Each audit record stores the hash of the previous one, so editing or deleting a past record is detectable.
- Strict security headers (CSP, no framing, no sniffing), request size limits, and path-safe static file serving.

## Database (SQLite, built into Node)

- `agents(name, key_hash, key_prefix, created_at)`
- `audit_log(ts, source, agent, tool, decision, risk, reason, latency_ms, payload_enc, findings_json, prev_hash, row_hash)`
- `approvals(audit_id, agent, tool, reason, payload_enc, status, decided_at, decided_by, result)`
- `policy_versions(ts, author, policy_json)`
- `eval_runs(ts, total, accuracy, recall, fpr, avg_ms, p95_ms)`

## Deploy

- **CI**: `.github/workflows/ci.yml` runs `npm test` on every push to GitHub.
- **Docker**: `docker build -t toolgate . && docker run -p 3000:3000 -e ADMIN_PASSWORD=... toolgate`
- **Render.com (free)**: New → Web Service → connect the GitHub repo → Build command `npm install`, Start command `npm start`, add the environment variables `ADMIN_PASSWORD` and `TOOLGATE_SECRET`. The free plan's disk is temporary, so the database resets when the service restarts.

## Evaluation

The **Evaluation** tab (or `npm test`) runs 41 labelled cases, 29 attacks across 6 categories and 12 normal calls, and reports detection rate, false-positive rate, accuracy and latency. The team wrote the test set, so it shows the rules work as designed. It is not a measure against unseen real-world attacks.

## Limits and next steps

- Detection is rule-based and deterministic (fast and explainable). Next step: add an ML classifier for prompt injection alongside the rules.
- The execution harness simulates tool results; in production it would forward allowed calls to the real tools.
- Next: notifications for pending approvals, per-tenant policies, and Postgres for multi-instance deployments.
