# BlackBox v3: Build Documentation

**A tamper-proof security gateway and verifiable flight recorder for web apps, APIs and AI agents.**
One project, one gateway, one ledger, one witness, one verifier.

- Event: ASYNC'26 (Ramaiah Institute of Technology, CSE AIML and CSE CY, with CyreneAI)
- Track: 3, Cybersecurity and Defense
- Status: design complete (merge of v1 and v2), build not started. Last updated 28 Sep 2026.
- Final build window (per the brief): 24 hours on campus, 30 Sep to 1 Oct.
- Tagline: *Cryptography remembers. AI investigates. Humans stay in control.*

---

## 0. How to read this document

- Sections 1 to 3: BlackBox in plain words. Read these first.
- Sections 4 and 5: hackathon context, prior art and comparison.
- Sections 6 to 14: how BlackBox works, component by component.
- Sections 15 and 16: threat model and honest limits.
- Sections 17 to 19: testing, tech stack, repo layout and interfaces.
- Sections 20 to 22: 24-hour build plan, demo script with judge questions, deck updates.
- Section 23: decisions made and open. Section 24: glossary. Appendix A: flow diagrams.

Every technical section starts with an **In plain words** paragraph.

**Priority tags**

| Tag | Meaning |
|---|---|
| P0 | Must be in the final build. The demo breaks without it. |
| P1 | Should be in the final build if time allows. High value. |
| P2 | Roadmap. Show on a slide, build only if time is left. |

### 0.1 Where v3 comes from

There were two earlier documents:

- **v1 (BLACKBOX_DOCUMENTATION.md):** "A verifiable flight recorder for AI agents." Strong on agents: credential brokering, intent and outcome records, reconciliation against a provider's own logs, MCP adapter, policy and approvals, constrained AI investigator, evidence bundle and offline verifier.
- **v2 (BlackBox_Build_Documentation_v2.md):** "A tamper-proof security gateway for web apps." Strong on defence and depth: signed request verification, rules, honeytokens, forward-secure key ratchet, witness and heartbeats, origin lock-down, tiered active response, write-journal recovery, threat levels, AI attacker testing, a 24-hour plan.

They already shared a spine (gateway, hash-chained Merkle ledger, independent witness, offline verifier, cited AI narrator, "assume breach, still prove everything"). v3 keeps that spine once and puts both sets of ideas on top of it.

### 0.2 How each overlapping idea was merged

| Topic | v1 said | v2 said | v3 decision |
|---|---|---|---|
| What it protects | AI agent actions | Web app and API traffic | **Both, through two lanes of one gateway** (web lane and agent lane) |
| Entry protection | Ed25519 signature, JSON canonicalization, epoch signing keys | Encrypted with a forward-secure key ratchet, hash chain, keys wrapped to a split root key | **Both.** Every entry is canonicalized, signed by a short-lived epoch key, encrypted with a ratchet key, chained and put in the Merkle tree |
| Entry shape | Two entries per action: intent, then outcome | One entry per request | **Two-phase (intent then outcome) for anything forwarded**; one entry for blocked requests |
| Privacy | Commitments in the ledger, raw data in a separate encrypted store, crypto-shredding | Tokenized analyst view plus a sealed payload for replay | **Both:** tokenized entry, commitments, separate encrypted payload store that can be shredded |
| Second source of truth | Reconcile with the provider's own logs | Origin echo (idea, P2) | **Reconciler with two feeds:** provider logs (agent lane, P0) and origin echo (web lane, P1) |
| Bypass | Credential brokering plus egress control | Origin lock-down plus gateway-signed header | **Both,** described once in section 10 |
| Response | Policy engine, human approval for high-impact actions | Tiered automatic containment with safety rails | **Tiers 1 to 4 automatic with safety rails; agent-side high-impact actions need human approval** |
| Recovery | Evidence bundle, cited report | Blast radius, write-journal replay, patch verification | **All of it,** plus an agent-action review in the report |
| AI | Investigator over sanitized, verified input, citations checked | Local narrator, injection defences, AI attacker in tests, anomaly model on roadmap | **One narrator/investigator** with the strict rules of both, plus the AI attacker as a test tool |
| Violations | Named violation codes | Per-entry statuses | **Both:** statuses per entry, violation codes per finding (section 9.5) |
| Team and time | 4 people, 24 to 36 hours | 4 streams, 24 hours | **4 streams, 24 hours** |

---

## 1. BlackBox v3 on one page

### In plain words

Think of your web app, and the AI helpers that work for it, as a building with staff.

- **The guard at the door** checks every visitor's pass, turns away forged or reused passes and known trick patterns.
- **The chaperone** (for AI helpers) holds all the keys to the storeroom. The AI helper never carries a key. It asks the chaperone, and the chaperone writes down what was asked before doing anything.
- **The diary** records everything. Every page is sealed to the page before it and locked with its own one-use key. Nobody can secretly edit, delete or reorder pages.
- **The notary** sits somewhere else and stamps the diary every few seconds. If someone rewrites history on the server, the stamps stop matching.
- **The bank statement check** compares the diary with the outside world's own records (the payment provider's log, the app's own record). If something happened that the diary does not mention, that is caught.
- **The alarm** rings if the guard goes quiet, or the diary and the notary disagree.
- **The response team** cuts off the attacker, changes exposed passwords and shuts the attacked door. Big decisions still go to a human.
- **The recovery desk** tells you exactly what was touched and helps you restore with almost no loss.

### One-line definition

BlackBox is a gateway that sits in front of a web app and its AI agents, blocks attacks, records everything in a way that an attacker (or an insider) cannot fake or erase even after fully taking over the server, proves it to a stranger, locks the attacker out, and tells you exactly what to restore.

### The core assumption

**The server will be breached, so the evidence must survive the breach.** Normal logging, even encrypted logging, trusts the machine it runs on. BlackBox does not.

### The components

| Component | Plain name | Job | Trust |
|---|---|---|---|
| Gateway | The guard and chaperone | Verifies requests, enforces policy, brokers credentials for agents, forwards, responds, seals log entries | Assumed attackable |
| Ledger | The diary | Append-only store of sealed, hash-chained entries; builds the Merkle tree | Assumed attackable |
| Witness | The notary | Countersigns checkpoints, checks heartbeats, runs continuous verification | Trusted |
| Reconciler | The bank statement check | Matches the ledger against provider logs and origin echo | Verifier side |

Helpers: **dashboard**, **verifier CLI** (offline), **responder**, **recovery toolkit**, **AI narrator/investigator**, **client SDK**.

### What v3 proves and does not prove

**Proves:** entries were not altered, deleted or reordered after being written and witnessed; what crossed the gateway boundary; which rule or policy decided; whether outside records contradict the ledger.
**Does not prove:** that an agent's decision was correct, or anything that happened outside the gateway, or before the gateway itself was compromised.

### The lifecycle

| Phase | What BlackBox does |
|---|---|
| Before | Verified requests only, rate limits, rules, honeytokens, agents holding no credentials |
| Normal use | Every request and agent action becomes a sealed, witnessed, two-phase record |
| During an attack | Blocks, cuts sessions, bans keys, rotates exposed credentials, quarantines the route, pauses risky agent actions for approval |
| After an attack | Verifies the whole log, reconciles with outside records, rebuilds the timeline, produces the recovery report, replays good writes, proves the fix, produces an evidence bundle |

### What BlackBox does not do (say this openly)

- It cannot make a breach impossible.
- It cannot heal a machine the attacker already fully controls.
- It only sees traffic that passes through it.
- If the gateway itself is rooted, forged entries going forward are **detected afterwards**, not prevented (sections 9, 10, 16).

---

## 2. The problem

Three things go wrong at once when a server or an agent is compromised:

1. **You do not know what happened.** Attackers (and insiders) edit or wipe logs early.
2. **You cannot trust your own evidence.** Logs live on machines the attacker controls, and encryption does not help if the same machine holds the keys.
3. **You do not know what to restore or rotate,** so recovery is blind.

Two trends make this worse:

- **AI-driven attacks** (automated scanning, credential stuffing, injection at scale) make breaches faster and more common.
- **AI agents now hold real permissions** (refunds, infrastructure changes, database queries, email). A prompt-injected or misbehaving agent leaves the question: what exactly happened, who authorized it, and can we prove it to someone who does not trust us?

### Why ordinary logging fails as evidence

| Weakness | Consequence |
|---|---|
| Logs are controlled by the operator | A root attacker or insider can edit or delete them undetectably |
| Agents can call APIs directly | Unrecorded actions leave no trace, so an incomplete log looks complete |
| Only the request is captured | The downstream outcome is unproven |
| One source of truth | Everything depends on trusting one party |
| Exports are not portable evidence | Auditors must trust a dashboard |
| Untrusted text flows into AI log summarizers | Prompt injection can corrupt investigations |

### The objection we worked through

Objection: "Logs alone do not get my system back, so what is the use?" Correct. Real recovery is: isolate, scope, kill access, rotate secrets, patch the hole, restore from a clean backup, monitor. BlackBox helps at steps 2 to 6: it scopes the breach, tells you what to rotate, shows the entry point, and shrinks the data-loss window. On top of that, v3 adds **active response** and **write-journal recovery** (restore a backup, then replay the legitimate writes from the verified log).

---

## 3. Who uses it

- Startups, fintech and healthcare backends running APIs
- Companies deploying AI agents with real permissions (fintech, healthtech, SaaS, DevOps)
- SOC and incident-response teams, compliance, legal and audit teams
- Agent vendors who must prove to enterprise customers what their agents did
- Anyone who must prove to an auditor, insurer, regulator or court what happened

The end user of the protected app never sees BlackBox.

**Regulatory hooks (verify before citing publicly):**
- India, CERT-In 2022 directions: report listed incidents within 6 hours of noticing; keep ICT logs securely for a rolling 180 days within India and provide them with incident reports. BlackBox can draft the report and the verified log package (section 13).
- Record-keeping expectations for AI systems (for example EU AI Act logging, DORA, SEC disclosure rules, India's DPDP Act). Exact obligations vary by system and jurisdiction; confirm before naming any of them on a slide.

---

## 4. Hackathon context

### The event

- ASYNC'26: flagship 24-hour hackathon at Ramaiah Institute of Technology. Prize pool ₹1,00,000, ₹25,000 per track across four tracks (Sovereign AI, Wellness and Lifestyle, Cybersecurity and Defense, Open).
- Timeline from the brief: idea deck deadline 22 Sep; guided build with mentors 22 to 28 Sep; final 24-hour build on campus 30 Sep to 1 Oct.
- Ask the organisers whether code built before the 24 hours is allowed.

### Track 3 brief: Observe, Detect, Explain, Respond

| Stage | BlackBox v3 feature |
|---|---|
| Observe | Sealed, witnessed record of every request and every agent action |
| Detect | Rules, honeytokens, tamper and gap detection, reconciliation, policy violations, optional anomaly model |
| Explain | Forensic timeline, blast-radius report, cited AI narrator |
| Respond | Tiered containment, key rotation, quarantine, approval-gated agent controls |

The brief lists "automated defensive response and containment" and "AI-assisted SOC and incident-analysis systems" as example directions. v3 hits both.

### Judging

| Criterion | Weight | Where v3 scores |
|---|---|---|
| Technical Execution | 30% | Forward-secure sealed log, Merkle and witness, verifier, tamper battery |
| Innovation | 20% | Assembly plus recovery workflow, dual-source verification for agents |
| Impact | 20% | Breach evidence, regulation, agents with real permissions |
| Product Experience | 15% | Dashboard timeline, one-command demo, cited reports |
| Demo and Completeness | 15% | Attack, block, tamper, detect, respond, recover, in one story |

### The event's pillars

AI-Powered Systems, Privacy First, Built to Own. v2 was weak on the first pillar. v3 covers it: an AI agent under protection (v1), a cited local narrator, and an AI attacker in the test loop. Privacy First and Built to Own hold through self-hosting, local models, split keys, commitments and crypto-shredding.

---

## 5. Innovation, prior art and comparison

### 5.1 Not new (say this before the faculty does)

| Building block | Prior art |
|---|---|
| Forward-secure logging | Bellare-Yee, Schneier-Kelsey; systemd-journald Forward Secure Sealing |
| Merkle logs with signed checkpoints and witnesses | Certificate Transparency, Trillian, Sigstore Rekor, Go checksum database |
| Tamper-evident storage | immudb; AWS CloudTrail log file integrity validation |
| Off-box shipping and immutable storage | SIEMs (Splunk, Wazuh, Elastic), remote syslog, S3 Object Lock |
| Request blocking | WAFs (ModSecurity, Cloudflare) |
| Request signing with timestamps and nonces | AWS SigV4, HTTP Message Signatures (RFC 9421) |
| AI incident summaries | SIEM copilots and various startups |

### 5.2 Defensible contribution: the assembly

1. Third-party-verifiable proof of **completeness** (witness, checkpoints, heartbeats) plus **forward security** for the whole record, with key custody split across people.
2. **Verified ingress and live containment in the same system as the record.**
3. **Complete-by-construction capture for agents:** credential brokering plus egress control makes bypass hard and detectable.
4. **Dual-source verification:** reconcile against provider logs and origin echo, so erased or bypassing actions are exposed.
5. **Agent-specific evidence:** delegation chain, policy version, approval receipts, tool-definition hashes (to catch tool poisoning), and which untrusted inputs were in context before each action.
6. **A recovery workflow built on the verified record:** blast radius, write-journal replay, patch verification.
7. **Injection-resistant AI narrator** limited to verified, sanitized, structured input with mandatory citations.
8. **Portable evidence bundle** anyone can verify offline.

### 5.3 Comparison table (draft, verify every cell before it goes on a slide)

| | Survives rooted host (shipped events) | Forward-secure keys | Detects missing windows | Independent witness | Verified ingress | Agent credential brokering | Cross-checks outside records | Active response | Recovery guidance |
|---|---|---|---|---|---|---|---|---|---|
| SIEM or remote syslog | Yes | No | Partial (silence alerts) | No | No | No | No | Some (SOAR) | Partial |
| S3 Object Lock | Yes | No | No | No | No | No | No | No | No |
| journald FSS | Detects tampering of sealed past | Yes (local) | Partial | No | No | No | No | No | No |
| CloudTrail integrity validation | Yes | No | Yes | AWS is the anchor | No | No | No | No | No |
| immudb | Tamper-evident | No | Via proofs | No | No | No | No | No | No |
| Trillian or CT-style log | Yes | No | Yes | Yes | No | No | No | No | No |
| Plain MCP interceptor or agent observability | No | No | No | No | No | Weak | No | Some (guardrails) | No |
| **BlackBox v3** | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes |

Do **not** claim a SIEM cannot notice a silent log source. It can. The edge is third-party-verifiable proof of completeness, plus everything else living in one system.

### 5.4 Where BlackBox is not better

- Adds latency and infrastructure; overkill when nobody will ever dispute actions.
- It does not make agents safer by itself; pair it with guardrails.
- Blind to anything outside the gateway boundary.
- Value depends on the witness being trusted and the verifier being adopted.

Check current vendor feature sets before making claims about specific products.

### 5.5 The demo comparison

Run the same attack against (a) plain remote logging and (b) BlackBox. BlackBox flags the deleted window and pinpoints tampered entries; the plain setup has no proof either way.

---

## 6. System architecture

### In plain words

Everything, human-driven or AI-driven, flows through one gateway. The gateway writes a sealed diary entry before and after each action. The notary, elsewhere, keeps checking the diary keeper. A separate checker compares the diary with the outside world.

### Diagram

```
   WEB LANE                                                    AGENT LANE
 Client (SDK signs) ─────────┐                     ┌──────── AI agent (holds NO keys)
                             ▼                     ▼
                     ┌───────────────────────────────────┐
                     │             GATEWAY               │
                     │ sanity → signature → rate limit → │
                     │ rules → honeytokens → policy      │
                     │ (agent lane: credential broker,   │
                     │  tool-def hash, approvals)        │
                     │ write INTENT → forward → OUTCOME  │
                     └──┬────────────┬───────────┬───────┘
      forward, gateway- │            │ sealed    │ signed
      signed header     ▼            ▼ entries   ▼ heartbeats
                  ORIGIN APP     LEDGER        WITNESS
                  (only gateway  hash chain,   cosigns checkpoints,
                   can reach it) Merkle tree   checks heartbeats,
                        │            │          continuous verify
   PROVIDER APIs ◄──────┤            │              │
   (brokered creds)     │ origin     │              │
        │ provider      │ echo       ▼              ▼
        └── logs ───────┴──────► RECONCILER ──► VERIFIER (offline CLI, bundle)
                                       │
                                       ▼
                     DASHBOARD · RESPONDER · RECOVERY · AI NARRATOR
```

### Flow of one allowed web request

1. Client signs the request and sends it to the gateway.
2. Gateway checks size, signature, timestamp, nonce, rate limit and rules.
3. Gateway writes an **intent** entry, then forwards to the origin with a gateway-signed header.
4. Gateway returns the response (plus an optional signed receipt) and writes the **outcome** entry.
5. Ledger appends, updates the Merkle tree, and periodically produces a checkpoint.
6. Witness checks the checkpoint is a legitimate extension of the last one, then cosigns.
7. Gateway sends signed heartbeats; witness compares them with the ledger.

### Flow of one agent action

1. The agent asks the gateway to call a tool (MCP or HTTP adapter). It holds no API keys.
2. Gateway canonicalizes the call and evaluates policy: allow, block, or require approval.
3. Gateway writes a signed **intent** entry (who, which agent, which tool, policy version, untrusted inputs in context) and waits for the durable commit.
4. High-risk actions also wait for the witness to acknowledge the checkpoint containing that intent.
5. Gateway forwards the call to the provider using credentials only it holds.
6. Gateway writes the **outcome** entry (status, result commitment, provider request ID).
7. Later, the reconciler matches provider events against outcomes.

### Flow of an attack plus tampering

1. Attacker sends malicious requests (or an injected document steers the agent). The gateway blocks or pauses them and logs the rule or policy that fired.
2. The responder escalates according to the tier policy.
3. The attacker roots a machine and edits or deletes ledger rows.
4. The next witness check finds the ledger no longer matches cosigned checkpoints. Verify marks exact entries TAMPERED or MISSING; the reconciler flags provider events with no ledger entry.
5. The responder quarantines and alerts. The recovery report is generated.

---

## 7. Gateway (the guard and the chaperone)

### In plain words

Every visitor must show a valid, unforged, unused pass. The guard limits how fast anyone can knock, checks for trick patterns and leaves fake rooms only an intruder would enter. AI helpers never hold keys: the chaperone holds them, checks the rulebook and writes down every request before acting.

### Implementation

FastAPI reverse proxy with httpx, one pipeline, two lanes. Use the `cryptography` library for all crypto. Never hand-roll primitives.

### 7.1 Common pipeline (both lanes, in order)

1. **Sanity checks (P0):** body size limit, allowed content types, header shape.
2. **Signature verification, RFC 9421 (P0):** the client signs method, path, query, body digest (Content-Digest, RFC 9530), timestamp, one-time nonce and key ID. The gateway checks: timestamp within about 60 s; nonce unseen (Redis `SET NX`, TTL about 2x window); key ID known and not revoked; Ed25519 signature valid; body digest matches. Agents authenticate the same way, with their own agent key IDs.
3. **Rate limiting (P0):** Redis sliding window per key ID and per IP; stricter on login routes and on agent tools.
4. **Rule engine (P0):** YAML rules for SQL injection, path traversal, XSS, malformed payloads, and behaviour rules ("20 failed logins in 60 seconds").
5. **Honeytoken check (P1):** fake routes (`/.env`, `/admin-old`). Any hit is a high-confidence alert.
6. **Policy decision (P0):** allow, block, or (agent lane) require approval. Record the **policy version** with every decision.
7. **Two-phase record (P0):** intent entry, forward, outcome entry (section 8).

Check whether the `http-message-signatures` PyPI package fits (30 minutes maximum) before writing a parser.

### 7.2 Rule format

```yaml
- id: SQLI-001
  target: [query, body]
  pattern: "(?i)(union\\s+select|or\\s+1=1|sleep\\(|--\\s)"
  severity: high
  action: block

- id: TRAV-001
  target: [path, query]
  pattern: "(\\.\\./|%2e%2e%2f)"
  severity: high
  action: block

- id: BRUTE-001
  type: behavior
  match: { path: "/login", status: 401 }
  threshold: 20
  window_seconds: 60
  group_by: key_id_or_ip
  action: escalate
```

### 7.3 Agent lane (P0 core, P1 extras)

- **Adapters.** HTTP reverse-proxy adapter at `/proxy/{provider}/...` (P0, reuses the same pipeline and the mock provider). **MCP adapter** (P1): wraps `tools/call` requests and responses on the JSON-RPC stream, and captures the tool list. Optional SDK wrapper for plain function-calling frameworks (P2).
- **Credential broker (P0).** The agent runtime holds no long-lived secrets. The broker strips agent-supplied credentials, injects brokered ones, and where the provider supports it issues short-lived, narrowly scoped tokens per call.
- **Egress control (P0 in Docker).** Network rules stop the agent runtime reaching provider endpoints directly. Bypass attempts show up as provider events with no ledger entry.
- **Policy engine (P0 simple rules, P2 OPA or Cedar).** Example rules: refunds above a threshold need human approval; destructive database operations blocked; only allow-listed tools. Approvals are signed **approval receipts** linked to the intent entry.
- **Tool-definition hashing (P1).** Hash tool definitions each session; a silent change raises `TOOL_DEF_CHANGE` (tool poisoning).
- **Influence lineage (P1, basic).** Each intent records the untrusted inputs in the agent's context (document ID, hash, trust label). Full lineage tracking is roadmap.
- **Idempotency key (P0).** Generated per call so retries and replays are safe.
- **Failure policy.** If the gateway cannot write to the ledger: fail **closed** for high-risk tools and writes, fail **open with a flagged gap** for low-risk reads (configurable).
- **Assurance tiers.** High-risk actions wait for witness acknowledgment of the checkpoint containing the intent before forwarding; low-risk reads are batched asynchronously.

### 7.4 Honest positioning of request signing

Signing works for API clients, mobile apps, service-to-service traffic, agents and single-page apps holding a per-session key. A plain browser form cannot sign. So pitch BlackBox for **APIs, services and agents**, ship a roughly 10-line client snippet in Python and JavaScript, and add a **monitor-only mode** for unsigned browser traffic (P1).

### 7.5 Gateway secrets policy

The gateway holds **no long-term secrets of its own** (its logging keys are short-lived). It does hold the provider credentials it brokers for agents, and it holds the current chain key. Be precise on the slide: "holds only short-lived logging keys and the credentials it brokers." Provider credentials should be scoped, short-lived where possible, and rotatable by the responder.

---

## 8. Ledger (the diary) and the key design

### In plain words

Each diary page is locked with its own one-use key. The key comes from the previous key, and the old key is destroyed right after use. Each page is sealed to the one before it and signed by a short-lived signing key. The keys that could reopen old pages sit in a box only 3 of 5 people can open together.

### 8.1 Entry types

`intent`, `outcome`, `blocked`, `action` (an automated response taken), `approval`, `heartbeat`, `epoch_start`, `backup_marker`, `breakglass`. An intent with no outcome after a timeout is flagged `ORPHAN_INTENT`; a `blocked` entry never expects an outcome.

### 8.2 Entry contents (before sealing)

```json
{
  "v": 1, "epoch": 3, "seq": 1042, "type": "intent",
  "ts": "2026-09-30T10:14:03.221Z", "prev_hash": "sha256:9f2c...",
  "lane": "agent",
  "principal": {
    "key_id": "client-7", "client_ip": "203.0.113.9",
    "human": "user:alice", "agent": "agent:refund-bot@v3",
    "delegation": ["user:alice", "agent:refund-bot", "tool:pay.refund"]
  },
  "action": {
    "adapter": "http", "method": "POST", "path": "/proxy/pay/refunds",
    "tool": "pay.create_refund", "body_digest": "sha-256=:...:",
    "args_commitment": "sha256:ab41...", "idempotency_key": "req-7f31",
    "payload_ref": "blob:4c9e..."
  },
  "policy": { "version": "p-2026-09-28", "decision": "allow",
              "rule_id": null, "severity": null, "approval_receipt": null },
  "context": {
    "system_prompt_hash": "sha256:11aa...", "tool_defs_hash": "sha256:52bc...",
    "model": "model-id@version",
    "inputs_in_context": [{"source": "doc:invoice-889.pdf", "hash": "sha256:77de...", "trust": "untrusted"}]
  },
  "gateway_cert_id": "gw-cert-12"
}
```

An `outcome` entry adds `intent_seq`, `upstream_status`, `result_commitment`, `provider_request_id` and `latency_ms`. Web-lane entries leave the agent-only fields empty.

### 8.3 Canonicalization and privacy

- Serialize every entry with **JSON Canonicalization Scheme (RFC 8785)** before hashing or signing, so all parties compute identical bytes.
- Sensitive fields (auth headers, passwords, personal data) are **tokenized** before the entry is built. This tokenized version is the **analyst view**.
- The ledger keeps **commitments** (salted hashes) of arguments and results. Raw bodies of allowed writes and agent calls go to a separate **payload store**, each encrypted under its own key wrapped to the root key. This is what write-journal recovery replays.
- **Crypto-shredding:** destroying a payload's key satisfies an erasure request (GDPR or DPDP style) without breaking the chain, because the chain covers only ciphertext and commitments.
- **Selective disclosure:** revealing a payload and its salt proves it matches a commitment.

### 8.4 Key design (draw as one diagram in the deck)

```
OFFLINE ROOT SIGNING KEY (Ed25519), kept offline
   certifies each gateway epoch signing key (key chain)

ROOT ENCRYPTION KEYPAIR (X25519)
   private half: split 3-of-5 (Shamir), NEVER on the gateway or ledger
   public half:  known to the gateway

GATEWAY, at the start of each epoch:
   SK_epoch = fresh Ed25519 signing key, certified by the offline root (memory only)
   CK_0     = 32 random bytes (memory only)

FOR EACH ENTRY i:
   EK_i    = HKDF(CK_i, info="entry")
   CK_i+1  = HKDF(CK_i, info="chain")
   delete CK_i, keep CK_i+1
   ct_i    = AES-256-GCM(EK_i, JCS(entry_i), aad = epoch || seq || prev_hash)
   wk_i    = wrap EK_i to the ROOT PUBLIC KEY (X25519 + HKDF + AES-GCM, ECIES style; HPKE RFC 9180 is the standard)
   h_i     = SHA-256(h_{i-1} || ct_i || aad)
   sig_i   = Ed25519(SK_epoch, JCS({epoch, seq, type, ts, ct_hash, wk, h_i}))
   send {epoch, seq, ct_i, wk_i, h_i, sig_i, metadata} to the ledger
   delete EK_i
AT EPOCH END: destroy SK_epoch and CK
```

### 8.5 What this gives you

| Attacker has | Can they read or forge past entries? |
|---|---|
| Today's chain key CK_n and signing key (root on the gateway) | No for the past: older chain keys are gone, and old epoch signing keys are destroyed. They can read and forge **new** entries in the current epoch. Detected afterwards, not prevented. |
| The ledger database | No. Ciphertexts and wrapped keys only; wrapped keys need the root private key. |
| One or two admin key shares | No. Threshold is 3 of 5. |
| Ledger superuser (can edit rows) | They can edit, but the Merkle tree, signatures and witness catch it. |

Seq and previous hash are bound into the encryption as authenticated data, so entries cannot be reordered without breaking decryption.

### 8.6 Epochs

A new epoch starts on every gateway restart **and** on a timer (for example every 10 minutes or 1,000 entries; demo: every 5 minutes). Each epoch begins with a signed `epoch_start` entry. Keys are never written to disk, so a crash simply starts a new epoch. Shorter epochs shrink what a stolen current key can forge.

### 8.7 Integrity decision

Forward-secure **confidentiality** comes from the ratchet. **Integrity** of the past comes from the epoch signatures, the hash chain and the witnessed Merkle checkpoints. A per-entry MAC keyed from the ratchet (as journald does) is P2 hardening.

### 8.8 Honest limits of the key design

Python cannot reliably wipe secrets from memory, and "secure deletion" of a key cannot be guaranteed on shared cloud infrastructure (snapshots, swap). Acceptable for a demo; production would use a zeroizing implementation and a KMS or HSM. Forward security is defence in depth, and **the witness is the main defence against rewrites.**

### 8.9 Append-only storage

- PostgreSQL, with the ledger role granted INSERT and SELECT only.
- The ledger rejects gaps, duplicates and out-of-order sequence numbers per epoch.
- A database superuser can still edit rows. That is exactly what the Merkle tree and witness exist to catch.

### 8.10 Merkle tree and checkpoints

- RFC 6962-style hashing: leaf = `SHA-256(0x00 || JCS(sealed envelope incl. signature))`, node = `SHA-256(0x01 || left || right)`.
- The ledger serves **inclusion proofs** and **consistency proofs**.
- A checkpoint (signed tree head) is `{tree_size, root_hash, timestamp, ledger_id}` signed by the ledger key. Produce one every N entries or T seconds (demo: 20 entries or 5 seconds). **The checkpoint interval is the residual attack window; publish it as a headline number.**

---

## 9. Witness, heartbeats, reconciliation and verification

### In plain words

The notary stamps the diary and checks the guard's "still alive, N pages written" signals. The bank statement check compares the diary with outside records. The verifier walks the whole diary and reports which pages are intact, changed or missing, and which outside events the diary never mentioned.

### 9.1 Witness (P0)

- Runs as a separate container (in production a separate host or account, run by a different party).
- Fetches each new checkpoint, checks a consistency proof against the last checkpoint it cosigned, and only then cosigns. If consistency fails it refuses and raises an alert.
- Keeps its own copy of all checkpoints (hashes only, never payloads).
- Runs the continuous monitor: verifies on every new checkpoint and on a schedule.
- With several witnesses, split views (different answers to different parties) can be detected. Roadmap.

### 9.2 Heartbeats prove completeness (P0)

Every few seconds the gateway sends the witness a signed heartbeat:

```
{ epoch, seq_head, chain_head_hash, entry_count, timestamp }
```

Signed with a short-lived key certified by the offline root (demo: pre-issued certificates). The witness compares it with the ledger. Alerts fire when heartbeats stop, when counts or hashes mismatch, or on a sequence gap. Silence shows that something stopped, not why.

### 9.3 Reconciler: two feeds (agent lane P0, web lane P1)

- **Provider feed.** A connector fetches the provider's own event log (payments, cloud audit, code host). It matches provider events to ledger outcomes by `provider_request_id` and idempotency key. MVP: one mock provider with its own log.
- **Origin echo (web lane, P1, promoted from v2's idea).** The origin app sends a minimal record of requests it received to the witness. A mismatch with the gateway's log exposes a lying or bypassed gateway.
- Findings: provider events with no ledger entry (`UNRECORDED_ACTION`), ledger outcomes with no provider event (`PHANTOM_OUTCOME`).

### 9.4 Verify (P0)

Verify walks the log and:

1. Verifies the offline-root certificate chain across epochs and every entry's signature.
2. Checks every hash chain link, canonical form and that `seq` is contiguous.
3. Rebuilds the Merkle tree and compares roots to witness-cosigned checkpoints of the same size.
4. Verifies consistency proofs between consecutive checkpoints.
5. Pairs every intent with an outcome.
6. Checks heartbeat continuity.
7. Runs the reconciler feeds and re-checks policy versions (an executed action that the policy would have blocked is a violation).
8. Computes the unwitnessed window.

Per-entry and per-window status:

| Status | Meaning |
|---|---|
| VERIFIED | Matches a cosigned checkpoint |
| TAMPERED | Content or order differs from what was cosigned |
| MISSING | Entries or a time window that should exist do not |
| UNVERIFIED | Newer than the latest cosigned checkpoint (residual window) |

### 9.5 Violation catalog and verdicts

| Code | Meaning | Severity |
|---|---|---|
| `BAD_SIGNATURE` | Entry not signed by a valid certified epoch key | Critical |
| `CHAIN_BREAK` | `prev_hash` does not match the previous entry | Critical |
| `SEQ_GAP` | Missing sequence numbers | Critical |
| `CHECKPOINT_MISMATCH` | Root differs from the witnessed checkpoint at that size | Critical |
| `CONSISTENCY_FAILURE` | Tree is not an append-only extension of an earlier witnessed one | Critical |
| `UNRECORDED_ACTION` | Provider or origin event with no ledger entry (bypass or erasure) | High |
| `PHANTOM_OUTCOME` | Ledger outcome with no provider event | High |
| `POLICY_VIOLATION` | Executed action the policy version would have blocked | High |
| `ORPHAN_INTENT` | Intent with no outcome | Medium |
| `TOOL_DEF_CHANGE` | Tool definitions hash changed mid-session | Medium |
| `HEARTBEAT_GAP` | Missing heartbeats (gateway silence) | Medium |
| `UNWITNESSED_WINDOW` | Entries newer than the last checkpoint | Info |

Verdicts: **VERIFIED** (no critical or high violations, window reported), **TAMPERING DETECTED** (one or more critical violations with exact sequence numbers), **INCOMPLETE** (integrity holds but reconciliation or heartbeats show missing coverage).

This output drives the dashboard, the recovery report and the AI narrator.

### 9.6 Signed receipts (P1)

The gateway returns a signed receipt header for each request (sequence number, entry hash, gateway signature). The client can later request the inclusion proof. If the server later forgets the request, the receipt contradicts the log.

### 9.7 Witness quorum and external anchoring (P2)

Run 2 of 3 witnesses on separate hosts or accounts. Anchor the daily root to an RFC 3161 timestamp authority or OpenTimestamps. Roadmap phase: SCITT-compatible signed statements and receipts.

---

## 10. Closing the bypass

### In plain words

If an attacker (or an AI agent) can walk around the guard through a side door, the guard is useless. Lock the side doors.

### Rules (P0)

- The origin accepts traffic **only from the gateway**: mTLS, or a network allowlist. In Docker Compose the origin has no published port and sits on an internal network only the gateway can reach.
- The gateway adds a **gateway-signed header** (method, path, body digest, timestamp, short-lived key). The origin rejects requests without a valid one.
- The **agent runtime cannot reach provider endpoints directly** (egress rules). It holds no credentials, so even a direct call would fail.
- Direct-to-origin or direct-to-provider attempts are logged and raised as alerts (P1). Any provider event with no ledger entry is a bypass finding (section 9.3).
- State plainly: forward-going forgery by a rooted gateway is **detected afterwards** (witness, receipts, heartbeats, reconciliation), not prevented.

---

## 11. Active response (the fighting-back layer)

### In plain words

When BlackBox sees an attack or tampering it acts in steps, and carefully, so it cannot be tricked into locking out real users. Anything with big consequences for an agent needs a human.

### Tiers

| Tier | Action | Trigger | Priority |
|---|---|---|---|
| 1 | Alert only | Low-severity rule hit | P0 |
| 2 | Rate limit | Repeated medium hits from one key or account | P0 |
| 3 | Block the signing key or account (auto-expiring); pause a misbehaving agent's tool | Repeated or high-severity hits, or a policy violation | P1 |
| 4 | Quarantine the route (503 until an admin clears it), kill sessions, revoke agent tokens, rotate exposed credentials | Only on **confirmed tamper** or a **honeytoken hit** | P1 |

### Human approval (from v1)

Policy can mark actions `require_approval` (for example refunds above a threshold). Recommendations from the AI narrator or rules (freeze evidence, revoke an agent session, disable a tool) are **proposals**: a human approves, the gateway executes, and the action is logged. Tier 1 to 4 automatic actions still run without approval, inside the safety rails.

### Safety rules (P1)

- Bans target the **signing key or account**, not IP alone.
- Bans auto-expire.
- An allowlist of keys and IPs is never auto-blocked.
- **Dry-run mode**: log what would have happened without doing it. Use it first in every new setup.
- Every automated action is written to the ledger as an `action` entry with the evidence that triggered it, so the automation is itself auditable.

### Adapters for the demo app (P0: one, P1: both)

- **Session revocation** via a webhook the origin exposes to the gateway only.
- **API key rotation** via an admin endpoint the origin exposes to the gateway only.
- **Agent token revocation** at the credential broker.

### Honest limit

Response acts at the gateway layer. It cannot evict an attacker from a machine already rooted. Full eviction is an incident-response job.

---

## 12. Recovery: turning the log into a way back

### In plain words

BlackBox does not hand your system back magically. It tells you exactly what was touched, what to change, which backup is clean, and then replays the good actions after that backup so you lose minutes, not a day.

### 12.1 Gateway-visible blast-radius report (P0)

What BlackBox can prove from traffic and agent actions that passed through it. Each finding is tagged **proven** or **inferred**. Contents:

- endpoints hit, and by whom (signing key, session, IP)
- records or volume returned, where the origin exposes counts
- tokens and credentials seen in traffic (IDs, not values)
- first anomalous request and last verified-clean checkpoint (**T_clean**)
- writes performed
- **agent-action review (from v1):** which tools each agent called, the policy version and approvals for each, which untrusted inputs were in context, and any `UNRECORDED_ACTION`, `PHANTOM_OUTCOME` or `TOOL_DEF_CHANGE` findings
- a mandatory **"Not visible to BlackBox"** section: host shell commands, direct database access, file changes, lateral movement, outbound connections, anything outside the gateway

### 12.2 Backup markers (P1)

The backup job writes a marker entry (backup ID, time, ledger sequence at backup). This gives replay an exact starting point.

### 12.3 Write-journal recovery (P1, high value)

1. From the report, find T_clean.
2. Restore the latest backup taken at or before T_clean into a fresh instance.
3. Break-glass step (3 of 5 shares): decrypt the writes logged after the backup.
4. Select writes that were allowed, not from attacker keys or sessions, and not flagged.
5. Replay them in order using idempotency keys.
6. Compare each replay result with the originally logged status; flag divergences for a human.
7. Cut over.

Say the caveats aloud: it covers only writes that passed through the gateway, needs idempotent or deterministic writes, and cannot undo external side effects (emails sent, payments made). For agent actions with external effects (a refund already paid), replay is **not** re-executed; the report instead lists them for a human to review or reverse at the provider, using the provider log as the source of truth.

### 12.4 Patch verification by replay (P1)

After the hole is fixed, replay the attacker's exact logged requests (and, for the agent lane, the injected-document scenario) against the patched staging build. Show they are now blocked or harmless.

### 12.5 The standard playbook and where BlackBox helps

| Step | What | BlackBox help |
|---|---|---|
| 1 | Isolate | Quarantine route |
| 2 | Scope the breach | Blast-radius report |
| 3 | Kill the attacker's access | Session kill, key ban, agent token revoke |
| 4 | Rotate exposed credentials | Report lists which |
| 5 | Patch the entry point | Report shows it; patch verification proves the fix |
| 6 | Restore from a clean backup | Report names the clean point; replay recovers later writes |
| 7 | Rebuild if unsure | Report shows how far the doubt extends |
| 8 | Monitor hard afterwards | Continuous verification and alerts |

---

## 13. Custody, disclosure and compliance

### In plain words

The key that opens the diary is split between 5 people; any 3 together can open it. An auditor can be shown only the pages they need, with proof the pages are genuine.

- **Split-key custody (P1).** Root private key split 3 of 5 with a vetted implementation (for example SLIP-39 `shamir-mnemonic`; verify before use). Opening logs is a break-glass action that is itself written to the ledger. P2: shares on hardware tokens.
- **Selective disclosure (P2).** Because every entry key is wrapped to the root key, the quorum can unwrap the keys for **specific entries only** and hand them to an auditor with Merkle inclusion proofs. Limit: the quorum tool briefly rebuilds the root key in memory on a clean machine.
- **Portable evidence bundle plus offline verifier (P1).** One file with entries, proofs, checkpoints, witness signatures, public keys and (optionally) the provider log. `blackbox verify bundle.zip` checks it using public keys only. Message: "do not trust our dashboard, run this."
- **CERT-In and compliance output (P2).** Draft incident report and verified log package for the 6-hour window; support for 180-day retention within India. A template on top of the bundle, not legal advice.
- **Privacy and erasure.** Commitments in the ledger, encrypted payload store, crypto-shredding (section 8.3).

---

## 14. The AI parts

### 14.1 One AI layer: narrator and investigator (P1)

Combines v1's investigator and v2's narrator.

- **Role.** Reconstruct what happened, when, what was affected, how the attack progressed, and recommended response. It **never** decides integrity; only the verifier does.
- **Runs locally** (for example Ollama) so no log data leaves the machine (Privacy First).
- **Reads only VERIFIED entries** and verifier output, as fixed-schema fields (tool names, statuses, timestamps, hashes), not raw log text.
- **Every sentence cites** entry IDs or violation codes. Output is labelled "summary, not evidence."
- **Query box:** "what happened between 2:10 and 2:15?" answered over the verified timeline only.

Output structure:

```json
{
  "timeline": [{"ts": "...", "summary": "...", "cites": ["seq:1042", "seq:1043"]}],
  "affected": [{"resource": "customer refunds", "cites": ["seq:1050"]}],
  "attack_progression": [{"stage": "prompt injection via invoice", "cites": ["seq:1038"]}],
  "integrity_findings": [{"code": "SEQ_GAP", "cites": ["violation:3"]}],
  "recommendations": [{"action": "revoke_agent_session", "requires_approval": true}]
}
```

### 14.2 Prompt-injection safety (mandatory)

Logs contain attacker-controlled text (paths, headers, bodies, tool outputs). Defences:

1. Fixed-schema fields only; untrusted strings truncated, escaped, marked as data, or replaced by hashes and IDs.
2. **No tools and no actions** for the model.
3. Programmatic citation check: reject claims with missing or unknown entry IDs; re-run or drop them.
4. Recommendations are proposals that need human approval and are logged.

### 14.3 The AI agent under protection (P0 demo actor)

A small demo "refund bot" agent (from v1) that can act only through the gateway. It is the target of a prompt-injection scenario (a poisoned invoice makes it request a suspicious refund). This is the "AI-Powered Systems" story: an AI system being protected, recorded and explained.

### 14.4 AI attacker (test tool, not product)

See section 17.3.

### 14.5 Anomaly model (P2)

Isolation forest over per-key and per-agent features (request rate, path or tool entropy, error ratio, payload size). Catches novel attacks the rules miss; the narrator explains the top features. Rules remain the trusted baseline.

### 14.6 Canary credentials (P2)

Plant fake credentials in an env file, a database row, a backup bucket. Seeing one used at the gateway tells you which store the attacker read from.

---

## 15. Threat model

### In plain words

Who might attack us, how far each kind gets, and what BlackBox does. Rule of thumb: **prevent** what you can at the door, **detect** the rest so well that hiding it is impossible.

### 15.1 What we trust

| Thing | Trusted? | Why |
|---|---|---|
| Gateway host | No | Internet edge; assume it gets rooted |
| Ledger host | No | Holds data the attacker wants |
| Origin app, provider APIs | No (the origin is the target; provider logs are trusted only as far as the provider) | Used as a second source, not a root of trust |
| Agent runtime and the agent itself | No | Can be prompt-injected or hijacked |
| Witness | Yes, with limits | Separate host or account, tiny surface; a single witness is still one point of trust |
| Root key shares (3 of 5) | Yes, while fewer than 3 holders are compromised | Threshold assumption |
| Offline root signing key | Yes | Kept offline |
| A client's signing key | Only as far as that client | A stolen key signs valid requests until revoked |
| Clocks | Roughly | 60 s window; keep NTP on |
| The AI narrator | No | Its output is a summary, never evidence |

### 15.2 Adversaries

| Level | Attacker | Can do | BlackBox response |
|---|---|---|---|
| L0 | Outsider | Scan, probe, brute force, inject | Signature check, rate limits, rules, honeytokens |
| L1 | Stolen client or agent key | Send validly signed requests | Rules, rate limits, behaviour rules; revoke and ban the key |
| L1a | **Prompt-injected agent** | Attempts harmful tool calls, tries to bypass the gateway | Policy, approvals, egress control, no credentials, lineage records the poisoned input |
| L2 | Root on the origin host | Read app data, change files | Gateway logs everything that came through; report lists it; host-level actions stated as not visible |
| L3 | Root on the ledger host | Edit or delete rows | Witness checkpoints no longer match; TAMPERED and MISSING |
| L4 | Root on the gateway | Read the current keys, forge **new** entries, silence logging | Past safe (forward security); new forgery detected afterwards (heartbeats, receipts, witness, reconciliation); not prevented |
| L5 | Insider with 1 or 2 key shares, or malicious admin | Try to read or alter history | Threshold of 3 blocks reading; edits are caught the same as L3; break-glass use is logged |
| L6 | **Log-content attacker** | Puts instructions in strings that reach the AI narrator | Fixed-schema input, no tools, citation validation |

### 15.3 Attack to defence map

| Attack | Defence | Residual risk |
|---|---|---|
| Forged request | Ed25519 signature | Stolen client key |
| Replay | One-time nonce plus 60 s window | Nonce store reliability |
| Body altered | Signed body digest | None for signed clients |
| Brute force, credential stuffing | Rate limit, BRUTE-001 | Distributed attacks |
| SQLi, traversal, XSS | Rule engine | Obfuscated payloads (anomaly model roadmap) |
| Reconnaissance | Honeytoken routes | None |
| Walking around the gateway | Origin lock-down, gateway-signed header | Misconfiguration |
| Agent calls provider directly | No credentials, egress control, reconciliation | Misconfiguration |
| Prompt-injected agent acts | Policy, approvals, lineage, tool-def hash | Approver fatigue |
| Tool poisoning | Tool-definition hash, `TOOL_DEF_CHANGE` | None once hashed |
| Editing one entry | Signature, hash chain, Merkle, witness | None once checkpointed |
| Deleting entries (middle) | Same plus sequence gap detection, reconciliation | None once checkpointed |
| Deleting the tail | Heartbeat count, checkpoint size | Residual window only |
| Reordering | AAD binding plus chain | None |
| Rewriting all history and recomputing hashes | Witness consistency proof fails | None while witness honest |
| Rolling ledger back to a snapshot | Witness has a larger tree size | None while witness honest |
| Silencing the gateway | Heartbeats stop | Detection time equals heartbeat interval |
| Stealing the current key | Forward security, short epochs, signing keys destroyed at epoch end | Rest of that epoch |
| Stealing the database | Encrypted entries, wrapped keys | None without quorum |
| Stealing 1 or 2 shares | 3-of-5 threshold | 3 or more compromised holders |
| Forging new entries while rooted | Receipts, heartbeat mismatch, witness, reconciliation, origin echo | Detected afterwards |
| Hijacking the narrator via log text | Section 14.2 | Low |
| Tricking the responder into lockouts | Tiered response, key bans, expiry, allowlist, dry-run | Some false positives |

### 15.4 Out of scope

Network-level denial of service (use a CDN); attacks that never touch the gateway (physical access, stolen cloud console credentials); full eviction from a rooted machine; agent actions outside the gateway (local shell, file writes), which need host-level capture (eBPF or auditd) in a later phase.

---

## 16. Honest limits (say all of these openly)

Judges in a cybersecurity track reward honesty and punish overclaiming. Keep this on a slide.

1. **Breach is not prevented.** BlackBox makes it detectable, provable and easier to recover from.
2. **A rooted gateway can forge new entries.** It is caught afterwards, not stopped. Forward security protects the past only.
3. **Residual window.** Entries newer than the last cosigned checkpoint are UNVERIFIED (demo: about 5 seconds).
4. **Single witness in the demo.** Quorum and external timestamp anchoring are roadmap.
5. **Only sees traffic through the gateway.** Host actions, direct database access, lateral movement, local agent shell or file actions are invisible. The report says so.
6. **Recovery replay has conditions.** Only gateway-visible writes, idempotent writes, no undoing of external effects.
7. **Request signing suits APIs, services and agents.** Browser forms run in monitor-only mode.
8. **Python cannot reliably erase secrets;** cloud key deletion is not guaranteed. Demo only.
9. **Demo certificates are pre-issued.** Automatic rotation is roadmap.
10. **The narrator is a summary, not evidence.** Only the verifier's output is evidence.
11. **Selective disclosure briefly rebuilds the root key** in memory.
12. **CERT-In output is a template, not legal advice.**
13. **BlackBox does not prove an agent's decision was correct,** only what was recorded and that the record was not tampered with.
14. **Provider and origin logs are trusted only as far as those parties are.**
15. **The building blocks are not new.** The contribution is the assembly and the recovery workflow.

---

## 17. Testing plan (including the AI attacker)

### In plain words

We build our own demo world on purpose with weak spots, put BlackBox in front, and attack it with automated tools, including an AI that invents new attacks. The results become the numbers on our slides. **We only ever attack our own demo on our own machine.**

### 17.1 The demo world

- **Demo shop app** (FastAPI and SQLite): `/login`, `/api/orders` (GET, POST, PUT, DELETE), `/api/search` (deliberately SQL-injectable when BlackBox is off), `/admin`, session and API-key tables. Writes carry client-supplied IDs so replay works. On an internal network with no published port. Exposes gateway-only adapters `/_bb/revoke-session` and `/_bb/rotate-key`.
- **Mock payment provider** with its own event log (for reconciliation) and a refunds endpoint.
- **Refund-bot agent** that can act only through the gateway, with a "read invoice" step that a poisoned document can hijack.

### 17.2 Attack battery

| ID | Attack | Tool | Expected result |
|---|---|---|---|
| A1 | SQL injection on `/api/search` | sqlmap | Blocked by SQLI-001, rule ID shown, logged |
| A2 | Path traversal | OWASP ZAP, custom | Blocked by TRAV-001 |
| A3 | Reflected and stored XSS | ZAP | Blocked by XSS rule |
| A4 | Credential stuffing on `/login` | Custom script | Rate limited, escalated by BRUTE-001, key banned |
| A5 | Replay of a captured signed request | Custom | Rejected (nonce seen) |
| A6 | Altered body with the old signature | Custom | Rejected (digest mismatch) |
| A7 | Unsigned or stale request | Custom | Rejected |
| A8 | Probe `/.env`, `/admin-old` | ZAP, custom | Honeytoken alert, tier 4 |
| A9 | Direct request to the origin | Custom | Refused by network or missing header, alert |
| A10 | AI-generated payload variants | LLM loop (17.3) | Report which got through, tighten rules, re-run |
| A11 | **Poisoned invoice makes the agent request a large refund** | Custom | Policy requires approval, untrusted input recorded in the intent, refund held |
| A12 | **Agent calls the payment provider directly** | Custom | Blocked by egress rules; if it got through, `UNRECORDED_ACTION` |
| A13 | **Tool definitions silently changed mid-session** | Custom | `TOOL_DEF_CHANGE` |
| A14 | **Prompt-injection text planted in a log field aimed at the narrator** | Custom | Narrator report unaffected; citations validated |

### 17.3 The AI attacker

Part of the test, not the product. In order of promise:

1. **Automation of existing tools (P0):** scripted sqlmap and ZAP runs against the demo, with and without BlackBox, results saved.
2. **LLM-driven attack loop (P1):** a script asks an LLM for obfuscated injection and traversal variants, sends them through BlackBox, records blocked versus slipped through, and feeds misses back. Each miss becomes a rule; re-run. Gives "AI attacks, BlackBox defends and improves" with real numbers.
3. **Existing AI pentest agents (P2):** check status and setup effort before promising them on a slide.

Always run each attack twice, once against the bare app and once through BlackBox.

### 17.4 Tamper battery (the most important test)

Each is a script that edits the ledger database or gateway behaviour directly.

| ID | Tamper | Expected result |
|---|---|---|
| T1 | Edit one field in one entry | TAMPERED (`BAD_SIGNATURE` or `CHAIN_BREAK`), exact entry ID |
| T2 | Delete an entry from the middle | MISSING (`SEQ_GAP`), chain break located; provider event shows as `UNRECORDED_ACTION` |
| T3 | Delete the last N entries | Heartbeat count and checkpoint size mismatch |
| T4 | Swap two entries | TAMPERED (chain and AAD break) |
| T5 | Insert a forged entry | TAMPERED or sequence gap |
| T6 | Rewrite history from a point and recompute every hash | `CONSISTENCY_FAILURE`; witness refuses to cosign, alert |
| T7 | Restore the ledger to an older snapshot | Witness holds a larger tree size, alert |
| T8 | Stop logging but keep the app running | `HEARTBEAT_GAP`, counts diverge, alert |
| T9 | Replay an old checkpoint to the witness | Rejected (not an extension) |
| T10 | Steal the current chain key and try to read older entries | Fails (older keys deleted, wrapped keys need the root) |
| T11 | Forge a new entry with a stolen current epoch key | Detected afterwards via heartbeat or reconciliation mismatch (documented as detect, not prevent) |

### 17.5 Unit and property tests

- Signature: valid, replayed, stale, future-dated, altered body, unknown key, revoked key.
- Ratchet: key for entry i cannot be derived from a later key. Hash chain and AAD: any change to seq, previous hash or ciphertext fails.
- Canonicalization: identical bytes across two implementations.
- Merkle: inclusion and consistency proofs verify for random sizes; a flipped bit fails.
- **Property test (Hypothesis):** apply a random mutation (edit, delete, insert, swap) to a valid log; Verify must never return all-VERIFIED.
- Responder: never bans an allowlisted key; bans expire; dry-run never acts.
- Narrator validator: rejects any cited entry ID that does not exist.

### 17.6 Numbers to collect (fill for the deck)

| Metric | How | Result |
|---|---|---|
| Block rate per attack class | A1 to A8, A11 to A13 | |
| Rule bypasses found by the AI loop, and after fixing | A10 | |
| False positive rate | Benign traffic replay | |
| Added latency per request (p50, p95) | Load test with and without BlackBox | |
| Latency of a high-risk agent action (waits for witness) | Timed run | |
| Throughput | Load test | |
| Bytes stored per entry | Ledger size / entry count | |
| Verify speed (entries per second) | Time a full verify | |
| Detection time for tampering | Tamper to alert | |
| Key wrap cost per entry versus per batch | Micro-benchmark | |

### 17.7 Definition of done

One command (`docker compose up`) starts everything; deterministic seeded demo data; the demo works end to end **three times in a row** without manual fixes (attack, block, tamper, detect, respond, report, recover); the verifier exits with a clear verdict and exact sequence numbers; a backup screen recording exists.

---

## 18. Technology stack

### In plain words

Use boring, well-known tools so the time goes into the security logic. **Do not write your own cryptography.**

| Layer | Choice | Why |
|---|---|---|
| Language | Python 3.11+ | Fast to build, strong crypto and test libraries |
| Web framework | FastAPI with uvicorn; httpx for forwarding | Async, simple proxying |
| Crypto | `cryptography` (Ed25519, X25519, HKDF, AES-GCM, SHA-256) | Audited, standard |
| Canonicalization | An RFC 8785 (JCS) library, verified before use | Identical bytes everywhere |
| Request signatures | RFC 9421 via `http-message-signatures` if it fits (30 minutes), else a simplified signed canonical string, documented as a deviation | Standard, but do not lose hours |
| Ledger database | PostgreSQL, INSERT and SELECT only for the ledger role (SQLite with triggers as fallback) | Append-only at database level |
| Nonces, rate limits | Redis (`SET NX` with TTL, sliding windows) | Built for this |
| Rules and policy | YAML rules; simple policy module (OPA or Cedar later) | Readable, editable live |
| Merkle tree | Own small RFC 6962-style implementation (about 100 lines) with tests, or a vetted library | Simple and testable |
| Key splitting | `shamir-mnemonic` (SLIP-39) or another vetted library | Never hand-roll Shamir |
| Witness | Separate FastAPI container | Independent process |
| Reconciler | Python module with a mock-provider connector | One connector for the demo |
| Verifier CLI | Python with Typer | Anyone can run it |
| Dashboard | FastAPI serving one static page, vanilla JS, server-sent events, a light chart library | 15% of score is product experience; must not eat crypto time |
| Agent adapters | HTTP proxy (P0); MCP JSON-RPC wrapper (P1) | Section 7.3 |
| Anomaly model (P2) | scikit-learn IsolationForest | Small and standard |
| AI narrator (P1) | Local model through Ollama, structured JSON output | Data stays on the machine |
| Tests | pytest and Hypothesis | Property tests for tamper detection |
| Attack tools | sqlmap, OWASP ZAP, custom scripts, LLM loop | Section 17 |
| Packaging | Docker Compose with separate networks | Makes "origin only reachable by the gateway" real |

Pin exact versions when installing and check each library works as assumed. This document was written before any code exists; treat library names as starting choices.

---

## 19. Repo layout and interfaces

### 19.1 Repo layout

```
blackbox/
├── docker-compose.yml          # gateway, ledger, witness, origin, provider, agent, postgres, redis, dashboard
├── README.md
├── docs/                       # this document, threat model, deck assets
├── shared/
│   ├── schemas.py              # entry, checkpoint, heartbeat, receipt, violation codes
│   ├── canonical.py            # RFC 8785 canonicalization
│   ├── crypto.py               # ratchet, AES-GCM, key wrap (ECIES/HPKE), Ed25519, epoch key chain
│   └── merkle.py               # RFC 6962-style tree, inclusion and consistency proofs
├── gateway/
│   ├── main.py                 # FastAPI proxy
│   ├── pipeline.py             # sanity, signature, rate limit, rules, honeytokens, policy
│   ├── rules/*.yaml
│   ├── policy.py               # allow, block, require_approval; policy versions
│   ├── broker.py               # credential brokering for the agent lane
│   ├── adapters/               # http_adapter.py, mcp_adapter.py (P1)
│   ├── logger.py               # two-phase intent/outcome, seal, ship
│   ├── responder.py            # tiers, bans, quarantine, approvals, adapters
│   └── heartbeat.py
├── ledger/
│   ├── main.py                 # append, read, proofs, checkpoints, bundle export
│   └── db.sql                  # tables and role permissions
├── witness/
│   ├── main.py                 # cosign, heartbeat check, alerts
│   └── monitor.py              # continuous verification
├── reconcile/                  # provider connector (mock_pay first), origin echo (P1)
├── verifier/
│   └── blackbox_verify.py      # CLI: verify live log or offline bundle; violation catalog
├── recovery/
│   ├── report.py               # blast radius (proven vs inferred), agent-action review
│   ├── replay.py               # write-journal replay, patch verification
│   └── quorum_tool.py          # break-glass with 3-of-5 shares
├── narrator/                   # sanitizer, prompt, citation validator, local LLM (P1)
├── dashboard/                  # live feed, timeline, verdict panel, side-by-side plain log
├── demo/                       # shop app, mock_pay provider, refund-bot agent, attack scripts
├── client_sdk/                 # python and js signing snippets
├── attacks/                    # sqlmap and ZAP runs, custom scripts, LLM loop
├── tamper/                     # T1 to T11 scripts
└── tests/
```

### 19.2 Ledger API

| Endpoint | Purpose |
|---|---|
| `POST /append` | Gateway sends one sealed entry (intent, outcome, blocked, action, and others). Rejects gaps, duplicates and out-of-order sequence numbers. Returns seq and a signed receipt. |
| `GET /entries?from=&to=` | Read a range |
| `GET /entries/{seq}` | One entry with its inclusion proof |
| `GET /proof/inclusion?seq=` | Merkle inclusion proof |
| `GET /proof/consistency?old=&new=` | Consistency proof |
| `GET /checkpoint/latest` | Latest signed tree head |
| `GET /bundle?from=&to=` | Evidence bundle export |

### 19.3 Witness API

| Endpoint | Purpose |
|---|---|
| `POST /heartbeat` | Gateway posts a signed heartbeat |
| `POST /origin-echo` | Origin posts its minimal request record (P1) |
| `GET /status` | Health, last cosigned checkpoint, heartbeat state |
| `GET /checkpoints` | Stored checkpoints (for verifiers) |
| `GET /alerts` | Alert feed for dashboard and responder |

The witness pulls each new checkpoint from the ledger, verifies the consistency proof, and cosigns.

### 19.4 Gateway admin API (internal only)

| Endpoint | Purpose |
|---|---|
| `GET /admin/state` | Mode, bans, quarantined routes, pending approvals |
| `POST /admin/unquarantine` | Clear a quarantined route |
| `POST /admin/approve` | Approve or deny a held agent action or a proposed response |
| `PUT /admin/mode` | dry-run, monitor-only or enforce |

### 19.5 Verifier CLI

```
blackbox-verify bundle.zip --recorder-key rec.pub --witness-key wit.pub --provider-log pay.json
blackbox-verify --live
blackbox-explain verdict.json      # AI narrator, cited output
```

### 19.6 Formats (sketches)

**Sealed entry as stored in the ledger**
```json
{ "epoch": 3, "seq": 1042, "type": "intent",
  "ct": "<AES-GCM ciphertext of the canonical entry>",
  "wk": "<entry key wrapped to the root public key>",
  "h": "<hash chain value>", "sig": "<Ed25519 by epoch key>",
  "gateway_cert_id": "gw-cert-12", "ts": "2026-09-30T10:14:03.221Z" }
```

**Checkpoint**
```json
{ "tree_size": 1042, "root_hash": "...", "ts": "...", "ledger_sig": "...", "witness_sigs": ["..."] }
```

**Heartbeat**
```json
{ "epoch": 3, "seq_head": 1042, "chain_head_hash": "...", "entry_count": 1042, "ts": "...", "sig": "..." }
```

**Receipt (response header)**
```json
{ "seq": 1042, "entry_hash": "...", "ts": "...", "gateway_sig": "..." }
```

### 19.7 Sensitive-field handling

Two views of a request: the **analyst view** (tokenized; what the dashboard, report and narrator see) and the **sealed payload** (full body of allowed writes and agent calls, encrypted in the payload store; readable only through the break-glass quorum; shreddable).

---

## 20. Build plan

### In plain words

The final build is 24 hours; there is no time for everything. Get the smallest version that tells the whole story working by hour 12, then add features by value. Anything not done by its cut-off is dropped and shown on the roadmap slide.

### 20.1 Before the 24 hours (28 to 30 Sep)

**Ask the organisers whether code written before the 24 hours is allowed.** Plan as if the answer is no.

- If allowed: build P0 scaffolding now (repo, Docker Compose, shared crypto and Merkle with tests, demo world, attack scripts). Saves about 6 hours.
- If not: finalise decisions (section 23), update the deck (section 22), write and dry-run the demo script, prepare test data, and pre-read RFC 6962, RFC 8785 and the `cryptography` docs.

### 20.2 Workstreams (four people, or in order if solo)

| Stream | Owns |
|---|---|
| W1 Gateway and agent lane | Pipeline, signing, rate limit, rules, honeytokens, policy, credential broker, responder, origin lock-down and egress control |
| W2 Ledger and crypto | Canonicalization, entry format, ratchet, epoch keys, signatures, chain, append API, Merkle, proofs, checkpoints |
| W3 Witness, verify and reconcile | Cosigning, heartbeats, Verify, violation catalog, reconciler, tamper scripts, blast-radius report |
| W4 Demo, attacks, dashboard, AI, pitch | Shop app, mock provider, refund-bot, client SDK, attack scripts, dashboard, narrator, metrics, slides, integration owner |

### 20.3 24-hour schedule

| Hours | Work | Output |
|---|---|---|
| 0 to 1 | Repo, Compose skeleton, key and certificate generation, lock schemas and API contracts together | Everything starts with `docker compose up` |
| 1 to 5 | W1 signing, rate limit, first rules, forwarding. W2 canonicalization, entry format, ratchet, signatures, chain, append API, Postgres roles. W4 shop app with weak endpoint, mock provider, client SDK, attack scripts v1 | An attack is blocked and logged as sealed entries |
| 5 to 9 | W2 Merkle, proofs, checkpoints. W3 witness cosigning and heartbeats. W1 honeytokens, origin lock-down, credential broker, two-phase intent/outcome, tiers 1 and 2. W4 refund-bot | Checkpoints cosigned, heartbeats flowing, agent acts only through the gateway |
| 9 to 12 | W3 Verify, violation catalog, provider reconciliation, tamper scripts T1 to T10. Integration run | **Gate 1 (hour 12):** attack, block, log, tamper, detect, reconcile work end to end |
| 12 to 16 | Dashboard (live feed, verified/tampered timeline). Tiers 3 and 4, one adapter, approval flow. Blast-radius report with agent-action review | Visual and actionable demo |
| 16 to 18 | Narrator (local LLM, verified entries only, injection-safe) | AI pillar covered |
| 18 to 21 | Write-journal recovery (or, if behind, only patch verification). Evidence bundle if time allows | Logs become a way back |
| 21 to 23 | **Feature freeze.** Rehearse three times, record backup video, run the metrics table, put real numbers in the deck | Definition of done met |
| 23 to 24 | Buffer and submission | |

### 20.4 Cut lines (drop first to last)

1. Evidence bundle and offline verifier polish
2. Origin echo
3. Second response adapter
4. MCP adapter (keep the HTTP adapter)
5. Write-journal recovery (fall back to patch verification only)
6. Narrator query box (keep the timeline summary)
7. Influence lineage and tool-definition hashing
8. Signed receipts
9. Monitor-only mode
10. Polished dashboard (fall back to terminal verifier output)
11. AI narrator (fall back to a template report)

**Never cut:** signature check, sealed log with Merkle checkpoints, witness, heartbeats, Verify, the tamper battery, the tiered response basics, credential brokering with the refund-bot scenario, provider reconciliation, the blast-radius report, and the honest limits slide.

### 20.5 What each priority level means

| Level | Contents | Result if only this is done |
|---|---|---|
| P0 | Signature, rate limit, rules, policy; sealed two-phase log with Merkle, witness, heartbeats, Verify; origin lock-down and egress control; credential broker and refund-bot; provider reconciliation; tiers 1 and 2 plus one adapter; blast-radius report | A complete, honest, demoable product |
| P1 | Honeytokens, receipts, monitor-only mode, MCP adapter, tool-def hashing, lineage basics, origin echo, backup markers, write-journal recovery, patch verification, evidence bundle, key custody, tiers 3 and 4, narrator | "And here is how you get your system back" |
| P2 | Anomaly model, witness quorum and anchoring, selective disclosure, hardware key shares, CERT-In template, canary credentials, OPA or Cedar, host-level capture | Roadmap slide |

---

## 21. Demo script and judge questions

### 21.1 The 7-minute demo

| Time | Step | What to say |
|---|---|---|
| 0:00 | Pitch and problem | "When a server or an AI agent is compromised, the evidence is erased and you recover blind." |
| 0:45 | Web attack hits the shop; dashboard blocks it; honeytoken hit | "Every block names the rule that fired." |
| 1:30 | Same attack against the bare app | "Without BlackBox, this got through." |
| 2:00 | Poisoned invoice steers the refund-bot; the large refund is held for approval | "The agent holds no keys. The gateway wrote down the request, and the poisoned input, before anything ran." |
| 2:45 | "Attacker gets root": tamper script edits and deletes log rows | "Now they cover their tracks." Show the plain log looks clean. |
| 3:30 | Alert, lockout, quarantine; the ledger entry recording the response | Tiered response, every action logged |
| 4:00 | Verify: intact, tampered, missing windows; provider log reveals the deleted refund | "The stolen key cannot open older entries." (T10) |
| 4:45 | Recovery report: what was touched, what to rotate, entry point, T_clean, "not visible" section | Honest scope |
| 5:15 | Restore backup and replay good writes (or patch verification) | "We lose minutes, not a day." |
| 5:45 | Narrator summary | "Summary, not evidence: every line cites verified entries." |
| 6:15 | **A judge edits a log entry** and Verify catches it | The moment they remember |
| 6:45 | Limits, roadmap, close | Honest limits slide |

### 21.2 Backup plan

Recorded screen capture of the full demo; each step is one command; pre-seeded data so the timeline is never empty.

### 21.3 Language

Use: "tamper-evident", "third-party verifiable", "evidence up to the gateway boundary". Avoid: "unhackable", "proves the agent's intent", "AI detects the truth".

### 21.4 Likely judge questions

| Question | Answer |
|---|---|
| Why not a SIEM or S3 Object Lock? | They protect what was already shipped. BlackBox adds forward-secure encryption, a witness that proves completeness, verified ingress, credential brokering, live containment, cross-checks against outside records and a recovery workflow. A SIEM can alert on a silent source but cannot give a third party proof of completeness. |
| Are Merkle logs and hash chains not old? | Yes, and we say so. The contribution is the assembly for web and agent traffic plus recovery. |
| Is this just Certificate Transparency? | It deliberately reuses that design, and applies it with brokering, reconciliation, policy records and active response. |
| What if the gateway is rooted? | The past stays safe. New forgery is detected afterwards by heartbeats, receipts, the witness and reconciliation. Not prevented. |
| What if auto-response locks out real users? | Bans are on keys, expire, respect an allowlist, dry-run exists; quarantine fires only on confirmed tamper or honeytoken; agent-side high-impact actions need a human. |
| Does it work for normal browsers? | Signing suits APIs, services and agents. Browsers run in monitor-only mode. |
| What if the witness is compromised? | One witness is a point of trust in the demo. Roadmap: 2-of-3 quorum plus external anchoring. |
| Can the AI hallucinate or be tricked? | It receives only verified, sanitized, structured data, has no tools, and every claim carries a citation a program checks. Integrity is decided by cryptography, not AI. |
| What is the performance cost? | The measured p50 and p95 latency and throughput from the metrics table. Only high-risk actions wait for the witness. |
| Privacy and GDPR or DPDP? | The ledger holds commitments; payloads are encrypted separately and can be crypto-shredded. |
| Does it prove the agent was right? | No. It proves what was recorded and that the record was not altered. |
| Who runs the witness? | A different party or account than the gateway; in production a customer, auditor or third-party service. |
| Is attack testing legal? | Only against our own demo on our own machine. |

---

## 22. Deck updates needed

1. **Title and pitch:** "tamper-proof gateway and verifiable flight recorder for web apps, APIs and AI agents."
2. **Threat model slide** (15.1, 15.2), including the prompt-injected agent.
3. **Comparison table** (5.3), fair to SIEMs.
4. **Key design diagram** (8.4), one picture.
5. **Two-lane architecture diagram** (section 6).
6. **Active response tiers** plus human approval (11).
7. **Recovery flow** (12).
8. **Real numbers** from the metrics table (17.6).
9. **Honest limits slide** (16), with the checkpoint interval as a headline number.
10. **AI slide:** protected agent, local narrator, AI attacker loop, anomaly model as roadmap.
11. **Roadmap slide:** all P2 items and hardening (confidential computing, host-level capture, SCITT, multiple witnesses).
12. Replace "holds no secrets" with "holds only short-lived logging keys and the credentials it brokers."

---

## 23. Decisions and open decisions

### 23.1 Decisions made

1. Track 3 (Cybersecurity and Defense).
2. "Assume breach, still prove everything" design.
3. Active response layer added after the "logs do not get my system back" objection.
4. Review-driven fixes accepted: scoped recovery report with proven versus inferred, fair comparison table, explicit key design, heartbeats that prove completeness, bypass closed, safe tiered response, honest signing positioning, safe narrator.
5. Advanced features ranked: write-journal recovery, patch verification and witness quorum lead.
6. AI attacker is part of testing, not product; own demo only.
7. **v3 merge decisions:** one gateway with a web lane and an agent lane; two-phase intent/outcome; signed and ratcheted entries together; reconciliation against provider logs (P0) and origin echo (P1); credential brokering plus origin lock-down; human approval for high-impact agent actions; one cited, injection-safe narrator; HTTP adapter first, MCP adapter as P1.

### 23.2 Open decisions (with recommendation)

| # | Decision | Recommendation |
|---|---|---|
| 1 | Ship the narrator | **Yes, P1.** Local, verified entries only, no tools, cites entry IDs. |
| 2 | Anomaly model | **Roadmap.** |
| 3 | Wrap keys per entry or per batch | **Per entry first;** measure; batch only if latency hurts. |
| 4 | Per-entry MAC from the ratchet | **P2.** |
| 5 | Ledger database | **PostgreSQL;** SQLite with triggers if setup exceeds an hour. |
| 6 | Origin echo | **P1,** cut line 2. |
| 7 | Witness quorum | **One witness in the demo,** quorum as roadmap. |
| 8 | RFC 9421 library or simplified scheme | **Try the library for 30 minutes,** then fall back and document. |
| 9 | Pre-event coding allowed | **Ask the organisers now;** plan as if no. |
| 10 | Sealed payload for replay | **Keep it.** |
| 11 | Signed receipts | **Build if hours 18 to 21 go well.** |
| 12 | Who presents and who owns each stream | **Decide before hour 0.** |
| 13 | MCP adapter in the final build | **P1;** HTTP adapter carries the demo. Decide at Gate 1. |
| 14 | Epoch length | **5 minutes in the demo,** tune after measuring. |
| 15 | Approval UX for held agent actions | **Dashboard button plus CLI,** keep it minimal. |

---

## 24. Glossary

| Term | Plain meaning |
|---|---|
| Gateway | The guard and chaperone: every request and agent action passes through it |
| Ledger | The diary: the store of sealed entries |
| Witness | The notary: independent service that countersigns the diary's state |
| Reconciler | Compares the diary with outside records |
| Origin (app) | The actual web app being protected |
| Lane | Web lane (signed client requests) or agent lane (AI tool calls) |
| Credential broker | Holds the real API keys so the AI agent never does |
| Egress control | Network rules that stop a system from reaching things directly |
| Intent / outcome | The record of what was requested, then what actually happened |
| Orphan intent | An intent that never got an outcome |
| Provider log | The outside service's own record of what it did |
| Origin echo | The app's own minimal record of requests it received |
| Policy version | Which rulebook was in force when a decision was made |
| Approval receipt | A signed record that a human approved an action |
| Tool poisoning | Silently changing what a tool does or says it does |
| Influence lineage | Which untrusted inputs an agent saw before acting |
| Honeytoken | A fake route, file or credential no real user touches; any use is a strong alarm |
| Canary credential | A honeytoken shaped like a password or key |
| Hash / SHA-256 | A short fingerprint of data; one changed bit changes it completely |
| Hash chain | Each entry's fingerprint includes the previous one's |
| Merkle tree | Entry fingerprints combined in pairs up to one top fingerprint |
| Inclusion proof | Short proof an entry is in the log |
| Consistency proof | Short proof a later log still contains the earlier log unchanged |
| Checkpoint (signed tree head) | Signed statement of the log's size and root at a time |
| Residual window | The newest entries not yet covered by a cosigned checkpoint |
| Epoch | One run of the keys between restarts or timer rollovers |
| Ratchet | A key that moves forward one step per entry and cannot be wound back |
| Forward security | Stealing today's key does not expose yesterday's entries |
| Chain key / entry key | The ratcheting key (CK) / the one-use key for one entry (EK) |
| HKDF | Standard way to derive new keys from a key |
| AES-256-GCM | Standard encryption that also detects any change |
| AAD | Extra data locked into the encryption so it cannot be changed |
| Key wrapping | Encrypting a key with another key |
| X25519, ECIES, HPKE | Standard ways to encrypt to someone's public key |
| Ed25519 | Standard digital signature scheme |
| Nonce / replay attack | One-time random value / re-sending a captured valid request |
| RFC 9421, RFC 9530 | Standards for signing HTTP requests and body digests |
| RFC 8785 (JCS) | A way to write JSON so every party gets identical bytes |
| Commitment | A salted hash that proves data later without revealing it |
| Crypto-shredding | Deleting a key so data becomes unreadable, satisfying erasure |
| Shamir secret sharing | Split a secret into N shares; any K rebuild it (here 3 of 5) |
| Break-glass | An emergency, logged action to open protected data |
| Selective disclosure | Revealing only chosen entries with proof they are genuine |
| Evidence bundle | One file that a stranger can verify offline |
| Rooted / root access | Full administrator control of a machine |
| Tokenization | Replacing sensitive values with placeholders |
| Rate limiting / sliding window | Restricting request counts over recent time |
| WAF, SIEM, SOC | Web application firewall; log collection and analysis system; security operations team |
| SQL injection, path traversal, XSS | Sneaking database commands, `../` file access, or script code into inputs |
| mTLS | Both sides prove identity with certificates |
| Idempotent / idempotency key | Doing it twice equals once / an ID that makes repeats recognisable |
| Blast radius | Everything an attack could have touched |
| T_clean | Last verified-clean checkpoint before the first attacker activity |
| Quarantine | Taking a route offline (503) until an admin clears it |
| Dry-run mode | Say what would happen without doing it |
| Prompt injection | Hiding instructions in data so an AI obeys the data |
| Isolation forest | Machine-learning method that flags unusual data points |
| RFC 3161 / OpenTimestamps | Third-party proof that data existed at a time |
| SCITT | Emerging standard for signed statements and transparency receipts |
| MCP | Model Context Protocol: how agents call tools |
| CERT-In | India's national cyber incident response team |
| Docker Compose, Redis, Ollama | Multi-service launcher; fast in-memory store; local model runner |
| sqlmap / OWASP ZAP | Open-source attack tools (only against our own demo) |
| CRUD | Create, read, update, delete |

---

## Appendix A. Flow diagrams

### A1. Lifecycle

```
  BEFORE                 NORMAL USE               DURING ATTACK             AFTER ATTACK
 ┌────────────────┐    ┌───────────────────┐    ┌────────────────────┐    ┌──────────────────────┐
 │ Verify request │    │ Every request and │    │ Block, rate limit, │    │ Verify + reconcile   │
 │ Rate limit     │───►│ agent action is a │───►│ ban key, kill      │───►│ Timeline, recovery   │
 │ Rules, policy  │    │ sealed, witnessed │    │ sessions, rotate,  │    │ report, replay,      │
 │ Agents keyless │    │ intent + outcome  │    │ quarantine, approve│    │ evidence bundle      │
 └────────────────┘    └───────────────────┘    └────────────────────┘    └──────────────────────┘
      PREVENT                 RECORD                    RESPOND                EXPLAIN + RECOVER
```

### A2. One request through the gateway

```
 incoming request (web lane or agent lane)
   1 Sanity ──► 2 Signature ──► 3 Rate limit ──► 4 Rules ──► 5 Honeytoken? ──► 6 Policy
      │             │               │              │              │(hit: alert+tier 4)   │
      └─────────────┴───────────────┴──────────────┴──────────────┘                       │
                any check fails ──► BLOCK (4xx naming the rule) ──► `blocked` entry       │
                                                                                          ▼
                                            allow ─► write INTENT ─► forward (brokered creds for agents)
                                            require_approval ─► hold, wait for human       │
                                                                                          ▼
                                                                        write OUTCOME ─► seal (A3) ─► ledger
```

### A3. Sealing one entry

```
   CK_i (memory only)
     ├── HKDF "entry" ──► EK_i
     └── HKDF "chain" ──► CK_i+1 (kept)        CK_i then DELETED

   entry_i (canonical JSON, tokenized) ─► AES-256-GCM(EK_i, aad = epoch|seq|prev_hash) ─► ct_i
   EK_i ── wrap to ROOT PUBLIC KEY ──► wk_i
   h_i   = SHA-256(h_i-1 | ct_i | aad)
   sig_i = Ed25519(SK_epoch, envelope)
   send {epoch, seq, ct_i, wk_i, h_i, sig_i} to the LEDGER, then DELETE EK_i

   Today's keys cannot open yesterday's entries. Only the 3-of-5 root key unwraps wk_i.
```

### A4. Ledger, witness, heartbeat

```
   GATEWAY                      LEDGER                       WITNESS
      │ append entry #1042        │                            │
      │──────────────────────────►│ add leaf, update tree      │
      │ heartbeat {epoch, seq, hash, count} ──────────────────►│ compare with ledger
      │                           │◄───────────────────────────│ latest checkpoint
      │                           │◄───────────────────────────│ consistency proof (old ─► new)
      │                           │──────── proof ────────────►│
      │                           │      valid? yes ─► cosign, store
      │                           │             no  ─► REFUSE + ALERT
      │ heartbeats stop, or counts/hashes disagree ───────────►│ ALERT
```

### A5. Agent action with dual-source check

```
 AI agent (no keys) ─► GATEWAY ─► policy ─► INTENT entry ─► (high risk: wait for witness ack)
                                                 │
                                                 ▼
                                   forward with brokered credential ─► PROVIDER
                                                 │                        │
                                     OUTCOME entry (status, provider_id)  │ provider's own log
                                                 │                        │
                                                 └──────► RECONCILER ◄────┘
                                        provider event, no ledger entry ─► UNRECORDED_ACTION
                                        ledger outcome, no provider event ─► PHANTOM_OUTCOME
```

### A6. Tampering and detection

```
 Attacker roots ledger host ─► edits or deletes rows
        │
        ▼
 Witness checks new checkpoint ─► ledger cannot produce a valid consistency proof
        │                                            │
        ▼                                            ▼
 witness refuses to cosign + ALERT          Verify marks each entry VERIFIED / TAMPERED / MISSING
        │                                   Reconciler flags outside events the ledger lacks
        ▼                                            │
 responder: tier 4 (quarantine, kill sessions,       ▼
 revoke agent tokens, rotate creds)          timeline + recovery report + narrator summary
```

### A7. Response tiers

```
   low-severity hit ............................ TIER 1  alert only
   repeated medium hits (same key/account) ..... TIER 2  rate limit
   repeated/high severity, policy violation .... TIER 3  block key (expires), pause agent tool
   CONFIRMED tamper or honeytoken hit .......... TIER 4  quarantine route, kill sessions,
                                                         revoke agent tokens, rotate credentials
   High-impact agent actions ................... human approval
   Rails: dry-run | allowlist | expiry | key-based bans | every action logged with evidence
```

### A8. How each entry gets its status

```
   newer than latest cosigned checkpoint? ─ yes ─► UNVERIFIED (residual window)
     │ no
   present, sequence continuous? ───────── no ──► MISSING
     │ yes
   signature, chain link and Merkle inclusion match the cosigned checkpoint? ─ no ─► TAMPERED
     │ yes
   VERIFIED     (then: reconciled against provider logs and origin echo)
```

### A9. Recovery

```
 attack detected ─► blast-radius report (endpoints, credentials, agent actions, first anomaly, T_clean)
   ─► isolate + kill access + rotate exposed credentials
   ─► patch entry point ─► patch verification (replay attacker's requests against patched staging)
   ─► restore latest backup at or before T_clean
   ─► break-glass (3 of 5): decrypt writes logged after that backup
   ─► keep only allowed, non-attacker, non-flagged writes ─► replay in order with idempotency keys
   ─► compare results with originally logged status; flag divergences for a human
   ─► external effects (payments, emails) listed for human review, not re-executed
   ─► cut over   (data lost: minutes, not everything since last backup)
```

### A10. Key custody and disclosure

```
 ROOT PRIVATE KEY ─ Shamir split ─► share 1..5 (five people)
      any 3 together (break-glass, itself logged) ─► unwrap entry keys
            │                                    │
            ▼                                    ▼
   whole log for recovery              only chosen entries for an auditor
                                       + Merkle inclusion proofs ─► verified with public keys alone
```

### A11. Build dependency order

```
   shared canonical + crypto + Merkle
        ┌───────┴────────┐
     ledger          gateway pipeline ─► demo shop + mock provider + refund-bot + attack scripts
   (append, proofs)       │
        │            logger (two-phase seal + ship), credential broker
        └───────┬────────┘
       witness + heartbeats + reconciler
                │
   Verify + tamper scripts T1..T11 ══► GATE 1 (hour 12)
                │
     dashboard · responder tiers 3-4 + approvals · blast-radius report
                │
   narrator ─► write-journal recovery / patch verification ─► FEATURE FREEZE ─► rehearse
```
