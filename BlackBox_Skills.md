# BlackBox - Agent Skills (single file)

Spec: docs/BlackBox_v4.md. Load the Architecture section first, then the section for the component you are touching.

---

## BlackBox - agent instructions

Tamper-evident flight recorder for AI agents. Spec: docs/BlackBox_v4.md.
Always load the `blackbox-architecture` skill first; then the skill for the component you are touching (skills in .claude/skills/).

Non-negotiables: only services/signer touches private keys; signer is single-worker; all crypto in libs/blackbox_core; no floats in signed data; domain-separated signatures; provider recomputes body digest; every claim needs a test; do not advance a build stage until its gate (G1-G4) passes.

Stack: Python 3.11, FastAPI, httpx, `cryptography`, PostgreSQL 16, Redis, Docker Compose, pytest + Hypothesis.

---

<!-- skill: blackbox-architecture -->
**Use when:** Core architecture, trust zones, invariants and build order for the BlackBox tamper-evident flight recorder for AI agents. Use this skill FIRST whenever working anywhere in this repo, deciding which component owns a responsibility, adding a service or file, or when unsure about a design rule. Also use when the user mentions gateway, signer, ledger, witness, reconciler, verifier, epochs, checkpoints or "BlackBox".


### BlackBox architecture (read first)

BlackBox is an **accountability and forensics** system, not a prompt-injection filter. Full spec: `docs/BlackBox_v4.md`.

### Components and what each is trusted for
| Component | Dir | Trusted for | NOT trusted for |
|---|---|---|---|
| Gateway | services/gateway | routing, availability | integrity (checked by signer, provider, witnesses, reconciler) |
| Signer | services/signer | key custody only; tiny; single writer | nothing else |
| Ledger | services/ledger | storage, proofs | integrity at all (it only stores what is signed) |
| Witnesses x3 | services/witness | refusing inconsistent checkpoints (via quorum 2/3) | — |
| Provider (mock) | services/provider_mock | verifying attestations, own event log | must be deployed independently of gateway |
| Reconciler | services/reconciler | read-only comparison | holds NO keys |
| Verifier | tools/verifier | offline checks with pinned keys | never contacts the deployment |

### Hard invariants (never violate)
1. Only `services/signer` ever imports or touches private signing keys. Not tests, not other services.
2. Signer runs ONE worker. Never `--workers >1`.
3. All crypto/schema/canonical logic lives in `libs/blackbox_core` and is imported by every component including the verifier.
4. No floats in any signed structure. Amounts are integer minor units or decimal strings.
5. Every signature covers `label || log_id || canonical_bytes` (domain separation).
6. Unknown fields are rejected, never ignored.
7. DB append-only triggers are a speed bump, NOT a security boundary; witnesses and anchors are.
8. Provider MUST recompute the body digest itself; never trust the digest in the attestation.
9. High-risk actions fail closed; low-risk reads queue locally and fail open with a `gap` entry.
10. Every claim in docs/report must map to a test (E1-E12 or G1-G4).

### Trust chain
root (offline) -> intermediate (~30d) -> epoch key (5 min, memory only, destroyed at rollover) -> entry.

### Build order and decision gates
1. libs/blackbox_core + tools/verifier + tamper battery -> pass G1, G2 before anything else.
2. signer, ledger, witness -> pass G3 before building gateway.
3. provider_mock, gateway, approval, reconciler, agent -> pass G4, then demo 25.1.
4. Optional later: web lane, MCP adapter, secrecy module, OpenTimestamps, Go verifier.

When adding code, state which component owns it and confirm it does not violate the table above.

---

<!-- skill: blackbox-crypto-canonical -->
**Use when:** Canonical JSON (RFC 8785), encodings, domain-separated signing labels, Ed25519 wrappers, hash chain and entry sealing for BlackBox. Use when writing or editing libs/blackbox_core canonical.py, encoding.py, labels.py, crypto.py, chain.py, sealing.py, schemas.py, or any code that hashes, signs, serializes or validates entries, checkpoints, heartbeats, attestations or receipts.


### Canonicalization, signing, chain, sealing

### Primitives (use vetted libs only, `cryptography` package)
SHA-256, Ed25519, HMAC-SHA256 (web lane), X25519/HKDF/AES-GCM (secrecy module only). Never hand-roll a primitive.

### Canonical serialization
- RFC 8785 JCS. Validate against official test vectors in `tests/vectors/`.
- No floats (reject at schema level). Binary = base64url no padding. Hashes = lowercase hex with `sha256:` prefix. Timestamps = UTC RFC 3339, millisecond precision. NFC-normalize user text.
- Strict pydantic models with `extra="forbid"` per entry type.
- Canonicalization MUST be idempotent. Sealer and verifier share the same function.

### Domain separation
Signed message = `label || log_id || canonical_bytes`. Labels (distinct constants): entry, checkpoint, heartbeat, epoch_cert, intermediate_cert, attestation, approval_receipt, cosignature, witness_set, revocation. `log_id = sha256(root_pubkey || log_name)`.

### Sealing procedure
1. canonicalize candidate body (already contains `prev_hash`)
2. `entry_hash = sha256(canonical body)`
3. epoch key signs `entry_hash` under entry label
4. sealed entry = body + signature
5. Merkle leaf is computed over the SEALED entry bytes (signature included)

### Chain
`prev_hash` links entries; genesis uses a fixed constant. `verify_chain()` must report the exact seq of each break, not just pass/fail.

### Common entry fields
format version, log_id, epoch_id, seq (global, +1 each), type, signer timestamp, prev_hash, lane (web|agent), epoch cert id. Types: intent, outcome, blocked, approval, action, epoch_start, epoch_end, tool_defs, gap, breakglass.

### Pitfalls
- Any canonicalization difference between sealer and verifier silently breaks every signature; test both on identical vectors.
- Property-test (Hypothesis): canonicalize is idempotent; any single-bit change never verifies.

---

<!-- skill: blackbox-merkle-rfc6962 -->
**Use when:** RFC 6962/9162 Merkle tree implementation for BlackBox - leaf/node hashing, right frontier, inclusion proofs, consistency proofs, checkpoints and cosignatures. Use when writing or debugging merkle.py, checkpoint.py, ledger merkle_store.py, proof endpoints, or any off-by-one issue with non-power-of-two tree sizes.


### Merkle tree (RFC 6962)

### Hashing
- leaf = SHA256(0x00 || leaf_bytes); node = SHA256(0x01 || left || right).
- For n leaves, left subtree has the largest power of two strictly less than n.
- Empty tree root = SHA256("").

### Required API (in libs/blackbox_core/merkle.py)
- `root(leaves)`, incremental `append(leaf)` with persisted right frontier (O(log n))
- `inclusion_proof(m, n)` and `verify_inclusion(leaf_hash, m, n, proof, root)`
- `consistency_proof(m, n)` and `verify_consistency(m, n, old_root, new_root, proof)`

### Checkpoint
Signed: log_id, tree_size, root_hash, latest_seq, epoch_id, signer timestamp. Cosignature: checkpoint_hash, witness_id, witness timestamp, signature. "Witnessed" = quorum (default 2 of 3) valid cosignatures from the witness-set in force.

### Testing (gate G2, mandatory before moving on)
- Official RFC 6962 vectors.
- Compare against a slow independent reference on random trees.
- For EVERY size 1..200: all inclusion proofs verify; consistency proofs between EVERY pair m<n verify.
- Flip any single bit in any proof -> must fail.
- Non-power-of-two sizes are where bugs live; always test them.

---

<!-- skill: blackbox-signer -->
**Use when:** Design rules for the BlackBox signer service - Seal, Attest, Checkpoint, heartbeat, epoch rollover, signer_rules pure function. Use when editing services/signer, libs/blackbox_core/signer_rules.py or epochs.py, handling key material, sequence numbers, epoch certificates, rate caps, or anything that signs.


### Signer

The only holder of signing keys. Small API, strict rules, no operation that reveals key material.

### Operations
Seal(candidate), Attest(intent_seq), Checkpoint(request), Heartbeat (self-initiated every 5s), Rollover (self-initiated every 5 min).

### Rules on every Seal (implement as a PURE function in signer_rules.py, unit-test without networking)
- seq == last_seq + 1; prev_hash == last entry hash
- type known; schema exact (unknown fields rejected)
- per-second entry cap
- epoch key unexpired, else roll over first
- `epoch_start` / `epoch_end` are signer-only types, rejected if requested by gateway
- outcome: referenced intent_id exists and has no outcome (unless marked retry with same idempotency key)

### Rules on Attest
- intent exists and sealed; not already attested with a different digest
- attested digest == digest recorded in the sealed intent
- high-risk intents: signer must have seen a witnessed checkpoint covering the intent first

### Checkpoint
Ledger supplies tree state; signer verifies size and latest entry hash match what IT last sealed, then signs.

### Epochs
New keypair generated in memory only. Intermediate key signs epoch cert (id, pubkey, validity window, intermediate id). Seal `epoch_start` with cert. At end seal `epoch_end` (last signature of that key), destroy private key. Epoch ids +1, windows contiguous. Test rollover under load, mid-checkpoint, and during an outage.

### Concurrency
Single writer, single Uvicorn worker. Throughput via batching into one unit of work, never parallel signing.

### Honest limit
Process-level signer != HSM. Document that production uses HSM/TPM/KMS.

---

<!-- skill: blackbox-witness-ledger -->
**Use when:** BlackBox ledger service and witness implementation rules - append-only Postgres schema, checkpoint scheduling, witness checkpoint processing, quorum, heartbeat monitoring, gossip and split-view detection, anchoring. Use when editing services/ledger, services/witness, services/anchor, witness_set.py, or implementing alarms like WITNESS_REFUSAL, SPLIT_VIEW, CHECKPOINT_STALL, HEARTBEAT_STALL.


### Ledger and witnesses

### Ledger
- Postgres 16. App role has INSERT+SELECT only on entries; triggers reject UPDATE/DELETE. Remember: speed bump, not the security anchor.
- Holds no signing keys. Accepts writes only from the signer.
- Checkpoints every 5s, every N entries, and on demand (for high-risk intents). After signing, fan out to all witnesses, collect cosignatures, mark WITNESSED at quorum.
- Read API: latest checkpoint, latest witnessed checkpoint, entries by range, inclusion proof, consistency proof, evidence bundle, alarms/findings.

### Witness checkpoint processing (exact order)
1. verify cert chain (pinned root -> intermediate -> epoch) and checkpoint signature; check revocations
2. epoch id and validity window contiguous with last seen
3. first checkpoint for the log: accept and store
4. else require size >= previous size
5. equal size -> roots must be equal
6. larger -> fetch consistency proof from ledger and verify new root extends stored root
7. valid -> **fsync stored state BEFORE** returning cosignature(checkpoint hash, witness id, witness timestamp)
8. invalid -> refuse, store evidence, raise WITNESS_REFUSAL

Witness only ever signs checkpoint-consistency verdicts. Own keys, own storage, own append-only store, separate host/volume.

### Heartbeat monitor
HEARTBEAT_STALL (no heartbeat > interval x tolerance), HEARTBEAT_MISMATCH (claimed state contradicts a checkpoint), CHECKPOINT_STALL.

### Gossip
Periodically pull peers' latest cosigned checkpoint; same size + different roots -> SPLIT_VIEW. Also lets lagging witnesses catch up.

### Failure behavior
1 witness down: quorum holds, alarm. 2 down: no witnessed checkpoints, unverified window grows, high-risk fails closed.

### Anchoring (optional)
Every 5 min publish latest witnessed checkpoint hash to an append-only public Git repo (OpenTimestamps later). Never on the critical path; failure = low-severity ANCHOR_FAILURE.

---

<!-- skill: blackbox-gateway-agent-lane -->
**Use when:** BlackBox gateway implementation - common request pipeline, agent identity and delegation, credential broker, policy engine, approvals with signed receipts, commitments and payload store, assurance tiers, failure policy and local queue, tool-definition hashing, optional web lane and MCP adapter. Use when editing services/gateway, services/approval, services/payload_store, agent/, or policy rules.


### Gateway

### Pipeline (services/gateway/pipeline.py)
1 authenticate + resolve identity -> 2 normalize, body digest, args commitment, store payload+salt -> 3 evaluate rules/policy, classify risk -> 4 seal intent (or `blocked`) via signer -> 5 apply assurance tier -> 6 request attestation -> 7 forward with brokered creds + attestation -> 8 seal outcome -> 9 return response. Retries reuse the same idempotency key.

### Commitments
`commitment = SHA256(salt || value)` with random salt; value+salt in payload store; only commitment + reference in the ledger entry.

### Agent lane
- Agents hold NO provider credentials. Gateway discards any creds supplied and injects brokered, short-lived, scoped ones.
- Egress control via Docker networks so the agent runtime physically cannot reach provider/internet.
- Intent entry carries: principal (human, agent id+version, delegation chain), action (adapter, method/path, tool, body digest, args commitment, idempotency key), policy (version, decision, rule id, severity, approval receipt id), context (system-prompt hash, tool-defs hash, model id, untrusted inputs with source/content hash/trust label), claimed time.
- Tool-defs hash recorded per session; silent change -> TOOL_DEF_CHANGE.
- Intent without outcome after 60s -> ORPHAN_INTENT (reconciler).

### Policy and approvals
Declarative rules.yaml (allow-list, amount thresholds, destructive blocks, rate limits); every decision records policy version + rule id. `require_approval` -> seal intent as `pending`, approver signs receipt binding (intent seq, args commitment, expiry 10 min, single-use nonce). Approval service checks: registered approver key, approver != requester, nonce unused, not expired, args commitment matches. Failures are sealed as `blocked` with the reason.

### Assurance tiers
High-risk: after intent sealed, request on-demand checkpoint, wait up to 10s for WITNESSED coverage, else fail closed (`blocked`). Low-risk: forward immediately; UNVERIFIED until next checkpoint.

### Failure policy
Signer/ledger down: high-risk fail closed; low-risk queue to disk (bounded, alarm at 50%), later signer seals a `gap` entry then queued entries. Witness quorum down: high-risk fail closed, low-risk forward + alarm. High-risk never uses the queue.

### Web lane (small, optional)
HMAC-SHA256 over method, path, body digest, timestamp, nonce; 60s window; Redis nonce uniqueness; token-bucket rate limit; size limits, path allow-list, few injection signatures; sealed `blocked` on reject.

---

<!-- skill: blackbox-attestation-provider -->
**Use when:** Attestation flow and the mock payments provider for BlackBox - binding the logged body digest to the forwarded body, provider-side verification, enforcement mode, idempotency, defense-in-depth limits and the provider event feed. Use when editing services/provider_mock, attestation.py, or anything about ATTESTATION_BODY_MISMATCH, UNATTESTED events or "log one thing, send another".


### Attestation and mock provider

### Attestation contents
log_id, intent_seq, idempotency_key, SHA-256 digest of the exact body to forward, issuing time, expiry (30s). Signed by the attestation key under the attestation label. Sent in a header.

### Why it works
Signer attests only digests recorded in a sealed intent. A different body needs a different sealed intent (visible in ledger) or a stolen attestation key (requires compromising the signer).

### Provider MUST
1. verify attestation signature chain + expiry
2. **recompute digest of the body it actually received** and compare -> mismatch: reject, record ATTESTATION_BODY_MISMATCH
3. enforcement mode: reject missing/invalid attestation, record UNATTESTED event
4. keep its OWN append-only event log: timestamp, intent seq, idempotency key, received body digest, action, own request id
5. expose read-only event feed for the reconciler
6. honor idempotency key (replays don't repeat effects)
7. enforce its own limits (max refund per call/day) independent of BlackBox policy

### Deployment rule
Separate compose project / credentials / DB from the gateway, or reconciliation evaluation is meaningless. Reports must say it is a mock.

---

<!-- skill: blackbox-reconciler -->
**Use when:** BlackBox reconciler logic - joining ledger entries with the provider event feed and emitting findings (UNRECORDED_ACTION, UNATTESTED_ACTION, PHANTOM_OUTCOME, ORPHAN_INTENT, ARGS_MISMATCH, RESULT_MISMATCH). Use when editing services/reconciler or writing tests for bypass and mismatch detection.


### Reconciler

Read-only, holds no keys, cannot alter the ledger. Runs every 10s with a 30s grace window.

Join keys: intent seq (from attestation), idempotency key, provider request id, time window.

| Condition | Finding |
|---|---|
| provider event, valid attestation, no ledger entry | UNRECORDED_ACTION (critical) |
| provider event, missing/invalid attestation | UNATTESTED_ACTION (bypass) |
| ledger outcome, no provider event after grace | PHANTOM_OUTCOME |
| intent with no outcome after 60s | ORPHAN_INTENT |
| ledger body digest != provider received digest | ARGS_MISMATCH (critical) |
| result commitment inconsistent with provider record | RESULT_MISMATCH |

Findings are NOT sealed entries; they reference ledger seqs and provider event ids, are stored, alarmed, and included in evidence bundles. Always state in output which party operates the provider log.

---

<!-- skill: blackbox-verifier-bundles -->
**Use when:** Offline verifier, verdict precedence and evidence bundle format for BlackBox. Use when editing tools/verifier, tools/cli.py, bundle_export.py, tools/ceremony.py, or the optional Go/Rust second verifier; also when asked how to verify a ledger offline or produce an evidence bundle.


### Verifier and bundles

### Principles
Offline, standalone, minimal deps, trusts ONLY pinned root + witness keys passed at runtime, never calls the deployment.

### Algorithm
1 load pinned keys + witness-set in force -> 2 validate cert chains for referenced epochs, apply revocations -> 3 per entry: verify signature, recompute entry_hash, check prev_hash and seq continuity -> 4 epoch rules (contiguous ids/windows, epoch_start/end present) -> 5 rebuild Merkle roots, check inclusion proofs -> 6 verify checkpoint signatures and cosignature quorum -> 7 consistency between successive checkpoints -> 8 optional anchors -> 9 verify opened commitments -> 10 assign verdicts.

### Verdict precedence
TAMPERED > MISSING > UNVERIFIED > VERIFIED. Reconciler findings are separate flags, not verdicts.

### Bundle contents
Entries + inclusion proofs, witnessed checkpoints + cosignatures (+ anchor proofs), epoch cert chains, revocation notices, witness-set doc, optional payload openings (value+salt), reconciler findings for the range.

### CLI
`verify`, `export-bundle`, `status`, `reconcile-report`, `attack-suite`.

### Ceremony (tools/ceremony.py)
Offline: generate root keypair + log_id, sign first intermediate cert and first witness-set doc. Dev uses throwaway root.

### Second verifier (optional)
Go/Rust, same bundle format, must output identical verdicts on a shared corpus.

---

<!-- skill: blackbox-testing-gates -->
**Use when:** Test strategy for BlackBox - build gates G1-G4, tamper battery, property tests, acceptance runs E1-E12 with expected alarms and verdicts, fuzzing, controls and result reporting. Use when writing tests, tests/gates, tests/acceptance, tools/attack_suite, bench/, or when deciding whether a stage is done and the next may begin.


### Testing and gates

### Gates (block the next stage)
- G1 (end Stage 1): 10 entries; edit #5 and recompute hashes of #5+ -> verifier says TAMPERED at 5 (cannot re-sign). Control: bare hash chain accepts. Variant: delete #7 -> MISSING.
- G2: Merkle exhaustive 1..200 (see blackbox-merkle-rfc6962).
- G3 (end Stage 2): witness cosigned size 10; ledger offers rebuilt, correctly signed size 12 with different first 10 -> witness refuses, WITNESS_REFUSAL. Control: no witness accepts.
- G4 (end Stage 3): attest small body, forward different body -> provider rejects; signer refuses to attest unsealed digest.

### Acceptance E1-E12
E1 honest path 10 min across a rollover (must pass first) | E2 poisoned invoice, deny/approve | E3 ledger-host rewrite -> WITNESS_REFUSAL x3, MISSING/TAMPERED, UNRECORDED_ACTION | E4 gateway logs one thing sends another (4 variants) | E5 agent-network bypass | E6 witness outage (1, 2, partition, recover) | E7 split view | E8 byte-flip fuzzing, 100% detection | E9 load/perf | E10 approval abuse (self, altered args, nonce reuse, expired, unregistered key) | E11 stolen epoch key / rogue epoch / revocation | E12 tool poisoning.

### Per-test rules
Every attack has a CONTROL against a plain log. After each attack check three things: alarm within time budget, verifier verdict, offline bundle verifies on a machine with only pinned keys. Run each from a clean snapshot 3 times. Record failures honestly (FAIL bug / FAIL design gap / INCONCLUSIVE).

### Time budgets
Witness refusal ~10s; stall alarms ~15s; reconciler ~40s; ORPHAN_INTENT 60s.

### Tooling
pytest, Hypothesis, RFC vectors, locust/wrk; CI runs unit tests + tamper battery on every push.
