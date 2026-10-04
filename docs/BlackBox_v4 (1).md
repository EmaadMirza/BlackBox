# BlackBox v4

**A tamper-evident flight recorder for AI agents and web clients.**
Complete architecture, design logic and build guide.

> Audience: a human engineer or an AI agent who has never seen BlackBox. After reading this document, you should be able to explain every component, justify every design decision, and build the system without further clarification. This document contains logic and architecture only: no code, no file layout, no frontend design.

---

## Table of contents

1. Overview
2. Goals, claims and boundaries
3. Threat model
4. Glossary
5. Cryptographic conventions
6. System architecture
7. Key management
8. Data model
9. The signer
10. The ledger service
11. Witnesses
12. External anchoring
13. The gateway
14. Attestation and downstream requirements
15. The reconciler
16. The verifier and evidence bundles
17. Alarms and the operational interface
18. Secrecy module (optional)
19. Security argument
20. Failure modes and recovery
21. Technology stack
22. Build guide, stage by stage
23. Testing and evaluation plan
24. Default parameters
25. Demonstration scenarios
26. Report outline and related work
27. Roadmap (outside v4)
28. Implementation pitfalls checklist
29. Test cases and acceptance runs

---

## 1. Overview

### 1.1 The problem

Systems keep logs, and logs live on machines an attacker can take over. An attacker who gains control can edit or delete the evidence of what he did. AI agents make this worse: an agent holding credentials can issue refunds, query databases, send messages and change records on behalf of a human. If the agent is tricked (for example by a prompt-injection hidden in an invoice), the organization needs to prove afterwards exactly what the agent did, who delegated and approved it, and that the record has not been altered, to a reviewer who does not trust the organization's own servers.

### 1.2 The solution in one paragraph

A **gateway** sits in front of the protected service. Every request or tool call passes through it. The gateway writes a sealed record before forwarding (the *intent*) and after the response (the *outcome*). Records are sealed by an isolated **signer**, chained by hash, organized in a **Merkle tree**, and summarized in signed **checkpoints**. Independent **witnesses** on separate machines cosign a checkpoint only if it provably extends everything they saw before. A **reconciler** compares the ledger with the downstream service's own log. A standalone **verifier** lets any third party check the evidence offline.

### 1.3 Pitch

*"If something acted on your systems, BlackBox can prove what it did, who allowed it, and whether the evidence has been touched, even if the machine that recorded it was later compromised."*

### 1.4 What is new about it, and what is not

- The cryptographic ingredients (hash chains, Merkle logs, witnesses, signed checkpoints) come from established work: Certificate Transparency, Trillian, Sigstore Rekor, journald forward-secure sealing, immudb, AWS CloudTrail log validation. BlackBox does not claim to invent them.
- The contribution is the **combination applied to AI agents**: credential brokering, two-phase intent/outcome records with delegation chains and approval receipts, argument binding between what was logged and what the downstream service received, and reconciliation against the provider's own record.
- Honest positioning: BlackBox is an **accountability and forensics** system. It does not prevent an agent from being fooled and does not judge whether a decision was right.

### 1.5 Two lanes, one spine

| Lane | Callers | Threat focus | Weight in v4 |
|---|---|---|---|
| Agent lane | AI agents calling tools and APIs | Hijacked or misbehaving agents, insiders | Primary |
| Web lane | Ordinary HTTP clients | External attackers against a web application | Small: enough to demonstrate attack, block, record, verify |

Both lanes share the entire sealing, witnessing, reconciliation and verification spine.

---

## 2. Goals, claims and boundaries

### 2.1 Precise security claims

1. **History integrity.** Any modification, deletion, reordering, truncation or replacement of entries older than the last witnessed checkpoint is detected, and the verifier identifies the affected range.
2. **Completeness.** Every action that passes through the gateway, or reaches the downstream service, is either present in the ledger or raised as a discrepancy by the reconciler, the heartbeats or the witnesses.
3. **Bounded forward-forgery.** A fully compromised gateway can append false entries only until a witness, heartbeat or reconciliation check contradicts them. The length of this window is measured and published.
4. **Independent verifiability.** Anyone with the pinned public keys and an evidence bundle can verify offline, without trusting BlackBox's infrastructure.
5. **Agent accountability.** For each agent action the record shows: the human principal, the agent identity and version, the delegation chain, the policy version and decision, the approval receipt (if required), hashes of the system prompt and tool definitions, the model identifier, the untrusted inputs present in the agent's context, a commitment to the arguments, and the outcome.

### 2.2 Non-goals and boundaries

- BlackBox records and proves. It is not a prompt-injection filter. Its policy engine is a guardrail, not a security boundary against a manipulated model or a compromised gateway.
- Coverage is limited to actions routed through the gateway or visible to the downstream service. Local agent actions that touch neither (reading a local file, for example) are invisible.
- Reconciliation is only as independent as the downstream log. Every report must state which downstream logs are real third-party sources and which are test mocks.
- The security argument assumes the signing infrastructure was not backdoored before first use. Pinned dependencies, signed container images and reproducible builds are recommended practice but are not BlackBox features.
- Python cannot reliably erase secrets from memory. Production deployments should hold keys in an HSM, TPM or cloud KMS. The isolated signer process is the demonstrable project-scale equivalent.
- BlackBox does not prevent availability attacks; it detects and alarms on them and fails closed for high-risk actions.

### 2.3 Assumptions

- The root private key stays offline and uncompromised, or compromise is detected through witnesses and anchors.
- At least one witness host, plus the public anchors, is outside the attacker's control.
- Clocks are NTP-synchronized to within a few seconds. Witness clocks are the reference for time bounds.
- The downstream service's own event log is not controlled by the same attacker who controls the gateway (this is the independence assumption, which must be stated per deployment).

---

## 3. Threat model

### 3.1 Adversaries

| ID | Adversary | Capability |
|---|---|---|
| A1 | External web attacker | Sends crafted requests at the protected application |
| A2 | Hijacked agent | Agent steered by injected instructions; holds only what the gateway allows |
| A3 | Malicious insider | Legitimate human with some access, wants to hide or alter actions |
| A4 | Gateway-compromise attacker | Full control of the gateway host after a breach |
| A5 | Ledger-host attacker | Full control of the ledger database host and its application |
| A6 | Multi-system attacker | Controls gateway, ledger and some (not all) witnesses or the provider |
| A7 | Network attacker | Can drop, delay, replay or reorder traffic between components |

### 3.2 What each adversary can and cannot achieve

- **A1** can be blocked or recorded; cannot suppress records of requests that reach the gateway.
- **A2** can only act through the gateway because it holds no provider credentials; every attempt produces an intent entry or a blocked entry; bypass attempts show up downstream with no matching entry.
- **A3** cannot alter sealed history without detection; can try to approve their own action (prevented by approval receipts bound to a distinct approver key).
- **A4** can append plausible false entries through the signer, but only in order and within the current epoch; cannot rewrite the past; cannot mint new epochs without the intermediate key; is contradicted by heartbeats, downstream attestation checks and reconciliation.
- **A5** can alter or delete database rows but cannot re-sign them; the verifier flags them; witnesses refuse rewritten checkpoints.
- **A6** needs to defeat each trust domain separately; the quorum, anchors and downstream log make this expensive and noisy rather than impossible. Compromise of every witness plus the ledger leaves only public anchors and the downstream log as evidence.
- **A7** cannot forge signed messages; replay is blocked by nonces, sequence numbers and timestamps; dropping witness traffic triggers stall alarms.

### 3.3 Explicit residual risk

A compromised gateway that is not yet contradicted can append false entries. A fully compromised ledger plus all witnesses plus the downstream log defeats detection other than public anchors. Both are stated in the report as limits, not hidden.

---

## 4. Glossary

| Term | Meaning |
|---|---|
| Entry | One sealed record in the ledger |
| Candidate | An entry body before sealing |
| Sealed entry | A candidate plus its entry hash and epoch-key signature |
| Hash chain | Each entry contains the hash of the previous entry |
| Merkle tree | Tree over sealed entries; its root fingerprints the whole ledger |
| Inclusion proof | Short proof that one entry is in a tree of a given root |
| Consistency proof | Proof that a newer tree extends an older tree without rewriting it |
| Checkpoint | Signed snapshot of tree size, root and metadata |
| Cosignature | A witness's signature on a checkpoint |
| Witnessed checkpoint | A checkpoint with a quorum of valid cosignatures |
| Epoch | Period with a single signing key, destroyed at the end |
| Heartbeat | Signed periodic statement of how many entries exist and the latest hash |
| Attestation | Signer-issued proof that a specific request body belongs to a specific sealed intent |
| Commitment | Salted hash standing in for sensitive data |
| Reconciler | Component joining the ledger with downstream records |
| Evidence bundle | Self-contained package for offline verification |
| Quorum | Minimum number of witness cosignatures (default 2 of 3) |
| High-risk / low-risk | Policy classification controlling assurance tier |

---

## 5. Cryptographic conventions

### 5.1 Primitives

| Need | Primitive |
|---|---|
| Hashing | SHA-256 |
| Signatures | Ed25519 |
| Key agreement (secrecy module) | X25519 |
| Key derivation | HKDF-SHA256 |
| Authenticated encryption (secrecy module) | AES-256-GCM |
| Request authentication (web lane) | HMAC-SHA256 |
| Secret sharing (secrecy module) | Shamir (SLIP-39 implementation) |

Use a vetted library for every primitive. Never implement a primitive by hand.

### 5.2 Canonical serialization

All signed and hashed structures are serialized with **JSON Canonicalization Scheme (RFC 8785)**. Rules that keep canonicalization safe:

- No floating-point numbers in signed structures. Amounts are integers in minor units or decimal strings.
- All binary values are encoded as base64url without padding; all hashes as lowercase hex with a `sha256:` prefix.
- All timestamps are UTC RFC 3339 with millisecond precision.
- Strings are NFC-normalized before canonicalization where user text is included.
- Unknown fields are rejected, not ignored, so a verifier never accepts data it did not understand.

### 5.3 Domain separation

Every signature covers `label || log_id || canonical bytes`, where `label` is a constant unique to the signature type and `log_id` identifies this ledger (hash of the root public key and a log name). Labels exist for: entry, checkpoint, heartbeat, epoch certificate, intermediate certificate, attestation, approval receipt, cosignature, witness-set document, revocation notice. A signature of one type can therefore never be replayed as another type, nor in another log.

### 5.4 Identifiers

- `log_id`: stable identity of the ledger.
- `epoch_id`: monotonically increasing integer.
- `seq`: global sequence number across all epochs, starting at 0, strictly increasing by 1.
- `intent_id`: the sequence number of the sealed intent entry.
- `idempotency_key`: hash of agent id plus the caller's logical call identifier, stable across retries.

---

## 6. System architecture

### 6.1 Components

| Component | Responsibility |
|---|---|
| Gateway | Authenticate, apply rules and policy, broker credentials, request sealing, forward with attestation, record outcomes |
| Signer | Only holder of signing keys; seals entries, issues attestations, signs checkpoints and heartbeats, performs epoch rollover |
| Ledger service | Stores sealed entries append-only, maintains the Merkle tree, produces checkpoints and proofs, distributes checkpoints to witnesses |
| Witnesses (three) | Independent hosts that cosign only consistent checkpoints, monitor heartbeats, gossip with each other |
| Anchoring job | Publishes witnessed checkpoint hashes to external public timestamps |
| Provider / origin | The protected downstream service; verifies attestations; keeps its own event log |
| Reconciler | Joins ledger entries with downstream events, raises findings |
| Payload store | Holds raw payloads and salts referenced by commitments |
| Verifier | Offline tool producing per-entry verdicts |
| Alerting | Collects alarms from all components |
| Approval service | Collects human approvals and verifies signed approval receipts |

### 6.2 Trust zones and networking

- **Zone A, untrusted callers.** Clients and agent runtimes. The agent runtime's network has no route to providers or the internet except through the gateway.
- **Zone B, enforcement.** Gateway, rate-limit and nonce store.
- **Zone C, sealing.** Signer, ledger service, ledger database, payload store. The signer accepts connections only from the gateway; the ledger accepts writes only from the signer.
- **Zone D, downstream.** Provider or origin. Accepts traffic only from the gateway network and only with a valid attestation.
- **Zone E, independence.** Three witnesses on separate machines, with their own keys, storage and administrators where possible. Mutually authenticated TLS to the ledger.
- **Offline.** Root key custody on an air-gapped device used only for key ceremonies.

### 6.3 End-to-end flow for a high-risk agent action

1. Agent calls the gateway with a tool request. It has no provider credentials.
2. Gateway authenticates the agent, resolves the human delegation, normalizes the request, computes the body digest and arguments commitment, and evaluates policy.
3. If policy requires approval, the gateway seals an intent marked `pending`, requests approval, receives a signed approval receipt, and seals an `approval` entry.
4. Gateway asks the signer to seal the intent. The signer validates sequence and schema, signs, and returns the sealed entry; the ledger stores it.
5. For high-risk actions, the gateway requests an on-demand checkpoint and waits until a witnessed checkpoint covers the intent. If this does not happen within the timeout, the action is not forwarded.
6. Gateway asks the signer for an attestation bound to the sealed intent. The signer verifies the intent exists and that the digest matches.
7. Gateway adds brokered credentials and the attestation, forwards the request to the provider.
8. Provider verifies the attestation (including recomputing the body digest), executes, and records the event in its own log.
9. Gateway seals the outcome entry and returns the response to the agent.
10. Reconciler later joins the intent, outcome and provider event and confirms agreement or raises a finding.
11. Verifier can at any time label every entry and produce an evidence bundle.

### 6.4 Design principle

**Each component's trust requirements are minimal and different.** The gateway is trusted for availability and routing but its integrity is checked by the signer's rules, the provider's attestation check, the witnesses and the reconciler. The signer is trusted for key custody but is tiny. The ledger is not trusted at all for integrity; it can only store what has been signed. Witnesses are trusted collectively through a quorum. The verifier trusts only pinned public keys.

---

## 7. Key management

### 7.1 Key hierarchy

| Key | Location | Signs | Lifetime |
|---|---|---|---|
| Root (Ed25519) | Offline device | Intermediate certificates, witness-set documents, revocation notices | Years |
| Intermediate (Ed25519) | Signer's protected storage | Epoch certificates | About 30 days |
| Epoch (Ed25519) | Signer memory only, generated at runtime | Entries, checkpoints, heartbeats | 5 minutes |
| Attestation (Ed25519) | Signer | Attestations to downstream | About 30 days |
| Witness (Ed25519) | Each witness host | Cosignatures | Long, rotatable |
| Approver (Ed25519) | Approver's device | Approval receipts | Per person |
| Client HMAC secrets | Per-client | Web-lane requests | Rotatable |

Trust chain for entries: **root → intermediate → epoch → entry**.

### 7.2 Root ceremony

On an offline machine: generate the root key pair, record the public key and `log_id`, sign the first intermediate certificate (validity window, intermediate id) and the first witness-set document (witness ids, public keys, quorum, version). Distribute the root public key and witness public keys to verifiers and witnesses out of band. These pinned keys are the verifier's only roots of trust.

### 7.3 Epoch lifecycle

- At startup or rollover the signer generates a fresh epoch key pair inside its process.
- The intermediate key signs an **epoch certificate**: epoch id, epoch public key, validity window, intermediate id.
- The signer seals an `epoch_start` entry carrying the certificate.
- Entries, checkpoints and heartbeats during the epoch are signed with the epoch key.
- At rollover the signer seals an `epoch_end` entry as the epoch key's final signature, then destroys the private key and starts the next epoch.
- Epoch ids increase by exactly one. Validity windows are contiguous. Witnesses and the verifier reject non-contiguous or out-of-order epochs, which is how an attacker minting a rogue epoch is detected.

### 7.4 Intermediate rotation and revocation

- Before the intermediate certificate expires, the offline root signs a new one, delivered manually.
- If an intermediate is suspected compromised, the root signs a **revocation notice** with an effective time. Witnesses and verifiers refuse anything certified by that intermediate after that time, and the incident is investigated using the witnessed history up to that time.

### 7.5 Compromise handling

- **Epoch key stolen:** damage is limited to the remainder of the current epoch, and only as strictly ordered appends accepted by the signer's rules. Past epochs are unaffected because their keys no longer exist.
- **Signer host compromised:** assume intermediate and attestation keys are exposed. The root revokes the intermediate, a new signer is provisioned, the log continues under a new epoch series; witnesses permit this only with a root-signed notice.
- **Witness compromised:** the witness set document is re-issued without it; the quorum continues with the others.

---

## 8. Data model

### 8.1 Entry types

| Type | Meaning |
|---|---|
| `intent` | Recorded before forwarding an action |
| `outcome` | Recorded after the downstream response |
| `blocked` | Request rejected by rules or policy; no outcome expected |
| `approval` | A signed approval receipt was verified |
| `action` | An automated response BlackBox took (for example revoking a token) |
| `epoch_start`, `epoch_end` | Key lifecycle |
| `tool_defs` | Snapshot of the tool list for a session |
| `gap` | Marks an interval during which entries were queued because sealing was unavailable |
| `breakglass` | Records privileged access to protected material |

### 8.2 Common fields

Every entry carries: format version, `log_id`, epoch id, `seq`, type, signer timestamp, `prev_hash`, lane (`web` or `agent`), and the certificate id of the epoch certificate in force.

### 8.3 Request-bearing entries

- **principal:** client key id, source address, human identity, agent identity and version, delegation chain (for example user, then agent, then tool).
- **action:** adapter (http or mcp), method and path, tool name, body digest, arguments commitment, idempotency key, payload reference.
- **policy:** policy version, decision (allow, block, require_approval), matching rule id, severity, approval receipt id.
- **context (agent lane):** system-prompt hash, tool-definitions hash, model identifier and version, and a list of untrusted inputs (source, content hash, trust label).
- **claimed time:** the gateway's observed time, separate from the signer's sealing time. The difference is visible and large differences raise an alert.

`outcome` entries add: the intent's sequence number, upstream status, result commitment, provider request id, latency.

### 8.4 Commitments and the payload store

Raw bodies, arguments and results are not stored in the ledger. For each sensitive value the gateway generates a random salt, computes `commitment = SHA-256(salt || value)`, stores the value and salt in the payload store under a reference, and puts only the commitment and reference in the entry. This prevents guessing low-entropy values from a bare hash and lets the owner later open a commitment selectively for an auditor.

### 8.5 Sealing procedure

1. The candidate body is canonicalized.
2. `entry_hash = SHA-256(canonical body)`. The body already contains `prev_hash`, so entries chain.
3. The epoch key signs `entry_hash` under the entry label.
4. The sealed entry is the body plus signature.
5. The Merkle leaf is computed over the sealed entry bytes (so the signature is covered by the tree).

### 8.6 Other signed structures

- **Checkpoint:** log id, tree size, root hash, latest sequence number, epoch id, signer timestamp.
- **Cosignature:** checkpoint hash, witness id, witness timestamp, witness signature.
- **Heartbeat:** log id, epoch id, latest sequence number, latest entry hash, queue depth, signer timestamp.
- **Attestation:** log id, intent sequence number, idempotency key, body digest, issuing time, expiry.
- **Approval receipt:** approver id, intent sequence number, arguments commitment, expiry, single-use nonce.
- **Witness-set document:** version, witness ids and public keys, quorum, effective time, signed by root.
- **Finding (reconciler):** finding type, references to ledger sequence numbers and provider event ids, detection time. Findings are not sealed entries; they point at sealed evidence.

---

## 9. The signer

### 9.1 Purpose

The signer is a very small, separate process and container. It is the only component that ever holds signing keys. Its small API and strict rules mean that even a fully compromised gateway cannot do anything beyond appending well-formed, in-order entries.

### 9.2 Operations

1. **Seal(candidate):** produce a sealed entry.
2. **Attest(intent_seq):** issue an attestation for a sealed intent.
3. **Checkpoint(request):** sign a checkpoint over a tree state provided by the ledger after the signer checks that the claimed size and latest entry hash match what it last sealed.
4. **Heartbeat:** periodic, self-initiated.
5. **Rollover:** self-initiated at epoch end.

There is no operation that reveals key material.

### 9.3 Rules enforced on every Seal

- `seq` equals last sealed `seq` plus one.
- `prev_hash` equals the hash of the last sealed entry.
- The entry type is known and the schema is satisfied exactly.
- A per-second cap on entries (a compromised gateway cannot flood the ledger).
- The epoch key is unexpired. Otherwise the signer rolls over first.
- Types reserved to the signer (`epoch_start`, `epoch_end`) cannot be requested by the gateway.
- For `outcome` entries, the referenced `intent_id` exists and has no existing outcome (except for explicit retries, which carry the same idempotency key and are marked).

### 9.4 Rules enforced on Attest

- The named intent exists, is sealed, and is not already attested with a different digest.
- The digest in the attestation equals the digest recorded in that intent.
- High-risk intents require the signer to have seen a witnessed checkpoint covering the intent before it attests.

This is what binds *what was logged* to *what is sent*: the signer will only vouch for the body whose digest is in the sealed intent.

### 9.5 Concurrency

The signer is single-writer. Sequence numbers and the hash chain are strictly serial. Throughput is improved by batching candidate entries into one signed unit of work, never by parallel signing.

### 9.6 Honest limitation

A process-level signer is not equivalent to a hardware module: a host-root attacker can read process memory. The report names an HSM, TPM or KMS as the production answer and explains that the project achieves the same *interface* (sign-only, rule-enforcing) but not the same *physical* protection.

---

## 10. The ledger service

### 10.1 Storage

- Relational database with tables for sealed entries, checkpoints, cosignatures, payload references, approvals, findings and alarms.
- The application's database role has INSERT and SELECT only on the entries table. Triggers reject UPDATE and DELETE. This is a speed bump; **the security anchor is the witnesses and anchors, not the database.**
- The ledger holds no signing keys.

### 10.2 Merkle tree

Follow RFC 6962 (also RFC 9162) exactly:
- Leaf hash: SHA-256 of 0x00 followed by the leaf bytes.
- Node hash: SHA-256 of 0x01 followed by left and right child hashes.
- For a tree of `n` leaves, the left subtree contains the largest power of two strictly less than `n` leaves.
- Maintain a compact right frontier so appending a leaf costs logarithmic time.
- **Inclusion proof** for leaf `m` in a tree of size `n`: the list of sibling hashes from leaf to root, in order.
- **Consistency proof** between sizes `m < n`: the minimal set of node hashes that lets a verifier reconstruct both the old root and the new root.

### 10.3 Checkpoints

- Produced every 5 seconds, after a configurable number of entries, or on demand (used for high-risk intents).
- The ledger gives the signer the tree state; the signer verifies it against its own record of the last sealed entry and signs.
- The ledger then sends the checkpoint to every witness and collects cosignatures. Once the quorum is reached the checkpoint becomes **witnessed**.
- Entries are classified by coverage: those at or below the latest witnessed checkpoint's size are covered, newer ones are in the unverified window.

### 10.4 Read-only API (logic)

Latest checkpoint; latest witnessed checkpoint; entries by sequence range; inclusion proof for an entry in a given tree size; consistency proof between two sizes; evidence-bundle export for a range; list of alarms and findings.

### 10.5 Local queue during outages

If the signer or ledger is unreachable, the gateway queues candidate entries locally (bounded size, persisted to disk). When sealing recovers, the signer first seals a `gap` entry stating the start and end of the outage and the number of queued entries, then seals the queued entries in order, each carrying the gateway's claimed time. High-risk actions never use the queue; they fail closed.

---

## 11. Witnesses

### 11.1 Why witnesses exist

The ledger signs its own checkpoints, so a ledger-host attacker could rebuild the tree and sign a fresh, internally consistent history. A witness is a party that remembers what it has already accepted and refuses anything that does not extend it. Independence is the whole point.

### 11.2 Design rules

- Small code base, minimal dependencies, own storage, own keys.
- Runs on a different machine than the ledger, preferably different network and administrator.
- Accepts only: a checkpoint, an epoch certificate chain, and a consistency proof. It stores everything it accepts in an append-only private store.
- Never signs anything that is not a checkpoint-consistency verdict.

### 11.3 Processing a checkpoint

1. Verify the certificate chain (pinned root, intermediate, epoch key) and the checkpoint signature. Check the intermediate against known revocations.
2. Check epoch id and validity window are contiguous with what was last seen.
3. If this is the first checkpoint for this log, accept and store it.
4. Otherwise require `tree size ≥ previous size`.
5. If sizes are equal, roots must be equal.
6. If larger, request a consistency proof from the ledger and verify that the new root extends the stored root.
7. Valid: cosign `(checkpoint hash, witness id, witness timestamp)` and return the cosignature.
8. Invalid: refuse, store the evidence, raise `WITNESS_REFUSAL`.

The witness timestamp provides a time bound the gateway cannot backdate: the checkpoint existed no later than that instant.

### 11.4 Heartbeat monitoring

Witnesses receive heartbeats and track the highest claimed sequence number and latest hash. They raise:
- `HEARTBEAT_STALL` when heartbeats stop for more than the expected interval times a tolerance.
- `HEARTBEAT_MISMATCH` when a heartbeat's claimed state contradicts a checkpoint (for example a latest sequence number below the checkpoint's latest).
- `CHECKPOINT_STALL` when no new valid checkpoint arrives in time.

### 11.5 Gossip

Witnesses periodically pull each other's latest cosigned checkpoint. If two witnesses hold different roots for the same tree size, they raise `SPLIT_VIEW`. Gossip also lets a lagging witness catch up.

### 11.6 Quorum and witness-set changes

- Default quorum is 2 of 3. The verifier and the signer require the quorum for a checkpoint to count as witnessed.
- Changing the witness set requires a root-signed witness-set document with a higher version; verifiers use the set in force at each checkpoint's time.

### 11.7 Witness failure behavior

- One witness down: quorum still possible, an alarm is raised.
- Two witnesses down: no new witnessed checkpoints; the unverified window grows; high-risk actions fail closed; alarms escalate.

---

## 12. External anchoring

- Every 5 minutes an anchoring job takes the latest witnessed checkpoint hash and publishes it to (a) OpenTimestamps, which anchors into the Bitcoin chain, and (b) an append-only public Git repository with one line per anchor. An RFC 3161 timestamp authority is an alternative to (a).
- The anchor proves a checkpoint hash existed before a time none of BlackBox's own machines can rewrite.
- The verifier can optionally validate anchors.
- If the anchoring job fails, the system continues and raises a low-severity alarm; anchoring strengthens the guarantee but is not on the critical path.

---

## 13. The gateway

### 13.1 Role and trust

The gateway authenticates, enforces policy, brokers credentials, asks the signer to seal, forwards with attestation and records outcomes. It is the component most exposed to attackers, so everything it asks for is independently checked by the signer, the provider, the witnesses and the reconciler.

### 13.2 Common request pipeline

1. Authenticate the caller and resolve identity.
2. Normalize the request; compute body digest and arguments commitment; store payload and salt.
3. Evaluate lane rules and policy; classify risk.
4. Seal the intent (or a `blocked` entry) through the signer.
5. Apply the assurance tier (13.6).
6. Request an attestation from the signer.
7. Forward with brokered credentials and attestation.
8. Seal the outcome.
9. Return the response.

Retries and replays use the same idempotency key so they are recognizable and safe.

### 13.3 Web lane

- **Request authentication:** each client signs requests with HMAC-SHA256 over method, path, body digest, timestamp and a nonce. The gateway enforces a 60-second timestamp window and nonce uniqueness in the shared store, preventing replay.
- **Rate limiting:** per-client token bucket.
- **Rules:** body-size limits, path allow-list, and a small set of signatures for common injection patterns.
- **Blocking:** a `blocked` entry is sealed and the request is rejected; no outcome is expected.
- Scope is deliberately small. The web lane exists to demonstrate attack, block, record and verify, not to replace a web application firewall.

### 13.4 Agent lane

- **Agent identity:** per-agent credential or mutual TLS. The human principal arrives as a signed delegation token issued by the host application, recorded as the delegation chain.
- **Credential broker:** agents hold no long-lived provider secrets. The gateway discards any credentials the agent supplies, injects brokered credentials at forward time, and where the provider supports it issues short-lived, narrowly scoped tokens per call.
- **Egress control:** network rules prevent the agent runtime from reaching providers directly. Bypass attempts show up downstream as events with no matching ledger entry.
- **Two-phase logging:** intent before forwarding, outcome after. An intent with no outcome within 60 seconds becomes `ORPHAN_INTENT`.
- **Tool-definition hashing:** the hash of the session's tool definitions is recorded; a silent change in a later request raises `TOOL_DEF_CHANGE` (tool poisoning).
- **Influence lineage (basic):** each intent lists the untrusted inputs present in the agent's context, with source, content hash and a trust label. Full flow tracking is outside v4.
- **MCP adapter (Stage 5):** wraps JSON-RPC `tools/call`, captures `tools/list`, and applies the same pipeline.

### 13.5 Policy engine and approvals

- **Rules:** declarative; per-tool allow-lists, amount thresholds, destructive-operation blocks, per-agent rate limits. Every decision records the policy version and matching rule id.
- **Approval flow:** a `require_approval` rule causes the gateway to seal the intent with decision `pending` and notify an approver through the approval service. The approver authenticates and signs an **approval receipt** binding: the intent sequence number, the arguments commitment, an expiry, and a single-use nonce. The approval service verifies the signature against the approver's registered key, checks the approver is not the requester, then returns the receipt. The gateway seals an `approval` entry that references the receipt, and only then proceeds.
- A receipt for different arguments, an expired receipt, a reused nonce, or a self-approval is rejected and sealed as a `blocked` entry.
- Policy is a guardrail. It does not defend against a compromised gateway; provider-side limits (14.3) are the defense in depth.

### 13.6 Assurance tiers

- **High-risk actions** (writes, payments, destructive tools): after the intent is sealed, the gateway requests an on-demand checkpoint and waits until a *witnessed* checkpoint covers the intent, up to a timeout (default 10 seconds). If the timeout expires, the action fails closed and a `blocked` entry records it.
- **Low-risk reads:** forwarded immediately; their entries are covered by the next scheduled checkpoint and are `UNVERIFIED` briefly.
- Tool risk classes live in the policy and are versioned.

### 13.7 Failure policy

| Failure | High-risk | Low-risk |
|---|---|---|
| Signer unreachable | Fail closed | Queue locally, fail open with gap marker |
| Ledger unreachable | Fail closed | Queue locally |
| Witness quorum unavailable | Fail closed | Forward; widen the unverified window; alarm |
| Provider unreachable | Return error, seal outcome as failed | Same |

---

## 14. Attestation and downstream requirements

### 14.1 Attestation

For every forwarded request, the signer issues an attestation containing: the intent sequence number, the idempotency key, the SHA-256 digest of the exact body to be forwarded, issuing time and a short expiry. The gateway sends it in a header alongside the request.

### 14.2 What the downstream service must do

1. Verify the attestation signature against the attestation public key chain and check expiry.
2. **Recompute the digest of the body it actually received** and compare it to the attested digest. A mismatch means the body was altered after attestation: reject and record `ATTESTATION_BODY_MISMATCH`.
3. In enforcement mode, reject requests without a valid attestation and record them as `UNATTESTED` events.
4. Keep an append-only event log of every received request: timestamp, attested intent sequence number, idempotency key, received body digest, resulting action, its own request id.
5. Expose that event log via a read-only feed for the reconciler.
6. Honor the idempotency key so replays do not repeat effects.

### 14.3 Defense-in-depth limits at the provider

The provider keeps its own limits (for example a maximum refund per call and per day) independent of BlackBox policy. If the gateway is compromised, these limits still bound the damage.

### 14.4 The test provider (mock payments service)

A small service with refund and charge endpoints, idempotency support, its own database, its own event feed, and an enforcement-mode switch. It runs under different credentials and in a separate deployment from the gateway so evaluation of independence is honest. The report states plainly that it is a mock, and discusses what changes with a real third-party provider whose log the attacker cannot touch.

### 14.5 Why this closes "log one thing, send another"

To have a different body accepted, the attacker needs an attestation for that body's digest. The signer issues attestations only for digests recorded in sealed intents. So a different body requires sealing an intent that records the different digest, which is in the ledger for all to see. The attacker's remaining option is to forge a header with a stolen attestation key, which requires compromising the signer itself.

---

## 15. The reconciler

### 15.1 Purpose

A compromised gateway can sign anything the signer's rules allow. Reconciliation compares the ledger with an independent second record.

### 15.2 Join keys

Intent sequence number (from the attestation), idempotency key, provider request id and a time window.

### 15.3 Verdicts

| Condition | Finding |
|---|---|
| Provider event with valid attestation but no ledger entry | `UNRECORDED_ACTION` |
| Provider event without or with an invalid attestation | `UNATTESTED_ACTION` (bypass attempt) |
| Ledger `outcome` with no provider event after grace window | `PHANTOM_OUTCOME` |
| Intent with no outcome after timeout | `ORPHAN_INTENT` |
| Ledger body digest differs from provider's received digest | `ARGS_MISMATCH` |
| Result commitment inconsistent with provider's response record | `RESULT_MISMATCH` |
| Sequence gap or heartbeat count mismatch | `MISSING` (reported by verifier, referenced here) |

### 15.4 Operation

Runs continuously (default every 10 seconds) with a 30-second grace window to allow normal latency. Findings are stored, alarmed, and included in evidence bundles. The reconciler itself holds no signing keys and cannot alter the ledger; it only reads two sources and reports disagreements.

### 15.5 Independence statement

Reconciliation provides real protection only when the provider's log is outside the attacker's control. Every report states, per deployment, which party operates the provider log.

---

## 16. The verifier and evidence bundles

### 16.1 Verifier principles

- Offline, standalone, minimal dependencies.
- Trusts only pinned public keys (root and witness set) supplied at run time.
- Never contacts BlackBox servers when verifying a bundle.

### 16.2 Evidence bundle contents

The requested entries and their inclusion proofs; the relevant witnessed checkpoints with cosignatures and any anchor proofs; certificate chains for all epochs used; revocation notices; the witness-set document; optional payload openings (value and salt) for selected entries; reconciler findings for the range.

### 16.3 Verification algorithm

1. Load pinned root and witness keys; load the applicable witness-set document.
2. Validate certificate chains for every epoch referenced; apply revocations.
3. For each entry: verify signature, recompute `entry_hash`, check `prev_hash` link and sequence continuity.
4. Verify epoch rules: contiguous ids, contiguous windows, `epoch_start` and `epoch_end` present.
5. Rebuild Merkle roots and verify inclusion proofs against checkpoint roots.
6. Verify each checkpoint signature and its cosignatures against the quorum rule.
7. Verify consistency between successive checkpoints.
8. Optionally verify external anchors.
9. Verify any opened commitments against ledger commitments.
10. Assign verdicts.

### 16.4 Verdicts and precedence

1. **TAMPERED:** any signature, hash, chain or Merkle check fails.
2. **MISSING:** a gap in the sequence or a count contradicted by a witnessed checkpoint or heartbeat.
3. **UNVERIFIED:** consistent but newer than the latest witnessed checkpoint (the residual window).
4. **VERIFIED:** covered by a witnessed checkpoint with all checks passing.

Reconciler findings are reported as separate flags, not entry verdicts.

### 16.5 Second independent verifier

A small second implementation in another language (Go or Rust) reads the same bundle format and must output identical verdicts on a shared test corpus. This demonstrates that the format is fully specified and that verification does not depend on BlackBox's own code.

---

## 17. Alarms and the operational interface

No user interface design is part of v4. Operators interact through alarms, a read-only API and command-line tools.

### 17.1 Alarm catalogue

| Alarm | Raised by | Meaning | Severity |
|---|---|---|---|
| `WITNESS_REFUSAL` | Witness | A checkpoint failed the consistency check | Critical |
| `SPLIT_VIEW` | Witness gossip | Different roots for the same size | Critical |
| `CHECKPOINT_STALL` | Witness | No valid checkpoint in time | High |
| `HEARTBEAT_STALL` | Witness | Heartbeats stopped | High |
| `HEARTBEAT_MISMATCH` | Witness | Heartbeat contradicts checkpoints | Critical |
| `UNRECORDED_ACTION` | Reconciler | Provider event with no ledger entry | Critical |
| `UNATTESTED_ACTION` | Reconciler | Provider event with no valid attestation | High |
| `PHANTOM_OUTCOME` | Reconciler | Ledger outcome with no provider event | High |
| `ARGS_MISMATCH` | Reconciler | Logged digest differs from received | Critical |
| `RESULT_MISMATCH` | Reconciler | Result commitment inconsistent | High |
| `ORPHAN_INTENT` | Reconciler | Intent without outcome | Medium |
| `TOOL_DEF_CHANGE` | Gateway | Tool definitions changed silently | High |
| `ATTESTATION_BODY_MISMATCH` | Provider | Body altered after attestation | Critical |
| `QUEUE_BACKLOG` | Gateway | Local queue growing | Medium |
| `ANCHOR_FAILURE` | Anchoring job | Could not publish anchor | Low |
| `KEY_ROTATION_DUE` | Signer | Intermediate nearing expiry | Medium |
| `CLOCK_SKEW` | Any | Gateway claimed time far from signer time | Medium |

### 17.2 Read-only API (logic)

Status of all components; current unverified-window length; witness health and last cosign times; open alarms and findings; entries and proofs; evidence bundle export.

### 17.3 Command-line tools (logic)

- **verify:** verify a ledger snapshot or bundle with pinned keys and print verdicts.
- **export-bundle:** produce an evidence bundle for a sequence range or an action.
- **status:** show component health, current epoch, latest witnessed checkpoint.
- **attack-suite:** run the tamper battery against a test deployment.
- **reconcile-report:** print current findings.

---

## 18. Secrecy module (optional, Stage 5)

Integrity is the core. Secrecy is an add-on that does not change the integrity design. Without it, BlackBox already avoids storing raw sensitive data in the ledger by using commitments (8.4).

- **Per-entry encryption:** AES-256-GCM with a fresh key per entry; authentication also detects ciphertext tampering.
- **Key ratchet:** a chain key advances through HKDF-SHA256 per entry; the entry key is derived from it; the previous chain key is deleted. Recovering past entry keys from a stolen current chain key is not possible.
- **Wrapped keys:** each entry key is wrapped (X25519 key agreement, HKDF, AES-GCM) to a root encryption public key whose private half never resides on servers.
- **Shamir 3-of-5:** the root encryption private key is split into five shares; any three reconstruct it for audits or break-glass, which is itself sealed as a `breakglass` entry.
- **Crypto-shredding:** destroying a payload blob or its key makes the data unrecoverable while the ledger still proves the event occurred.
- **Distinction that must appear in the report:** the ratchet protects secrecy of the past, not integrity of the past. Integrity comes from signatures, the Merkle tree, witnesses and anchors.

---

## 19. Security argument

| Attacker capability | Outcome | Mechanism |
|---|---|---|
| Edits or deletes old entries | Detected, range identified | Signatures, chain, Merkle roots vs witnessed checkpoint |
| Reorders or truncates | Detected | Sequence continuity, chain, cosigned tree size |
| Rewrites history and re-signs | Witnesses refuse | Consistency proof cannot exist; anchors |
| Steals current epoch key | Limited to ordered appends in current epoch | Short epochs, signer rules, destroyed past keys |
| Mints a rogue epoch | Detected | Contiguous-epoch checks, intermediate certification |
| Fully controls the gateway | Can append false entries until contradicted | Signer rules, heartbeats, attestation, reconciliation |
| Logs one body, sends another | Rejected or `ARGS_MISMATCH` | Signer-issued attestation bound to the sealed digest; provider recomputes digest |
| Calls the provider directly | `UNATTESTED_ACTION` or `UNRECORDED_ACTION` | Egress control, enforcement mode, reconciliation |
| Blocks or crashes witnesses | Alarms; high-risk actions stop | Stall alarms, fail-closed tier |
| Shows different histories to different parties | `SPLIT_VIEW` | Multi-witness gossip, public anchors |
| Rolls back an older snapshot | Witnesses refuse | Size and consistency checks |
| Compromises ledger and one witness | Quorum holds | 2-of-3 cosignatures on separate hosts |
| Compromises ledger and all witnesses | Anchors and provider log remain | External anchoring, independent provider log |
| Backdates entries | Bounded | Witness timestamps, anchors |
| Replays old requests | Rejected | Nonces, timestamps, idempotency keys, single-use approval nonces |
| Approves own action | Rejected | Approver key distinct from requester; receipt binds arguments |

### 19.1 What BlackBox will never claim

It will not claim to prevent an attack, to survive total compromise of every independent party, to prove an agent's decision was correct, or to see actions that never touch the gateway or the provider.

---

## 20. Failure modes and recovery

| Situation | System behavior | Operator action |
|---|---|---|
| Signer crash | Gateway queues low-risk entries, fails closed on high-risk; restart triggers new epoch | Investigate, restart |
| Ledger database loss | Rebuild from witnesses' stored checkpoints and signed entries held by gateway queue if any; verifier flags gaps | Restore backup; compare to witness state |
| Witness loss | Quorum continues, alarm | Replace witness, root issues new witness-set |
| Clock drift | `CLOCK_SKEW` alarm; large drift blocks high-risk actions | Fix NTP |
| Intermediate expiry | `KEY_ROTATION_DUE` first, then failure to start new epochs | Offline root ceremony |
| Suspected key compromise | Revocation notice; new signer; continued log under new epoch series | Incident response using witnessed history |
| Anchor failure | Continues; low-severity alarm | Retry, check network |

---

## 21. Technology stack

| Purpose | Tool |
|---|---|
| Core language | Python 3.11 or newer |
| Second verifier | Go or Rust |
| Web framework | FastAPI with Uvicorn (signer runs a single worker) |
| HTTP client | httpx |
| Cryptography | `cryptography` library |
| Canonical JSON | A strict RFC 8785 implementation, validated against RFC 8785 test vectors |
| Secret sharing | `shamir-mnemonic` (SLIP-39) |
| Database | PostgreSQL 16 |
| Rate limiting, nonces | Redis |
| Containers and networking | Docker Compose with separate internal networks; witnesses on separate hosts |
| Anchoring | OpenTimestamps client; a public GitHub repository |
| MCP | Official MCP Python SDK (Stage 5) |
| Test agent | A plain tool-calling loop around any LLM API or local Ollama model |
| Testing | pytest, Hypothesis, RFC 6962 and RFC 8785 test vectors |
| Load testing | locust or wrk |
| Web attack demonstration | sqlmap, OWASP ZAP, custom scripts |
| Baselines | Plain Postgres logs, append-only Postgres, immudb |
| Agent benchmarks | AgentDojo, InjecAgent |
| CI | GitHub Actions |

Hardware needs are modest: a laptop for the main stack, a second device or inexpensive VPS for at least one witness (ideally all three on distinct hosts), and optionally a USB stick as the offline root device.

---

## 22. Build guide, stage by stage

### Stage 0: Preparation

- Read RFC 6962 sections on the Merkle tree and RFC 8785.
- Decide the log name and generate a test root key (a throwaway one for development; the real ceremony comes at the end).
- Decide the repository layout and CI skeleton.

### Stage 1: Tamper-evident log library (no networking)

Build, in this order:
1. **Entry format and canonicalization.** Implement the entry schema with strict validation (unknown fields rejected, no floats). Canonicalize with RFC 8785. Test with the official vectors.
2. **Hash chain.** `prev_hash` linkage, `entry_hash`, genesis rule (the first entry's previous hash is a constant). Verify function that reports the precise position of each break.
3. **Signing and the signer rules.** Ed25519 sealing with domain-separated labels. Implement the signer's rule checks as a pure function so they are testable without networking. Include epoch certificates and rollover logic using a development intermediate key.
4. **Merkle tree.** Implement RFC 6962 hashing, root computation, inclusion proofs and consistency proofs. Validate against published RFC 6962 vectors and against an independent reference implementation on random trees of many sizes.
5. **Checkpoints.** Build, sign and verify.
6. **Offline verifier.** Implement the verification algorithm of 16.3 and verdict precedence on a local ledger file.
7. **Tamper battery v1.** Scripts that edit a field, delete an entry, reorder entries, truncate the tail, replay an entry, swap a signature, and re-hash the chain after editing (the case a bare hash chain cannot detect, which signatures must catch).

**Done when:** RFC vectors pass, property tests pass, and the battery labels every attack correctly.

### Stage 2: Ledger service and witnesses

1. **Ledger service:** database schema, append-only enforcement, Merkle frontier persistence, checkpoint scheduling, proof endpoints.
2. **Signer as a service:** single-writer process exposing Seal, Attest, Checkpoint, with heartbeats and rollover.
3. **Witness service:** checkpoint processing (11.3), append-only private store, cosignature with timestamps.
4. **Quorum logic and witness-set documents.**
5. **Heartbeats and stall alarms.**
6. **Gossip between witnesses.**
7. **Deployment:** witnesses on separate machines with mutual TLS.

**Done when:** a rewritten ledger is refused and alarmed; killing one witness keeps the quorum and raises an alarm; killing two stops witnessed checkpoints and raises escalating alarms; split-view is detected in a staged test.

### Stage 3: Gateway, agent lane and reconciler

1. **Gateway skeleton** with authentication and the common pipeline, talking to the signer.
2. **Commitments and payload store.**
3. **Credential broker and egress rules** (Docker networks that physically prevent the agent runtime reaching the provider).
4. **Policy engine and approval service** with signed receipts.
5. **Attestation flow** (signer issues, provider verifies and recomputes digest).
6. **Mock provider** with event feed, idempotency, enforcement mode and its own limits.
7. **Reconciler** with all verdicts of 15.3.
8. **Assurance tiers and failure policy** including the local queue and gap marker.
9. **Web lane** basics: HMAC authentication, rate limits, small rule set.
10. **Test agent:** a tool-calling loop that handles invoices and issues refunds.

**Done when:** the end-to-end story (25.1) works, and each bypass or mismatch scenario triggers its intended finding.

### Stage 4: Evaluation

Run everything in section 23, execute the end-to-end acceptance suite of section 29, and write up results. This is what turns a working system into a convincing project.

### Stage 5: Extensions, in this order

1. Public anchoring and hardened multi-witness operations.
2. Evidence bundles and the second verifier.
3. MCP adapter with tool-definition hashing.
4. Secrecy module.
5. Documentation polish and report.

### Decision gates

- After Stage 1: if the tamper battery does not pass completely, do not proceed.
- After Stage 2: if witnesses cannot reliably refuse a rewrite, do not build the gateway.
- After Stage 3: if reconciliation cannot catch deliberate mismatch and bypass, the agent-lane claim is unproven; fix before evaluating.

---

## 23. Testing and evaluation plan

*The end-to-end acceptance tests (red-team runs against the finished deployment) are specified in section 29; build-time gate tests are in section 29.7.*

1. **Standard vectors:** RFC 6962 Merkle vectors; RFC 8785 canonicalization vectors.
2. **Property tests (Hypothesis):** for random entries and tree sizes, inclusion and consistency proofs always verify; any single-bit change never verifies; canonicalization is idempotent.
3. **Tamper battery**, each with an expected verdict: edit field, delete entry, reorder, truncate tail, replay old entry, fork the ledger, swap a signature, forge with a stolen epoch key outside its epoch, re-sign rewritten history, roll back a snapshot, present a split view, mint a rogue epoch. Report a table of attack, expected verdict, actual verdict.
4. **Fuzzing:** flip random bytes in stored ledgers thousands of times; target 100% detection for witnessed entries and report every miss.
5. **Ablation:** disable each layer in turn (chain, signature, Merkle, witness, anchor, attestation) and report which attacks then go undetected. Layers that add nothing are removed from the design.
6. **Agent evaluation:** run AgentDojo and InjecAgent cases through the test agent behind the gateway. Measure logging completeness (target 100%), reconciler detection rate when bypass is injected, policy block rate versus disruption of legitimate tasks. State plainly that BlackBox is not measured as an injection filter.
7. **Performance:** added latency (p50, p95) with and without BlackBox; throughput in entries per second; checkpoint-to-witnessed latency; proof size and verification time versus log size; storage per entry; measured unverified window.
8. **Baselines:** run the same tamper attacks against plain logs, append-only Postgres and immudb; report what each detects, including attacks where a baseline does better.
9. **Reproducibility:** one-command start, test, benchmark and attack runs; pinned dependencies; CI running the unit tests and tamper battery on every push; a README that regenerates every table and graph in the report.

---

## 24. Default parameters

| Parameter | Default |
|---|---|
| Epoch length | 5 minutes |
| Checkpoint interval | 5 seconds, plus on demand |
| Heartbeat interval | 5 seconds |
| Witness quorum | 2 of 3 |
| High-risk witness wait timeout | 10 seconds |
| Orphan intent timeout | 60 seconds |
| Reconciliation interval | 10 seconds |
| Reconciliation grace window | 30 seconds |
| Intermediate and attestation key validity | 30 days |
| Web request timestamp window | 60 seconds |
| Attestation expiry | 30 seconds |
| Approval receipt expiry | 10 minutes |
| Anchoring interval | 5 minutes |
| Signer entry rate cap | Configurable per deployment |
| Local queue limit | Configurable; alarm at 50% |

---

## 25. Demonstration scenarios

*Each scenario below is also an acceptance run with exact pass criteria in section 29 (mapping in 29.3).*

### 25.1 Primary story: the hijacked refund agent

1. A refund agent processes an invoice containing a hidden instruction to refund a large amount to an attacker's account.
2. The agent attempts the refund. The gateway records the untrusted invoice in the intent's context, policy sees the amount above the threshold and requires approval.
3. Case A: approval denied; a `blocked` entry records the attempt, with the input lineage showing the invoice as the source.
4. Case B: a human approves (for the demonstration); the intent, approval, attestation, provider event and outcome all line up; the reconciler confirms agreement.
5. The verifier produces an evidence bundle for the action showing the human, agent, delegation chain, policy decision, approval receipt and outcome.

### 25.2 Tamper story

An attacker with ledger-host access deletes the refund intent and re-signs a rewritten tail. The witnesses refuse the rewritten checkpoint, `WITNESS_REFUSAL` fires, and the verifier marks the range `TAMPERED` or `MISSING`, while the provider's event feed shows the refund without a matching entry (`UNRECORDED_ACTION`).

### 25.3 Gateway-compromise story

The attacker controls the gateway and logs a small refund while sending a large one. The signer will not attest the large body, so the provider rejects the request; if the attacker sends the large body with the small body's attestation, the provider's digest recomputation raises `ATTESTATION_BODY_MISMATCH`. The attacker's other option, calling the provider directly, produces `UNATTESTED_ACTION`.

### 25.4 Availability story

Two witnesses are taken offline. Checkpoints stop being witnessed, alarms escalate, the unverified window grows, and high-risk actions stop while low-risk reads continue with a recorded gap.

### 25.5 Tool-poisoning story

A tool's description changes silently between sessions. `TOOL_DEF_CHANGE` fires and the new hash is recorded.

---

## 26. Report outline and related work

### 26.1 Report outline

1. Problem and motivation
2. Threat model
3. Design overview
4. Cryptographic construction and security argument
5. Agent-lane design
6. Implementation
7. Evaluation (section 23 results)
8. Related work
9. Limitations (section 2.2 and 3.3)
10. Future work (section 27)

### 26.2 Related work to position against

Certificate Transparency (RFC 6962 and 9162); Trillian; Sigstore Rekor; journald forward-secure sealing; immudb; AWS CloudTrail log-file integrity validation; checkpoint and witness protocols from the transparency-log community; agent observability and guardrail tools. For each, state what it provides and what BlackBox adds or lacks.

---

## 27. Roadmap (outside v4)

Honeytokens; write-journal replay recovery; an LLM-generated incident narrative; automated response actions; full influence-lineage tracking; OPA or Cedar policy engines; SDK wrappers for plain function-calling frameworks; real HSM or KMS integration; formal verification of the ledger and witness protocol (for example a TLA+ model of the property "no undetected rewrite of witnessed history").

---

## 28. Implementation pitfalls checklist

- Canonicalization differences between the sealer and the verifier silently break every signature. Test both sides on identical vectors.
- Never use floating-point numbers in signed data.
- Merkle trees with sizes that are not powers of two are where off-by-one errors live. Test every size from 1 to at least 200 against a reference.
- Domain labels and the log id must be part of every signed message.
- The signer must be single-writer; multiple Uvicorn workers will corrupt the sequence.
- Do not let any component other than the signer touch signing keys, even in tests of other components.
- Epoch rollover is a critical path: test rollover under load, mid-checkpoint, and during an outage.
- The witness must store state durably before it returns a cosignature; otherwise a restart can forget what it accepted.
- Clock handling: use the witness's time as the reference; log the claimed-versus-sealed difference.
- Database append-only enforcement is not a security boundary. Do not let it substitute for witness checks in your tests or your claims.
- The provider must recompute body digests itself; trusting the attestation's digest without recomputing defeats argument binding.
- The mock provider must be independent in deployment from the gateway, or the evaluation of reconciliation is meaningless.
- Keep every claim in the report tied to a test in section 23; remove claims without a test.
- State every limitation in the report. Honest limits increase credibility.

---

## 29. Test cases and acceptance runs

This section defines how the **finished** system is tested end to end. Section 23 describes the evaluation programme (vectors, property tests, benchmarks, baselines); this section is the executable acceptance suite: concrete scenarios in which an attacker is played against a running deployment, with exact expected alarms, verdicts and pass criteria. Section 29.7 adds short build-time gate tests that decide whether the next build stage may begin.

### 29.1 Principles

1. **Test the deployed system, not the parts.** Every acceptance run uses the full topology of section 6: gateway, signer, ledger, three witnesses, anchoring job, mock provider, approval service, reconciler and a test agent.
2. **Two roles.** An *honest workload* produces normal traffic. An *attacker script* acts from one declared position (29.2) and attempts one declared goal.
3. **Three questions after every attack.** A run passes only if all three are answered correctly:
   - **Alarm:** did the expected alarm fire, within its time budget?
   - **Verdict:** did the verifier label the affected entries as expected?
   - **Offline evidence:** can an evidence bundle for the affected range be verified on a separate machine that has only the pinned keys and no network access to the deployment?
4. **Every attack has a control.** The same attack is run against a baseline (plain log file or plain database table, no signing, no witnesses). The control demonstrates that the attack genuinely works against an ordinary setup. A BlackBox pass with no control proves little.
5. **Failures are findings.** An attack that succeeds is recorded and analysed, never hidden. A report that lists caught and uncaught attacks honestly is stronger than one claiming perfection.
6. **Repeatability.** Each run starts from a restored clean snapshot and is repeated three times; results must agree.

### 29.2 Test environment

**Deployment.** All components of section 6 running. Witnesses should be on separate machines. If only one machine is available, witnesses run as separate containers with separate volumes and keys, and every report states "reduced witness independence".

**Attacker positions** (each test names one):

| Position | Meaning | What the attacker can do |
|---|---|---|
| P1 Agent runtime | Inside the agent's network and process | Send arbitrary tool calls; try to reach the provider or internet directly |
| P2 Gateway host | Shell on the gateway machine | Read gateway memory and config; call the signer's API as the gateway; alter forwarded requests |
| P3 Ledger host | Shell on the ledger machine | Read and modify the database and files; run arbitrary code as the ledger |
| P4 Network | On-path between components | Drop, delay, replay, reorder messages |
| P5 Witness host | Shell on one witness machine | Read and modify that witness's storage and keys |
| P6 Provider side | Control of the mock provider's event log | Alter provider events (used only for limit tests) |

**Fixtures:**
- An honest workload generator producing mixed low-risk reads and high-risk writes at a configurable rate.
- A set of invoice documents: several clean ones and one carrying a hidden instruction to issue a large refund to an attacker-controlled account.
- A policy with a refund threshold requiring approval, a tool allow-list, and a destructive-operation block.
- A registered approver key and a registered requester identity (distinct).
- A pinned-key configuration file used by the verifier, kept on the offline verification machine.
- The baseline setup: the same application writing plain logs, with no BlackBox components.
- A snapshot and restore procedure for every component's storage, so each run starts clean.

**Clock discipline:** all hosts synchronize with NTP before each session; the session log records the measured offsets.

### 29.3 Test record format and traceability

Every test is documented with: ID, claim exercised, attacker position, preconditions, steps, expected alarms (with time budget), expected verdicts, expected reconciler findings, control behaviour, pass criteria, and the evidence captured (alarm log, verifier output, bundle, timing).

**Traceability from claims (section 2.1) and demonstrations (section 25) to tests:**

| Claim or demo | Tests |
|---|---|
| Claim 1, history integrity | E3, E7, E8, E11 |
| Claim 2, completeness | E4, E5, E6 |
| Claim 3, bounded forward-forgery | E4, E6, E11 |
| Claim 4, independent verifiability | E1 and the offline-evidence check in every test |
| Claim 5, agent accountability | E1, E2, E10, E12 |
| Demo 25.1 hijacked refund agent | E2, E10 |
| Demo 25.2 tamper story | E3 |
| Demo 25.3 gateway-compromise story | E4, E5 |
| Demo 25.4 availability story | E6 |
| Demo 25.5 tool-poisoning story | E12 |

**Time budgets** are derived from the defaults of section 24:
- Witness refusal alarm: within one checkpoint interval plus one network round trip (about 10 seconds).
- Heartbeat or checkpoint stall alarm: within three heartbeat intervals (about 15 seconds).
- Reconciler findings: within reconciliation interval plus grace window (about 40 seconds); `ORPHAN_INTENT` after the 60-second timeout.
- Verifier verdicts: immediately on running the verifier against the stored ledger.

### 29.4 Acceptance tests

#### E1: Honest path (baseline)

- **Claim:** 4 and 5; establishes that the system works before anything is attacked.
- **Position:** none.
- **Steps:** run the honest workload for ten minutes (spanning at least one epoch rollover). Include low-risk reads and several high-risk refunds, including at least one requiring approval and being approved by the registered approver.
- **Expected:** all entries become `VERIFIED` after the next witnessed checkpoint; the unverified window stays within the configured bound; reconciler reports zero findings; no alarms except informational ones; the `epoch_end` and `epoch_start` entries are present and contiguous.
- **Offline evidence:** export a bundle for one refund action; verify it on the offline machine; the bundle shows human, agent, delegation chain, policy decision, approval receipt, provider event reference and outcome.
- **Control:** none needed.
- **Pass:** all of the above. If E1 fails, no other result is meaningful, so stop and fix.

#### E2: Hijacked agent with a poisoned invoice

- **Claim:** 5.
- **Position:** P1 (the injection arrives through the agent's input).
- **Steps:** give the agent the invoice carrying a hidden instruction to refund a large amount to an attacker account. Run it twice: (a) the approver denies; (b) the approver approves, simulating a fooled human.
- **Expected (a):** a sealed `intent` marked pending with the invoice listed as an untrusted input in context; a `blocked` entry recording the denial; no provider event; no findings.
- **Expected (b):** intent, `approval`, outcome and the provider event all present and consistent; reconciler agrees; the evidence bundle shows the invoice hash and trust label in the intent's context, so an investigator can trace the cause.
- **Control:** a plain log records the refund call but not the delegation chain, approval or input lineage; show what an investigator could and could not reconstruct from it.
- **Pass:** every named field is present and verifies offline. State that the test shows the *record is complete*, not that the injection was prevented.

#### E3: Ledger-host rewrite

- **Claim:** 1.
- **Position:** P3.
- **Steps:** after a refund has been witnessed, gain a shell on the ledger host. Delete the refund intent and outcome from the database, rebuild the Merkle tree, append new innocuous entries, and produce the best forgery possible: a new checkpoint of larger size. If the attacker has no signing key, sign with a self-generated key; as a second variant, sign with a copy of an old epoch certificate and key obtained from a previous epoch export (which must fail because past epoch keys do not exist). Offer the forged checkpoint to the witnesses.
- **Expected alarms:** `WITNESS_REFUSAL` from every witness within the time budget.
- **Expected verdicts:** the verifier marks the deleted range `MISSING` or `TAMPERED` against the last witnessed checkpoint; the reconciler raises `UNRECORDED_ACTION` for the refund still present in the provider's event log.
- **Offline evidence:** the bundle built from the witnesses' stored checkpoints and the pre-attack ledger copy verifies; the bundle built from the rewritten ledger fails.
- **Control:** the plain log accepts the rewrite with no alarm.
- **Pass:** all three witnesses refuse; no quorum is reached; all verdicts and findings as listed.

#### E4: Compromised gateway logs one thing and sends another

- **Claim:** 2 and 3.
- **Position:** P2.
- **Steps:** with gateway control, run four attacks in sequence. (i) Seal an intent for a small refund and forward a large-refund body together with the small body's attestation. (ii) Seal an intent for a large refund honestly and then alter the logged digest in the ledger afterwards. (iii) Skip sealing entirely and forward a request straight to the provider using the gateway's brokered credentials. (iv) Ask the signer to attest a digest that does not match the sealed intent.
- **Expected:** (i) provider recomputes the body digest, rejects, records `ATTESTATION_BODY_MISMATCH`, alarm fires. (ii) detected as in E3 (altered entry cannot be re-signed). (iii) the provider records an event without a valid attestation: `UNATTESTED_ACTION`, and if enforcement mode is on, the request is rejected. (iv) the signer refuses; the refusal is logged.
- **Control:** a gateway-only logging design (no attestation, no signer rules) accepts all four.
- **Pass:** every variant is rejected or flagged as stated; none results in a provider effect without a matching verified ledger entry.

#### E5: Bypass from the agent network

- **Claim:** 2.
- **Position:** P1.
- **Steps:** from the agent runtime, try to reach the provider directly, then external hosts. Then deliberately loosen the egress rule and repeat.
- **Expected:** with egress control on, connections fail and nothing reaches the provider. With the rule loosened, requests reach the provider, which records `UNATTESTED` events; the reconciler raises `UNATTESTED_ACTION` within the time budget.
- **Control:** without egress control and enforcement, the direct calls succeed silently.
- **Pass:** both layers behave as stated, showing the first line of defence and the safety net separately.

#### E6: Witness outage and availability attacks

- **Claim:** 2 and 3.
- **Position:** P4 or P5.
- **Steps:** (a) stop one witness; (b) stop a second witness; (c) block traffic between ledger and witnesses with the witnesses still alive; (d) restore everything. Throughout, run the honest workload with both high-risk and low-risk calls.
- **Expected (a):** a witness-health alarm; quorum still met; normal operation. **(b):** `CHECKPOINT_STALL` and `HEARTBEAT_STALL` escalating; high-risk actions fail closed with `blocked` entries; low-risk reads continue and are queued with a `gap` marker when sealing is impaired; the unverified window grows and is reported. **(c):** same as (b). **(d):** witnesses catch up through gossip, the unverified window shrinks, entries become `VERIFIED`, the `gap` marker is visible in the ledger.
- **Control:** a single-logger setup keeps running with no indication that anything is wrong.
- **Pass:** the fail-closed and fail-open behaviours match section 13.7 exactly and recovery completes without ledger corruption.

#### E7: Split view

- **Claim:** 1.
- **Position:** P3 combined with control of what each witness sees.
- **Steps:** make the ledger present checkpoint A to witness one and a different but internally valid checkpoint B (same size, different root) to witness two.
- **Expected:** gossip detects differing roots for the same size; `SPLIT_VIEW` fires; no quorum for the contested checkpoint.
- **Control:** a design with a single witness cannot detect it.
- **Pass:** `SPLIT_VIEW` within the time budget and no cosigned checkpoint for the conflicting size.

#### E8: Stored-ledger fuzzing

- **Claim:** 1.
- **Position:** P3.
- **Steps:** take a snapshot of a ledger covered by witnessed checkpoints. For several thousand iterations, flip a random byte (or random bits) in a random stored location, including signatures, hashes, sequence numbers, timestamps, payload references and certificates; run the verifier; restore. Also run structure-aware mutations: swap two entries, duplicate an entry, truncate, splice in an entry from another log.
- **Expected:** every mutation to witnessed content yields a non-`VERIFIED` verdict on the affected range.
- **Pass:** 100% detection. Any miss is a real defect: capture the mutation, classify the cause, and fix or document it as a limit.

#### E9: Load and performance

- **Claim:** supports claim of practicality; produces report numbers.
- **Steps:** with the load tool, ramp traffic through several rates while attacks E3 and E6 are not running; repeat once with BlackBox bypassed to obtain a baseline.
- **Measure:** added latency (p50, p95, p99); throughput in entries per second; time from sealing to witnessed checkpoint; unverified-window length; storage per entry; proof size and verification time as the ledger grows.
- **Pass:** no sequence gaps, chain breaks or signer errors under load; high-risk waits stay under the timeout; results recorded in a table and graph. This test passes on integrity, not on speed: speed is reported, not judged.

#### E10: Approval abuse

- **Claim:** 5.
- **Position:** P1 and P2.
- **Steps:** attempt (i) self-approval by the requester; (ii) an approval receipt for the original arguments reused on altered arguments; (iii) a reused receipt nonce; (iv) an expired receipt; (v) a receipt signed by an unregistered key.
- **Expected:** each attempt is rejected and recorded as a `blocked` entry stating the reason; no provider event occurs.
- **Control:** an approval flow based on a plain flag in a database accepts (ii) and (iii).
- **Pass:** all five rejected and sealed; the offline evidence shows the denials.

#### E11: Key compromise and rogue epochs

- **Claim:** 1 and 3.
- **Position:** P2 with a stolen current epoch key.
- **Steps:** (i) with the current epoch key, craft entries outside the signer (directly into the ledger) and sign them; (ii) try to sign entries after the epoch has rolled over using the stolen key; (iii) try to introduce an epoch with a non-contiguous id, or one certified by an unknown intermediate; (iv) revoke the intermediate with a root-signed notice and confirm later epochs under it are refused.
- **Expected:** (i) entries inserted outside the signer's sequence rules are caught by the sequence, chain and witness checks (they conflict with the signer's actual chain and the heartbeat counts); (ii) the verifier rejects signatures from an expired epoch window; (iii) witnesses and verifier reject the rogue epoch; (iv) revoked certification is refused after the effective time.
- **Control:** a design with one long-lived signing key accepts all of (i) to (iii) indefinitely.
- **Pass:** the damage of a stolen epoch key is demonstrably limited to ordered appends within the epoch, as claimed.

#### E12: Tool poisoning

- **Claim:** 5.
- **Position:** P2 or a malicious tool server.
- **Steps:** between two sessions, silently change a tool's description or schema served to the agent.
- **Expected:** the recorded tool-definitions hash changes; `TOOL_DEF_CHANGE` fires; the new hash appears in subsequent intents so an investigator can see exactly when the change took effect.
- **Control:** no plain-log setup records tool definitions.
- **Pass:** alarm within the time budget and the hash change is visible in the evidence.

### 29.5 Recording and reporting results

Every test run records: the test id and attack variant; the date and component versions; the alarms observed with timestamps; verdicts and findings; the offline-verification result; the control result; and any anomalies.

**Results table** (one row per test and variant): attack, position, expected alarm, observed alarm, detection time, expected verdict, observed verdict, expected finding, observed finding, offline evidence valid, control result, outcome.

**Outcome classification:**
- **PASS:** all expected observations occurred within budget.
- **FAIL (bug):** the design promises detection but the implementation misses it; fix and rerun.
- **FAIL (design gap):** the design itself does not cover the attack; document it as a limit and add it to the report's limitations.
- **INCONCLUSIVE:** environment problem (clock skew, network fault); rerun.

**Reporting rules:** include failures; include the control results; state witness independence level and which provider log is a mock; report the three repeated runs and any disagreement between them.

### 29.6 Exit criteria for "BlackBox v4 is complete"

1. E1 through E12 each executed three times from clean snapshots with consistent results.
2. E1 passes; E2, E3, E4, E5, E7, E10, E11 and E12 pass with controls demonstrating that the attacks work against a plain setup.
3. E6 shows fail-closed and fail-open behaviour exactly as specified, with clean recovery.
4. E8 shows 100% detection, or every miss is documented and understood.
5. E9 produces the performance table with no integrity errors.
6. Every claim in section 2.1 maps to at least one passing test; any claim without a passing test is removed or weakened in the report.
7. Offline evidence verification succeeded on a machine with no connection to the deployment, and, once built, the second independent verifier produces identical verdicts.

### 29.7 Build-time gate tests

These short tests run during the build and decide whether the next stage may begin (the decision gates of section 22).

- **G1: smart attacker on the bare library (end of Stage 1).** Build ten sealed entries. Edit entry five, then recompute the hashes of entry five and everything after it so the chain looks valid. Expected: the verifier returns `TAMPERED` at entry five because the attacker cannot re-sign. As a control, show that a bare hash chain without signatures accepts the forgery. Variant: also delete entry seven; expected `MISSING`.
- **G2: Merkle exhaustive correctness (Stage 1).** Pass the RFC 6962 vectors. For every tree size from 1 to at least 200, every inclusion proof must verify and every consistency proof between every pair of sizes must verify; flipping any single bit in any proof must cause failure.
- **G3: witness refuses a rewrite (end of Stage 2).** A witness has cosigned size 10. The ledger offers a rebuilt tree of size 12 whose first ten entries differ and which is correctly signed. Expected: no consistency proof exists, the witness refuses, `WITNESS_REFUSAL` fires. Control: with no witness, the rewrite is silently accepted.
- **G4: attestation binding (end of Stage 3).** Seal an intent for a small body and attempt to forward a different body with the resulting attestation. Expected: the provider's recomputed digest differs and the request is rejected. Also attempt to obtain an attestation for a digest not in any sealed intent; expected: the signer refuses.

### 29.8 Limits of this suite

- The suite shows that BlackBox detects the attacks written for it. Fuzzing (E8) and ablation (section 23) widen coverage but cannot prove that no undetected attack exists.
- Because the mock provider and (possibly) the witnesses are run by the tester, independence is partly simulated. Results on reconciliation and witness quorum are strongest when the provider log and at least one witness are genuinely operated by a different party or on a genuinely separate network.
- Timing results depend on the chosen parameters of section 24; changing them changes expected budgets.
- The suite does not evaluate whether agent decisions are correct or whether the injection was prevented; it evaluates whether the record is complete, tamper-evident and verifiable.

---

*End of BlackBox v4.*
