# Scaffold limitations and specification ambiguities

Stage 1 core, Stage 2 signer, ledger and witness foundations have implemented,
locally verified behavior. Stage 3 prototype is authorized with a limited scope
(see `AGENTS.md` § Current scope). G4 and acceptance tests E1–E12 remain
expected-failure placeholders; an xfail test never counts as a passed gate.

## Conflicting requirements requiring a later decision

1. **Key custody:** architecture skill invariant 1 says only `services/signer` touches
   private signing keys, including in tests. Spec §7.1 assigns keys to independent
   witnesses, approver devices and an offline root ceremony; skills also require
   witness-owned keys. There are no key imports, key generation or signing operations
   in this scaffold. Mounts are empty placeholders. Opaque signing callbacks in core
   represent future interfaces only; they do not resolve ownership.
2. **Signer ingress:** §6.2 says signer accepts only gateway connections, while §10.3
   has ledger supply signer tree state. The request relay/authentication design is
   unspecified. Shared Compose networks do not enforce directed access. Only gateway
   has a localhost host port; this is not proof that peers cannot reach signer.
3. **Ledger writes:** signer-only sealed-entry append (§6.2) must coexist with witness
   cosignatures, approval records, alarms and reconciler findings (§10.1). Writer
   identities and record-specific authorization are unspecified. SQL permissions
   are not caller authentication. Reconciler must remain unable to modify entries.
4. **Provider access:** §6.2 restricts provider traffic to gateway, while §15 requires
   reconciler access to its read-only feed. Compose provides that route but does not
   implement endpoint-specific authorization.

## Incomplete wire and interface definitions

- §8 describes fields without defining exact JSON spellings, nullability, version
  type, timestamp grammar enforcement, signature envelopes, or latency unit. Python
  snake_case fields and integer latency are provisional declarations, not a frozen
  wire format. Context/receipt references can be explicitly null; other listed
  fields are required for the scaffold. Web-lane applicability needs specification.
- Intent `pending` state, denial reason, approval receipt embedding/reference,
  automated-action payload, tool snapshot/session format and breakglass details are
  not specified. Their entry stubs deliberately do not invent fields. They cannot
  yet represent the full required evidence of E2/E10/E12.
- Epoch certificate fields come from §7.3; gap fields come from §10.5. Intermediate
  certificates, revocations, signature label bytes, concatenation framing, genesis
  previous-hash constant, integer range and format version are not fully specified.
- SealedEntry's body/signature envelope is provisional. Whether entry_hash is
  persisted on wire, the unsigned/signed checkpoint split, canonicalization of
  HTTP bodies, retry markers and approval domain-separation log context need a
  decision before Stage 1. Declaration-level strictness does not implement NFC,
  RFC 3339, base64url, hash-prefix checks, bounds or cryptographic verification.
- Signer endpoint paths/status codes, rejection payloads and interim bearer auth
  are defined in [signer-http-contract.md](signer-http-contract.md); `/health` and
  shared bearer-auth enforcement are implemented, while operation routes remain
  unimplemented. Other endpoint contracts, bundle
  manifest, pinned-key JSON format and policy rule grammar/precedence remain
  placeholders. CLI names are fixed by §17.3 but argument parsing is unimplemented.
- Signer chain state records `log_id` and refuses uncertain commits, missing
  initialized state and legacy/corrupt state. The signer also persists a versioned,
  signer-owned outcome index beside chain state and uses a shared pre-commit marker
  so an interrupted state/index replacement fails closed. Recovery is still
  fail-closed: there is no operator rebuild protocol, real ledger-backed
  `HistorySource`, power-loss injection evidence, or transaction spanning signer
  state, the outcome index and the ledger. The current history source is a test-only
  protocol/fake and is not a network or ledger implementation.
- A crash inside the state+index commit window blocks the signer until an operator
  recovers it; future hardening could store old/new file hashes in the marker so the
  signer can finish the commit automatically.
- The proposed Option D issuance journal protects against crashes and operator
  error only, not a malicious signer host; witness quorum remains the defence
  against journal rewriting or host equivocation.
- Task R's development directory adapter loads the intermediate private key into
  the signer process; production must replace it with KMS/HSM custody. Python
  memory cannot guarantee private-key zeroization; key zeroization remains unproven.
- K2b removes the idle-key-retention limitation through a cooperative `tick()` that
  is serialized with `seal()`. It rolls expired epochs before releasing the new
  runtime and emits a heartbeat after the configured interval. A thin runner is
  intentionally scheduler-driven rather than thread-based in this scope.
- During rollover, `epoch_end` carries the nominal window-end timestamp rather than
  wall-clock signing time; the old key therefore signs one final entry after
  wall-clock expiry. A lost rollover response means entries were issued but
  undelivered; Task E2b's issuance journal and Task L ledger delivery must reconcile
  that case. Power-loss recovery, HSM/KMS custody, and Docker deployment behavior
  remain unverified. Lost-response entries and durable reconciliation remain pending
  E2b. K2c removes the frozen-object mutation used by the earlier tick path: after
  commit, the old runtime is released normally, while the manager's explicit
  `destroy_current_key()` guard remains available for signer-level key invalidation.
- A1 attestation does not require a persisted prior-attested-digest record for
  uniqueness: the digest is cryptographically bound to the sealed intent. After a
  restart, the signer may re-issue an attestation for that same digest with a fresh
  expiry. The real witnessed-checkpoint source is not implemented, so high-risk
  attestations fail closed except through test-only evidence; provider-side
  attestation verification remains pending.
- A1b report: `attest()` obtains the intent from the authenticated history source
  and requires a matching current-process sealed-intent record. That sealed-intent
  map is not persisted or rebuilt across signer restart, so an intent sealed before
  restart cannot currently be attested after restart; this is a known gap.
- K1a defaults: the ledger supplies checkpoint tree metadata; the signer checks it
  against its own durable last-sealed state but does not rebuild the Merkle tree.
  Root correctness is delegated to witnesses and the offline verifier. Pure
  checkpoint request rules do not implement HTTP, persistence, or signing.
- K1b implements signed checkpoint issuance and persists the last checkpoint in a
  versioned atomic checkpoint sidecar protected by the signer commit marker. The
  signer still does not rebuild Merkle trees; ledger root construction and witness
  consistency remain external responsibilities. Real witness and ledger services,
  HSM/KMS custody, and production power-loss validation remain unproven.
- K1c now verifies witnessed checkpoint evidence locally before allowing a
  high-risk attestation: pinned root/intermediate/epoch certificates, witness-set
  authentication, distinct witness cosignatures, quorum, log binding, and intent
  coverage are checked. No network or witness service is used; production delivery
  of this evidence to the signer is deferred to Task W.
- K2a adds a signed `POST /heartbeat` operation. It claims only the durable signer
  state, does not consume the entry rate quota or advance the chain, and is checked
  against the current epoch window. The witness-side stall/mismatch service remains
  unimplemented; the pure heartbeat/checkpoint comparison helper is covered only by
  unit tests.
- Tick-produced rollover entries and sealed entries are retained in the signer
  outbox and delivered at least once in sequence by the cooperative delivery
  worker. The outbox migration is manual: pre-outbox entries may already have
  been lost, and migration creates an empty queue only after an operator proves
  the supplied ledger head equals the durable signer head.
- L2b-2 now proves signer-to-ledger delivery against a real local PostgreSQL
  database, with an in-process transport calling the FastAPI ledger app. It does
  not prove a real network deployment, Compose startup, or cross-process HTTP.
  The integration bundle is exported from PostgreSQL rows and verified offline.
- L3a persists append-only right-frontier snapshots and recomputes each log from
  entries at ledger startup in O(N) time. A mismatch degrades checkpoint service
  with `merkle_frontier_mismatch` while entry reads remain available; checkpoint
  scheduling and witness consistency are still unimplemented.
- `services/signer/heartbeat.py:run()` is now a thin async loop over `TickRunner`.
  It does not create threads or own signer concurrency; deployment remains
  responsible for invoking it with the single signer instance.
- Source wording about expired epoch keys must distinguish historical verification
  of valid in-window signatures from use of an old key for new out-of-window data.
- E6's partition model does not specify whether heartbeat traffic is also blocked;
  checkpoint stalls alone do not inherently imply heartbeat stalls.

## Deployment and storage

- Main stack networks are internal. Provider runs in a separate Compose project,
  shares the downstream network only, and has a separate database and credentials.
  On one machine both provider independence and witness independence are reduced.
  The provider is always described as a mock operated by the local tester.
- Three witness containers have separate storage and empty key volumes. Real keys,
  mTLS, pinned roots, independent administrators and remote provisioning are absent.
  The remote witness template needs an authenticated TLS ingress and ledger route.
- App database logins are intentionally unprovisioned; migration creates NOLOGIN
  capability roles only. The database admin exists for initialization, and its
  credentials must never be used by a service. Provision least-privilege logins
  before runtime implementation; provider tables/login also remain unimplemented.
- Initial migration is intended for a fresh database and has not been executed.
  It adds append-only frontier snapshots for §10.2. Triggers also reject TRUNCATE;
  database owners/superusers can bypass controls. Byte columns preserve canonical
  evidence alongside JSONB; JSONB alone cannot preserve signed serialization.
- Read-only containers' data-volume ownership needs provisioning before runtime.
  Agent model configuration is intentionally absent. Stage 5 anchor has no public
  egress in the main scaffold and requires explicit future deployment design.
- Sample thresholds are illustrative, not spec defaults. Rate cap, queue capacity,
  checkpoint entry threshold and provider caps require deployment configuration.
- No HSM/TPM/KMS guarantees, key erasure guarantee, prompt-injection prevention,
  successful acceptance scenario, or production readiness is claimed.

## Known limitations — Stage 3 prototype exclusions

The following items are explicitly out of scope for the current Stage 3 prototype.
They are not built, not tested, and must not be claimed as passing. Each remains a
documented limitation until a future stage authorizes it.

1. **Docker/Compose validation (DK2, DK3).** The three Compose files
   (`docker-compose.yml`, `docker-compose.provider.yml`,
   `deploy/witness-host/docker-compose.yml`) are not validated. Container startup,
   network isolation, volume ownership, and cross-process HTTP behavior are unproven.
2. **Acceptance scenario E5 (agent-network bypass).** Requires Docker egress
   control and container-level network enforcement; cannot be tested without
   Docker.
3. **Acceptance scenario E9 (load/performance).** Requires a fully deployed stack
   under load (locust/wrk); integrity-under-load and latency measurement are
   deferred.
4. **Acceptance scenario E11 (stolen epoch key / rogue epoch / HSM).** Requires
   HSM/KMS custody to demonstrate bounded forward forgery; process-level key
   custody cannot prove key zeroization or hardware isolation.
5. **HSM/KMS/TPM key custody and key zeroization.** Python process memory cannot
   guarantee private-key zeroization. Production custody requires HSM/KMS/TPM
   integration that is not implemented.
6. **Anchor service (`services/anchor`).** OpenTimestamps and public Git
   anchoring are optional and not on the critical path; all three endpoint stubs
   remain `NotImplementedError`.
7. **Task E full recovery.** Durable recovery quarantine, startup-enforced
   recovery anchor, and the two recovery outcomes (same-log continuation,
   new-log restart) described in `docs/task-e-addendum.md` are not implemented.
   Recovery remains fail-closed with manual operator intervention.
8. **Task E2b (issuance journal).** The crash/lost-response journal for
   signer-to-ledger reconciliation is not implemented. Lost rollover responses
   and durable reconciliation remain pending.
9. **Task R (automated operator rebuild tool).** No rebuild command exists.
   Recovery from a pre-commit marker requires the deployment's approved recovery
   tooling or a controlled maintenance script, as documented in
   `docs/task-c-recovery.md`.
10. **mTLS and directional caller-/operation-specific authorization.** The shared
    bearer token is an interim transport credential. Network membership is not
    authentication. The gateway/ledger ingress conflict (§6.2 vs §10.3) is not
    resolved by this prototype.
11. **Power-loss injection tests.** No power-loss, filesystem-failure, or
    device-failure injection has been performed against the signer filesystem or
    PostgreSQL. Crash-point coverage is analysis-based (`docs/task-c-recovery.md`),
    not empirical.

## Security Claims and Test Mapping

### Verified Claims

| Claim | Description | Proving Tests |
| --- | --- | --- |
| **Tamper Evidence & History Integrity** | Any mutation or deletion in sealed ledger history is detected and refused. | `tests/gates/test_g1_tamper.py`<br>`tests/gates/test_g2_merkle.py`<br>`tests/gates/test_g3.py`<br>`tests/gates/test_g3_witness_refusal.py`<br>`tests/acceptance/test_e03.py`<br>`tests/acceptance/test_e08.py` |
| **Witness Quorum & Split-View Defense** | Checkpoints require distinct witness quorum (2/3); conflicting roots for same tree size trigger `SPLIT_VIEW`. | `tests/acceptance/test_e06.py`<br>`tests/acceptance/test_e07.py`<br>`tests/unit/test_w4_gossip.py`<br>`tests/unit/test_witness_http_processor.py` |
| **Attestation Binding & Body Integrity** | Provider recomputes raw request-body digest and rejects mismatched attestations; signer refuses unsealed intents. | `tests/gates/test_g4.py`<br>`tests/acceptance/test_e04.py`<br>`tests/unit/test_attestation.py` |
| **Approval Guardrails & Nonce Freshness** | Self-approvals, altered argument commitments, reused nonces, and expired keys/receipts fail closed as `blocked` ledger entries. | `tests/acceptance/test_e02.py`<br>`tests/acceptance/test_e10.py`<br>`tests/unit/test_po2_approval.py` |
| **Tool Definition Integrity** | Unauthorized modification of session tool definitions triggers `TOOL_DEF_CHANGE` and fails closed without provider effect. | `tests/acceptance/test_e12.py` |
| **Independent Offline Verification** | Pinned public keys verify Merkle inclusion, hash chain continuity, and certificate chains without connecting to the deployment. | `tests/acceptance/test_e01.py`<br>`tests/unit/test_verifier.py`<br>`tools/verifier/` |
| **Reconciler Verification** | Read-only join between ledger and provider event logs flags `UNRECORDED_ACTION`, `UNATTESTED_ACTION`, `PHANTOM_OUTCOME`, `ORPHAN_INTENT`, `ARGS_MISMATCH`. | `tests/acceptance/test_e01.py`<br>`tests/acceptance/test_e03.py`<br>`tests/acceptance/test_e04.py` |

### Not Claimed (Out of Prototype Scope)

The following claims are **not proven** and are **not claimed** by this prototype:

| Unproven Claim | Reason / Missing Infrastructure | Tracked Acceptance Scenario (XFAIL) |
| --- | --- | --- |
| **Network Egress Isolation** | Requires Docker/Compose container egress control and firewall enforcement. | `tests/acceptance/test_e05.py` |
| **Performance Under Load** | Throughput, latency percentiles (p50/p95/p99), and integrity under stress require full load-test infrastructure. | `tests/acceptance/test_e09.py` |
| **Hardware Key Custody & Zeroization** | Bounded forward forgery under key theft requires HSM/KMS/TPM hardware custody; Python memory cannot guarantee key zeroization. | `tests/acceptance/test_e11.py` |
| **Public Anchor Durability** | OpenTimestamps and public Git anchoring (`services/anchor`) are not implemented. | Deferred to Stage 5 |
| **Crash / Lost-Response Reconciliation** | Signer-to-ledger issuance journal (Task E2b) and automated operator rebuild tool (Task R) are not implemented. | Recovery remains fail-closed |
