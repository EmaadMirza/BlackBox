# BlackBox agent instructions

Read the architecture section of `BlackBox_Skills.md` first, then the component skill.
The canonical implementation reference is `docs/BlackBox_v4.md`; the original root
copy is preserved. Keep copies consistent if the user later authorizes spec edits.

## Current scope
Stage 1 (core library, offline verifier, CLI, tests) and Stage 2 (signer, ledger,
witness in-process) are complete. Follow `docs/stage1-protocol.md` for concrete
choices left unspecified in the prose spec. Do not modify the original spec.

Stage 3 is now authorized, limited to this prototype scope:
- Gateway: minimal pipeline (authenticate, normalize, seal intent, forward, seal
  outcome). No web lane, no MCP adapter.
- Provider mock: body-digest enforcement, attestation verification, event log,
  enforcement mode, idempotency and per-call limits.
- Payload store: commitment storage and resolution.
- Signer `/checkpoint` HTTP route: wire the existing pure checkpoint rules to HTTP.
- Approval service: receipt verification, registered-key check, nonce uniqueness,
  expiry, approver-≠-requester, args-commitment match.
- Reconciler: join ledger entries with provider event feed, emit findings
  (UNRECORDED_ACTION, UNATTESTED_ACTION, PHANTOM_OUTCOME, ORPHAN_INTENT,
  ARGS_MISMATCH, RESULT_MISMATCH).
- Witness HTTP processor: expose the existing checkpoint-verification logic over
  HTTP so witnesses can be called by the ledger fan-out.

Explicitly out of scope for this stage (do not build; each is recorded in
`docs/limitations.md` § Known limitations):
- Docker/Compose validation (DK2, DK3).
- Acceptance scenarios E5 (agent-network bypass), E9 (load/performance),
  E11 (stolen epoch key / HSM).
- HSM/KMS/TPM key custody and key zeroization.
- Anchor service (`services/anchor`).
- Task E full recovery (durable quarantine, recovery anchor enforcement).
- Task E2b (issuance journal for lost-response reconciliation).
- Task R (automated operator rebuild tool).
- mTLS and directional caller-/operation-specific authorization.
- Power-loss injection tests.

Tests/_dev_keys.py and tools/ceremony.py are the only key-generation sites;
ephemeral keys may be passed into library signing operations. This is the user's
explicit temporary deviation from signer-only key custody.

## Ownership and invariants
- All schema, canonicalization and cryptographic logic belongs to `libs/blackbox_core`.
  Services and offline verifier share it. Core has no networking dependencies.
- Only `services/signer` may handle private signing keys under the current skill rule.
  The Stage 1 test/ceremony exception above takes precedence; production witness,
  approver and offline custody remain Stage 2/3 deployment questions.
- Signer is a single writer and runs exactly one Uvicorn worker.
- Signed structures reject unknown fields and floats; amounts use int/string.
- Signatures are domain separated by structure label and log identity.
- Provider recomputes the received-body digest; agent has no provider credentials.
- High-risk actions fail closed; any low-risk queue recovery records a gap.
- Append-only SQL is a speed bump, not the integrity boundary.
- Verifier is offline and trusts only externally pinned public keys.
- Every security claim maps to G1–G4 or E1–E12; do not claim scaffold tests prove it.

## Checks and stage gates
Use `uv sync --frozen --extra services --extra dev`, then `make lint` and `make test`.
G1/G2 precede service implementation (passed). G3 precedes building gateway
behavior (passed, in-process + local PostgreSQL). G4 precedes evaluation; it is
the current target gate for Stage 3 prototype scope. XFAIL does not pass a gate.
No stage advances on a placeholder, missing tool, skipped test, or unverified
security claim. Do not weaken any existing G1–G3 test.
