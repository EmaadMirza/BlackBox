# BlackBox agent instructions

Read the architecture section of `BlackBox_Skills.md` first, then the component skill.
The canonical implementation reference is `docs/BlackBox_v4.md`; the original root
copy is preserved. Keep copies consistent if the user later authorizes spec edits.

## Current scope
Stage 1 is authorized: pure core library, offline verifier, CLI and tests. Follow
`docs/stage1-protocol.md` for concrete choices left unspecified in the prose spec.
The user authorized proceeding with these documented choices. Do not modify the
original spec. Stage 2 services remain stubs until the next authorized stage.
Tests/_dev_keys.py and tools/ceremony.py are the only Stage 1 key-generation sites;
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
Validate all three Compose files. G1/G2 precede service implementation; G3 precedes
building gateway behavior; G4 precedes evaluation. XFAIL does not pass a gate.
Record actual validation outcomes and unresolved spec ambiguities. No stage advances
on a placeholder, missing tool, skipped test, or unverified security claim.
