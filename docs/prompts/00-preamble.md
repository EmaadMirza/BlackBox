# Stage 3 implementation preamble

These decisions are fixed for Stage 3 and must not be reopened during
implementation. Where the canonical specification defines a requirement more
strictly, the specification wins and the conflict must be reported in the
relevant implementation or acceptance report.

## Fixed Stage 3 decisions

- **Attestation transport:** HTTP header `X-BlackBox-Attestation` carrying JSON
  `{attestation, epoch_cert, intermediate_cert}`. The provider is configured
  with the pinned ROOT public key only. It verifies the certificate chain,
  signature, signing label, `log_id`, and the 30-second expiry. It then
  recomputes SHA-256 over the exact raw request-body bytes received and compares
  that value with the attested digest. It never trusts a digest supplied by the
  gateway or agent.
- **Provider state:** the provider has its own state directory containing an
  append-only, hash-chained, fsynced JSON-lines event log and an idempotency
  store. It shares no storage with the gateway, signer, or ledger.
- **Provider enforcement:** enforcement is ON by default. It may be OFF only
  in explicit control or baseline tests.
- **Signer boundary:** the gateway never holds signing keys. It reaches the
  signer only through the authenticated signer API. The signer is the only
  sequencer. Amounts are integer minor units and never floats.
- **Payload commitments:** compute
  `SHA-256(salt || value)` with a random 32-byte salt. The ledger stores only
  commitments; values and salts remain in the payload store.
- **Approvals:** an approval receipt binds the intent sequence, arguments
  commitment, ten-minute expiry, and a single-use nonce. Approver public keys
  come from a registry; the approver must differ from the requester; the nonce
  store is durable.
- **High-risk path:** seal the intent, request an on-demand checkpoint, then
  wait up to 10 seconds (using an injected clock in tests) for WITNESSED
  coverage. If coverage is not obtained, seal a blocked entry and fail closed.
  High-risk actions never use the local queue.
- **Low-risk path:** forward immediately and mark the action `UNVERIFIED` until
  it is covered by a witnessed checkpoint.
- **Execution boundary:** all Stage 3 services run in-process with real
  PostgreSQL behind the ledger. Separate application instances and state
  directories model separate hosts. Containers, Compose, and real network
  isolation are deferred.
- **Provider independence:** the provider is a mock operated by the same team.
  Every report must explicitly state **reduced independence**.

## Spec conflict record

The canonical specification agrees with the substantive decisions above on
provider-side raw-body digest recomputation, provider-owned event state,
authenticated certificate-chain verification, payload commitments, approval
bindings, integer amounts, high-risk witnessed coverage, and the high-risk
fail-closed/local-queue distinction.

The specification describes the attestation transport as a header carrying the
attestation but does not freeze the exact header name or the complete JSON
envelope. The fixed `X-BlackBox-Attestation` envelope above resolves that
interface ambiguity for Stage 3.

The specification describes the provider as a separate deployment and
independent downstream boundary. The fixed Stage 3 test profile keeps the
provider as a same-team mock with separate state and credentials; this is a
test limitation, not a claim of production independence. Reports must say
**reduced independence** and must continue to defer real third-party/provider
independence and real network/container validation.
