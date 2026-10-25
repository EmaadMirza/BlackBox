# Witness protocol amendment

This amendment records the fixed witness decisions used by the Stage 2 witness
implementation. The repository's original witness section describes the same
consistency, certificate, monotonicity and refusal model, but does not define
the HTTP envelope or durable commit ordering below.

- `GET /v1/state?log_id=` returns the stored `tree_size`, `root_hash`, and
  `epoch_id` for the configured log.
- `POST /v1/checkpoint` accepts `{log_id, checkpoint, from_size,
  consistency_proof}`. The submitter supplies the proof; the witness verifies
  it against its own stored root and the new root. The witness makes no
  outbound network calls.
- The witness is configured with the pinned root, signed witness-set document,
  intermediate certificates and epoch certificates. It trusts no other key
  material.
- A cosignature is computed first; a temporary-file/fsync/replace/directory-
  fsync commit stores the checkpoint and produced cosignature; only then is the
  cosignature released. Identical resubmission returns the stored cosignature.
- Stable refusal codes are: `rollback`, `root_mismatch`, `bad_proof`,
  `proof_required`, `bad_signature`, `bad_cert_chain`, `wrong_log`,
  `epoch_regression`, `malformed`, and `witness_unavailable`.
- Every refusal except `malformed` is appended to the witness's own
  append-only hash-chained evidence log.
- Development witness private keys are persistent files with mode `0600`.
  Production custody is HSM/KMS. Witnesses sign only cosignatures.
- Witnesses use independent file stores. PostgreSQL remains a ledger-only
  dependency. Separate hosts are represented by separate app instances and
  state directories.
