# Stage 1 protocol profile

These implementation decisions fill gaps in the prose specification under the user's
instruction to proceed. The original specification is unchanged.

- Format version is the string `4`; global sequence and epoch ids begin at zero.
- Hashes use `sha256:` plus 64 lowercase hex digits. Genesis prev_hash is 32 zero bytes.
- JCS uses the existing rfc8785 dependency. BlackBox preprocessing NFC-normalizes
  all keys/string values, rejects normalization collisions, duplicate raw JSON keys,
  non-finite numbers, all float tokens, lone surrogates and integers outside ±(2^53−1).
  This is a deliberately narrower input profile than general JCS.
- Labels are ASCII `BLACKBOX:v4:<type>\0`. Signing context concatenates that label,
  raw 32-byte decoded log_id, and payload. log_id hashes root-public-key bytes plus
  the UTF-8 NFC log name. Entry payload is the raw entry hash (§8.5); other signed
  payloads are canonical unsigned JSON (§5.3). This resolves the prose conflict.
- Signed objects include a signature field excluded from their signing payload.
  Sealed entry envelope is {body, signature}; entry hash is recomputed, not trusted.
- Timestamps use exactly UTC Z with three fractional digits. Sub-ms values are
  rejected, not rounded. Epoch/certificate windows are half-open [from, until).
- Version-one offline bundles contain a complete prefix beginning at seq 0; partial
  range export is deferred. Witness-set version 1 only; rotations require Stage 2
  policy rather than trusting arbitrary root-signed historic sets.
- G1 uses ten total entries, seq 0..9, including two epoch starts and the first epoch end; edits
  target seq 5 and deletion targets seq 7. A valid live final epoch may remain open.
- Test/ceremony key generation is the explicitly authorized Stage 1 exception to
  signer-only custody. Library code accepts signing objects/callbacks, never generates keys.

## Concrete fields and signature envelopes

Schemas keep the scaffold snake_case names. `latency` is integer milliseconds.
Specialized fields: intent `status` (pending/ready); blocked `reason`; approval
`receipt`; action `action_name`, `reason`, `target_reference`; tool_defs `session_id`,
`definitions_hash`, `payload_reference`; breakglass `principal_id`, `reason`,
`material_reference`. Outcome `retry` is false unless explicitly recording a same-key
retry. Nullable context/receipt references are explicit JSON nulls.

Epoch certificates and all other independently signed structures include `log_id`.
Intermediate certificates contain `intermediate_id`, `public_key`, validity times
and signature. Revocations contain intermediate id, effective time and signature.
Certificate identifiers hash the complete signed certificate. Signatures may be
empty only while constructing an unsigned object; verification never accepts empty
signatures. Epoch start carries the complete signed certificate.

NFC preprocessing intentionally changes U+FB33 in the RFC sorting example; tests
check both the unmodified RFC/JCS result and the BlackBox preprocessing result.
RFC 6962 has no normative numerical test-vector appendix. The committed numeric
vectors are from Google's Certificate Transparency reference tests, attributed in
`tests/vectors/rfc6962.json`; they are not represented as text from the RFC itself.


## Offline trust and limitations

Pinned keys include log_id, log_name, root_public_key, witness_public_keys, optional
minimum_tree_size and known root-signed revocations. A trusted minimum prevents
rollback below a previously observed size. An offline verifier cannot discover a
new checkpoint or revocation withheld from every supplied trusted input.

Bundle format_version is `4`. Required collections: entries (sealed objects),
intermediates, epochs, witness_set, checkpoints (checkpoint + cosignatures),
inclusion_proofs (seq, tree_size, proof) and consistency_proofs (old_size, new_size,
proof). Optional revocations, openings and findings default to empty arrays.
Openings bind a sequence and commitment field to base64url value/salt. Findings are
separate unverified operational annotations, not entry-integrity verdicts. Anchor
proofs and partial-range bundles are not accepted by this Stage 1 format.

Safe verification limits: 64 MiB per input file and 100,000 entries/tree leaves.
Oversized or malformed envelopes fail the CLI with exit 2; there is no reliable
sequence to attribute to malformed transport JSON. Parsed evidence has per-sequence
reasons. VERIFIED exits 0; TAMPERED/MISSING/UNVERIFIED exit 1.

A missing witness quorum is UNVERIFIED; a supplied invalid cosignature is TAMPERED.
Distinct valid witness identities are counted once. Signature failure at a modified
entry takes precedence over dependent chain/proof failures. Missing entries are
reported at the absent sequence, not misclassified solely because adjacent leaves
cannot reconstruct a full Merkle tree. Existing proofs still verify surviving leaves.

Agent request context is mandatory, idempotency keys are hashes, and commitment salts
must be at least 16 bytes (new salts are 32 bytes). The final epoch may be live/open;
every observed transition requires an epoch_end followed by epoch_start. Dates in
the deterministic test corpus are fixed and evaluated against certificate windows,
not the current wall clock: historical evidence stays verifiable after expiry.
