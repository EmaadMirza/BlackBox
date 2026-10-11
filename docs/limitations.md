# Scaffold limitations and specification ambiguities

No security behavior is implemented or verified. Function bodies raise
`NotImplementedError`; HTTP factories do not create apps, register routes, or serve
healthchecks. All tests are expected-failure placeholders. No gate has passed.

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
- Signer chain state now records `log_id` and refuses uncertain commits, missing
  initialized state and legacy/corrupt state. Recovery is fail-closed but does not
  yet provide an operator rebuild protocol or a transaction spanning chain state,
  the future outcome index and the ledger.
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

## Traceability

| Future claim | Planned tests (currently XFAIL) |
| --- | --- |
| History integrity | G1, G2, G3; E3, E7, E8, E11 |
| Completeness | G4; E4, E5, E6 |
| Bounded forward forgery | E4, E6, E11 |
| Independent verification | E1 and offline evidence in each applicable acceptance run |
| Agent accountability | E1, E2, E10, E12 |
| Practicality measurements | E9 (integrity criteria, performance reported) |
