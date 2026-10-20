# Task E design: epoch recovery after signer crash

**Status:** design only. No recovery implementation is authorized by this
document.

## Scope and source constraints

This design uses only repository guidance and `docs/BlackBox_v4.md`. The source
spec says that epoch keys are memory-only, generated at startup/rollover, and
destroyed after `epoch_end` (§7.1 and §7.3). It also says that `seq` is global
across epochs and increases by exactly one (§8.2), and that the verifier checks
epoch contiguity plus `epoch_start`/`epoch_end` presence (§16.3). The current
Task C marker procedure is in `docs/task-c-recovery.md`.

The spec does not define a recovery certificate, an issuance journal, a
recovery-generation field, or a verifier flag for a deliberate discontinuity.
Those are therefore design proposals, not claims about the current wire
format.

## Non-negotiable sequence invariant

After **any** recovery—Task C marker recovery, process restart, epoch restart,
or host replacement—the signer must not sign a different body at a sequence
number that may already have been issued.

The difficult case is an entry returned to the gateway after signing but before
the signer persisted state, the ledger accepted it, or a witness covered it.
The local state alone cannot prove whether that entry was observed externally.
Therefore the recovery protocol must treat the uncertain sequence as already
reserved:

1. Quarantine signing on marker detection or uncertain shutdown.
2. Obtain an authenticated frontier from witnesses/checkpoints plus any
   signer-issued-entry journal and gateway receipts available to the operator.
3. If the body at the uncertain sequence is known, retain its exact hash and
   continue only from the authenticated frontier.
4. If the body is unknown, permanently burn that sequence in the old log
   namespace. The next signed entry is after the burned sequence, with a
   signed recovery/gap record only if the selected protocol can authoritatively
   represent it. Never fill the burned sequence with a different body.
5. If no authenticated frontier or safe burned-sequence procedure is available,
   start a new `log_id`; do not reuse the old `(log_id, seq)` pair.

This requires a durable issuance record or equivalent pre-return reservation in
the final implementation. A marker containing only old/new state hashes is
useful for file recovery but does not by itself prove what was returned to the
gateway. The current Task C implementation does not yet provide that
issuance-level guarantee; this is an explicit Task E gap.

## Options

### Option A — always start a new epoch on restart

**Outline.** On every restart, generate a new epoch key and certificate. Keep
the global sequence strictly monotonic. The intended normal path seals the old
epoch's `epoch_end`, then the new epoch's `epoch_start`, with contiguous epoch
IDs and windows.

**Important ambiguity.** If the process crashed after destroying the old key,
the signer cannot create a valid old-epoch `epoch_end` under the current §7.3
rule. A new key cannot sign it. Therefore the phrase “seal a recovery/
`epoch_end` for the lost epoch” requires one of these spec changes:

- pre-sign and durably retain the old `epoch_end` before destroying the key;
- introduce a distinct recovery record signed by the intermediate/root rather
  than pretending it is an old-epoch `epoch_end`; or
- retain encrypted key material, which becomes Option B.

Without one of these changes, Option A cannot promise an `epoch_end` after key
loss and must expose a discontinuity instead of silently fabricating one.

**Security impact.** Disk theft does not reveal the destroyed epoch private
key. A host attacker can still observe or alter recovery metadata and can
cause denial of service, but cannot create a valid old-epoch signature after
destruction. If the new-epoch private key is exposed, the damage is limited to
that epoch under the existing assumptions.

**Offline verifier.** With a pre-signed end, it sees a normal contiguous
`epoch_end` → `epoch_start` transition. Without one, it sees a missing old
`epoch_end` or an explicit recovery boundary. Under the current §16.3 and
§16.4 rules this must not be reported as an ordinary clean `VERIFIED` chain.

**In-flight intents and outcome index.** Intents whose bodies are known remain
valid and may be completed only with their original idempotency key. Unknown
returned entries reserve their sequences. The outcome index must be rebuilt
from authenticated outcomes; a local “no outcome” response is not proof of
absence. Entries from the old epoch are read-only after quarantine.

**Checkpoints and witnesses.** Witnesses can accept the new epoch only after
the sequence frontier, epoch transition, and any recovery certificate are
consistent with their last checkpoint. A checkpoint that skips an uncertain
sequence needs an explicit gap/recovery representation; otherwise witnesses
should refuse it under the existing continuity rule.

**Intermediate-key unavailable.** The signer cannot mint a valid new epoch
certificate. It remains stopped; operator obtains the next certificate through
the offline root/intermediate process described in §7.2 and §7.4, or chooses a
new log namespace under the approved recovery protocol.

**Complexity and crash-injection plan.** Medium complexity, but the
pre-signed-end versus lost-key ambiguity must be resolved first. Inject crashes
after old-end signing, after old-end persistence, after key destruction, before
new-start signing, after new-start persistence, and before witness submission.
Expected results: no duplicate `(log_id, seq)`, no old-key signature after
destruction, marker/quarantine on uncertainty, and explicit verifier
discontinuity when an end cannot be authenticated.

**Change to `docs/task-c-recovery.md`.** Same-log marker recovery must first
reserve/reconcile uncertain sequences, then establish the authenticated
frontier. Epoch restart creates a new key/certificate but cannot use it to
backfill the lost epoch's `epoch_end`; the procedure must either install a
pre-signed end or invoke the explicit recovery-boundary path.

### Option B — persist the epoch key encrypted

**Outline.** Store the epoch private key encrypted under a KMS, TPM, or sealed
local secret. After restart, resume the same epoch only if its certificate
window remains valid and the authenticated sequence frontier is recovered.
Otherwise roll to a new epoch.

**Security impact.** Disk theft alone should reveal ciphertext, but host
compromise or access to the unseal mechanism may expose the current epoch key.
The attacker gains the ability to produce ordered current-epoch entries within
the remaining validity window, matching the threat described in §7.5 for a
stolen epoch key. Key custody, erasure, backup, rotation, and KMS/TPM failure
become deployment-critical guarantees absent from the current scaffold.

**Offline verifier.** A successful resume is a normal continuation of the
same epoch, with no extra epoch boundary. An expired/unavailable key causes a
new epoch. Any skipped sequence, missing `epoch_end`, or unexplained change is
reported as a gap or explicit recovery flag, never silently normalized.

**In-flight intents and outcome index.** Same-epoch resume may complete known
in-flight intents after authenticated reconciliation. It must not issue a
different body at an uncertain sequence. The outcome index remains signer-owned
and is rebuilt/validated before resuming; corrupt or ambiguous index state
keeps the signer stopped.

**Checkpoints and witnesses.** Witnesses can continue the same epoch only if
the recovered frontier extends their latest accepted checkpoint. A resume
after an uncheckpointed returned entry requires an issuance journal or burned
sequence; otherwise witnesses must refuse the conflicting continuation.

**Intermediate-key unavailable.** Resume is possible only while the existing
epoch certificate is independently available and valid. If a new certificate
is needed, stop until the intermediate/root path provisions it; do not create
an uncertified epoch.

**Complexity and crash-injection plan.** Highest operational complexity and
largest key-custody surface. Inject crashes during encrypted-key write,
before/after KMS unseal, after sequence reservation, after signing but before
state replacement, after state replacement but before ledger append, and during
checkpoint submission. Expected results: ciphertext is never accepted as a
key, failed unseal is fail-closed, resume never reuses a possibly issued
sequence, and a valid same-epoch continuation produces no false epoch gap.

**Change to `docs/task-c-recovery.md`.** Add a key-unseal decision before
frontier repair. If unseal and certificate-window checks succeed, recover the
same log/epoch using Option A's authenticated-frontier and sequence-reservation
steps. If either fails, retain the marker and choose a new epoch or new log;
never guess from the local state/index pair.

### Option C — hybrid short-window resume

**Outline.** Keep the epoch key in sealed encrypted storage and permit resume
only during a short, explicitly configured grace window. Outside that window,
destroy/retire the key and start a new epoch or new log according to the
frontier result.

**Security impact.** Limits the time in which a stolen sealed key is useful,
but adds policy and clock-boundary risk. A host attacker who can invoke the
unseal path during the grace window still gains current-epoch signing ability.
The grace policy must not override certificate validity or witness continuity.

**Offline verifier.** In-window resume looks like ordinary same-epoch
continuation. Out-of-window recovery produces a new epoch boundary or an
explicit recovery discontinuity. The verifier must show which policy branch
was taken and must not hide a missing `epoch_end`.

**In-flight intents and outcome index.** Same as Option B during the grace
window. After expiry, old-epoch in-flight work can only be completed under a
new epoch if its intent and sequence treatment are explicitly authorized; the
outcome index is not evidence that a missing outcome was never issued.

**Checkpoints and witnesses.** Witnesses need the grace decision, certificate
validity, and authenticated frontier to distinguish a permitted resume from a
fork. A checkpoint after the grace boundary must carry the new epoch/recovery
metadata required by the chosen protocol.

**Intermediate-key unavailable.** Resume can continue only with the existing
valid certificate and sealed key. Otherwise quarantine; after the grace window,
the signer waits for certificate provisioning or uses a new log namespace.

**Complexity and crash-injection plan.** More complex than Option A and less
key-custody-heavy than Option B, but introduces boundary tests. Inject crashes
just before, exactly at, and just after grace expiry; with valid/expired
certificates; before/after key unseal; and at every Task C replacement point.
Expected results: deterministic branch selection, no clock-based sequence
reuse, no same-epoch resume after policy expiry, and visible recovery flags.

**Change to `docs/task-c-recovery.md`.** Add a first-class grace-window check
after forensic capture. Within the window follow authenticated same-epoch
recovery; outside it follow new-epoch/new-log recovery. Record the policy
version and trusted time in the recovery receipt. A local wall clock alone is
not enough if it can be rolled back.

### Option D — immutable issuance journal plus new epoch

**Outline.** Before returning a sealed entry to the gateway, append and `fsync`
an issuance record containing `(log_id, seq, body_hash, epoch_id)` to signer
storage or an independent append-only service. On restart, use this journal and
authenticated checkpoints to distinguish a known issued entry from an unknown
reserved sequence, then always generate a fresh epoch key.

**Security impact.** The journal reduces ambiguity but becomes another
integrity boundary. A host attacker who can rewrite it can attempt equivocation;
therefore it needs append-only protection, independent anchoring, or witness
coverage. The old epoch private key is still destroyed, so post-crash forgery
with it is not enabled.

**Offline verifier.** A journal-backed known entry can be reconciled against
the ledger. An unknown reserved sequence is shown as a recovery gap or
`RECOVERY_DISCONTINUITY`; it is never filled by a different entry. The new
epoch is visible through its certificate and start entry.

**In-flight intents and outcome index.** The journal is authoritative for what
the signer returned, while authenticated history is authoritative for what was
accepted. The outcome index is rebuilt only from authenticated outcomes and
cross-checked with journal records; disagreement blocks signing. In-flight
intents can be retried only with the original idempotency key and an explicit
retry policy.

**Checkpoints and witnesses.** The journal can provide evidence for entries
not yet witnessed, but it does not replace witness quorum. Checkpoints must
still extend the accepted chain, and witnesses must reject any attempt to
fill a reserved sequence with another body.

**Intermediate-key unavailable.** A new epoch cannot start without a valid
certificate. The journal remains preserved and the signer stays stopped until
the offline certificate process completes, or the operator starts a new log
under a separately authorized recovery certificate.

**Complexity and crash-injection plan.** Highest implementation/storage
complexity, but it directly addresses the “returned but not persisted” case.
Inject crashes before journal fsync, after journal fsync/before response, after
response/before state replacement, after state replacement/before ledger
append, and during journal compaction. Expected results: journal records are
never silently lost or rewritten, a reserved sequence is never reused, and
verifier output distinguishes a known entry from an unknown recovery gap.

**Change to `docs/task-c-recovery.md`.** Add journal capture and independent
verification before comparing state and index. If the journal says a sequence
was returned but no authenticated body exists, reserve that sequence and report
the discontinuity; do not reconstruct a body from the candidate or index.

## Verifier output for recovery discontinuity

The verifier must add a non-silent operational flag:

```text
RECOVERY_DISCONTINUITY
```

It should include old/new `log_id`, old trusted sequence/hash when known, new
epoch/log identity, recovery-generation or certificate identity, reason,
whether the old frontier was complete, and affected sequence ranges. This is a
flag in addition to the existing per-entry verdicts, not a replacement for
them. A valid recovery certificate may leave entries individually
`VERIFIED`, but the report is not a silent clean continuation. An invalid
certificate, forged link, or unexplained gap remains subject to the existing
`TAMPERED`/`MISSING`/`UNVERIFIED` precedence in §16.4.

## Spec sections requiring change

The following are exact current references and the required change:

- **§7.1 Key hierarchy:** replace the unconditional “Epoch ... Signer memory
  only” rule with the selected custody/recovery rule, including whether sealed
  encrypted persistence is allowed and what protects unseal operations.
- **§7.3 Epoch lifecycle:** define crash recovery, whether `epoch_end` may be
  pre-signed, how a lost key is represented, the recovery certificate, and how
  epoch IDs/windows behave when a restart cannot authenticate the old end.
- **§7.5 Compromise handling:** state what disk theft, host compromise, KMS
  compromise, or journal compromise permits under the selected option.
- **§8.2/common entry fields:** define any recovery certificate, recovery
  generation, gap/reservation, or discontinuity fields and their canonical
  signed form. The current spec only explicitly states the global sequence
  and epoch fields.
- **§10.2/§10.3 checkpoint and witness behavior:** define whether a recovery
  boundary can be checkpointed, what witnesses require, and how an uncertain
  returned-but-unwitnessed entry affects acceptance.
- **§16.2 Evidence bundle contents:** include recovery certificates, issuance
  journal proofs or reservations, and the old/new frontier evidence.
- **§16.3 Verification algorithm:** add recovery-boundary validation,
  reservation/non-reuse checks, and the rule for missing `epoch_end` after key
  loss.
- **§16.4 Verdicts and precedence:** define `RECOVERY_DISCONTINUITY` as a
  report flag and specify whether unexplained recovery is `MISSING`,
  `UNVERIFIED`, or a new verdict. The current four verdicts do not answer this.
- **§20 Failure modes and recovery:** replace the current “restart triggers new
  epoch” row with the selected option's quarantine, anchor, operator, and
  verifier-visible behavior.

These changes are required because the current text says both “epoch key is
destroyed” (§7.3) and “restart triggers new epoch” (§20) but does not define
how a returned-but-unpersisted sequence or absent old `epoch_end` is handled.

## Recommendation

Choose **Option D: immutable issuance journal plus new epoch**, combined with
Option A's default of fresh epoch keys. It is the only compared option that
directly records the exact failure case where an entry was returned to the
gateway but not yet persisted or witnessed, while preserving the current
security benefit that destroyed epoch keys cannot sign after rollover. It still
requires an independently protected/anchored journal; a signer-local mutable
file alone is not sufficient.

Exact required changes for that recommendation:

1. Add a versioned, append-only issuance record and durable pre-response
   sequence reservation.
2. Extend the marker/recovery record with old/new state hashes, journal range,
   recovery generation, and authenticated frontier evidence.
3. Define a signed recovery certificate and explicit reservation/gap encoding;
   do not label a post-crash record as the lost epoch's `epoch_end` unless it
   was genuinely signed by that epoch key.
4. Keep global sequence numbers monotonic for same-log continuation; burn any
   uncertain sequence and never reuse it.
5. Add `RECOVERY_DISCONTINUITY` to verifier output and update §16.2–§16.4,
   §7.1/§7.3/§7.5, §8.2, §10.2/§10.3, and §20 as listed above.
6. Add crash-injection tests for journal, marker, state/index, ledger append,
   checkpoint, witness, and restart boundaries before claiming Task E complete.

## Open questions

1. Should the system permit a deliberate new `log_id` after an unknown
   frontier, or must every deployment recover the original log through
   witnesses?
2. Is a signer-issued entry journal allowed to live outside the signer host,
   and which independent authority anchors it?
3. May the protocol introduce a signed recovery record distinct from
   `epoch_end`, or must every epoch transition contain a genuine old-key
   `epoch_end`?
4. Should an unknown returned sequence be represented by a signed `gap` entry,
   a recovery certificate range, or only an offline verifier flag?
5. What exact status should a verifier assign to an authorized but incomplete
   recovery boundary: `UNVERIFIED`, `MISSING`, or a new verdict?
6. What KMS/TPM/sealed-storage guarantees, if any, are in scope for production?
7. What is the trusted time source for a hybrid grace window, and how is clock
   rollback detected?
8. What witness quorum and checkpoint evidence are required before `/seal` may
   be re-enabled after recovery?
