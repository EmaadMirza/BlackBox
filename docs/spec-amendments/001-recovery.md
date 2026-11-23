# Spec amendment 001: signed recovery discontinuities

This amendment is proposed for Task E2a. It does not edit
`docs/BlackBox_v4.md`; it records the approved Option D design and the exact
normative changes required before a future spec revision.

## Security boundary

The issuance journal is a crash- and operator-error recovery aid. It is **not**
a defence against a malicious signer host or a host attacker who can rewrite
the journal. Journal contents must therefore be checked against the signed
ledger and witness state. Witness quorum remains the defence against a
malicious host, split view, or rewritten journal. A journal-only claim never
authorizes a recovery or changes an offline verdict.

## Recovery entry

Add a new signed entry type, `recovery`, sealed by the **new** epoch key. It
contains:

- `burned_first_seq` and `burned_last_seq`, an exact inclusive range;
- `last_known_entry_hash`, the hash of the last authenticated entry before the
  range; and
- `lost_epoch_id`, the epoch whose continuation was lost.

The recovery entry's own `seq` is `burned_last_seq + 1`, its `prev_hash` is
`last_known_entry_hash`, its `epoch_id` is strictly newer than
`lost_epoch_id`, and the transition must be consistent with the previous
authenticated entry. The range must be non-empty, non-reversed, non-overlapping
with known entries, and begin at the sequence immediately after the last known
entry. A recovery entry is the explicit authorization for a sequence
discontinuity; a deleted entry, a local marker, a journal row, or a ledger
absence is not.

An old verifier that does not understand `recovery` must fail closed when it
parses the new type. It must not reinterpret it as an ordinary action or
silently accept the burned range. The format remains versioned; the new type is
accepted only by a verifier implementing this amendment, while unknown types
remain schema errors for older implementations.

## Section-by-section changes

### §7.1 — Key hierarchy

Retain epoch private keys in memory only by default. Add an issuance journal
reservation before returning a sealed entry, but state that the journal does
not defend against a malicious host. Witnesses remain the integrity defence.
Define the recovery entry as signed by the new epoch key; the destroyed/lost
epoch key is never reconstructed merely to manufacture an `epoch_end`.

### §7.3 — Epoch lifecycle

Add the crash path: after an unrecoverable epoch key, a new epoch may begin only
after an authenticated frontier is established. If sequences were burned, the
first new-epoch recovery entry must declare the exact range and lost epoch and
must chain from the last known authenticated entry. It is not an `epoch_end`
for the lost epoch. A recovery entry signed by the old epoch, with an invalid
new-epoch transition, or with no authenticated previous hash is invalid.

### §7.5 — Compromise handling

Clarify that the issuance journal limits crash/operator ambiguity only. A
malicious host may alter it; witnesses and signed checkpoints detect that
equivocation. Host compromise still requires witness investigation, possible
intermediate revocation, and a new signer/epoch series as already contemplated
by this section.

### §8.2 — Common entry fields and entry types

Add `recovery` to the entry-type registry and define its four fields:
`burned_first_seq`, `burned_last_seq`, `last_known_entry_hash`, and
`lost_epoch_id`. State the exact sequence and hash-link rules above. Preserve
the global sequence rule: burned sequence numbers are never reused, even after
epoch restart. The amendment must also define the canonical serialization and
domain-separated signature coverage for this type.

### §§10.2–10.3 — Checkpoints and witnesses

Require checkpoints to preserve the recovery entry and its preceding
authenticated frontier. Witnesses accept a discontinuity only when the
recovery entry is valid, signed by the new epoch, chains correctly, and declares
the exact range. A journal, operator assertion, or “no outcome” query cannot
replace the recovery entry or witness evidence. A conflicting recovery entry
or rewritten journal is refused and alarmed.

### §16.2 — Evidence bundle contents

Add recovery entries, the authenticated last-known entry, certificate chains
for both the lost and new epoch where available, the recovery certificate or
operator authorization if introduced by deployment policy, issuance-journal
proofs, and the relevant witnessed checkpoints. Journal data must be labelled
auxiliary and must never be treated as a trust root.

### §16.3 — Verification algorithm

After normal signature, certificate, sequence, and hash checks:

1. Recognize `recovery` only under the amended schema.
2. Verify it with the new epoch certificate and pinned trust chain.
3. Verify `seq == burned_last_seq + 1`,
   `prev_hash == last_known_entry_hash`,
   `burned_first_seq == previous_seq + 1`, and
   `last_known_entry_hash == hash(previous authenticated entry)`.
4. Verify `lost_epoch_id` identifies the prior epoch and the new epoch is
   strictly later.
5. Reject reversed, overlapping, unexplained, or partially declared ranges.
6. Mark the range as an authorized recovery discontinuity only when every
   check succeeds. A plain deletion remains `MISSING`; an edited or forged
   recovery remains `TAMPERED`.

### §16.4 — Verdicts and precedence

Add the report flag:

```text
RECOVERY_DISCONTINUITY
```

The flag is never a clean `VERIFIED` result. Proposed precedence, from lowest
to highest severity, is:

```text
VERIFIED < UNVERIFIED < RECOVERY_DISCONTINUITY < MISSING < TAMPERED
```

The flag must appear in CLI output and bundle summaries even when all ordinary
entries pass signature and checkpoint checks. A valid authorized recovery may
leave individual entries `VERIFIED`, but the report must expose the flag and
must not summarize the recovered bundle as silently `VERIFIED`. An invalid or
missing recovery entry keeps the existing `MISSING`/`TAMPERED` result.

### §20 — Failure modes and recovery

Replace the simple “restart triggers new epoch” behavior with quarantine,
authenticated frontier recovery, issuance-journal reconciliation, and the
signed recovery-entry rule. State that a crash in the state/index commit window
blocks signing until operator recovery. State that a malicious host can defeat
the journal but not the witness-based integrity check. Define operator steps
for preserving the old evidence, authenticating the frontier, burning uncertain
sequences, creating the new epoch recovery entry, and obtaining witness
acceptance before resuming.

## Compatibility and failure-closed rule

The existing format version remains versioned. Implementations that do not know
the `recovery` discriminator reject the sealed body as an unknown entry type;
they do not coerce it to another type. New implementations must reject missing
recovery evidence, wrong epoch signatures, wrong ranges, wrong previous hashes,
overlap, reversal, and a plain deletion without a signed recovery entry.
