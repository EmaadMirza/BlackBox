# Task E addendum: recovery, sequence reuse, and `/seal` error handling

This is a design document only. It records the required Task E decisions; it
does not implement them or change the current Stage 2 code.

## 1. Sequence reuse and equivocation

### Decision

The signer must never resume signing from a locally reconstructed sequence
frontier unless that frontier is anchored to an authenticated external record.
The state file, outcome index, marker payload, filesystem timestamps, and a
ledger “no outcome” response are insufficient by themselves.

There are two permitted recovery outcomes:

| Recovery outcome | Sequence rule | Required anchor |
| --- | --- | --- |
| **Same-log continuation** | Preserve the externally observed high-water mark. The next entry is strictly `max_observed_seq + 1`; no lower or equal sequence may be signed. The recovered `last_hash` must be the authenticated hash at that frontier. | A quorum-authenticated ledger/checkpoint record, or an independently verified immutable backup containing the complete prefix and frontier |
| **New-log restart** | Generate a new `log_id` and start a new sequence namespace at genesis. Never append to the old log and never reuse an old `(log_id, seq)` pair. | A signed recovery certificate linking the old log frontier to the new log identity, with operator identity, reason, source checkpoint/hash, and monotonic recovery generation |

An epoch restart **within the same `log_id` does not reset sequence numbers**.
Epoch identifiers and certificates distinguish signing epochs; they do not make
reuse of an already issued sequence safe. If the old frontier cannot be
established, the only safe restart is a new `log_id` with an explicit recovery
discontinuity.

The signer therefore remains quarantined after either marker recovery or epoch
restart until all of the following hold:

1. The recovery owner has authenticated the old frontier or authorized a new
   log namespace.
2. State, outcome index, epoch metadata, and the recovery record agree.
3. The signer has durably persisted the recovery generation/anchor before
   accepting `/seal`.
4. A startup check rejects an old state, stale recovery generation, duplicate
   `(log_id, seq)`, or a proposed sequence at or below the anchored frontier.

This is the no-equivocation invariant: every issued sequence is either retained
in the same authenticated prefix or remains permanently reserved in the old
log namespace.

## 2. Changes to `docs/task-c-recovery.md` by option

The existing marker procedure is extended as follows.

### Option A: same-log continuation

After the forensic-copy step, the operator must obtain the highest
quorum-authenticated frontier, not merely compare the two local JSON files.
The recovery procedure must then:

- verify the complete prefix through that frontier;
- set state to exactly that frontier and rebuild the outcome index from
  authenticated entries;
- reject any local state/index entry beyond or conflicting with the frontier;
- persist a recovery receipt containing `log_id`, frontier sequence/hash,
  checkpoint identity, and recovery generation;
- remove the marker only after the pair and receipt are durable; and
- allow signing only at `frontier + 1`.

If the external source cannot distinguish two entries at the same sequence,
the operator must not choose one. The log remains quarantined and recovery
escalates to Option B or incident handling.

### Option B: new-log restart

If the old frontier cannot be established, the operator must not repair the old
log by guessing or rolling it back. Instead the procedure must:

- preserve the old log, marker, state and index as evidence;
- obtain approval for a new `log_id` and recovery generation;
- create a signed recovery certificate linking the old log identity and last
  trusted checkpoint (if known) to the new log identity;
- initialize the new log at its own genesis without importing old sequence
  numbers; and
- publish the recovery certificate before enabling `/seal`.

The old log remains permanently read-only. A new-log restart is not a silent
continuation and cannot be represented as ordinary epoch rollover.

### Epoch restart

For an epoch restart with a known same-log frontier, use Option A and preserve
the global sequence. For an epoch restart without a known frontier, use Option
B. Changing only `epoch_id` or `epoch_certificate_id` is never an acceptable
way to resolve sequence uncertainty.

## 3. Verifier behavior for recovery discontinuity

The verifier must expose a non-silent operational flag:

```text
RECOVERY_DISCONTINUITY
```

The flag is emitted when a new log is linked to an old log by a recovery
certificate, or when a verified bundle starts after an explicitly documented
recovery boundary. It includes, at minimum:

- old `log_id` and last trusted sequence/hash, when known;
- new `log_id` and first sequence;
- recovery certificate identity and verification status;
- recovery generation and operator/authority identity; and
- whether the old frontier was complete or only bounded.

`RECOVERY_DISCONTINUITY` is not equivalent to `VERIFIED`. Existing entry
integrity verdicts remain unchanged: an invalid certificate, forged link, or
unexplained gap is `TAMPERED`, `MISSING`, or `UNVERIFIED` according to existing
precedence. A valid and authorized recovery link may leave individual entries
`VERIFIED`, but the report must still contain the explicit flag and the CLI
must display it. A new log without a valid recovery certificate is an
unexplained discontinuity and is not silently accepted as a clean continuation.

The Task E acceptance tests must assert both the ordinary per-entry verdict and
the presence/absence of `RECOVERY_DISCONTINUITY`.

## 4. `/seal` sanitized error mapping

The current `/seal` boundary catches the relevant exception classes before the
generic handler:

| Exception | Sanitized envelope | Current mapping evidence |
| --- | --- | --- |
| `HistoryIntegrityError` (`ValueError`) | HTTP 409, `{"code":"history_integrity","message":"History evidence failed integrity validation."}` | Explicit branch in `services/signer/main.py` |
| `HistorySourceError` (`OSError`) | HTTP 503, `{"code":"signer_unavailable","message":"Signer unavailable."}` | Explicit branch in `services/signer/main.py` |
| `OutcomeConflictError` (`ValueError`) | HTTP 409, `{"code":"outcome_conflict","message":"The intent already has a conflicting outcome."}` | Explicit branch in `services/signer/main.py` |
| `OutcomeIndexError` (`ValueError`) | HTTP 409, `{"code":"outcome_index_invalid","message":"Signer outcome state is invalid."}` | Explicit branch in `services/signer/main.py` |

Thus all four are sanitized and exception details are not exposed. `503` is
reserved for the retryable history-source availability failure; the three
integrity/conflict/state failures use `409` so callers do not blindly retry.
The new parameterized coverage is in
`tests/unit/test_signer_task_c_error_mapping.py`; existing tests were not
modified.

## Task E implementation gate

Task E must not claim completion until it has:

- implemented one of the two recovery outcomes above;
- made the recovery anchor durable and startup-enforced;
- added the explicit verifier discontinuity flag;
- added named-exception `/seal` tests for all four mappings; and
- rerun the full baseline after any code or test changes.
