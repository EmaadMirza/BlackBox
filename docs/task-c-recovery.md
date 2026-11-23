# Task C evidence and operator recovery

This document records the remaining Task C evidence before Task E. It describes
the current implementation; it does not claim power-loss injection or a real
ledger transaction.

## Crash-point matrix: state and outcome-index replacement

`persist_state()` creates a pre-commit marker before replacing either durable
file. The marker is intentionally left behind on every exception after marker
creation. On restart, the marker is a fail-closed condition. Temporary files
are cleaned by the `finally` block where possible; their presence is not a
recovery signal.

| Failure point | Durable result | Restart/signing result | Recovery step |
| --- | --- | --- | --- |
| Input validation, previous-state validation, or outcome-index validation before marker creation | Previous state and index unchanged; no marker | Normal operation remains possible | Fix the rejected input or index; retry only after validation succeeds |
| Marker creation (`O_EXCL`) | Previous pair unchanged; an existing marker remains | Operation fails closed because an uncertain commit already exists | Stop concurrent signer activity; follow the marker-present procedure below |
| Marker write, marker flush, marker `fsync`, or parent-directory `fsync` | Previous pair unchanged; marker remains | Fail closed on restart | Preserve marker and both data files; recover from a trusted coherent snapshot |
| State temporary-file creation, write, flush, `fsync`, or permission setup | Previous pair unchanged; marker remains | Fail closed | Do not remove marker; repair filesystem/permissions and restore or rebuild a coherent pair |
| Outcome-index temporary-file creation, write, flush, `fsync`, or permission setup | Previous pair unchanged; marker remains | Fail closed | Same as above; the index is mandatory once state exists |
| `os.replace(state_tmp, state)` | State may be new; index is still old; marker remains | Fail closed; state/index disagreement is not trusted | Do not sign. Compare with a trusted snapshot or ledger evidence, then replace both through the approved recovery process |
| `os.replace(index_tmp, index)` | State and index are both new; marker remains until cleanup | Fail closed conservatively, even if files appear coherent | Verify both files and the marker payload against a trusted snapshot; complete recovery and remove marker only after durable verification |
| Parent-directory `fsync` after either replacement | One or both replacements may be durable; marker remains | Fail closed because rename durability is uncertain | Treat the pair as uncertain; use the marker-present procedure and do not infer durability from file contents alone |
| Initialized-sentinel creation or its `fsync`/directory `fsync` | State/index may be new; marker remains; sentinel may be absent | Fail closed via marker (and subsequently via missing initialization sentinel) | Recover the complete state/index/sentinel set from a trusted coherent snapshot |
| Marker unlink | State/index/sentinel are already replaced; marker remains if unlink fails | Fail closed although the pair may be coherent | Verify the pair and marker payload; once an operator has established a coherent recovery point, remove the marker with the signer stopped and durably `fsync` the directory |
| Process crash at any instruction after marker creation | Any intermediate combination above; marker may or may not have reached stable storage | If marker is visible, fail closed; if marker was not durable, filesystem recovery is outside the application guarantee | Treat any observed marker as authoritative; if no marker is visible, independently validate state, index and sentinel before restart |

The current implementation has no automated operator rebuild tool and no
rollback journal. Therefore “recovery” means establishing a trusted coherent
pair, not guessing which file is newer.

## New rejection paths and tests

The implementation currently exposes typed Python exceptions. The labels below
are stable documentation codes for mapping those exceptions to a future HTTP
or service error envelope; they are not new wire-level codes.

| Rejection path | Error code / current exception | Test |
| --- | --- | --- |
| History record has invalid shape, missing target, stale target, or incomplete prefix | `HISTORY_INTEGRITY` / `HistoryIntegrityError` | `test_complete_prefix_history_verifies`; `test_tampered_or_broken_history_fails_closed` |
| History entry has wrong sequence or `log_id` | `HISTORY_INTEGRITY` / `HistoryIntegrityError` | `test_tampered_or_broken_history_fails_closed` |
| History chain, genesis link, signature, certificate reference, or epoch transition is invalid | `HISTORY_INTEGRITY` / `HistoryIntegrityError` | `test_tampered_or_broken_history_fails_closed` |
| Outcome sealing has no history source | `HISTORY_UNAVAILABLE` / `HistorySourceError` | `test_missing_history_source_fails_closed` |
| History intent disagrees with candidate idempotency key | `HISTORY_INTEGRITY` / `HistoryIntegrityError` | `test_history_disagreement_is_alarm_grade_rejection` |
| Signer-owned index already contains an outcome and candidate is not an explicit retry | `OUTCOME_CONFLICT` / `OutcomeConflictError` | `test_duplicate_outcome_is_rejected_from_own_index` |
| Indexed prior outcome cannot be authenticated or disagrees with the index | `HISTORY_INTEGRITY` / `HistoryIntegrityError` | `test_same_key_retry_verifies_prior_outcome_and_updates_index` |
| State/index outcome sidecar is missing or uses an unsupported version | `OUTCOME_INDEX_INVALID` / `OutcomeIndexError` | `test_missing_or_corrupt_outcome_index_fails_closed` |
| Outcome-index sequence/hash is malformed or compaction input is invalid | `OUTCOME_INDEX_INVALID` / `OutcomeIndexError` | `test_compaction_is_lossless_and_deterministic` |

## Operator recovery: marker present and state/index disagree

This is an incident-recovery procedure, not a normal startup action.

1. **Stop the signer and prevent concurrent starts.** Do not call `/seal`, do
   not delete the marker, and do not manually edit either JSON file in place.
2. **Make a forensic copy** of the state file, outcome-index file, marker,
   initialization sentinel, and any temporary files. Record ownership, mode,
   timestamps, filesystem errors, and the marker payload. Preserve the original
   directory read-only if possible.
3. **Confirm the configured identity.** The marker, state and outcome index must
   refer to the same configured `log_id`. A mismatch is not repairable by
   choosing the most recent file.
4. **Obtain a trusted coherent source.** Use an approved backup/snapshot or an
   independently verified signer/ledger record set. The marker payload is an
   intended state, not proof that the state or index replacement completed.
5. **Reconstruct both files from that one source.** The state `last_seq` and
   `last_hash` must match the authenticated chain frontier. Every index entry
   must map an intent sequence to the authenticated hash of its outcome. Reject
   any index entry that cannot be proven from authenticated history. The current
   repository does not provide the rebuild command; this step requires the
   deployment's approved recovery tooling or a controlled maintenance script.
6. **Validate the reconstructed pair offline.** Validate exact schemas, format
   version, `log_id`, hashes, sequence monotonicity, and the complete-prefix
   history evidence. If state and index cannot both be established from trusted
   evidence, keep the signer stopped and escalate.
7. **Install the pair as one recovery point.** With the signer stopped, write
   both files to temporary files, `fsync` each, replace both, `fsync` the parent
   directory, ensure the initialization sentinel exists and is durable, then
   remove the marker and `fsync` the directory again. Do not remove the marker
   before both files are verified.
8. **Restart in read-only/health mode first.** Confirm startup loads state and
   index without an uncertainty error. Perform one controlled seal only after
   the recovery owner approves the evidence and records the recovery receipt.

If no trusted coherent source exists, the required result is continued
fail-closed operation and escalation. Never resolve disagreement by deleting
the index, accepting a ledger “no outcome” response, rolling state backward, or
guessing from filesystem timestamps.
