# G3 Stage 2 acceptance report

Date: 2026-10-25  
Baseline: W4 (`70c91d0`, tag `w4-done`)  
Branch: `task-gate-g3`

## Claim-to-test results

| Claim | Test / command | Result |
|---|---|---|
| G3 core refuses a correctly signed checkpoint over rewritten history, while the plain-ledger control accepts the rewrite | `tests/gates/test_g3_witness_refusal.py::test_g3_witness_refuses_rewritten_history_and_plain_ledger_control` | **VERIFIED-IN-PROCESS+POSTGRES** — passed; witness refused with `bad_proof`, recorded `WITNESS_REFUSAL`, and the offline evidence remained verified while the rewritten bundle was non-verified. |
| Witness persists state before returning a cosignature | `tests/unit/test_witness_service.py::test_witness_accepts_first_checkpoint_persists_and_replays_cosignature`; `tests/gates/test_g3_witness_refusal.py::test_g3_witness_refuses_rewritten_history_and_plain_ledger_control` | **VERIFIED-IN-PROCESS+POSTGRES** — file-backed state is committed before the response; replay returns the stored cosignature; refusal leaves the prior state intact. |
| One witness failure preserves quorum and records an alarm | `tests/integration/test_w2a_quorum.py::test_one_witness_down_quorum_holds_and_alarm_is_recorded` | **VERIFIED-IN-PROCESS+POSTGRES** — passed against local PostgreSQL. |
| Two witness failures prevent a witnessed checkpoint; recovery catches up without conflict | `tests/integration/test_w2a_quorum.py::test_two_witnesses_down_then_recovery_catches_up_without_conflict` | **VERIFIED-IN-PROCESS+POSTGRES** — passed against local PostgreSQL. |
| Split view is detected for equal-size checkpoints with different roots | `tests/unit/test_w4_gossip.py::test_same_size_different_roots_is_split_view`; `tests/unit/test_w4_gossip.py::test_latest_checkpoint_is_read_only_and_bearer_authenticated` | **VERIFIED-IN-PROCESS+POSTGRES** — split-view predicate and authenticated read-only latest-checkpoint endpoint passed. The test is in-process; real network behavior remains deferred. |
| Ledger inclusion/consistency proofs and tampered stored-row rejection work | `tests/integration/test_l3b_proofs.py`; `tests/integration/test_l3c_checkpointer.py::test_checkpoint_and_exported_bundle_are_core_verifiable`; `tests/integration/test_l3b_proofs.py::test_tampered_stored_row_proof_fails_against_signed_checkpoint_root` | **VERIFIED-IN-PROCESS+POSTGRES** — integration proof tests passed against local PostgreSQL. |
| Durable signer-to-ledger delivery survives outage/restart and preserves ordering | `tests/integration/test_l2_delivery_e2e.py::test_real_postgres_end_to_end_and_offline_verification`; `::test_ledger_down_then_drains_in_order`; `::test_restart_delivers_each_row_once`; `::test_equivocation_records_conflict_and_degrades_signer`; `::test_out_of_order_stops_worker` | **VERIFIED-IN-PROCESS+POSTGRES** — passed against local PostgreSQL; delivery is cooperative/in-process. |
| High-risk attestation requires witnessed evidence | Existing attestation unit/core coverage in `tests/unit/`; `tests/integration/test_w2a_quorum.py` witnessed-evidence coverage | **DEFERRED** — the current Stage 2 implementation fails closed for high-risk attestation when real witnessed-checkpoint evidence is unavailable, but no complete production gateway-to-signer high-risk acceptance flow is proven by this gate. |
| Full baseline, integration suite, gates and attack battery are green | `make test`; `make test-integration`; `make gates`; `make attack`; `make lint` | **VERIFIED-IN-PROCESS+POSTGRES** — `make test`: 604 passed, 13 xfailed; integration: 53 passed; gates: 207 passed, 1 xfailed (`G4`, not built); attack battery passed; lint passed. The xfail count was not reduced from the W4 baseline, so this report does not claim xfail cleanup. |

## Checks and interpretation

- The dedicated G3 gate passed: **1 passed**.
- The control in that test is intentionally a plain ledger rewrite; it accepts the rewritten content, demonstrating why witness validation is required.
- No G3 xfail was removed: the G3 test is already a real passing gate, while the remaining gate xfail is G4 and is unrelated to G3.
- PostgreSQL claims above use the configured local `LEDGER_TEST_DSN` database. No Docker or Compose validation was run.

## Not proven / deferred

This acceptance does **not** prove:

- independent custody or independence of witnesses; all witness processes are controlled by the same test operator and host;
- behavior under actual power loss or filesystem/device failure;
- HSM, KMS, TPM, key zeroization, or production private-key custody;
- real network partitions, transport authentication outside in-process HTTP clients, or deployment-level timing;
- container and Compose behavior;
- production external notification, deployment, or operational monitoring;
- a complete end-to-end high-risk gateway/provider attestation path using live witnessed evidence.

These are deliberately recorded as deferred rather than inferred from the passing in-process and local-PostgreSQL tests.
