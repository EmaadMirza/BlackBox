# BlackBox: Tamper-Evident Flight Recorder for AI Agents

BlackBox provides verifiable forensics and accountability for autonomous AI agents interacting with sensitive APIs and financial services. Full specification: [docs/BlackBox_v4.md](docs/BlackBox_v4.md).

## Architecture Overview

```
                      ┌────────────────────────────────────────┐
                      │          Agent Application             │
                      └──────────────────┬─────────────────────┘
                                         │ Bearer Token
                                         ▼
                      ┌────────────────────────────────────────┐
                      │            Gateway Service             │
                      │   - Normalize & Policy Evaluation      │
                      │   - Tool Definition Change Detection   │
                      └───────┬──────────────┬───────────────┬─┘
                              │              │               │
                              │ 1. Seal      │ 2. Check      │ 3. Forward
                              ▼              ▼               ▼
┌───────────────────────────────┐  ┌───────────────────┐  ┌──────────────────┐
│        Signer Service         │  │ Approval Service  │  │  Provider Mock   │
│ - Single-writer key custody   │  │ - Registered keys │  │ - Recomputes body│
│ - Hash chain & entry sealing  │  │ - Nonce freshness │  │   SHA-256 digest │
│ - Attestations & Checkpoints  │  │ - Approver!=Agent │  │ - Event log feed │
└──────────────┬────────────────┘  └───────────────────┘  └────────┬─────────┘
               │                                                   │
               │ Push entries                                      │
               ▼                                                   │
┌───────────────────────────────┐                                  │
│        Ledger Service         │                                  │
│ - PostgreSQL append-only store│                                  │
│ - RFC 6962 Merkle frontier    │                                  │
└──────────────┬────────────────┘                                  │
               │                                                   │
               │ Fan-out                                           │
               ▼                                                   │
┌───────────────────────────────┐                                  │
│       Witnesses (Quorum)      │                                  │
│ - Consistency proof checks    │                                  │
│ - Cosignatures & alarms       │                                  │
└──────────────┬────────────────┘                                  │
               │                                                   │
               │ Witnessed checkpoints & Provider feed             │
               ▼                                                   │
┌──────────────────────────────────────────────────────────────────┴┐
│                       Reconciler Service                          │
│ - Read-only join between ledger and provider event logs           │
│ - Emits forensic findings: UNRECORDED_ACTION, UNATTESTED_ACTION,   │
│   PHANTOM_OUTCOME, ORPHAN_INTENT, ARGS_MISMATCH, RESULT_MISMATCH  │
└───────────────────────────────────────────────────────────────────┘
```

## Security Claims and Test Mapping

### Verified Claims

| Security Claim | Description | Proving Tests |
| --- | --- | --- |
| **History Integrity & Tamper Evidence** | Any mutation or deletion in ledger history is detected by offline verification and rejected by witnesses. | `tests/gates/test_g1_tamper.py`<br>`tests/gates/test_g2_merkle.py`<br>`tests/gates/test_g3.py`<br>`tests/gates/test_g3_witness_refusal.py`<br>`tests/acceptance/test_e03.py`<br>`tests/acceptance/test_e08.py` |
| **Witness Quorum & Split-View Defense** | Checkpoints require distinct witness quorum (2/3); conflicting roots for same tree size trigger `SPLIT_VIEW`. | `tests/acceptance/test_e06.py`<br>`tests/acceptance/test_e07.py`<br>`tests/unit/test_w4_gossip.py`<br>`tests/unit/test_witness_http_processor.py` |
| **Attestation Binding & Body Integrity** | Provider independently recomputes raw request-body digest and rejects mismatched attestations; signer refuses unsealed intents. | `tests/gates/test_g4.py`<br>`tests/acceptance/test_e04.py`<br>`tests/unit/test_attestation.py` |
| **Approval Guardrails & Nonce Freshness** | Self-approvals, altered argument commitments, reused nonces, and expired keys/receipts fail closed as `blocked` ledger entries. | `tests/acceptance/test_e02.py`<br>`tests/acceptance/test_e10.py`<br>`tests/unit/test_po2_approval.py` |
| **Tool Definition Integrity** | Unauthorized modification of session tool definitions triggers `TOOL_DEF_CHANGE` and fails closed without provider effect. | `tests/acceptance/test_e12.py` |
| **Independent Offline Verification** | Pinned public keys verify Merkle inclusion, hash chain continuity, and certificate chains without connecting to the deployment. | `tests/acceptance/test_e01.py`<br>`tests/unit/test_verifier.py`<br>`tools/verifier/` |
| **Reconciler Forensic Verification** | Read-only join between ledger and provider event logs flags disagreements. | `tests/acceptance/test_e01.py`<br>`tests/acceptance/test_e03.py`<br>`tests/acceptance/test_e04.py` |
| **Epoch Key Containment & Rogue Epoch Defense** | A stolen epoch signing key cannot produce entries accepted outside that epoch's half-open validity window [from, until), produce entries under a revoked/never-issued epoch cert, or rewrite witnessed history. Proven with software keys; key extraction from process memory is out of scope. | `tests/acceptance/test_e11.py`<br>`tests/property/test_epoch_rollover.py`<br>`tests/unit/test_epochs_rules.py` |
| **Performance Under Load (Locust Benchmarking)** | Harness drives Gateway -> Signer -> Ledger -> ProviderMock under concurrent load with zero errors, continuous ledger sequences, and verified offline bundles. | `tests/acceptance/test_e09.py`<br>`bench/locustfile.py`<br>`bench/results.json` |
| **Crash Recovery & Fault Tolerance (Tasks C, E, E2b, R)** | Signer issuance journal prevents lost-response equivocation; durable quarantine and startup-enforced recovery anchor fail closed; operator rebuild CLI reconstructs state/index and authorizes sequence burns. | `tests/unit/test_signer_issuance_journal.py`<br>`tests/unit/test_signer_quarantine.py`<br>`tests/unit/test_signer_recovery_anchor.py`<br>`tests/unit/test_signer_rebuild_tool.py`<br>`tools/rebuild.py` |
| **Network Egress Control & Bypass Reconciliation** | Egress policy blocks direct agent network access to downstream providers (Layer 1); bypassed or loosened rules trigger provider UNATTESTED event logging and reconciler UNATTESTED_ACTION detection (Layer 2). | `tests/acceptance/test_e05.py`<br>`services/gateway/egress.py` |

### Not Claimed (Out of Prototype Scope)

The following capabilities are **not proven** and are **not claimed** by this in-process prototype:

| Unproven Area | Rationale / Missing Prerequisite | Tracked Scenario (XFAIL) |
| --- | --- | --- |
| **Hardware Key Custody & Zeroization** | Key extraction from process memory is out of scope. Hardware isolation and true key zeroization require HSM/KMS/TPM hardware custody. | Out of scope |
| **Public Anchor Durability** | OpenTimestamps and public Git anchoring (`services/anchor`) are optional Stage 5 extensions. | Deferred |

## Running Tests

```bash
uv sync --frozen --extra services --extra dev
uv run pytest
```
