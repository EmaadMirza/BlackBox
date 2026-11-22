# BlackBox Security Claims

## Verified Claims

| Security Claim | Description | Proving Tests | Status |
| --- | --- | --- | --- |
| **History Integrity & Tamper Evidence** | Any mutation or deletion in ledger history is detected by offline verification and rejected by witnesses. | `tests/gates/test_g1_tamper.py`<br>`tests/gates/test_g2_merkle.py`<br>`tests/gates/test_g3.py`<br>`tests/gates/test_g3_witness_refusal.py`<br>`tests/acceptance/test_e03.py`<br>`tests/acceptance/test_e08.py` | Proven |
| **Witness Quorum & Split-View Defense** | Checkpoints require distinct witness quorum (2/3); conflicting roots for same tree size trigger `SPLIT_VIEW`. | `tests/acceptance/test_e06.py`<br>`tests/acceptance/test_e07.py`<br>`tests/unit/test_w4_gossip.py`<br>`tests/unit/test_witness_http_processor.py` | Proven |
| **Attestation Binding & Body Integrity** | Provider independently recomputes raw request-body digest and rejects mismatched attestations; signer refuses unsealed intents. | `tests/gates/test_g4.py`<br>`tests/acceptance/test_e04.py`<br>`tests/unit/test_attestation.py` | Proven |
| **Approval Guardrails & Nonce Freshness** | Self-approvals, altered argument commitments, reused nonces, and expired keys/receipts fail closed as `blocked` ledger entries. | `tests/acceptance/test_e02.py`<br>`tests/acceptance/test_e10.py`<br>`tests/unit/test_po2_approval.py` | Proven |
| **Tool Definition Integrity** | Unauthorized modification of session tool definitions triggers `TOOL_DEF_CHANGE` and fails closed without provider effect. | `tests/acceptance/test_e12.py` | Proven |
| **Independent Offline Verification** | Pinned public keys verify Merkle inclusion, hash chain continuity, and certificate chains without connecting to the deployment. | `tests/acceptance/test_e01.py`<br>`tests/unit/test_verifier.py`<br>`tools/verifier/` | Proven |
| **Reconciler Forensic Verification** | Read-only join between ledger and provider event logs flags disagreements. | `tests/acceptance/test_e01.py`<br>`tests/acceptance/test_e03.py`<br>`tests/acceptance/test_e04.py` | Proven |
| **Epoch Key Containment & Rogue Epoch Defense** | A stolen epoch signing key cannot (a) produce entries accepted outside that epoch's half-open validity window `[from, until)`, (b) produce entries under a revoked or never-issued epoch cert, or (c) rewrite witnessed history. | `tests/acceptance/test_e11.py`<br>`tests/property/test_epoch_rollover.py`<br>`tests/unit/test_epochs_rules.py` | Proven (software keys; the key-custody threat is NOT addressed) |
| **Performance Under Load (Locust Benchmarking)** | Harness drives Gateway -> Signer -> Ledger -> ProviderMock under concurrent load with zero errors, continuous ledger sequences, and verified offline bundles. | `tests/acceptance/test_e09.py`<br>`bench/locustfile.py`<br>`bench/results.json` | Proven (single laptop, local in-process / PostgreSQL interface, not a production benchmark) |

### Performance Benchmark Measurements (`bench/results.json`)

> [!NOTE]
> **Environment & Machine Specs:** macOS (Apple Silicon arm64, 10 CPU cores, Python 3.14.4).  
> *Single laptop, local in-process / PostgreSQL interface, not a production benchmark.*

#### 1. Latency per Action (Direct Provider vs Through BlackBox)
| Metric | Direct Provider Mock | Through BlackBox Gateway | Added Overhead ($\Delta$) |
| --- | :---: | :---: | :---: |
| **p50 Latency** | 0.007 ms | 1.200 ms | **+1.193 ms** |
| **p95 Latency** | 0.011 ms | 1.383 ms | **+1.372 ms** |
| **p99 Latency** | 0.109 ms | 1.839 ms | **+1.730 ms** |
| **Mean Latency** | 0.008 ms | 1.221 ms | **+1.213 ms** |

#### 2. Throughput Under Locust Concurrent Load
| Load Level | Concurrency (Users) | Spawn Rate | Actions/sec | Sealed Entries/sec | Failures |
| --- | :---: | :---: | :---: | :---: | :---: |
| **Low Load** | 2 | 2 / s | 337.0 req/s | **674.0 entries/s** | 0 |
| **Medium Load** | 10 | 5 / s | 780.2 req/s | **1560.4 entries/s** | 0 |
| **High Load** | 25 | 10 / s | 762.2 req/s | **1524.4 entries/s** | 0 |

#### 3. Merkle Proof Generation Time
| Tree Size | Tree Build Time | Inclusion Proof (Mid-Tree) | Proof Length | Consistency Proof (Mid-to-Full) | Proof Length |
| --- | :---: | :---: | :---: | :---: | :---: |
| **1,000 entries** | 0.015 ms | 0.844 ms | 10 hashes | 0.007 ms | 9 hashes |
| **10,000 entries** | 0.034 ms | 7.888 ms | 14 hashes | 0.007 ms | 12 hashes |

#### 4. Offline Evidence Bundle Verification
| Bundle Size | Verification Time | Verification Rate | Verifier Verdict |
| --- | :---: | :---: | :---: |
| **1,000 entries** | 719.83 ms | 1389.2 entries/sec | **VERIFIED** (0 errors) |
| **10,000 entries** | 7281.84 ms | 1373.3 entries/sec | **VERIFIED** (0 errors) |

#### 5. Unverified-Window Length
- **Action Execution Duration:** 1.98 ms
- **Checkpoint Issuance & Witness Cosigning:** 1863.11 ms
- **Total Unverified Window:** **1865.09 ms (~1.86 s)**

---

### 10. Crash Recovery & Fault Tolerance (Tasks C, E, E2b, R)
- **Signer Issuance Journal (Task E2b):** Append-only durable journal (`services/signer/journal.py`) guarantees every sealed entry is persisted and `fsync`ed before returning to callers, preventing sequence equivocation across crashes and enabling lost-response reconciliation.
- **Durable Quarantine Storage (Task E):** Unclean shutdown or marker detection triggers persistent quarantine (`services/signer/quarantine.py`); `/seal` and `/attest` fail closed with HTTP 503 `quarantined`.
- **Startup-Enforced Recovery Anchor (Task E):** Rejects state sequences below the authenticated recovery frontier; prevents sequence rollback.
- **Automated Operator Rebuild CLI (Task R):** `tools/rebuild.py` inspects health (`status`), enters quarantine (`quarantine`), reconstructs state and outcome indexes from complete prefix evidence (`rebuild`), and mints signed `Recovery` entries for authorized sequence burning (`burn`) per Spec Amendment 001.
- **Proving Tests:** `tests/unit/test_signer_issuance_journal.py`, `tests/unit/test_signer_quarantine.py`, `tests/unit/test_signer_recovery_anchor.py`, `tests/unit/test_signer_rebuild_tool.py`.

---

### 11. Network Egress Control & Bypass Reconciliation (Scenario E5)
- **Active Egress Control (Layer 1):** Agent network boundary (`services/gateway/egress.py`) blocks direct outbound connections from agent containers to downstream providers; direct attempts fail closed (`EgressBlockedError`), ensuring zero direct traffic reaches providers.
- **Safety Net & Reconciler Detection (Layer 2):** When egress control is bypassed or loosened, requests reach the provider without valid Gateway attestations. In enforcement mode, the provider rejects with HTTP 403 and alarms `UNATTESTED_ACTION`. In non-enforcing audit mode, the direct call succeeds at the provider (HTTP 200), but the Reconciler independently joins the ledger and provider logs, flagging `UNATTESTED_ACTION`.
- **Proving Tests:** `tests/acceptance/test_e05.py`.

---

## Not Claimed (Out of Prototype Scope)

The following capabilities are **not proven** and are **not claimed** by this in-process prototype:

- **Key extraction from process memory is out of scope:** Python process memory cannot guarantee key zeroization. Bounded forward forgery in the presence of physical or host memory compromise requires HSM/KMS hardware custody.
- **Public Anchor Durability:** OpenTimestamps and public Git anchoring (`services/anchor`) are optional Stage 5 extensions.
