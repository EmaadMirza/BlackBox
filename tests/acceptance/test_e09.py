"""E9: Load and performance smoke test.

Asserts that under concurrent load:
- The Gateway -> Signer -> Ledger -> ProviderMock pipeline executes with zero errors.
- Every sealed entry appears in the ledger exactly once (continuous, gapless sequence).
- Offline evidence verification of the resulting ledger entries produces verdict VERIFIED
  with zero verifier failures.

Does NOT assert an arbitrary speed target.
"""

from __future__ import annotations

import concurrent.futures
from pathlib import Path

from bench.harness import BenchmarkContext
from libs.blackbox_core.chain import GENESIS_PREV_HASH, entry_hash
from libs.blackbox_core.checkpoint import (
    build_checkpoint,
    build_cosignature,
    sign_checkpoint,
)
from libs.blackbox_core.encoding import (
    encode_base64url,
    encode_hash,
)
from libs.blackbox_core.evidence import (
    Bundle,
    CheckpointEvidence,
    InclusionProof,
    PinnedKeys,
)
from libs.blackbox_core.merkle import MerkleTree
from libs.blackbox_core.schemas import WitnessIdentity, WitnessSet
from libs.blackbox_core.sealing import sealed_bytes
from libs.blackbox_core.signing import sign_structure, structure_hash
from services.signer.clock import system_utc_now
from tools.verifier.verify import verify_evidence


def test_e09(tmp_path: Path) -> None:
    """E9 smoke test: harness runs, zero verifier failures, exact ledger completeness."""
    context = BenchmarkContext(tmp_path)
    concurrency = 5
    actions_per_worker = 10
    total_actions = concurrency * actions_per_worker
    expected_sealed_entries = (
        1 + total_actions * 2
    )  # 1 genesis epoch_start + (1 intent + 1 outcome) per action

    body = b'{"action":"read_invoice","invoice_id":"inv-load-test"}'
    results = []
    errors = []

    def worker_task(worker_id: int) -> None:
        for idx in range(actions_per_worker):
            idemp = f"sha256:{worker_id:08x}{idx:056x}"
            try:
                res = context.pipeline.execute("agent-1", "token-1", "read_invoice", body, idemp)
                results.append(res)
                if res.get("status") != "ok":
                    errors.append(f"Worker {worker_id} action {idx} status not ok: {res}")
            except Exception as exc:
                errors.append(f"Worker {worker_id} action {idx} raised {exc}")

    # Run concurrent workers
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(worker_task, w) for w in range(concurrency)]
        concurrent.futures.wait(futures)

    # 1. Assert zero pipeline errors
    assert len(errors) == 0, f"Harness produced errors under load: {errors}"
    assert len(results) == total_actions, f"Expected {total_actions} results, got {len(results)}"

    # 2. Assert every sealed entry appears in the ledger exactly once
    records = [r for (log, _), r in context.ledger.entries.items() if log == context.log_id]
    assert len(records) == expected_sealed_entries, (
        f"Expected {expected_sealed_entries} entries in ledger, found {len(records)}"
    )

    records.sort(key=lambda r: r.entry.body.seq)
    seqs = [r.entry.body.seq for r in records]
    assert seqs == list(range(expected_sealed_entries)), (
        "Sequences must be strictly continuous from 0..N-1"
    )
    assert len(set(seqs)) == expected_sealed_entries, "All sequence numbers must be unique"

    # Verify hash chain continuity
    for idx, record in enumerate(records):
        entry_body = record.entry.body
        if idx == 0:
            assert entry_body.prev_hash == GENESIS_PREV_HASH
        else:
            prev_entry = records[idx - 1].entry.body
            assert entry_body.prev_hash == entry_hash(prev_entry), f"Hash chain broken at seq {idx}"

    # 3. Offline verification under load
    leaves = [sealed_bytes(r.entry) for r in records]
    tree = MerkleTree(leaves)
    latest_entry = records[-1].entry
    stamp = system_utc_now()

    cp = sign_checkpoint(
        build_checkpoint(
            context.log_id,
            len(leaves),
            encode_hash(tree.root()),
            latest_entry.body.seq,
            0,
            stamp,
            latest_entry_hash=records[-1].entry_hash,
        ),
        context.epoch0[0],
    )
    cosigs = [
        build_cosignature(structure_hash(cp), f"w{i}", stamp, w[0], log_id=context.log_id)
        for i, w in enumerate(context.witnesses[:2])
    ]
    inc_proofs = [
        InclusionProof(
            seq=seq,
            tree_size=len(leaves),
            proof=[encode_hash(h) for h in tree.inclusion_proof(seq, len(leaves))],
        )
        for seq in range(len(leaves))
    ]
    ws = sign_structure(
        WitnessSet(
            log_id=context.log_id,
            version=1,
            witnesses=[
                WitnessIdentity(witness_id=f"w{i}", public_key=encode_base64url(k[1]))
                for i, k in enumerate(context.witnesses)
            ],
            quorum=2,
            effective_time="2026-01-01T00:00:00.000Z",
        ),
        context.root[0],
        "witness_set",
    )
    bundle = Bundle(
        format_version="4",
        log_id=context.log_id,
        log_name="bench-log",
        witness_set=ws,
        intermediates=[context.ic],
        epochs=[context.ec],
        checkpoints=[CheckpointEvidence(checkpoint=cp, cosignatures=cosigs)],
        entries=[r.entry.model_dump(mode="json") for r in records],
        inclusion_proofs=inc_proofs,
        consistency_proofs=[],
    )
    pins = PinnedKeys(
        log_id=context.log_id,
        log_name="bench-log",
        root_public_key=encode_base64url(context.root[1]),
        witness_public_keys={
            f"w{i}": encode_base64url(w[1]) for i, w in enumerate(context.witnesses)
        },
        minimum_tree_size=1,
    )

    report = verify_evidence(bundle, pins)
    assert report.verdict == "VERIFIED", (
        f"Offline verifier failed on load bundle: {report.to_dict()}"
    )
    assert all(e.verdict == "VERIFIED" for e in report.entries), (
        "All entries must verify without failure"
    )
