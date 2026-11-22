"""BlackBox E9 Load & Performance Benchmarking Harness.

Uses Locust to drive Gateway -> Signer -> Ledger -> ProviderMock under load
and measures latency, throughput, Merkle proofs, offline verification,
and unverified-window length.
"""

from __future__ import annotations

import json
import multiprocessing
import platform
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from locust import User, between, task
from locust.env import Environment

from bench.harness import BenchmarkContext
from libs.blackbox_core.chain import GENESIS_PREV_HASH, entry_hash
from libs.blackbox_core.checkpoint import (
    build_checkpoint,
    build_cosignature,
    sign_checkpoint,
)
from libs.blackbox_core.crypto import sha256
from libs.blackbox_core.encoding import (
    encode_base64url,
    encode_hash,
)
from libs.blackbox_core.epochs import (
    build_epoch_certificate,
    build_intermediate_certificate,
    certificate_id,
)
from libs.blackbox_core.evidence import (
    Bundle,
    CheckpointEvidence,
    InclusionProof,
    PinnedKeys,
)
from libs.blackbox_core.labels import derive_log_id
from libs.blackbox_core.merkle import MerkleTree, leaf_hash
from libs.blackbox_core.schemas import (
    WitnessIdentity,
    WitnessSet,
    parse_entry,
)
from libs.blackbox_core.sealing import seal, sealed_bytes
from libs.blackbox_core.signing import sign_structure, structure_hash
from services.signer.clock import system_utc_now
from tests._dev_keys import dev_key
from tools.verifier.verify import verify_evidence

# Global benchmark context for Locust worker tasks
_GLOBAL_CONTEXT: BenchmarkContext | None = None


def get_context() -> BenchmarkContext:
    global _GLOBAL_CONTEXT
    if _GLOBAL_CONTEXT is None:
        temp_dir = Path(tempfile.mkdtemp(prefix="blackbox_bench_"))
        _GLOBAL_CONTEXT = BenchmarkContext(temp_dir)
    return _GLOBAL_CONTEXT


class BlackBoxUser(User):
    """Locust user driving honest agent actions through the BlackBox Gateway."""

    wait_time = between(0.001, 0.005)

    def on_start(self) -> None:
        self.context = get_context()
        self.body = b'{"action":"read_invoice","invoice_id":"inv-101"}'

    @task(5)
    def action_through_blackbox(self) -> None:
        idemp = self.context.next_action_id()
        t0 = time.perf_counter()
        exception = None
        try:
            res = self.context.pipeline.execute(
                "agent-1", "token-1", "read_invoice", self.body, idemp
            )
            if res.get("status") != "ok":
                exception = RuntimeError(f"Unexpected status: {res.get('status')}")
        except Exception as e:
            exception = e
        elapsed_ms = (time.perf_counter() - t0) * 1000

        self.environment.events.request.fire(
            request_type="EXEC",
            name="blackbox_gateway_action",
            response_time=elapsed_ms,
            response_length=len(self.body),
            exception=exception,
            context={},
        )

    @task(1)
    def action_direct_provider(self) -> None:
        t0 = time.perf_counter()
        exception = None
        try:
            self.context.provider.request(self.body, {})
        except Exception as e:
            exception = e
        elapsed_ms = (time.perf_counter() - t0) * 1000

        self.environment.events.request.fire(
            request_type="EXEC",
            name="direct_provider_action",
            response_time=elapsed_ms,
            response_length=len(self.body),
            exception=exception,
            context={},
        )


def measure_latencies(context: BenchmarkContext, n: int = 100) -> dict[str, dict[str, float]]:
    """Measure direct provider vs BlackBox latency percentiles (p50/p95/p99)."""
    body = b'{"action":"read_invoice","invoice_id":"inv-101"}'

    # 1. Direct provider calls
    direct_times = []
    for _ in range(n):
        t0 = time.perf_counter()
        context.provider.request(body, {})
        direct_times.append((time.perf_counter() - t0) * 1000)
    direct_times.sort()

    # 2. BlackBox Gateway calls
    bb_times = []
    for _ in range(n):
        idemp = context.next_action_id()
        t0 = time.perf_counter()
        context.pipeline.execute("agent-1", "token-1", "read_invoice", body, idemp)
        bb_times.append((time.perf_counter() - t0) * 1000)
    bb_times.sort()

    def percentiles(arr: list[float]) -> dict[str, float]:
        return {
            "p50_ms": round(arr[int(len(arr) * 0.50)], 3),
            "p95_ms": round(arr[int(len(arr) * 0.95)], 3),
            "p99_ms": round(arr[int(len(arr) * 0.99)], 3),
            "mean_ms": round(sum(arr) / len(arr), 3),
        }

    p_direct = percentiles(direct_times)
    p_bb = percentiles(bb_times)
    p_added = {
        "p50_ms": round(p_bb["p50_ms"] - p_direct["p50_ms"], 3),
        "p95_ms": round(p_bb["p95_ms"] - p_direct["p95_ms"], 3),
        "p99_ms": round(p_bb["p99_ms"] - p_direct["p99_ms"], 3),
        "mean_ms": round(p_bb["mean_ms"] - p_direct["mean_ms"], 3),
    }

    return {
        "direct_provider": p_direct,
        "through_blackbox": p_bb,
        "added_overhead": p_added,
    }


def measure_merkle_proofs(
    sizes: tuple[int, ...] = (1000, 10000),
) -> dict[str, dict[str, Any]]:
    """Measure Merkle inclusion and consistency proof generation times."""
    results = {}
    for n in sizes:
        leaves = [leaf_hash(sha256(f"leaf-{i}".encode())) for i in range(n)]
        t0 = time.perf_counter()
        tree = MerkleTree(leaves)
        tree_build_ms = (time.perf_counter() - t0) * 1000

        t0 = time.perf_counter()
        inc_proof = tree.inclusion_proof(n // 2, n)
        inc_ms = (time.perf_counter() - t0) * 1000

        t0 = time.perf_counter()
        cons_proof = tree.consistency_proof(n // 2, n)
        cons_ms = (time.perf_counter() - t0) * 1000

        results[f"{n}_entries"] = {
            "tree_size": n,
            "tree_build_ms": round(tree_build_ms, 3),
            "inclusion_proof_ms": round(inc_ms, 3),
            "inclusion_proof_length": len(inc_proof),
            "consistency_proof_ms": round(cons_ms, 3),
            "consistency_proof_length": len(cons_proof),
        }
    return results


def measure_offline_verification(
    sizes: tuple[int, ...] = (1000, 10000),
) -> dict[str, dict[str, Any]]:
    """Measure offline evidence verification times for synthetic bundles."""
    keys = [(dev_key(i), dev_key(i).public_key().public_bytes_raw()) for i in range(1, 8)]
    root, inter, epoch0, epoch1, *witnesses = keys
    log = derive_log_id(root[1], "bench-verify-log")

    ic = build_intermediate_certificate(
        log,
        "intermediate-0",
        encode_base64url(inter[1]),
        "2026-01-01T00:00:00.000Z",
        "2026-02-01T00:00:00.000Z",
        root[0],
    )
    ec = build_epoch_certificate(
        0,
        encode_base64url(epoch0[1]),
        "2026-01-01T00:00:00.000Z",
        "2026-01-02T00:00:00.000Z",
        "intermediate-0",
        log_id=log,
        signing_operation=inter[0],
    )
    ws = sign_structure(
        WitnessSet(
            log_id=log,
            version=1,
            witnesses=[
                WitnessIdentity(witness_id=f"w{i}", public_key=encode_base64url(k[1]))
                for i, k in enumerate(witnesses)
            ],
            quorum=2,
            effective_time="2026-01-01T00:00:00.000Z",
        ),
        root[0],
        "witness_set",
    )
    pins = PinnedKeys(
        log_id=log,
        log_name="bench-verify-log",
        root_public_key=encode_base64url(root[1]),
        witness_public_keys={f"w{i}": encode_base64url(w[1]) for i, w in enumerate(witnesses)},
        minimum_tree_size=1,
    )

    results = {}
    for n in sizes:
        entries = []
        prev = GENESIS_PREV_HASH
        for seq in range(n):
            body = dict(
                format_version="4",
                log_id=log,
                epoch_id=0,
                seq=seq,
                signer_timestamp=f"2026-01-01T00:{seq // 600:02d}:{(seq % 600) // 10:02d}.{seq % 10:03d}Z",
                prev_hash=prev,
                lane="agent",
                epoch_certificate_id=certificate_id(ec),
            )
            if seq == 0:
                body.update(type="epoch_start", certificate=ec.model_dump())
            else:
                body.update(
                    type="action",
                    action_name="bench_action",
                    reason="bench",
                    target_reference=f"ref-{seq}",
                )
            entry = seal(parse_entry(body), epoch0[0])
            entries.append(entry)
            prev = entry_hash(entry.body)

        tree = MerkleTree([sealed_bytes(e) for e in entries])
        stamp = "2026-01-01T00:59:59.000Z"
        cp = sign_checkpoint(
            build_checkpoint(
                log,
                n,
                encode_hash(tree.root()),
                n - 1,
                0,
                stamp,
                latest_entry_hash=prev,
            ),
            epoch0[0],
        )
        cosigs = [
            build_cosignature(structure_hash(cp), f"w{i}", stamp, w[0], log_id=log)
            for i, w in enumerate(witnesses[:2])
        ]
        inc_proofs = [
            InclusionProof(
                seq=seq,
                tree_size=n,
                proof=[encode_hash(h) for h in tree.inclusion_proof(seq, n)],
            )
            for seq in range(n)
        ]
        bundle = Bundle(
            format_version="4",
            log_id=log,
            log_name="bench-verify-log",
            witness_set=ws,
            intermediates=[ic],
            epochs=[ec],
            checkpoints=[CheckpointEvidence(checkpoint=cp, cosignatures=cosigs)],
            entries=[e.model_dump(mode="json") for e in entries],
            inclusion_proofs=inc_proofs,
            consistency_proofs=[],
        )

        t0 = time.perf_counter()
        report = verify_evidence(bundle, pins)
        ver_ms = (time.perf_counter() - t0) * 1000

        results[f"{n}_entries"] = {
            "entries_count": n,
            "verification_time_ms": round(ver_ms, 3),
            "verdict": report.verdict,
            "rate_entries_per_sec": round(n / (ver_ms / 1000), 1),
        }
    return results


def measure_unverified_window(context: BenchmarkContext) -> dict[str, float]:
    """Measure the time between an action completing and its checkpoint being cosigned."""
    body = b'{"action":"read_invoice","invoice_id":"inv-101"}'
    idemp = context.next_action_id()

    # 1. Action completes and seals outcome
    t_start = time.perf_counter()
    context.pipeline.execute("agent-1", "token-1", "read_invoice", body, idemp)
    t_action_done = time.perf_counter()

    # 2. Checkpointer forms checkpoint from ledger entries
    stored = context.ledger.entries
    records = [r for (log, _), r in stored.items() if log == context.log_id]
    records.sort(key=lambda r: r.entry.body.seq)
    leaves = [sealed_bytes(r.entry) for r in records]
    tree = MerkleTree(leaves)
    latest = records[-1].entry

    cp = sign_checkpoint(
        build_checkpoint(
            context.log_id,
            len(leaves),
            encode_hash(tree.root()),
            latest.body.seq,
            0,
            system_utc_now(),
            latest_entry_hash=records[-1].entry_hash,
        ),
        context.epoch0[0],
    )

    # 3. Witnesses cosign
    stamp = system_utc_now()
    _ = [
        build_cosignature(structure_hash(cp), f"w{i}", stamp, w[0], log_id=context.log_id)
        for i, w in enumerate(context.witnesses[:2])
    ]
    t_cosigned = time.perf_counter()

    action_duration_ms = (t_action_done - t_start) * 1000
    checkpointing_ms = (t_cosigned - t_action_done) * 1000
    total_unverified_window_ms = (t_cosigned - t_start) * 1000

    return {
        "action_execution_ms": round(action_duration_ms, 3),
        "checkpoint_cosigning_ms": round(checkpointing_ms, 3),
        "unverified_window_ms": round(total_unverified_window_ms, 3),
    }


def run_locust_load_test(
    user_count: int, spawn_rate: float, duration_seconds: int
) -> dict[str, Any]:
    """Run a headless Locust load test at a specified concurrency level."""
    import gevent

    env = Environment(user_classes=[BlackBoxUser])
    runner = env.create_local_runner()
    runner.start(user_count=user_count, spawn_rate=spawn_rate)
    gevent.sleep(duration_seconds)
    runner.stop()

    stats_bb = env.stats.get("blackbox_gateway_action", "EXEC")

    total_actions = stats_bb.num_requests
    sealed_entries = total_actions * 2  # 1 intent + 1 outcome per action
    actions_per_sec = total_actions / duration_seconds if duration_seconds > 0 else 0
    entries_per_sec = sealed_entries / duration_seconds if duration_seconds > 0 else 0

    return {
        "concurrency_users": user_count,
        "spawn_rate": spawn_rate,
        "duration_seconds": duration_seconds,
        "total_actions": total_actions,
        "sealed_entries": sealed_entries,
        "failures": stats_bb.num_failures,
        "actions_per_sec": round(actions_per_sec, 1),
        "sealed_entries_per_sec": round(entries_per_sec, 1),
        "latency_p50_ms": round(stats_bb.get_response_time_percentile(0.5) or 0, 2),
        "latency_p95_ms": round(stats_bb.get_response_time_percentile(0.95) or 0, 2),
        "latency_p99_ms": round(stats_bb.get_response_time_percentile(0.99) or 0, 2),
    }


def run_all_benchmarks() -> dict[str, Any]:
    """Execute all benchmark suites and compile the comprehensive results."""
    print("Running BlackBox benchmarks...")
    temp_dir = Path(tempfile.mkdtemp(prefix="blackbox_e09_"))
    context = BenchmarkContext(temp_dir)
    global _GLOBAL_CONTEXT
    _GLOBAL_CONTEXT = context

    # System Specs
    specs = {
        "os": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "cpu_count": multiprocessing.cpu_count(),
        "python_version": platform.python_version(),
        "benchmark_environment": "single laptop, local in-process / PostgreSQL interface, not a production benchmark",
    }
    print(f"Machine: {specs['machine']}, {specs['cpu_count']} cores, {specs['os']}")

    # 1. Latency percentiles comparison
    print("Measuring added latency (direct vs BlackBox)...")
    latencies = measure_latencies(context, n=100)

    # 2. Locust Load Levels (Low, Medium, High)
    print("Running Locust load levels (low=2 users, med=10 users, high=25 users)...")
    load_results = {
        "low_load": run_locust_load_test(user_count=2, spawn_rate=2, duration_seconds=5),
        "medium_load": run_locust_load_test(user_count=10, spawn_rate=5, duration_seconds=5),
        "high_load": run_locust_load_test(user_count=25, spawn_rate=10, duration_seconds=5),
    }

    # 3. Merkle proof generation times
    print("Measuring Merkle proof generation times (1k and 10k)...")
    merkle_proofs = measure_merkle_proofs((1000, 10000))

    # 4. Offline verification times
    print("Measuring offline evidence verification (1k and 10k)...")
    offline_ver = measure_offline_verification((1000, 10000))

    # 5. Unverified-window length
    print("Measuring unverified-window length...")
    unverified_window = measure_unverified_window(context)

    # Compile final results
    results = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "system_specs": specs,
        "latency_percentiles": latencies,
        "locust_load_levels": load_results,
        "merkle_proof_generation": merkle_proofs,
        "offline_bundle_verification": offline_ver,
        "unverified_window": unverified_window,
    }

    # Write results.json
    out_path = Path("bench/results.json")
    out_path.write_text(json.dumps(results, indent=2))
    print(f"Results written to {out_path}")
    return results


def main() -> None:
    results = run_all_benchmarks()
    print("\nBenchmark Summary:")
    print(f"  Added latency (p50): {results['latency_percentiles']['added_overhead']['p50_ms']} ms")
    print(
        f"  Throughput (high load): {results['locust_load_levels']['high_load']['sealed_entries_per_sec']} entries/sec"
    )
    print(
        f"  10k Merkle inclusion proof: {results['merkle_proof_generation']['10000_entries']['inclusion_proof_ms']} ms"
    )
    print(
        f"  10k bundle offline verify: {results['offline_bundle_verification']['10000_entries']['verification_time_ms']} ms"
    )
    print(f"  Unverified window: {results['unverified_window']['unverified_window_ms']} ms")


if __name__ == "__main__":
    main()
