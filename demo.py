"""BlackBox End-to-End Forensic Demonstration.

Runs 5 core security scenarios and verifies defenses:
1. Honest agent session -> verifier: VERIFIED
2. Edit one entry -> verifier: TAMPERED
3. Delete one entry -> verifier: MISSING
4. Gateway logs one body, sends another -> provider rejects
5. Ledger rewrite -> witness refuses
"""

from __future__ import annotations

import json
import sys
import tempfile
import warnings
from pathlib import Path

from fastapi.testclient import TestClient

from libs.blackbox_core.checkpoint import build_checkpoint, sign_checkpoint
from libs.blackbox_core.encoding import encode_base64url
from libs.blackbox_core.schemas import SealedEntry
from services.gateway.pipeline import GatewayPipeline
from services.gateway.policy.engine import PolicyEngine, load_rules
from services.payload_store.main import PayloadStore
from services.provider_mock.main import ProviderMock
from services.witness.main import WitnessConfig
from services.witness.main import create_app as create_witness_app
from tools.attack_suite.fixture import build_demo
from tools.attack_suite.tamper_battery import variants
from tools.ceremony import generate_dev_keys
from tools.verifier.verify import verify_evidence

warnings.filterwarnings("ignore")

# ANSI color codes
GREEN = "\033[92m"
RED = "\033[91m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def print_banner(step_num: int, title: str) -> None:
    print(f"\n{BOLD}{CYAN}{'=' * 68}{RESET}")
    print(f"{BOLD}{CYAN}Step {step_num}: {title}{RESET}")
    print(f"{BOLD}{CYAN}{'=' * 68}{RESET}")


def print_result(label: str, passed: bool, detail: str = "") -> None:
    tag = f"{GREEN}{BOLD}[PASS]{RESET}" if passed else f"{RED}{BOLD}[FAIL]{RESET}"
    print(f"\nResult: {tag} {label}")
    if detail:
        print(f"{DIM}{detail}{RESET}")


def step_1_honest() -> tuple[object, object]:
    print_banner(1, "Honest Agent Session -> Offline Verifier")
    print("Action:")
    print("  - Generating an honest workload: root/intermediate/epoch certificates,")
    print("    intents, approvals, tool-defs, and outcomes across 2 epoch windows.")
    print("  - Running offline verifier against externally pinned root public keys.")

    keys = generate_dev_keys()
    bundle, pins = build_demo(keys)

    report = verify_evidence(bundle, pins)
    passed = report.verdict == "VERIFIED"
    print_result(
        f"Verifier Verdict: {report.verdict}",
        passed,
        f"Verified {len(bundle.entries)} entries, Merkle inclusion proofs, and cosigned checkpoints.",
    )
    if not passed:
        sys.exit(1)
    return bundle, pins


def step_2_tampered(bundle: object, pins: object) -> None:
    print_banner(2, "Edit One Entry -> Tamper Detection")
    print("Action:")
    print("  - Simulating an attacker modifying entry #5 payload on disk.")
    print("  - Attacker recomputed the hash chain (prev_hash) forward to mask the edit.")
    print("  - Running offline verifier to inspect signature against signer epoch certificate.")

    battery = variants(bundle)
    tampered_bundle = battery["edit_and_rehash"]

    report = verify_evidence(tampered_bundle, pins)
    passed = report.verdict == "TAMPERED"
    print_result(
        f"Verifier Verdict: {report.verdict}",
        passed,
        "Signature mismatch detected on modified entry body; chain re-hashing could not forge signature.",
    )
    if not passed:
        sys.exit(1)


def step_3_missing(bundle: object, pins: object) -> None:
    print_banner(3, "Delete One Entry -> Missing Entry Detection")
    print("Action:")
    print("  - Simulating host operator deleting entry #7 to hide forensic trace.")
    print("  - Running offline verifier against witnessed checkpoints.")

    battery = variants(bundle)
    missing_bundle = battery["delete_seq_7"]

    report = verify_evidence(missing_bundle, pins)
    passed = report.verdict == "MISSING"
    print_result(
        f"Verifier Verdict: {report.verdict}",
        passed,
        "Sequence gap detected against witnessed tree size and hash frontier.",
    )
    if not passed:
        sys.exit(1)


def step_4_gateway_discrepancy() -> None:
    print_banner(4, "Compromised Gateway Logs One Body, Sends Another -> Provider Rejects")
    print("Action:")
    print(
        '  - Gateway logs & seals intent for $1.00 refund: b\'{"action":"refund","amount_minor":100}\''
    )
    print("  - Gateway attempts forwarding $50,000 to attacker using that same attestation.")
    print("  - Mock Provider recomputes raw SHA-256 digest on received request body.")

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        rules = load_rules(Path("services/gateway/policy/rules.yaml"))
        policy = PolicyEngine(rules)
        provider = ProviderMock(enforcement_enabled=True)

        class DemoSigner:
            def __init__(self) -> None:
                self.sealed_intents: dict[int, object] = {}
                self._seq = 0

            def seal(self, candidate: object) -> SealedEntry:
                body = candidate.model_copy(update={"seq": self._seq})
                self._seq += 1
                sealed = SealedEntry(body=body, signature=encode_base64url(b"\x00" * 64))
                if getattr(body, "type", "") == "intent":
                    self.sealed_intents[body.seq] = body
                return sealed

            def attest(self, intent_or_seq: object) -> dict[str, object]:
                seq = intent_or_seq if isinstance(intent_or_seq, int) else intent_or_seq.seq
                it = self.sealed_intents[seq]
                return {
                    "log_id": it.log_id,
                    "intent_seq": it.seq,
                    "idempotency_key": it.action.idempotency_key,
                    "body_digest": it.action.body_digest,
                    "issued_at": it.signer_timestamp,
                    "expires_at": "2026-01-01T00:10:00.000Z",
                    "signature": encode_base64url(b"\x00" * 64),
                }

        signer = DemoSigner()
        pipeline = GatewayPipeline(
            signer=signer,
            provider=provider,
            payload_store=PayloadStore(tmp_path / "store"),
            policy=policy,
            agent_tokens={"agent-1": "token-xyz"},
            clock=lambda: "2026-01-01T00:00:00.000Z",
        )

        logged_body = b'{"action":"refund","amount_minor":100}'
        dispatched_body = b'{"action":"refund","amount_minor":5000000}'

        # Seal genuine intent for $1.00
        res = pipeline.execute(
            "agent-1", "token-xyz", "read_invoice", logged_body, "sha256:" + "4" * 64
        )
        attestation = signer.attest(res["intent_seq"])

        # Forward $50,000 using $1.00 attestation
        headers = {"X-BlackBox-Attestation": json.dumps(attestation)}
        tampered_response = provider.request(dispatched_body, headers)

        passed = (
            tampered_response["status"] == 400
            and tampered_response.get("error") == "ATTESTATION_BODY_MISMATCH"
        )
        print_result(
            "Provider Rejected Tampered Body with ATTESTATION_BODY_MISMATCH",
            passed,
            f"Provider HTTP status: {tampered_response['status']}, error: {tampered_response.get('error')}",
        )
        if not passed:
            sys.exit(1)


def step_5_ledger_rewrite() -> None:
    print_banner(5, "Ledger Rewrite -> Witness Refusal & Quorum Failure")
    print("Action:")
    print("  - Initial legitimate checkpoint submitted to Witness -> Accepted (200 OK).")
    print("  - Host rewrites history and attempts to obtain a cosignature on altered root.")
    print("  - Witness validates RFC 6962 consistency proof against previous tree state.")

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        keys = generate_dev_keys()
        bundle, pins = build_demo(keys)
        first_checkpoint = bundle.checkpoints[-1].checkpoint

        w_key = keys[4]
        key_path = tmp_path / "w0.raw"
        key_path.write_bytes(w_key[0].private_bytes_raw())
        key_path.chmod(0o600)

        config = WitnessConfig(
            root_public_key=pins.root_public_key,
            witness_set=bundle.witness_set,
            intermediates=bundle.intermediates,
            epochs=bundle.epochs,
            witness_id="w0",
            witness_key_path=key_path,
            state_dir=tmp_path / "state",
            evidence_dir=tmp_path / "evidence",
            bearer_token="token",
            clock=lambda: "2026-01-01T01:00:00.000Z",
        )

        app = create_witness_app(config)
        with TestClient(app) as client:
            headers = {"Authorization": "Bearer token"}

            # 1. Accept first checkpoint
            resp_init = client.post(
                "/v1/checkpoint",
                json={
                    "log_id": first_checkpoint.log_id,
                    "checkpoint": first_checkpoint.model_dump(mode="json"),
                    "from_size": 0,
                    "consistency_proof": [],
                },
                headers=headers,
            )
            assert resp_init.status_code == 200

            # 2. Attempt rewritten checkpoint with conflicting root
            rewritten_checkpoint = sign_checkpoint(
                build_checkpoint(
                    first_checkpoint.log_id,
                    first_checkpoint.tree_size + 2,
                    "sha256:" + "f" * 64,
                    first_checkpoint.tree_size + 1,
                    first_checkpoint.epoch_id,
                    "2026-01-01T00:09:59.000Z",
                ),
                keys[3][0],
            )
            resp_rewrite = client.post(
                "/v1/checkpoint",
                json={
                    "log_id": first_checkpoint.log_id,
                    "checkpoint": rewritten_checkpoint.model_dump(mode="json"),
                    "from_size": first_checkpoint.tree_size,
                    "consistency_proof": ["sha256:" + "0" * 64],
                },
                headers=headers,
            )

            alarms = client.get(
                "/v1/alarms", params={"log_id": first_checkpoint.log_id}, headers=headers
            ).json()

            passed = (
                resp_rewrite.status_code == 409
                and resp_rewrite.json().get("error", {}).get("code") == "bad_proof"
                and any(a.get("alarm_type") == "WITNESS_REFUSAL" for a in alarms)
            )

            print_result(
                "Witness Refused Rewritten History with 'bad_proof' (HTTP 409)",
                passed,
                "WITNESS_REFUSAL alarm logged; cosignature denied; ledger rewrite blocked from quorum.",
            )
            if not passed:
                sys.exit(1)


def main() -> None:
    print(f"\n{BOLD}{'#' * 68}")
    print("#  BLACKBOX FORENSIC PROTOTYPE: END-TO-END VERIFICATION DEMO")
    print(f"{'#' * 68}{RESET}")

    bundle, pins = step_1_honest()
    step_2_tampered(bundle, pins)
    step_3_missing(bundle, pins)
    step_4_gateway_discrepancy()
    step_5_ledger_rewrite()

    print(f"\n{BOLD}{GREEN}{'=' * 68}")
    print("ALL 5 FORENSIC SCENARIOS COMPLETED SUCCESSFULLY [PASS]")
    print(f"{'=' * 68}{RESET}\n")


if __name__ == "__main__":
    main()
