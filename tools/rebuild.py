"""Signer crash recovery and state rebuild CLI tool (Task C, E, R)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.serialization import load_pem_private_key

from libs.blackbox_core.schemas import SealedEntry, parse_entry
from services.signer import quarantine, rebuild


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="blackbox-rebuild",
        description="BlackBox Signer State Rebuild & Recovery Tool (Task R)",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    # status
    p_status = commands.add_parser("status", help="Inspect signer storage health")
    p_status.add_argument("--state-path", type=Path, default=None)

    # quarantine
    p_quarantine = commands.add_parser("quarantine", help="Place signer into durable quarantine")
    p_quarantine.add_argument("--state-path", type=Path, default=None)
    p_quarantine.add_argument("--log-id", required=True)
    p_quarantine.add_argument("--reason", required=True)
    p_quarantine.add_argument("--details", default="")

    # rebuild
    p_rebuild = commands.add_parser("rebuild", help="Rebuild state and index from history prefix")
    p_rebuild.add_argument("--state-path", type=Path, required=True)
    p_rebuild.add_argument("--log-id", required=True)
    p_rebuild.add_argument("--frontier-seq", type=int, required=True)
    p_rebuild.add_argument("--frontier-hash", required=True)
    p_rebuild.add_argument("--history-file", type=Path, required=True)
    p_rebuild.add_argument("--operator-id", required=True)
    p_rebuild.add_argument("--reason", required=True)

    # burn
    p_burn = commands.add_parser("burn", help="Burn uncertain sequence range with Recovery entry")
    p_burn.add_argument("--state-path", type=Path, required=True)
    p_burn.add_argument("--log-id", required=True)
    p_burn.add_argument("--burned-first-seq", type=int, required=True)
    p_burn.add_argument("--burned-last-seq", type=int, required=True)
    p_burn.add_argument("--last-known-hash", required=True)
    p_burn.add_argument("--lost-epoch-id", type=int, required=True)
    p_burn.add_argument("--new-epoch-id", type=int, required=True)
    p_burn.add_argument("--key-file", type=Path, required=True)
    p_burn.add_argument("--operator-id", required=True)
    p_burn.add_argument("--reason", required=True)

    args = parser.parse_args(argv)

    try:
        if args.command == "status":
            status = rebuild.get_signer_status(args.state_path)
            print(json.dumps(status.to_dict(), indent=2))
            sys.exit(0 if status.healthy else 1)

        elif args.command == "quarantine":
            record = quarantine.enter_quarantine(
                log_id=args.log_id,
                reason=args.reason,
                details=args.details,
                path=args.state_path,
            )
            print(json.dumps(record.to_dict(), indent=2))

        elif args.command == "rebuild":
            # Read history file (array of JSON objects or JSONL)
            history_entries = []
            content = args.history_file.read_text(encoding="utf-8").strip()
            if content.startswith("["):
                raw_list = json.loads(content)
                for item in raw_list:
                    if "body" in item:
                        history_entries.append(SealedEntry.model_validate(item))
                    else:
                        history_entries.append(SealedEntry(body=parse_entry(item)))
            else:
                for line in content.splitlines():
                    if line.strip():
                        item = json.loads(line)
                        if "body" in item:
                            history_entries.append(SealedEntry.model_validate(item))
                        else:
                            history_entries.append(SealedEntry(body=parse_entry(item)))

            anchor = rebuild.rebuild_same_log(
                state_path=args.state_path,
                expected_log_id=args.log_id,
                frontier_seq=args.frontier_seq,
                frontier_hash=args.frontier_hash,
                history_entries=history_entries,
                operator_id=args.operator_id,
                reason=args.reason,
            )
            print(json.dumps(anchor.to_dict(), indent=2))

        elif args.command == "burn":
            key_bytes = args.key_file.read_bytes()
            signing_key = load_pem_private_key(key_bytes, password=None)
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

            if not isinstance(signing_key, Ed25519PrivateKey):
                raise ValueError("Key must be an Ed25519 private key")

            sealed, anchor = rebuild.burn_discontinuity(
                state_path=args.state_path,
                expected_log_id=args.log_id,
                burned_first_seq=args.burned_first_seq,
                burned_last_seq=args.burned_last_seq,
                last_known_hash=args.last_known_hash,
                lost_epoch_id=args.lost_epoch_id,
                new_epoch_id=args.new_epoch_id,
                signing_operation=signing_key.sign,
                operator_id=args.operator_id,
                reason=args.reason,
            )
            print(
                json.dumps(
                    {
                        "recovery_entry": sealed.model_dump(),
                        "recovery_anchor": anchor.to_dict(),
                    },
                    indent=2,
                )
            )

    except Exception as exc:
        print(json.dumps({"error": str(exc), "code": getattr(exc, "code", "rebuild_failed")}))
        sys.exit(2)


if __name__ == "__main__":
    main()
