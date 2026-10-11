"""Offline verifier and development attack-suite CLI (spec §17.3)."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from tools.verifier.verify import verify_bundle


def main() -> None:
    parser = argparse.ArgumentParser(prog="blackbox")
    commands = parser.add_subparsers(dest="command", required=True)
    verifier = commands.add_parser("verify")
    verifier.add_argument("bundle", type=Path)
    verifier.add_argument("--pinned-keys", type=Path, required=True)
    attacks = commands.add_parser("attack-suite")
    attacks.add_argument("--output", type=Path)
    for name in ("export-bundle", "status", "reconcile-report"):
        commands.add_parser(name)
    args = parser.parse_args()
    if args.command == "verify":
        try:
            report = verify_bundle(args.bundle, args.pinned_keys)
        except (ValueError, OSError, RecursionError) as exc:
            print(
                json.dumps(
                    {
                        "error": str(exc),
                        "verdict": "TAMPERED",
                        "scope": "input could not be verified",
                    }
                )
            )
            raise SystemExit(2) from exc
        print(json.dumps(report.to_dict(), indent=2))
        raise SystemExit(0 if report.verdict == "VERIFIED" else 1)
    if args.command == "attack-suite":
        from tools.attack_suite.tamper_battery import run

        print(json.dumps(run(args.output), indent=2))
        return
    parser.error(f"{args.command} requires later service stages; not implemented")


if __name__ == "__main__":
    main()
