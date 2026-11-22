"""Offline verifier, operator CLI, and attack-suite runner (spec §17.3)."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from tools.verifier.verify import verify_bundle


def main() -> None:
    parser = argparse.ArgumentParser(prog="blackbox")
    commands = parser.add_subparsers(dest="command", required=True)

    # 1. verify
    verifier = commands.add_parser("verify", help="Verify a ledger snapshot or bundle offline")
    verifier.add_argument("bundle", type=Path, help="Path to evidence bundle JSON")
    verifier.add_argument(
        "--pinned-keys", type=Path, required=True, help="Path to pinned keys JSON"
    )

    # 2. attack-suite
    attacks = commands.add_parser("attack-suite", help="Run forensic attack batteries")
    attacks.add_argument("--output", "-o", type=Path, help="Output JSON report path")

    # 3. export-bundle
    exporter = commands.add_parser(
        "export-bundle", help="Produce an evidence bundle for a sequence range"
    )
    exporter.add_argument(
        "--from", "--start", dest="start_seq", type=int, default=0, help="Start sequence number"
    )
    exporter.add_argument(
        "--to",
        "--end",
        dest="end_seq",
        type=int,
        default=None,
        help="End sequence number (inclusive)",
    )
    exporter.add_argument("--output", "-o", type=Path, help="Output path for bundle JSON")
    exporter.add_argument("--ledger-url", type=str, default=None, help="Ledger service URL")
    exporter.add_argument("--token", type=str, default=None, help="Bearer token")
    exporter.add_argument("--dsn", type=str, default=None, help="PostgreSQL DSN")
    exporter.add_argument("--log-name", type=str, default="", help="Log name")
    exporter.add_argument("--log-id", type=str, default=None, help="Log ID")

    # 4. status
    status_p = commands.add_parser(
        "status", help="Show component health, current epoch, latest witnessed checkpoint"
    )
    status_p.add_argument("--signer-url", type=str, default=None, help="Signer service URL")
    status_p.add_argument("--ledger-url", type=str, default=None, help="Ledger service URL")
    status_p.add_argument(
        "--witness-urls", type=str, default=None, help="Comma-separated witness service URLs"
    )
    status_p.add_argument(
        "--signer-state-dir", type=Path, default=None, help="Path to local signer state dir"
    )
    status_p.add_argument("--token", type=str, default=None, help="Bearer token")
    status_p.add_argument("--output", "-o", type=Path, help="Output path for JSON status")

    # 5. reconcile-report
    reconcile_p = commands.add_parser(
        "reconcile-report", help="Print current reconciliation findings"
    )
    reconcile_p.add_argument(
        "--store", type=Path, default=None, help="Path to findings JSON store file"
    )
    reconcile_p.add_argument(
        "--reconciler-url", type=str, default=None, help="Reconciler service URL"
    )
    reconcile_p.add_argument("--token", type=str, default=None, help="Bearer token")
    reconcile_p.add_argument("--output", "-o", type=Path, help="Output path for report JSON")

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
        from tools.attack_suite import run_all

        report = run_all(args.output)
        print(json.dumps(report, indent=2))
        raise SystemExit(0 if report["verdict"] == "PASSED" else 1)

    if args.command == "export-bundle":
        from tools.bundle_export import export_bundle

        try:
            bundle_data = export_bundle(
                start_seq=args.start_seq,
                end_seq=args.end_seq,
                output=args.output,
                ledger_url=args.ledger_url,
                bearer_token=args.token,
                dsn=args.dsn,
                log_name=args.log_name,
                log_id=args.log_id,
            )
            if args.output is None:
                print(json.dumps(bundle_data, indent=2))
            return
        except Exception as exc:
            print(json.dumps({"error": str(exc)}))
            raise SystemExit(1) from exc

    if args.command == "status":
        from tools.status import get_status

        status_data = get_status(
            signer_url=args.signer_url,
            ledger_url=args.ledger_url,
            witness_urls=args.witness_urls,
            signer_state_dir=args.signer_state_dir,
            token=args.token,
            output=args.output,
        )
        if args.output is None:
            print(json.dumps(status_data, indent=2))
        return

    if args.command == "reconcile-report":
        from tools.reconcile_report import generate_reconcile_report

        report_data = generate_reconcile_report(
            store_path=args.store,
            reconciler_url=args.reconciler_url,
            token=args.token,
            output=args.output,
        )
        if args.output is None:
            print(json.dumps(report_data, indent=2))
        return


if __name__ == "__main__":
    main()
