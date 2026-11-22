"""Unified runner for BlackBox Forensic Audit & Attack Suite."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from tools.attack_suite import (
    e3_ledger_rewrite,
    e4_gateway_compromise,
    e5_bypass,
    e6_witness_outage,
    e7_split_view,
    e10_approval_abuse,
    e11_key_compromise,
    e12_tool_poisoning,
    fuzz_ledger,
    tamper_battery,
)


def run_all(output: Path | None = None) -> dict[str, Any]:
    """Execute all attack suite batteries and compile a consolidated forensic report."""
    with tempfile.TemporaryDirectory() as tmp_str:
        tmp_dir = Path(tmp_str)
        scenarios: dict[str, Any] = {}

        # 1. G1 Tamper Battery
        try:
            battery_result = tamper_battery.run()
            scenarios["G1_tamper_battery"] = {
                "verdict": "PASSED" if battery_result["honest"] == "VERIFIED" else "FAILED",
                "variants_tested": len(battery_result["variants"]),
                "control": battery_result["control"],
            }
        except Exception as e:
            scenarios["G1_tamper_battery"] = {"verdict": "FAILED", "error": str(e)}

        # 2. E3 Ledger Rewrite
        try:
            scenarios["E3_ledger_rewrite"] = e3_ledger_rewrite.run(tmp_dir / "e3")
        except Exception as e:
            scenarios["E3_ledger_rewrite"] = {"verdict": "FAILED", "error": str(e)}

        # 3. E4 Gateway Compromise
        try:
            scenarios["E4_gateway_compromise"] = e4_gateway_compromise.run(tmp_dir / "e4")
        except Exception as e:
            scenarios["E4_gateway_compromise"] = {"verdict": "FAILED", "error": str(e)}

        # 4. E5 Agent Network Bypass
        try:
            scenarios["E5_agent_bypass"] = e5_bypass.run(tmp_dir / "e5")
        except Exception as e:
            scenarios["E5_agent_bypass"] = {"verdict": "FAILED", "error": str(e)}

        # 5. E6 Witness Outage & Availability
        try:
            scenarios["E6_witness_outage"] = e6_witness_outage.run(tmp_dir / "e6")
        except Exception as e:
            scenarios["E6_witness_outage"] = {"verdict": "FAILED", "error": str(e)}

        # 6. E7 Split View Detection
        try:
            scenarios["E7_split_view"] = e7_split_view.run(tmp_dir / "e7")
        except Exception as e:
            scenarios["E7_split_view"] = {"verdict": "FAILED", "error": str(e)}

        # 7. E8 Stored Ledger Fuzzing
        try:
            scenarios["E8_stored_ledger_fuzz"] = fuzz_ledger.run(tmp_dir / "e8")
        except Exception as e:
            scenarios["E8_stored_ledger_fuzz"] = {"verdict": "FAILED", "error": str(e)}

        # 8. E10 Approval Abuse
        try:
            scenarios["E10_approval_abuse"] = e10_approval_abuse.run(tmp_dir / "e10")
        except Exception as e:
            scenarios["E10_approval_abuse"] = {"verdict": "FAILED", "error": str(e)}

        # 9. E11 Key Compromise & Rogue Epochs
        try:
            scenarios["E11_key_compromise"] = e11_key_compromise.run(tmp_dir / "e11")
        except Exception as e:
            scenarios["E11_key_compromise"] = {"verdict": "FAILED", "error": str(e)}

        # 10. E12 Tool Poisoning
        try:
            scenarios["E12_tool_poisoning"] = e12_tool_poisoning.run(tmp_dir / "e12")
        except Exception as e:
            scenarios["E12_tool_poisoning"] = {"verdict": "FAILED", "error": str(e)}

    total = len(scenarios)
    passed = sum(1 for s in scenarios.values() if s.get("verdict") == "PASSED")
    failed = total - passed
    overall_verdict = "PASSED" if failed == 0 else "FAILED"

    report = {
        "suite": "BlackBox Forensic Audit & Attack Suite",
        "verdict": overall_verdict,
        "summary": {
            "total_scenarios": total,
            "passed": passed,
            "failed": failed,
        },
        "scenarios": scenarios,
    }

    if output is not None:
        if output.is_dir() or output.suffix != ".json":
            output.mkdir(parents=True, exist_ok=True)
            report_path = output / "report.json"
        else:
            output.parent.mkdir(parents=True, exist_ok=True)
            report_path = output

        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

    return report


def main() -> None:
    print(json.dumps(run_all(), indent=2))


if __name__ == "__main__":
    main()
