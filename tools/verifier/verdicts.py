"""Verdict precedence and per-sequence reasons (spec §16.4)."""

from __future__ import annotations

from dataclasses import dataclass, field

PRECEDENCE = {"VERIFIED": 0, "UNVERIFIED": 1, "MISSING": 2, "TAMPERED": 3}


def resolve(verdicts: list[str]) -> str:
    return max(verdicts, key=PRECEDENCE.__getitem__, default="UNVERIFIED")


@dataclass
class EntryVerdict:
    seq: int
    verdict: str = "VERIFIED"
    reasons: list[str] = field(default_factory=list)

    def add(self, verdict: str, reason: str) -> None:
        self.verdict = resolve([self.verdict, verdict])
        if reason not in self.reasons:
            self.reasons.append(reason)


@dataclass
class VerificationReport:
    entries: list[EntryVerdict]
    findings: list[dict[str, object]] = field(default_factory=list)

    @property
    def verdict(self) -> str:
        return resolve([entry.verdict for entry in self.entries])

    def to_dict(self) -> dict[str, object]:
        return {
            "verdict": self.verdict,
            "entries": [
                {"seq": e.seq, "verdict": e.verdict, "reasons": e.reasons} for e in self.entries
            ],
            "findings": self.findings,
        }
