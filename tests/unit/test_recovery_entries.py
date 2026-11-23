"""Task E2a recovery-entry and discontinuity tests."""

from __future__ import annotations

import pytest

from libs.blackbox_core.chain import GENESIS_PREV_HASH, entry_hash
from libs.blackbox_core.schemas import Recovery, SealedEntry, parse_entry
from tools.verifier.verdicts import EntryVerdict, VerificationReport, resolve
from tools.verifier.verify import validate_recovery_transition

HASH_A = "sha256:" + "a" * 64
HASH_B = "sha256:" + "b" * 64
CERT = "sha256:" + "c" * 64
LOG = "sha256:" + "d" * 64


def previous_entry() -> SealedEntry:
    return SealedEntry(
        body=parse_entry(
            {
                "format_version": "4",
                "log_id": LOG,
                "epoch_id": 0,
                "seq": 4,
                "signer_timestamp": "2026-01-01T00:04:00.000Z",
                "prev_hash": HASH_B,
                "lane": "agent",
                "epoch_certificate_id": CERT,
                "type": "epoch_end",
            }
        )
    )


def recovery_body(**updates: object) -> dict[str, object]:
    body: dict[str, object] = {
        "format_version": "4",
        "log_id": LOG,
        "epoch_id": 1,
        "seq": 8,
        "signer_timestamp": "2026-01-01T00:05:00.000Z",
        "prev_hash": HASH_A,
        "lane": "agent",
        "epoch_certificate_id": CERT,
        "type": "recovery",
        "burned_first_seq": 5,
        "burned_last_seq": 7,
        "last_known_entry_hash": HASH_A,
        "lost_epoch_id": 0,
    }
    body.update(updates)
    return body


def test_recovery_entry_accepts_exact_burned_range() -> None:
    entry = parse_entry(recovery_body())
    previous = previous_entry()
    known_hash = entry_hash(previous.body)
    entry = entry.model_copy(update={"prev_hash": known_hash, "last_known_entry_hash": known_hash})

    assert isinstance(entry, Recovery)
    assert (entry.burned_first_seq, entry.burned_last_seq) == (5, 7)
    assert entry.last_known_entry_hash == known_hash
    validate_recovery_transition(previous, entry)


@pytest.mark.parametrize(
    "updates",
    [
        {"burned_first_seq": 6},
        {"burned_first_seq": 8, "burned_last_seq": 7},
        {"burned_first_seq": 5, "burned_last_seq": 5},
        {"burned_first_seq": 4},
        {"burned_last_seq": 9},
        {"prev_hash": HASH_B},
    ],
)
def test_invalid_or_non_exact_recovery_range_is_rejected(updates: dict[str, object]) -> None:
    previous = previous_entry()
    try:
        entry = parse_entry(recovery_body(**updates))
        known_hash = entry_hash(previous.body)
        if "prev_hash" not in updates:
            entry = entry.model_copy(
                update={"prev_hash": known_hash, "last_known_entry_hash": known_hash}
            )
    except ValueError:
        return
    with pytest.raises(ValueError):
        validate_recovery_transition(previous, entry)


def test_old_epoch_recovery_is_not_a_new_epoch_recovery() -> None:
    with pytest.raises(ValueError):
        parse_entry(recovery_body(epoch_id=0))
    entry = parse_entry(recovery_body())
    previous = previous_entry()
    with pytest.raises(ValueError):
        validate_recovery_transition(previous, entry.model_copy(update={"lost_epoch_id": 1}))


def test_plain_deleted_entry_has_no_recovery_authorization() -> None:
    with pytest.raises(ValueError):
        parse_entry(
            {
                **recovery_body(type="action"),
                "action_name": "audit",
                "reason": "deleted entry replacement",
                "target_reference": "seq-5",
                "prev_hash": GENESIS_PREV_HASH,
            }
        )


def test_missing_recovery_entry_is_not_authorized() -> None:
    previous = previous_entry()

    with pytest.raises(ValueError):
        validate_recovery_transition(previous, None)  # type: ignore[arg-type]


def test_recovery_discontinuity_precedence_is_between_unverified_and_verified() -> None:
    assert resolve(["VERIFIED", "RECOVERY_DISCONTINUITY"]) == "RECOVERY_DISCONTINUITY"
    assert resolve(["RECOVERY_DISCONTINUITY", "UNVERIFIED"]) == "RECOVERY_DISCONTINUITY"
    assert resolve(["RECOVERY_DISCONTINUITY", "MISSING"]) == "MISSING"
    assert resolve(["RECOVERY_DISCONTINUITY", "TAMPERED"]) == "TAMPERED"


def test_recovery_discontinuity_is_visible_in_report_summary() -> None:
    report = VerificationReport([EntryVerdict(8)], flags=["RECOVERY_DISCONTINUITY"])

    assert report.verdict == "RECOVERY_DISCONTINUITY"
    assert report.to_dict()["flags"] == ["RECOVERY_DISCONTINUITY"]
