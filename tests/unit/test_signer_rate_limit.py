"""File-backed, conservative per-calendar-second signer reservations."""

from __future__ import annotations

import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from libs.blackbox_core.errors import SignerRuleError
from services.signer import state
from services.signer.rate_limit import DurableRateLimiter

NOW = "2026-10-11T12:34:56.000Z"
NEXT = "2026-10-11T12:34:57.000Z"


def test_same_second_cap_survives_recreation(tmp_path: Path) -> None:
    path = tmp_path / "rate.sqlite3"
    DurableRateLimiter(path).reserve(NOW, 2)
    DurableRateLimiter(path).reserve(NOW, 2)
    with pytest.raises(SignerRuleError, match="^rate cap exceeded$"):
        DurableRateLimiter(path).reserve(NOW, 2)
    # A refusal does not spend quota: raising the cap admits exactly one more.
    DurableRateLimiter(path).reserve(NOW, 3)
    with pytest.raises(SignerRuleError, match="^rate cap exceeded$"):
        DurableRateLimiter(path).reserve(NOW, 3)


def test_next_calendar_second_resets_quota(tmp_path: Path) -> None:
    limiter = DurableRateLimiter(tmp_path / "rate.sqlite3")
    limiter.reserve("2026-10-11T23:59:59.999Z", 1)
    limiter.reserve("2026-10-12T00:00:00.000Z", 1)
    with pytest.raises(SignerRuleError, match="rate cap exceeded"):
        limiter.reserve("2026-10-12T00:00:00.999Z", 1)


def test_milliseconds_share_bucket_and_do_not_advance_clock(tmp_path: Path) -> None:
    limiter = DurableRateLimiter(tmp_path / "rate.sqlite3")
    limiter.reserve("2026-10-11T12:34:56.900Z", 2)
    limiter.reserve("2026-10-11T12:34:56.001Z", 2)
    with pytest.raises(SignerRuleError, match="rate cap exceeded"):
        limiter.reserve("2026-10-11T12:34:56.999Z", 2)
    # This is a calendar bucket, not a sliding interval after the first request.
    limiter.reserve(NEXT, 2)


def test_backward_second_is_rejected_without_spending_quota(tmp_path: Path) -> None:
    path = tmp_path / "rate.sqlite3"
    DurableRateLimiter(path).reserve(NEXT, 2)
    with pytest.raises(SignerRuleError, match="clock.*back|back.*clock"):
        DurableRateLimiter(path).reserve(NOW, 2)
    DurableRateLimiter(path).reserve(NEXT, 2)
    with pytest.raises(SignerRuleError, match="rate cap exceeded"):
        DurableRateLimiter(path).reserve(NEXT, 2)


def test_state_locations_are_isolated_and_bound_at_construction(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    first_state = tmp_path / "first" / "state.json"
    second_state = tmp_path / "second" / "other.json"
    monkeypatch.setenv("SIGNER_STATE_PATH", str(first_state))
    first = DurableRateLimiter()
    assert not first_state.parent.exists()
    monkeypatch.setenv("SIGNER_STATE_PATH", str(second_state))
    second = DurableRateLimiter()
    first.reserve(NOW, 1)
    second.reserve(NOW, 1)
    assert first_state.with_name("state.json.rate.sqlite3").is_file()
    assert second_state.with_name("other.json.rate.sqlite3").is_file()
    assert not first_state.exists()
    assert not second_state.exists()
    with pytest.raises(SignerRuleError, match="rate cap exceeded"):
        first.reserve(NOW, 1)
    with pytest.raises(SignerRuleError, match="rate cap exceeded"):
        DurableRateLimiter().reserve(NOW, 1)


def test_default_state_location_and_lazy_explicit_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("SIGNER_STATE_PATH", raising=False)
    default_state = tmp_path / "default" / "state.json"
    monkeypatch.setattr(state, "DEFAULT_STATE_PATH", default_state)
    limiter = DurableRateLimiter()
    explicit = DurableRateLimiter(tmp_path / "explicit" / "quota.sqlite3")
    assert not default_state.parent.exists()
    assert not (tmp_path / "explicit").exists()
    limiter.reserve(NOW, 1)
    explicit.reserve(NOW, 1)
    assert default_state.with_name("state.json.rate.sqlite3").is_file()
    assert (tmp_path / "explicit" / "quota.sqlite3").is_file()


def test_fresh_python_process_preserves_quota(tmp_path: Path) -> None:
    path = tmp_path / "rate.sqlite3"
    script = (
        "import sys\n"
        "from services.signer.rate_limit import DurableRateLimiter\n"
        "from libs.blackbox_core.errors import SignerRuleError\n"
        "try:\n"
        "    DurableRateLimiter(__import__('pathlib').Path(sys.argv[1])).reserve(sys.argv[2], 2)\n"
        "except SignerRuleError as exc:\n"
        "    print(str(exc))\n"
        "    sys.exit(3)\n"
    )
    project = Path(__file__).resolve().parents[2]
    for expected_code in (0, 0, 3):
        result = subprocess.run(
            [sys.executable, "-c", script, str(path), NOW],
            cwd=project,
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == expected_code, result.stderr
        if expected_code == 3:
            assert result.stdout.strip() == "rate cap exceeded"


@pytest.mark.parametrize("contents", [b"not sqlite", b"", b"SQLite format 3\x00broken"])
def test_malformed_existing_database_fails_closed(tmp_path: Path, contents: bytes) -> None:
    path = tmp_path / "rate.sqlite3"
    path.write_bytes(contents)
    with pytest.raises((OSError, ValueError)):
        DurableRateLimiter(path).reserve(NOW, 1)
    assert path.read_bytes() == contents


@pytest.mark.parametrize(
    "damage",
    [
        "DELETE FROM rate_bucket",
        "UPDATE rate_bucket SET count = 0",
        "UPDATE rate_bucket SET count = -1",
        "UPDATE rate_bucket SET count = 'broken'",
        "UPDATE rate_bucket SET last_second = -1",
        "UPDATE rate_bucket SET last_second = 1.5",
        "UPDATE rate_bucket SET singleton = 2",
        "INSERT INTO rate_bucket VALUES (2, 86400, 1)",
        "PRAGMA user_version = 2",
        "CREATE TABLE unexpected (value INTEGER)",
        "DROP TABLE rate_bucket",
    ],
)
def test_malformed_accounting_never_resets(tmp_path: Path, damage: str) -> None:
    path = tmp_path / "rate.sqlite3"
    DurableRateLimiter(path).reserve(NOW, 1)
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA ignore_check_constraints = ON")
        connection.execute(damage)
    before = path.read_bytes()
    with pytest.raises((OSError, ValueError)):
        DurableRateLimiter(path).reserve(NEXT, 1)
    assert path.read_bytes() == before


@pytest.mark.parametrize(
    "now",
    [
        None,
        123,
        "",
        "2026-10-11T12:34:56Z",
        "2026-10-11T12:34:56.000+00:00",
        "2026-02-30T12:34:56.000Z",
    ],
)
def test_invalid_timestamp_does_not_create_store(tmp_path: Path, now: object) -> None:
    path = tmp_path / "missing" / "rate.sqlite3"
    limiter = DurableRateLimiter(path)
    with pytest.raises(ValueError):
        limiter.reserve(now, 1)
    assert not path.parent.exists()


@pytest.mark.parametrize("cap", [None, "1", True, False, 0, -1, 1.5, 2**63])
def test_invalid_cap_does_not_create_store(tmp_path: Path, cap: object) -> None:
    path = tmp_path / "missing" / "rate.sqlite3"
    with pytest.raises(ValueError):
        DurableRateLimiter(path).reserve(NOW, cap)
    assert not path.parent.exists()


def test_invalid_inputs_do_not_spend_existing_quota(tmp_path: Path) -> None:
    path = tmp_path / "rate.sqlite3"
    limiter = DurableRateLimiter(path)
    limiter.reserve(NOW, 2)
    before = path.read_bytes()
    with pytest.raises(ValueError):
        limiter.reserve("invalid", 2)
    with pytest.raises(ValueError):
        limiter.reserve(NOW, 0)
    assert path.read_bytes() == before
    limiter.reserve(NOW, 2)
    with pytest.raises(SignerRuleError, match="rate cap exceeded"):
        limiter.reserve(NOW, 2)


def test_storage_path_error_fails_closed(tmp_path: Path) -> None:
    parent = tmp_path / "not-a-directory"
    parent.write_text("occupied", encoding="utf-8")
    with pytest.raises(OSError):
        DurableRateLimiter(parent / "rate.sqlite3").reserve(NOW, 1)
    assert parent.read_text(encoding="utf-8") == "occupied"


def test_disappeared_store_is_not_recreated_by_bound_limiter(tmp_path: Path) -> None:
    path = tmp_path / "rate.sqlite3"
    limiter = DurableRateLimiter(path)
    limiter.reserve(NOW, 1)
    path.unlink()
    with pytest.raises(OSError):
        limiter.reserve(NOW, 1)
    assert not path.exists()


def test_concurrent_reservations_cannot_overspend(tmp_path: Path) -> None:
    path = tmp_path / "rate.sqlite3"
    # Initialize before competing clients open the same file-backed store.
    DurableRateLimiter(path).reserve(NOW, 7)

    def reserve_once(_: int) -> bool:
        try:
            DurableRateLimiter(path).reserve(NOW, 7)
        except SignerRuleError:
            return False
        return True

    with ThreadPoolExecutor(max_workers=8) as executor:
        accepted = list(executor.map(reserve_once, range(24)))
    assert sum(accepted) == 6
