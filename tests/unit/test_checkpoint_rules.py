"""K1a pure checkpoint request rules."""

from dataclasses import replace

import pytest

from libs.blackbox_core.checkpoint import build_checkpoint
from libs.blackbox_core.errors import SignerRuleError
from libs.blackbox_core.schemas import Checkpoint
from libs.blackbox_core.signer_rules import SignerState, check_checkpoint_request

LOG = "sha256:" + "1" * 64
HASH_A = "sha256:" + "a" * 64
HASH_B = "sha256:" + "b" * 64
NOW = "2026-01-01T00:01:00.000Z"


def state() -> SignerState:
    return SignerState(
        last_seq=4,
        last_hash=HASH_A,
        epoch_id=2,
        epoch_certificate_id="sha256:" + "2" * 64,
        valid_from="2026-01-01T00:00:00.000Z",
        valid_until="2026-01-01T00:05:00.000Z",
        now=NOW,
        log_id=LOG,
    )


def request(
    size: int = 5, root: str = HASH_B, latest: int = 4, epoch: int = 2, latest_hash: str = HASH_A
):
    return build_checkpoint(LOG, size, root, latest, epoch, NOW).model_copy(
        update={"latest_entry_hash": latest_hash}
    )


def test_valid_checkpoint_request_and_growth() -> None:
    check_checkpoint_request(state(), None, request())
    previous = request()
    advanced = replace(state(), last_seq=5, last_hash=HASH_B)
    check_checkpoint_request(
        advanced, previous, request(size=6, latest=5, root=HASH_A, latest_hash=HASH_B)
    )


@pytest.mark.parametrize(
    ("changed", "code"),
    [
        ({"log_id": "sha256:" + "f" * 64}, "checkpoint_log_mismatch"),
        ({"tree_size": 4, "latest_seq": 3}, "checkpoint_stale"),
        ({"tree_size": 6}, "checkpoint_size_mismatch"),
        ({"latest_seq": 5}, "checkpoint_future"),
        ({"latest_entry_hash": HASH_B}, "checkpoint_latest_hash_mismatch"),
        ({"epoch_id": 1}, "checkpoint_epoch_mismatch"),
    ],
)
def test_checkpoint_rejections_have_stable_codes(changed: dict, code: str) -> None:
    candidate = request().model_copy(update=changed)
    with pytest.raises(SignerRuleError) as error:
        check_checkpoint_request(state(), None, candidate)
    assert getattr(error.value, "code") == code


def test_checkpoint_monotonicity_and_same_size_root() -> None:
    previous = request()
    with pytest.raises(SignerRuleError) as error:
        check_checkpoint_request(state(), previous, request(size=5, root=HASH_A))
    assert error.value.code == "checkpoint_root_conflict"
    with pytest.raises(SignerRuleError) as error:
        check_checkpoint_request(state(), previous, request(size=4, latest=3))
    assert error.value.code == "checkpoint_stale"


def test_unknown_checkpoint_field_is_rejected() -> None:
    with pytest.raises((ValueError, TypeError)):
        Checkpoint.model_validate(
            {**build_checkpoint(LOG, 5, HASH_B, 4, 2, NOW).model_dump(), "unknown": 1}
        )
