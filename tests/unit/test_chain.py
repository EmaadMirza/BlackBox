"""Entry signatures cannot be repaired by recomputing hash links."""

from libs.blackbox_core.chain import entry_hash, verify_chain
from libs.blackbox_core.schemas import parse_entry
from libs.blackbox_core.sealing import seal, sealed_bytes, verify_entry
from tests._dev_keys import dev_key
from tests.unit.test_schemas import action


def test_sealing_and_break_position() -> None:
    key = dev_key()
    body = action()
    entries = []
    for seq in range(3):
        body["seq"] = seq
        entries.append(seal(parse_entry(body), key))
        body["prev_hash"] = entry_hash(entries[-1].body)
    assert verify_chain(entries) is None
    assert verify_entry(entries[1], key.public_key().public_bytes_raw())
    changed = entries[1].body.model_copy(update={"reason": "forged"})
    forged = entries[1].model_copy(update={"body": changed})
    assert not verify_entry(forged, key.public_key().public_bytes_raw())
    assert sealed_bytes(forged) != sealed_bytes(entries[1])
    assert verify_chain([entries[0], entries[2]]).seq == 1
    wrong = entries[1].model_copy(
        update={"body": entries[1].body.model_copy(update={"prev_hash": "sha256:" + "a" * 64})}
    )
    assert verify_chain([entries[0], wrong]).seq == 1
