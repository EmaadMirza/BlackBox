"""Versioned signing domains and log identity (spec §5.3–5.4)."""

from __future__ import annotations

import hashlib
import unicodedata

from libs.blackbox_core.encoding import decode_hash, encode_hash

LABELS = {
    name: f"BLACKBOX:v4:{name}\0".encode("ascii")
    for name in (
        "entry",
        "checkpoint",
        "heartbeat",
        "epoch_cert",
        "intermediate_cert",
        "attestation",
        "approval_receipt",
        "cosignature",
        "witness_set",
        "revocation",
    )
}


def signature_label(structure_type: str) -> bytes:
    try:
        return LABELS[structure_type]
    except KeyError as exc:
        raise ValueError("unknown signature domain") from exc


def derive_log_id(root_public_key: bytes, log_name: str) -> str:
    if len(root_public_key) != 32 or not log_name:
        raise ValueError("32-byte root key and nonempty log name required")
    return encode_hash(
        hashlib.sha256(root_public_key + unicodedata.normalize("NFC", log_name).encode()).digest()
    )


def signature_message(label: bytes, log_id: str, canonical_bytes: bytes) -> bytes:
    if label not in LABELS.values():
        raise ValueError("unrecognized signature label")
    return label + decode_hash(log_id) + canonical_bytes
