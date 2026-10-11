"""Certificate verification and half-open epoch windows (spec §7)."""

from __future__ import annotations

from collections.abc import Sequence

from libs.blackbox_core.crypto import SigningOperation
from libs.blackbox_core.encoding import decode_base64url, parse_timestamp
from libs.blackbox_core.schemas import EpochCertificate, IntermediateCertificate, Revocation
from libs.blackbox_core.signing import sign_structure, structure_hash, verify_structure


def certificate_id(certificate: EpochCertificate) -> str:
    return structure_hash(certificate)


def valid_window(start: str, end: str) -> bool:
    return parse_timestamp(start) < parse_timestamp(end)


def in_window(now: str, start: str, end: str) -> bool:
    return parse_timestamp(start) <= parse_timestamp(now) < parse_timestamp(end)


def build_epoch_certificate(
    epoch_id: int,
    public_key: str,
    valid_from: str,
    valid_until: str,
    intermediate_id: str,
    *,
    log_id: str,
    signing_operation: SigningOperation,
) -> EpochCertificate:
    if not valid_window(valid_from, valid_until):
        raise ValueError("invalid epoch window")
    cert = EpochCertificate(
        log_id=log_id,
        epoch_id=epoch_id,
        epoch_public_key=public_key,
        valid_from=valid_from,
        valid_until=valid_until,
        intermediate_id=intermediate_id,
    )
    return sign_structure(cert, signing_operation, "epoch_cert")


def build_intermediate_certificate(
    log_id: str,
    intermediate_id: str,
    public_key: str,
    valid_from: str,
    valid_until: str,
    operation: SigningOperation,
) -> IntermediateCertificate:
    if not valid_window(valid_from, valid_until):
        raise ValueError("invalid intermediate window")
    return sign_structure(
        IntermediateCertificate(
            log_id=log_id,
            intermediate_id=intermediate_id,
            public_key=public_key,
            valid_from=valid_from,
            valid_until=valid_until,
        ),
        operation,
        "intermediate_cert",
    )


def verify_epoch_certificate(
    cert: EpochCertificate,
    intermediate: IntermediateCertificate,
    pinned_root: bytes,
    now: str,
    revocations: Sequence[Revocation] = (),
) -> bool:
    if cert.log_id != intermediate.log_id or cert.intermediate_id != intermediate.intermediate_id:
        return False
    if not verify_structure(intermediate, pinned_root, "intermediate_cert"):
        return False
    if not verify_structure(cert, decode_base64url(intermediate.public_key), "epoch_cert"):
        return False
    if not valid_window(cert.valid_from, cert.valid_until) or not valid_window(
        intermediate.valid_from, intermediate.valid_until
    ):
        return False
    if cert.valid_from < intermediate.valid_from or cert.valid_until > intermediate.valid_until:
        return False
    if not in_window(now, cert.valid_from, cert.valid_until):
        return False
    for notice in revocations:
        if notice.log_id != cert.log_id or not verify_structure(notice, pinned_root, "revocation"):
            return False
        if notice.intermediate_id == intermediate.intermediate_id and now >= notice.effective_time:
            return False
    return True


def validate_contiguity(previous: EpochCertificate, current: EpochCertificate) -> None:
    if (
        current.log_id != previous.log_id
        or current.epoch_id != previous.epoch_id + 1
        or current.valid_from != previous.valid_until
    ):
        raise ValueError("non-contiguous epoch ids/windows")


def verify_epoch_chain(
    certificates: Sequence[EpochCertificate],
    pinned_root: bytes,
    intermediates: Sequence[IntermediateCertificate] = (),
) -> bool:
    lookup = {c.intermediate_id: c for c in intermediates}
    try:
        for i, cert in enumerate(certificates):
            if not verify_epoch_certificate(
                cert, lookup[cert.intermediate_id], pinned_root, cert.valid_from
            ):
                return False
            if i:
                validate_contiguity(certificates[i - 1], cert)
        return bool(certificates)
    except (KeyError, ValueError):
        return False


def rollover_due(now: str, valid_until: str) -> bool:
    return parse_timestamp(now) >= parse_timestamp(valid_until)
