"""Signer-owned epoch key lifecycle and intermediate-signing adapters."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Protocol

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from libs.blackbox_core.crypto import SigningOperation
from libs.blackbox_core.encoding import encode_base64url, format_timestamp, parse_timestamp
from libs.blackbox_core.epochs import (
    build_epoch_certificate,
    certificate_id,
    verify_epoch_certificate,
)
from libs.blackbox_core.schemas import (
    EpochCertificate,
    EpochEnd,
    EpochStart,
    IntermediateCertificate,
    SealedEntry,
)
from libs.blackbox_core.sealing import seal


class IntermediateSigner(Protocol):
    """Signs and verifies epoch certificates without exposing key material."""

    certificate: IntermediateCertificate

    def sign_epoch_certificate(self, certificate: EpochCertificate) -> EpochCertificate: ...

    def verify_epoch_certificate(self, certificate: EpochCertificate) -> bool: ...


class EpochUnavailableError(OSError):
    """The signer has no usable epoch key and requires a new epoch."""


@dataclass(frozen=True)
class EpochRuntime:
    certificate: EpochCertificate
    signing_operation: SigningOperation


@dataclass(frozen=True)
class RolloverPlan:
    old_runtime: EpochRuntime
    new_runtime: EpochRuntime
    end: SealedEntry
    start: SealedEntry


class InMemoryIntermediateSigner:
    """Development adapter around already-loaded ceremony material."""

    def __init__(
        self,
        certificate: IntermediateCertificate,
        signing_operation: SigningOperation,
        root_public_key: bytes,
    ) -> None:
        self.certificate = certificate
        self._operation = signing_operation
        self._root_public_key = root_public_key

    def sign_epoch_certificate(self, certificate: EpochCertificate) -> EpochCertificate:
        if certificate.log_id != self.certificate.log_id:
            raise ValueError("intermediate log identity mismatch")
        if (
            certificate.valid_from < self.certificate.valid_from
            or certificate.valid_until > self.certificate.valid_until
        ):
            raise ValueError("intermediate certificate is expired or unavailable")
        signed = build_epoch_certificate(
            certificate.epoch_id,
            certificate.epoch_public_key,
            certificate.valid_from,
            certificate.valid_until,
            certificate.intermediate_id,
            log_id=certificate.log_id,
            signing_operation=self._operation,
        )
        if not self.verify_epoch_certificate(signed):
            raise ValueError("new epoch certificate failed verification")
        return signed

    def verify_epoch_certificate(self, certificate: EpochCertificate) -> bool:
        return verify_epoch_certificate(
            certificate,
            self.certificate,
            self._root_public_key,
            certificate.valid_from,
        )


class DirectoryIntermediateSigner(InMemoryIntermediateSigner):
    """Development-only loader for the output of ``tools/ceremony.py``."""

    def __init__(
        self, directory: Path, root_public_key: bytes, expected_log_id: str | None = None
    ) -> None:
        certificate = IntermediateCertificate.model_validate(
            json.loads((directory / "intermediate.json").read_text(encoding="utf-8"))
        )
        if expected_log_id is not None and certificate.log_id != expected_log_id:
            raise ValueError("intermediate certificate log identity mismatch")
        key_bytes = (directory / "intermediate.dev-private.pem").read_bytes()
        operation = serialization.load_pem_private_key(key_bytes, password=None)
        if not isinstance(operation, Ed25519PrivateKey):
            raise ValueError("development intermediate key is not Ed25519")
        super().__init__(certificate, operation, root_public_key)


class EpochManager:
    """Owns one live epoch key and creates the next contiguous certificate."""

    def __init__(
        self,
        *,
        log_id: str,
        intermediate_signer: IntermediateSigner,
        runtime: EpochRuntime,
        clock,
        epoch_duration: int = 300,
        roll_margin: int = 0,
        last_timestamp: str | None = None,
    ) -> None:
        if epoch_duration <= 0 or roll_margin < 0:
            raise ValueError("invalid epoch rollover configuration")
        self.log_id = log_id
        self.intermediate_signer = intermediate_signer
        self.runtime = runtime
        self.clock = clock
        self.epoch_duration = epoch_duration
        self.roll_margin = roll_margin
        self.degraded = False
        self.last_timestamp = last_timestamp or runtime.certificate.valid_from

    @property
    def certificate(self) -> EpochCertificate:
        return self.runtime.certificate

    @property
    def signing_operation(self) -> SigningOperation:
        return self.runtime.signing_operation

    @property
    def certificate_id(self) -> str:
        return certificate_id(self.certificate)

    def metadata(self) -> dict[str, object]:
        return self.metadata_for(self.runtime)

    def metadata_for(self, runtime: EpochRuntime) -> dict[str, object]:
        return {
            "format_version": "1",
            "log_id": self.log_id,
            "epoch_id": runtime.certificate.epoch_id,
            "epoch_certificate": runtime.certificate.model_dump(),
            "valid_from": runtime.certificate.valid_from,
            "valid_until": runtime.certificate.valid_until,
        }

    def due(self, now: str) -> bool:
        current = parse_timestamp(now)
        expiry = parse_timestamp(self.certificate.valid_until)
        return current >= expiry - timedelta(seconds=self.roll_margin)

    def begin_new_epoch(self, reason: str) -> EpochRuntime:
        del reason  # retained for the future recovery receipt API
        now = parse_timestamp(self.clock())
        old = self.certificate
        valid_from = parse_timestamp(old.valid_until)
        valid_until = max(valid_from, now) + timedelta(seconds=self.epoch_duration)
        key = Ed25519PrivateKey.generate()
        candidate = EpochCertificate(
            epoch_id=old.epoch_id + 1,
            log_id=self.log_id,
            epoch_public_key=encode_base64url(key.public_key().public_bytes_raw()),
            valid_from=format_timestamp(valid_from),
            valid_until=format_timestamp(valid_until),
            intermediate_id=self.intermediate_signer.certificate.intermediate_id,
        )
        signed = self.intermediate_signer.sign_epoch_certificate(candidate)
        if not self.intermediate_signer.verify_epoch_certificate(signed):
            raise ValueError("new epoch certificate failed verification")
        new_runtime = EpochRuntime(signed, key)
        self.runtime = new_runtime
        self.degraded = False
        return new_runtime

    def prepare_rollover(
        self, last_seq: int, last_hash: str, previous_entry_timestamp: str
    ) -> RolloverPlan:
        """Build both rollover entries without changing live key ownership."""

        old_runtime = self.runtime
        now = parse_timestamp(self.clock())
        old_end = parse_timestamp(old_runtime.certificate.valid_until)
        previous_time = parse_timestamp(previous_entry_timestamp)
        end_time = max(previous_time, min(now, old_end - timedelta(milliseconds=1)))
        new_runtime = self._new_runtime(now)
        end_body = EpochEnd(
            format_version="4",
            log_id=self.log_id,
            epoch_id=old_runtime.certificate.epoch_id,
            seq=last_seq + 1,
            signer_timestamp=format_timestamp(end_time),
            prev_hash=last_hash,
            lane="agent",
            epoch_certificate_id=self._certificate_id(old_runtime.certificate),
            type="epoch_end",
        )
        start_body = EpochStart(
            format_version="4",
            log_id=self.log_id,
            epoch_id=new_runtime.certificate.epoch_id,
            seq=last_seq + 2,
            signer_timestamp=format_timestamp(
                max(now, parse_timestamp(new_runtime.certificate.valid_from))
            ),
            prev_hash=self._entry_hash(end_body),
            lane="agent",
            epoch_certificate_id=self._certificate_id(new_runtime.certificate),
            type="epoch_start",
            certificate=new_runtime.certificate,
        )
        return RolloverPlan(
            old_runtime=old_runtime,
            new_runtime=new_runtime,
            end=seal(end_body, old_runtime.signing_operation),
            start=seal(start_body, new_runtime.signing_operation),
        )

    def commit_rollover(self, plan: RolloverPlan) -> None:
        if plan.old_runtime is not self.runtime:
            raise RuntimeError("stale rollover plan")
        self.runtime = plan.new_runtime
        self.last_timestamp = plan.start.body.signer_timestamp

    def fail_closed(self) -> None:
        self.degraded = True
        self.runtime = EpochRuntime(
            self.certificate, _DestroyedSigner(self.runtime.signing_operation)
        )

    def _new_runtime(self, now) -> EpochRuntime:
        old = self.certificate
        valid_from = parse_timestamp(old.valid_until)
        valid_until = max(valid_from, now) + timedelta(seconds=self.epoch_duration)
        key = Ed25519PrivateKey.generate()
        candidate = EpochCertificate(
            epoch_id=old.epoch_id + 1,
            log_id=self.log_id,
            epoch_public_key=encode_base64url(key.public_key().public_bytes_raw()),
            valid_from=format_timestamp(valid_from),
            valid_until=format_timestamp(valid_until),
            intermediate_id=self.intermediate_signer.certificate.intermediate_id,
        )
        signed = self.intermediate_signer.sign_epoch_certificate(candidate)
        if not self.intermediate_signer.verify_epoch_certificate(signed):
            raise ValueError("new epoch certificate failed verification")
        return EpochRuntime(signed, key)

    @staticmethod
    def _certificate_id(certificate: EpochCertificate) -> str:
        from libs.blackbox_core.epochs import certificate_id

        return certificate_id(certificate)

    @staticmethod
    def _entry_hash(body) -> str:
        from libs.blackbox_core.chain import entry_hash

        return entry_hash(body)

    def destroy_current_key(self) -> None:
        operation = self.runtime.signing_operation
        self.runtime = EpochRuntime(self.certificate, _DestroyedSigner(operation))


class _DestroyedSigner:
    def __init__(self, old: SigningOperation) -> None:
        self._old = old

    def sign(self, _data: bytes) -> bytes:
        del self._old
        raise RuntimeError("epoch private key has been destroyed")
