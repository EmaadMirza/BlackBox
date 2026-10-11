"""Signature domain and log-isolation tests."""

from libs.blackbox_core.crypto import sign, verify
from libs.blackbox_core.labels import LABELS, derive_log_id
from tests._dev_keys import dev_key


def test_every_cross_domain_and_cross_log_signature_fails() -> None:
    key = dev_key()
    public = key.public_key().public_bytes_raw()
    log = derive_log_id(public, "test")
    other = derive_log_id(public, "other")
    for domain in LABELS:
        sig = sign(b"payload", key, domain=domain, log_id=log)
        assert verify(public, sig, b"payload", domain=domain, log_id=log)
        for wrong in LABELS:
            if wrong != domain:
                assert not verify(public, sig, b"payload", domain=wrong, log_id=log)
        assert not verify(public, sig, b"payload", domain=domain, log_id=other)
        assert not verify(public, sig, b"changed", domain=domain, log_id=log)
        assert not verify(public, b"short", b"payload", domain=domain, log_id=log)
