"""TEST ONLY: authorized Stage 1 local key factory; never persist these keys."""

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def dev_key(index: int = 1) -> Ed25519PrivateKey:
    """Deterministic public test seeds; NEVER use for a deployed identity."""
    return Ed25519PrivateKey.from_private_bytes(index.to_bytes(32, "big"))
