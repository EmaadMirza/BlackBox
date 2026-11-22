"""Pure-Python Shamir's Secret Sharing over a 256-bit prime field (§7.2, Air-Gapped Root Ceremony)."""

from __future__ import annotations

import secrets
from dataclasses import dataclass

# Smallest prime strictly greater than 2**256: 2**256 + 297.
# Ensures any 32-byte Ed25519 seed / private scalar fits strictly in [0, P - 1].
PRIME: int = (1 << 256) + 297


@dataclass(frozen=True)
class ShamirShare:
    """A single shard (x, P(x)) belonging to a threshold K-of-N split."""

    index: int
    value: int
    threshold: int
    total_shares: int

    def to_dict(self) -> dict[str, object]:
        return {
            "index": self.index,
            "value": f"{self.value:064x}",
            "threshold": self.threshold,
            "total_shares": self.total_shares,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> ShamirShare:
        return cls(
            index=int(data["index"]),
            value=int(str(data["value"]), 16),
            threshold=int(data["threshold"]),
            total_shares=int(data["total_shares"]),
        )

    def to_string(self) -> str:
        return f"{self.index}:{self.threshold}:{self.total_shares}:{self.value:064x}"

    @classmethod
    def from_string(cls, text: str) -> ShamirShare:
        parts = text.strip().split(":")
        if len(parts) != 4:
            raise ValueError(f"Invalid ShamirShare string format: {text}")
        return cls(
            index=int(parts[0]),
            threshold=int(parts[1]),
            total_shares=int(parts[2]),
            value=int(parts[3], 16),
        )


def split_secret(
    secret: bytes,
    threshold: int,
    total_shares: int,
) -> list[ShamirShare]:
    """Split a 32-byte secret into N shares with threshold K over GF(PRIME)."""
    if len(secret) != 32:
        raise ValueError(f"Secret must be exactly 32 bytes, got {len(secret)}")
    if threshold < 1:
        raise ValueError(f"Threshold must be at least 1, got {threshold}")
    if total_shares < threshold:
        raise ValueError(f"Total shares ({total_shares}) must be >= threshold ({threshold})")
    if total_shares >= PRIME:
        raise ValueError(f"Total shares must be less than field size {PRIME}")

    s = int.from_bytes(secret, "big")
    if s >= PRIME:
        raise ValueError("Secret scalar exceeds prime field")

    # Generate random polynomial coefficients a_1 ... a_{k-1}
    # P(x) = s + a_1 * x + a_2 * x^2 + ... + a_{k-1} * x^{k-1} mod PRIME
    coefficients = [secrets.randbelow(PRIME) for _ in range(threshold - 1)]

    shares: list[ShamirShare] = []
    for x in range(1, total_shares + 1):
        y = s
        for deg, coeff in enumerate(coefficients, start=1):
            y = (y + coeff * pow(x, deg, PRIME)) % PRIME
        shares.append(
            ShamirShare(
                index=x,
                value=y,
                threshold=threshold,
                total_shares=total_shares,
            )
        )

    return shares


def combine_shares(
    shares: list[ShamirShare],
    threshold: int | None = None,
) -> bytes:
    """Reconstruct a 32-byte secret from K shares using Lagrange interpolation at x=0."""
    if not shares:
        raise ValueError("Cannot reconstruct secret from zero shares")

    # Validate share consistency
    first = shares[0]
    expected_k = threshold or first.threshold
    if len(shares) < expected_k:
        raise ValueError(f"Insufficient shares: got {len(shares)}, required {expected_k}")

    # Use first K distinct shares
    seen_indices: set[int] = set()
    selected: list[ShamirShare] = []
    for share in shares:
        if share.index in seen_indices:
            continue
        if share.index <= 0 or share.index >= PRIME:
            raise ValueError(f"Invalid share index: {share.index}")
        if share.value < 0 or share.value >= PRIME:
            raise ValueError(f"Invalid share value for index {share.index}")
        seen_indices.add(share.index)
        selected.append(share)
        if len(selected) == expected_k:
            break

    if len(selected) < expected_k:
        raise ValueError(
            f"Not enough distinct shares: {len(selected)} distinct, needed {expected_k}"
        )

    # Lagrange interpolation at x = 0:
    # L_i(0) = \prod_{j != i} (0 - x_j) / (x_i - x_j) mod PRIME
    secret_int = 0
    for i, share_i in enumerate(selected):
        xi, yi = share_i.index, share_i.value
        num = 1
        den = 1
        for j, share_j in enumerate(selected):
            if i == j:
                continue
            xj = share_j.index
            num = (num * (-xj)) % PRIME
            den = (den * (xi - xj)) % PRIME

        # Invert denominator modulo PRIME: den^(-1) = pow(den, PRIME - 2, PRIME)
        inv_den = pow(den, PRIME - 2, PRIME)
        term = (yi * num * inv_den) % PRIME
        secret_int = (secret_int + term) % PRIME

    return secret_int.to_bytes(32, "big")
