"""Web HMAC and nonce authentication with replay defense (spec §13.3).

Implements HMAC-SHA256 signature verification over incoming HTTP web requests,
timestamp window verification (60s), and Redis-backed nonce uniqueness tracking.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import time
from collections.abc import Callable
from datetime import datetime, timezone

from libs.blackbox_core import schemas
from libs.blackbox_core.crypto import sha256
from libs.blackbox_core.encoding import encode_hash


class WebAuthError(Exception):
    """Raised when web lane authentication or replay check fails."""


class NonceStore:
    """Abstract interface for recording and checking nonce uniqueness."""

    def check_and_record(self, key_id: str, nonce: str, ttl_seconds: int = 120) -> bool:
        """Return True if nonce is fresh and recorded; False if already used (replayed)."""
        raise NotImplementedError


class MemoryNonceStore(NonceStore):
    """Thread-safe in-memory nonce store with timestamp expiration."""

    def __init__(self) -> None:
        self._seen: dict[str, float] = {}

    def check_and_record(self, key_id: str, nonce: str, ttl_seconds: int = 120) -> bool:
        now = time.time()
        # Clean expired
        expired = [k for k, exp in self._seen.items() if exp < now]
        for k in expired:
            self._seen.pop(k, None)

        key = f"{key_id}:{nonce}"
        if key in self._seen:
            return False

        self._seen[key] = now + ttl_seconds
        return True


class RedisNonceStore(NonceStore):
    """Distributed Redis-backed nonce store using atomic SETNX with TTL."""

    def __init__(self, redis_url: str | None = None) -> None:
        import redis

        url = redis_url or os.environ.get("REDIS_URL", "redis://redis:6379/0")
        self._client = redis.Redis.from_url(url, decode_responses=True)

    def check_and_record(self, key_id: str, nonce: str, ttl_seconds: int = 120) -> bool:
        redis_key = f"blackbox:nonce:{key_id}:{nonce}"
        try:
            # SET key 1 EX ttl NX returns True if set, None/False if existed
            acquired = self._client.set(redis_key, "1", ex=ttl_seconds, nx=True)
            return bool(acquired)
        except Exception as e:
            # If Redis connection fails, fallback or raise depending on policy
            raise WebAuthError(f"Redis nonce store error: {e}") from e


def compute_canonical_string(
    method: str, path: str, body_digest: str, timestamp: str, nonce: str
) -> str:
    """Compute canonical string to sign for Web lane HMAC (spec §13.3)."""
    return f"{method.upper()}\n{path}\n{body_digest}\n{timestamp}\n{nonce}"


def sign_request(
    key_id: str,
    secret: bytes,
    method: str,
    path: str,
    body: bytes,
    timestamp: str | int | None = None,
    nonce: str | None = None,
) -> dict[str, str]:
    """Client utility to generate BlackBox HMAC authentication headers."""
    import uuid

    if timestamp is None:
        ts_str = datetime.now(timezone.utc).isoformat()
    elif isinstance(timestamp, (int, float)):
        ts_str = str(int(timestamp))
    else:
        ts_str = str(timestamp)

    n = nonce or uuid.uuid4().hex
    body_digest = encode_hash(sha256(body))
    canonical_str = compute_canonical_string(method, path, body_digest, ts_str, n)
    signature = hmac.new(secret, canonical_str.encode("utf-8"), hashlib.sha256).hexdigest()

    return {
        "X-BlackBox-KeyId": key_id,
        "X-BlackBox-Timestamp": ts_str,
        "X-BlackBox-Nonce": n,
        "X-BlackBox-Signature": signature,
    }


def _parse_timestamp(ts_str: str) -> float:
    """Parse integer epoch or ISO-8601 timestamp string into epoch seconds."""
    try:
        return float(ts_str)
    except ValueError:
        pass

    try:
        # ISO-8601 string
        clean_str = ts_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(clean_str)
        return dt.timestamp()
    except Exception as e:
        raise WebAuthError(f"Invalid timestamp format: {ts_str}") from e


_DEFAULT_MEMORY_STORE = MemoryNonceStore()


async def authenticate(
    method: str,
    path: str,
    body: bytes,
    headers: dict[str, str],
    *,
    secret_registry: dict[str, bytes] | None = None,
    nonce_store: NonceStore | None = None,
    clock: Callable[[], float] | None = None,
    max_skew_seconds: int = 60,
) -> schemas.Principal:
    """Authenticate Web lane request with HMAC signature and replay verification."""
    # Normalize headers to lowercase lookup
    norm_headers = {k.lower(): v for k, v in headers.items()}

    key_id = norm_headers.get("x-blackbox-keyid") or norm_headers.get("x-key-id")
    ts_str = norm_headers.get("x-blackbox-timestamp") or norm_headers.get("x-timestamp")
    nonce = norm_headers.get("x-blackbox-nonce") or norm_headers.get("x-nonce")
    signature = norm_headers.get("x-blackbox-signature") or norm_headers.get("x-signature")

    if not all([key_id, ts_str, nonce, signature]):
        raise WebAuthError(
            "Missing required authentication headers: key_id, timestamp, nonce, signature"
        )

    # 1. Resolve client secret
    secrets = secret_registry or {"web-default": b"secret-web-key"}
    secret = secrets.get(key_id)  # type: ignore[arg-type]
    if secret is None:
        raise WebAuthError(f"Unknown client key ID: {key_id}")

    # 2. Timestamp window validation (60s)
    req_time = _parse_timestamp(str(ts_str))
    current_time = clock() if clock is not None else time.time()
    if abs(current_time - req_time) > max_skew_seconds:
        raise WebAuthError(
            f"Timestamp outside acceptable window: diff {abs(current_time - req_time):.1f}s > {max_skew_seconds}s"
        )

    # 3. HMAC-SHA256 signature verification
    body_digest = encode_hash(sha256(body))
    canonical_str = compute_canonical_string(method, path, body_digest, str(ts_str), str(nonce))
    expected_hex = hmac.new(secret, canonical_str.encode("utf-8"), hashlib.sha256).hexdigest()

    # Support matching against hex or raw bytes/base64
    if not hmac.compare_digest(str(signature).lower(), expected_hex.lower()):
        raise WebAuthError("Invalid HMAC-SHA256 signature")

    # 4. Replay defense via Nonce Store
    active_nonce_store = nonce_store or _DEFAULT_MEMORY_STORE
    is_fresh = active_nonce_store.check_and_record(
        str(key_id), str(nonce), ttl_seconds=max_skew_seconds * 2
    )
    if not is_fresh:
        raise WebAuthError("Replay detected: nonce has already been used")

    # 5. Build Principal
    return schemas.Principal(
        client_key_id=str(key_id),
        source_address="web",
        human_identity=str(key_id),
        agent_identity="web-client",
        agent_version="1",
        delegation_chain=[],
    )
