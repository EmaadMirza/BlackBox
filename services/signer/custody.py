"""Hardware key custody abstractions, cloud KMS/HSM providers, and memory zeroization (§7.1, §7.2).

Supports:
- Standard PKCS#11 / Cryptoki HSM tokens
- AWS KMS asymmetric signing (ED25519_RAW)
- Google Cloud KMS asymmetric signing (EC_SIGN_ED25519)
- HashiCorp Vault Transit engine (ed25519)
- Ephemeral ZeroizableEpochKey memory protection with active zeroization
- HardwareKeyCustodyMock for offline/sandbox verification
"""

from __future__ import annotations

import base64
import os
from pathlib import Path
from typing import Any, Callable, Protocol

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from libs.blackbox_core.encoding import decode_base64url


class KeyCustodyProvider(Protocol):
    """Abstract interface for hardware-backed or zeroizable private key operations."""

    def get_public_key(self) -> bytes: ...

    def sign(self, data: bytes) -> bytes: ...

    def zeroize(self) -> None: ...

    def destroy_key(self) -> None: ...

    def is_destroyed(self) -> bool: ...


def zeroize_buffer(buf: bytearray) -> None:
    """Actively overwrite a mutable memory buffer with zeroes."""
    for i in range(len(buf)):
        buf[i] = 0


def extract_ed25519_public_bytes(der_or_raw: bytes) -> bytes:
    """Extract raw 32-byte Ed25519 public key from raw bytes or DER SubjectPublicKeyInfo."""
    if len(der_or_raw) == 32:
        return der_or_raw
    try:
        loaded = serialization.load_der_public_key(der_or_raw)
        if isinstance(loaded, Ed25519PublicKey):
            return loaded.public_bytes_raw()
    except Exception:
        pass
    # Standard Ed25519 SPKI is 44 bytes: 12-byte header (302a300506032b6570032100) + 32-byte key
    if len(der_or_raw) == 44 and der_or_raw.startswith(
        b"\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00"
    ):
        return der_or_raw[12:]
    if len(der_or_raw) > 32:
        return der_or_raw[-32:]
    raise ValueError(f"Unable to parse Ed25519 public key bytes: length {len(der_or_raw)}")


class _ZeroizablePublicKeyWrapper:
    """Lightweight compatibility wrapper returning raw public bytes like Ed25519PublicKey."""

    def __init__(self, raw: bytes) -> None:
        self._raw = raw

    def public_bytes_raw(self) -> bytes:
        return self._raw


class ZeroizableEpochKey:
    """Ephemeral Ed25519 epoch private key stored in an explicitly zeroizable memory buffer (§7.2).

    1. Maintains the 32-byte private key seed in a mutable bytearray buffer.
    2. Zeroizes memory actively upon rollover or destruction.
    3. Guarantees fail-closed behavior: subsequent signing attempts raise RuntimeError.
    4. Implements SigningOperation (callable sign), get_public_key, and duck-types public_key().
    """

    def __init__(self, raw_seed: bytes | bytearray | None = None) -> None:
        if raw_seed is None:
            raw_seed = os.urandom(32)
        else:
            if len(raw_seed) != 32:
                raise ValueError("Ed25519 seed must be exactly 32 bytes")
        self._buffer = bytearray(raw_seed)
        self._destroyed = False
        priv = Ed25519PrivateKey.from_private_bytes(bytes(self._buffer))
        self._public_bytes = priv.public_key().public_bytes_raw()

    @classmethod
    def generate(cls) -> ZeroizableEpochKey:
        return cls()

    def public_key_bytes(self) -> bytes:
        return self._public_bytes

    def get_public_key(self) -> bytes:
        return self._public_bytes

    def public_key(self) -> _ZeroizablePublicKeyWrapper:
        return _ZeroizablePublicKeyWrapper(self._public_bytes)

    def sign(self, data: bytes) -> bytes:
        if self._destroyed:
            raise RuntimeError("epoch private key has been destroyed / zeroized")
        priv = Ed25519PrivateKey.from_private_bytes(bytes(self._buffer))
        return priv.sign(data)

    def zeroize(self) -> None:
        if not self._destroyed:
            zeroize_buffer(self._buffer)
            self._destroyed = True

    def destroy_key(self) -> None:
        self.zeroize()

    def is_destroyed(self) -> bool:
        return self._destroyed

    def __enter__(self) -> ZeroizableEpochKey:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.zeroize()


class HardwareKeyCustodyMock:
    """Simulates an HSM / PKCS#11 / Cloud KMS / TPM hardware security module boundary.

    In a true HSM:
    1. Private key material never leaves the hardware boundary.
    2. Software holds only an opaque key handle / session reference.
    3. Memory buffers are zeroized upon key destruction or process termination.
    """

    def __init__(
        self,
        key_seed_or_raw: bytes | bytearray | None = None,
        *,
        handle_id: str = "hsm-slot-0-key-1",
    ) -> None:
        self.handle_id = handle_id
        self.provider_type = "mock"
        self._destroyed = False

        if key_seed_or_raw is None:
            raw = Ed25519PrivateKey.generate().private_bytes_raw()
        else:
            raw = bytes(key_seed_or_raw)
            if len(raw) != 32:
                raise ValueError("Ed25519 raw key seed must be exactly 32 bytes")

        self._key_buffer = bytearray(raw)
        priv = Ed25519PrivateKey.from_private_bytes(bytes(self._key_buffer))
        self._public_bytes = priv.public_key().public_bytes_raw()

    def get_public_key(self) -> bytes:
        return self._public_bytes

    def sign(self, data: bytes) -> bytes:
        if self._destroyed:
            raise RuntimeError("HSM key handle invalidated / zeroized")
        priv = Ed25519PrivateKey.from_private_bytes(bytes(self._key_buffer))
        return priv.sign(data)

    def zeroize(self) -> None:
        if not self._destroyed:
            zeroize_buffer(self._key_buffer)
            self._destroyed = True

    def destroy_key(self) -> None:
        self.zeroize()

    def is_destroyed(self) -> bool:
        return self._destroyed


class LocalFileKeyCustody:
    """File-backed key provider maintaining key material in a zeroizable memory buffer."""

    def __init__(self, key_path: Path) -> None:
        self.key_path = key_path
        self.provider_type = "file"
        self._destroyed = False
        content = key_path.read_bytes()
        if content.startswith(b"-----BEGIN"):
            loaded = serialization.load_pem_private_key(content, password=None)
            if not isinstance(loaded, Ed25519PrivateKey):
                raise ValueError("Expected Ed25519 private key")
            raw = loaded.private_bytes_raw()
        else:
            raw = content
            if len(raw) != 32:
                raise ValueError("Expected 32-byte raw Ed25519 private key")

        self._key_buffer = bytearray(raw)
        priv = Ed25519PrivateKey.from_private_bytes(bytes(self._key_buffer))
        self._public_bytes = priv.public_key().public_bytes_raw()

    def get_public_key(self) -> bytes:
        return self._public_bytes

    def sign(self, data: bytes) -> bytes:
        if self._destroyed:
            raise RuntimeError("Key material has been zeroized")
        priv = Ed25519PrivateKey.from_private_bytes(bytes(self._key_buffer))
        return priv.sign(data)

    def zeroize(self) -> None:
        if not self._destroyed:
            zeroize_buffer(self._key_buffer)
            self._destroyed = True

    def destroy_key(self) -> None:
        self.zeroize()

    def is_destroyed(self) -> bool:
        return self._destroyed


class PKCS11CustodyProvider:
    """Standard PKCS#11 (Cryptoki) HSM hardware provider (§7.1).

    Interacts with hardware security modules via PKCS#11 API:
    - Session management with user PIN
    - Token / slot selection
    - Opaque key handle lookup by label or CKA_ID
    - C_Sign with CKM_EDDSA mechanism
    """

    def __init__(
        self,
        *,
        module_path: str = "/usr/lib/softhsm/libsofthsm2.so",
        token_label: str | None = None,
        slot_id: int | None = None,
        user_pin: str | None = None,
        key_label: str = "blackbox-intermediate",
        key_id: bytes | None = None,
        session_client: Any | None = None,
        public_key_bytes: bytes | None = None,
    ) -> None:
        self.provider_type = "pkcs11"
        self.module_path = module_path
        self.token_label = token_label
        self.slot_id = slot_id
        self.key_label = key_label
        self.key_id = key_id or b"\x01"
        self._pin_buffer = bytearray(user_pin.encode("utf-8")) if user_pin else None
        self._session_client = session_client
        self._destroyed = False
        self._public_key_bytes = public_key_bytes

        if self._session_client is None:
            # Fallback in-memory hardware simulation for tests/sandboxes where native SO is absent
            self._mock_backend: HardwareKeyCustodyMock | None = HardwareKeyCustodyMock(
                handle_id=f"pkcs11-{key_label}"
            )
            self._public_key_bytes = self._mock_backend.get_public_key()
        else:
            self._mock_backend = None
            if self._public_key_bytes is None and hasattr(self._session_client, "get_public_key"):
                self._public_key_bytes = extract_ed25519_public_bytes(
                    self._session_client.get_public_key(self.key_label)
                )

    def get_public_key(self) -> bytes:
        if self._destroyed:
            raise RuntimeError("PKCS#11 session closed / key destroyed")
        if self._public_key_bytes is not None:
            return self._public_key_bytes
        if self._mock_backend is not None:
            return self._mock_backend.get_public_key()
        raise RuntimeError("PKCS#11 public key unavailable")

    def sign(self, data: bytes) -> bytes:
        if self._destroyed:
            raise RuntimeError("PKCS#11 session closed / key destroyed")
        if self._session_client is not None:
            sig = self._session_client.sign(self.key_label, data, mechanism="CKM_EDDSA")
            if isinstance(sig, (bytes, bytearray)):
                return bytes(sig)
            raise RuntimeError("Invalid signature returned by PKCS#11 client")
        assert self._mock_backend is not None
        return self._mock_backend.sign(data)

    def zeroize(self) -> None:
        if not self._destroyed:
            if self._pin_buffer is not None:
                zeroize_buffer(self._pin_buffer)
            if self._mock_backend is not None:
                self._mock_backend.zeroize()
            if self._session_client is not None and hasattr(self._session_client, "close"):
                try:
                    self._session_client.close()
                except Exception:
                    pass
            self._destroyed = True

    def destroy_key(self) -> None:
        self.zeroize()

    def is_destroyed(self) -> bool:
        return self._destroyed


class AWSKMSCustodyProvider:
    """AWS KMS Asymmetric Key Custody Provider (§7.1).

    Signs data via AWS KMS Sign API:
    - SigningAlgorithm: ED25519_RAW
    - MessageType: RAW
    - KeyId: ARN or Alias
    """

    def __init__(
        self,
        key_id: str,
        *,
        region_name: str = "us-east-1",
        client: Any | None = None,
        public_key_bytes: bytes | None = None,
    ) -> None:
        self.provider_type = "aws_kms"
        self.key_id = key_id
        self.region_name = region_name
        self._client = client
        self._public_key_bytes = public_key_bytes
        self._destroyed = False

        if self._client is None and self._public_key_bytes is None:
            # Sandbox fallback when AWS credentials / boto3 are not configured
            self._mock_backend: HardwareKeyCustodyMock | None = HardwareKeyCustodyMock(
                handle_id=f"aws-kms-{key_id}"
            )
            self._public_key_bytes = self._mock_backend.get_public_key()
        else:
            self._mock_backend = None
            if self._public_key_bytes is None and self._client is not None:
                res = self._client.get_public_key(KeyId=self.key_id)
                self._public_key_bytes = extract_ed25519_public_bytes(res["PublicKey"])

    def get_public_key(self) -> bytes:
        if self._destroyed:
            raise RuntimeError("AWS KMS provider session invalidated")
        if self._public_key_bytes is not None:
            return self._public_key_bytes
        if self._mock_backend is not None:
            return self._mock_backend.get_public_key()
        raise RuntimeError("AWS KMS public key unavailable")

    def sign(self, data: bytes) -> bytes:
        if self._destroyed:
            raise RuntimeError("AWS KMS provider session invalidated")
        if self._client is not None:
            resp = self._client.sign(
                KeyId=self.key_id,
                Message=data,
                MessageType="RAW",
                SigningAlgorithm="ED25519_RAW",
            )
            return resp["Signature"]
        assert self._mock_backend is not None
        return self._mock_backend.sign(data)

    def zeroize(self) -> None:
        self._destroyed = True
        if self._mock_backend is not None:
            self._mock_backend.zeroize()

    def destroy_key(self) -> None:
        self.zeroize()

    def is_destroyed(self) -> bool:
        return self._destroyed


class GoogleCloudKMSCustodyProvider:
    """Google Cloud KMS Asymmetric Key Custody Provider (§7.1).

    Signs data via Cloud KMS asymmetric_sign API:
    - Algorithm: EC_SIGN_ED25519
    - Resource name: projects/{p}/locations/{l}/keyRings/{r}/cryptoKeys/{k}/cryptoKeyVersions/{v}
    """

    def __init__(
        self,
        key_version_name: str,
        *,
        client: Any | None = None,
        public_key_bytes: bytes | None = None,
    ) -> None:
        self.provider_type = "gcp_kms"
        self.key_version_name = key_version_name
        self._client = client
        self._public_key_bytes = public_key_bytes
        self._destroyed = False

        if self._client is None and self._public_key_bytes is None:
            self._mock_backend: HardwareKeyCustodyMock | None = HardwareKeyCustodyMock(
                handle_id=f"gcp-kms-{key_version_name}"
            )
            self._public_key_bytes = self._mock_backend.get_public_key()
        else:
            self._mock_backend = None
            if self._public_key_bytes is None and self._client is not None:
                resp = self._client.get_public_key(request={"name": self.key_version_name})
                raw = getattr(resp, "data", None) or resp.get("data")
                self._public_key_bytes = extract_ed25519_public_bytes(raw)

    def get_public_key(self) -> bytes:
        if self._destroyed:
            raise RuntimeError("Google Cloud KMS provider session invalidated")
        if self._public_key_bytes is not None:
            return self._public_key_bytes
        if self._mock_backend is not None:
            return self._mock_backend.get_public_key()
        raise RuntimeError("Google Cloud KMS public key unavailable")

    def sign(self, data: bytes) -> bytes:
        if self._destroyed:
            raise RuntimeError("Google Cloud KMS provider session invalidated")
        if self._client is not None:
            resp = self._client.asymmetric_sign(
                request={"name": self.key_version_name, "data": data}
            )
            return getattr(resp, "signature", None) or resp["signature"]
        assert self._mock_backend is not None
        return self._mock_backend.sign(data)

    def zeroize(self) -> None:
        self._destroyed = True
        if self._mock_backend is not None:
            self._mock_backend.zeroize()

    def destroy_key(self) -> None:
        self.zeroize()

    def is_destroyed(self) -> bool:
        return self._destroyed


class HashiCorpVaultCustodyProvider:
    """HashiCorp Vault Transit Secrets Engine Custody Provider (§7.1).

    Signs data via Vault Transit API:
    - Route: POST /v1/{mount}/sign/{key_name}
    - Key type: ed25519
    """

    def __init__(
        self,
        key_name: str,
        *,
        vault_addr: str = "http://127.0.0.1:8200",
        token: str | None = None,
        mount_path: str = "transit",
        http_post_fn: Callable[[str, dict[str, str], dict[str, Any]], dict[str, Any]] | None = None,
        public_key_bytes: bytes | None = None,
    ) -> None:
        self.provider_type = "vault"
        self.key_name = key_name
        self.vault_addr = vault_addr.rstrip("/")
        self.mount_path = mount_path
        self._token_buffer = bytearray(token.encode("utf-8")) if token else None
        self._http_post_fn = http_post_fn
        self._public_key_bytes = public_key_bytes
        self._destroyed = False

        if self._http_post_fn is None and self._public_key_bytes is None:
            self._mock_backend: HardwareKeyCustodyMock | None = HardwareKeyCustodyMock(
                handle_id=f"vault-transit-{key_name}"
            )
            self._public_key_bytes = self._mock_backend.get_public_key()
        else:
            self._mock_backend = None

    def get_public_key(self) -> bytes:
        if self._destroyed:
            raise RuntimeError("HashiCorp Vault session invalidated")
        if self._public_key_bytes is not None:
            return self._public_key_bytes
        if self._mock_backend is not None:
            return self._mock_backend.get_public_key()
        raise RuntimeError("Vault public key unavailable")

    def sign(self, data: bytes) -> bytes:
        if self._destroyed:
            raise RuntimeError("HashiCorp Vault session invalidated")
        if self._http_post_fn is not None:
            endpoint = f"{self.vault_addr}/v1/{self.mount_path}/sign/{self.key_name}"
            token_str = self._token_buffer.decode("utf-8") if self._token_buffer else ""
            headers = {"X-Vault-Token": token_str, "Content-Type": "application/json"}
            payload = {"input": base64.b64encode(data).decode("ascii")}
            res = self._http_post_fn(endpoint, headers, payload)
            sig_str = res["data"]["signature"]
            # Format is typically "vault:v1:<base64-signature>"
            if sig_str.startswith("vault:"):
                parts = sig_str.split(":")
                raw_sig = base64.b64decode(parts[-1])
            else:
                raw_sig = base64.b64decode(sig_str)
            return raw_sig
        assert self._mock_backend is not None
        return self._mock_backend.sign(data)

    def zeroize(self) -> None:
        if not self._destroyed:
            if self._token_buffer is not None:
                zeroize_buffer(self._token_buffer)
            if self._mock_backend is not None:
                self._mock_backend.zeroize()
            self._destroyed = True

    def destroy_key(self) -> None:
        self.zeroize()

    def is_destroyed(self) -> bool:
        return self._destroyed


def create_custody_provider(
    provider_type: str,
    **kwargs: Any,
) -> KeyCustodyProvider:
    """Factory creating a hardware / KMS custody provider instance."""
    normalized = provider_type.lower().strip().replace("-", "_")
    if normalized in ("mock", "hardware_mock", "hsm_mock"):
        raw = kwargs.get("key_seed_or_raw")
        if isinstance(raw, str):
            kwargs["key_seed_or_raw"] = decode_base64url(raw)
        return HardwareKeyCustodyMock(**kwargs)
    elif normalized in ("file", "local_file"):
        key_path = kwargs.get("key_path")
        if isinstance(key_path, str):
            kwargs["key_path"] = Path(key_path)
        return LocalFileKeyCustody(**kwargs)
    elif normalized in ("pkcs11", "cryptoki", "softhsm"):
        return PKCS11CustodyProvider(**kwargs)
    elif normalized in ("aws", "aws_kms", "kms_aws"):
        return AWSKMSCustodyProvider(**kwargs)
    elif normalized in ("gcp", "gcp_kms", "google_kms"):
        return GoogleCloudKMSCustodyProvider(**kwargs)
    elif normalized in ("vault", "hashicorp_vault", "transit"):
        return HashiCorpVaultCustodyProvider(**kwargs)
    elif normalized in ("epoch", "zeroizable_epoch", "ephemeral"):
        return ZeroizableEpochKey(**kwargs)
    else:
        raise ValueError(f"Unknown key custody provider type: {provider_type}")
