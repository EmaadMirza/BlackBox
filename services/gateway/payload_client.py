"""Payload and salt storage client (spec §8.4)."""

from __future__ import annotations

import os

import httpx

from libs.blackbox_core.encoding import decode_base64url, encode_base64url


async def store(
    value: bytes,
    salt: bytes,
    *,
    payload_url: str | None = None,
    client: httpx.AsyncClient | None = None,
) -> str:
    """Store payload value and salt in PayloadStore, returning payload reference."""
    url = (payload_url or os.environ.get("PAYLOAD_URL", "http://payload_store:8000")).rstrip("/")
    body = {
        "value": encode_base64url(value),
        "salt": encode_base64url(salt),
    }
    if client is not None:
        res = await client.post(f"{url}/v1/payloads", json=body)
        res.raise_for_status()
        return res.json()["reference"]

    async with httpx.AsyncClient(timeout=5.0) as http_client:
        res = await http_client.post(f"{url}/v1/payloads", json=body)
        res.raise_for_status()
        return res.json()["reference"]


async def retrieve(
    reference: str,
    *,
    payload_url: str | None = None,
    client: httpx.AsyncClient | None = None,
) -> tuple[bytes, bytes]:
    """Retrieve payload value and salt from PayloadStore by reference."""
    url = (payload_url or os.environ.get("PAYLOAD_URL", "http://payload_store:8000")).rstrip("/")
    if client is not None:
        res = await client.get(f"{url}/v1/payloads/{reference}")
        res.raise_for_status()
        data = res.json()
        return decode_base64url(data["value"]), decode_base64url(data["salt"])

    async with httpx.AsyncClient(timeout=5.0) as http_client:
        res = await http_client.get(f"{url}/v1/payloads/{reference}")
        res.raise_for_status()
        data = res.json()
        return decode_base64url(data["value"]), decode_base64url(data["salt"])
