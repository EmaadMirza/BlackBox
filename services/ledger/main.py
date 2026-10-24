"""Ledger append/read API with independent entry verification."""

from __future__ import annotations

import os

from fastapi import Depends, FastAPI, Query, Request
from fastapi.responses import JSONResponse
from psycopg import errors
from psycopg.types.json import Jsonb
from pydantic import ValidationError

from libs.blackbox_core.canonical import loads
from libs.blackbox_core.chain import entry_hash
from libs.blackbox_core.encoding import decode_base64url
from libs.blackbox_core.epochs import certificate_id, in_window, verify_epoch_certificate
from libs.blackbox_core.schemas import (
    EpochCertificate,
    IntermediateCertificate,
    SealedEntry,
)
from libs.blackbox_core.sealing import verify_entry
from services.ledger import db, merkle_store
from services.ledger.store import LedgerStore, StoredEntry


class LedgerHTTPError(Exception):
    def __init__(self, status: int, code: str, message: str) -> None:
        self.status, self.code, self.message = status, code, message


def require_bearer(request: Request) -> None:
    expected = os.environ.get("LEDGER_AUTH_TOKEN")
    authorization = request.headers.get("authorization", "")
    if not expected or authorization != f"Bearer {expected}":
        raise LedgerHTTPError(401, "unauthorized", "Authentication required.")


def create_app(*, store: LedgerStore | None = None) -> FastAPI:
    app = FastAPI()
    app.state.store = store
    if store is None:
        app.state.pool = db.connect(os.environ.get("LEDGER_DATABASE_URL", "dbname=blackbox_ledger"))
        app.state.merkle_ready = True
        app.state.merkle_error = None
        try:
            merkle_store.validate_startup(app.state.pool)
        except merkle_store.MerkleStateError as exc:
            app.state.merkle_ready = False
            app.state.merkle_error = exc.code

    @app.exception_handler(LedgerHTTPError)
    async def ledger_error(_: Request, exc: LedgerHTTPError) -> JSONResponse:
        return JSONResponse(
            content={"error": {"code": exc.code, "message": exc.message}},
            status_code=exc.status,
        )

    @app.exception_handler(Exception)
    async def internal_error(_: Request, __: Exception) -> JSONResponse:
        return JSONResponse(
            content={"error": {"code": "internal_error", "message": "Internal error."}},
            status_code=500,
        )

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/entries")
    async def append(request: Request, _: None = Depends(require_bearer)) -> dict[str, object]:
        raw = await request.body()
        if len(raw) > 2 * 1024 * 1024:
            raise LedgerHTTPError(413, "body_too_large", "Request body is too large.")
        try:
            entry = SealedEntry.model_validate(loads(raw))
        except (RecursionError, TypeError, ValueError, UnicodeDecodeError, ValidationError) as exc:
            raise LedgerHTTPError(422, "invalid_request", "Invalid sealed entry.") from exc
        if app.state.store is not None:
            return _append_verified_store(app.state.store, entry)
        return _append_verified(app.state.pool, entry)

    @app.get("/entries")
    async def read_range(
        _: None = Depends(require_bearer),
        start: int = Query(alias="from", ge=0),
        end: int = Query(alias="to", ge=0),
    ) -> list[dict[str, object]]:
        if end < start or end - start > 1000:
            raise LedgerHTTPError(422, "invalid_range", "Invalid entry range.")
        entries = (
            app.state.store.read_entries(start, end)
            if app.state.store is not None
            else db.read_entries(app.state.pool, start, end)
        )
        return [entry.model_dump() for entry in entries]

    @app.get("/entries/{seq}")
    async def read_one(seq: int, _: None = Depends(require_bearer)) -> dict[str, object]:
        rows = (
            app.state.store.read_entries(seq, seq)
            if app.state.store is not None
            else db.read_entries(app.state.pool, seq, seq)
        )
        if not rows:
            raise LedgerHTTPError(404, "not_found", "Entry not found.")
        return rows[0].model_dump()

    @app.get("/checkpoints/latest")
    async def latest_checkpoint(_: None = Depends(require_bearer)) -> dict[str, object]:
        if app.state.store is None and not app.state.merkle_ready:
            raise LedgerHTTPError(
                503,
                merkle_store.MERKLE_FRONTIER_MISMATCH,
                "Ledger checkpoint state is unavailable.",
            )
        raise LedgerHTTPError(404, "checkpoint_unavailable", "No checkpoint is available.")

    return app


def _append_verified_store(store: LedgerStore, entry: SealedEntry) -> dict[str, object]:
    body = entry.body
    current_hash = entry_hash(body)
    existing = store.get_entry(body.log_id, body.seq)
    if existing is not None:
        if existing.entry_hash == current_hash and existing.entry.model_dump(
            mode="json"
        ) == entry.model_dump(mode="json"):
            return {"status": "stored", "entry_hash": current_hash}
        store.record_conflict(
            body.log_id,
            body.seq,
            existing.entry_hash,
            current_hash,
            {
                "existing": existing.entry.model_dump(mode="json"),
                "rejected": entry.model_dump(mode="json"),
            },
        )
        raise LedgerHTTPError(409, "equivocation", "Entry conflicts with existing history.")
    _verify_entry_store(store, entry)
    try:
        store.insert_entry(StoredEntry(entry, current_hash))
    except KeyError as exc:
        raise LedgerHTTPError(409, "conflict", "Entry conflicts with ledger state.") from exc
    return {"status": "stored", "entry_hash": current_hash}


def _verify_entry_store(store: LedgerStore, entry: SealedEntry) -> None:
    body = entry.body
    epoch = store.get_epoch(body.log_id, body.epoch_id)
    if epoch is None or certificate_id(epoch) != body.epoch_certificate_id:
        raise LedgerHTTPError(422, "certificate_unavailable", "Entry certificate is unavailable.")
    intermediate = store.get_intermediate(epoch.intermediate_id)
    root_key = store.get_root(body.log_id)
    if intermediate is None or root_key is None:
        raise LedgerHTTPError(422, "certificate_invalid", "Entry certificate is invalid.")
    if not verify_epoch_certificate(
        epoch, intermediate, decode_base64url(root_key), body.signer_timestamp
    ):
        raise LedgerHTTPError(422, "certificate_invalid", "Entry certificate is invalid.")
    if not in_window(body.signer_timestamp, epoch.valid_from, epoch.valid_until):
        raise LedgerHTTPError(422, "epoch_expired", "Entry is outside its epoch window.")
    if not verify_entry(entry, decode_base64url(epoch.epoch_public_key)):
        raise LedgerHTTPError(422, "signature_invalid", "Entry signature is invalid.")
    previous = store.latest_entry(body.log_id)
    if previous and (
        body.seq != previous.entry.body.seq + 1 or body.prev_hash != previous.entry_hash
    ):
        raise LedgerHTTPError(409, "out_of_order", "Entry is not contiguous.")
    if not previous and body.seq != 0:
        raise LedgerHTTPError(409, "out_of_order", "Entry is not contiguous.")


def _append_verified(pool, entry: SealedEntry) -> dict[str, object]:
    body = entry.body
    current_hash = entry_hash(body)
    conflict = False
    with pool.connection() as connection:
        with connection.transaction():
            row = connection.execute(
                "SELECT entry_hash, sealed_entry FROM blackbox.entries WHERE log_id=%s AND seq=%s",
                (body.log_id, body.seq),
            ).fetchone()
            if row:
                if row[0] == current_hash and row[1] == entry.model_dump(mode="json"):
                    return {"status": "stored", "entry_hash": current_hash}
                connection.execute(
                    "INSERT INTO blackbox.conflicts(log_id, seq, existing_hash, rejected_hash, evidence) VALUES (%s,%s,%s,%s,%s)",
                    (
                        body.log_id,
                        body.seq,
                        row[0],
                        current_hash,
                        Jsonb({"existing": row[1], "rejected": entry.model_dump(mode="json")}),
                    ),
                )
                conflict = True
            else:
                _verify_entry(pool, connection, entry)
                try:
                    connection.execute(
                        """INSERT INTO blackbox.entries
                        (log_id, seq, sealed_entry, entry_hash, prev_hash, epoch_id, type)
                        VALUES (%s,%s,%s,%s,%s,%s,%s)""",
                        (
                            body.log_id,
                            body.seq,
                            Jsonb(entry.model_dump(mode="json")),
                            current_hash,
                            body.prev_hash,
                            body.epoch_id,
                            body.type,
                        ),
                    )
                    merkle_store.append_in_transaction(connection, entry)
                except errors.UniqueViolation as exc:
                    raise LedgerHTTPError(
                        409, "conflict", "Entry conflicts with ledger state."
                    ) from exc
    if conflict:
        raise LedgerHTTPError(409, "equivocation", "Entry conflicts with existing history.")
    return {"status": "stored", "entry_hash": current_hash}


def _verify_entry(pool, connection, entry: SealedEntry) -> None:
    body = entry.body
    cert_row = connection.execute(
        "SELECT certificate FROM blackbox.epochs WHERE epoch_certificate_id=%s AND log_id=%s",
        (body.epoch_certificate_id, body.log_id),
    ).fetchone()
    if not cert_row:
        raise LedgerHTTPError(422, "certificate_unavailable", "Entry certificate is unavailable.")
    epoch = EpochCertificate.model_validate(cert_row[0])
    intermediate_row = connection.execute(
        "SELECT certificate FROM blackbox.intermediates WHERE intermediate_id=%s AND log_id=%s",
        (epoch.intermediate_id, body.log_id),
    ).fetchone()
    root_row = connection.execute(
        "SELECT root_public_key FROM blackbox.pinned_roots WHERE log_id=%s", (body.log_id,)
    ).fetchone()
    if not intermediate_row or not root_row or certificate_id(epoch) != body.epoch_certificate_id:
        raise LedgerHTTPError(422, "certificate_invalid", "Entry certificate is invalid.")
    intermediate = IntermediateCertificate.model_validate(intermediate_row[0])
    if not verify_epoch_certificate(
        epoch, intermediate, decode_base64url(root_row[0]), body.signer_timestamp
    ):
        raise LedgerHTTPError(422, "certificate_invalid", "Entry certificate is invalid.")
    if not in_window(body.signer_timestamp, epoch.valid_from, epoch.valid_until):
        raise LedgerHTTPError(422, "epoch_expired", "Entry is outside its epoch window.")
    if not verify_entry(entry, decode_base64url(epoch.epoch_public_key)):
        raise LedgerHTTPError(422, "signature_invalid", "Entry signature is invalid.")
    previous = connection.execute(
        "SELECT seq, entry_hash FROM blackbox.entries WHERE log_id=%s ORDER BY seq DESC LIMIT 1 FOR UPDATE",
        (body.log_id,),
    ).fetchone()
    if previous and (body.seq != previous[0] + 1 or body.prev_hash != previous[1]):
        raise LedgerHTTPError(409, "out_of_order", "Entry is not contiguous.")
    if not previous and body.seq != 0:
        raise LedgerHTTPError(409, "out_of_order", "Entry is not contiguous.")
