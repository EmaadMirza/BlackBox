"""Local durable quota reservations; the signer spends quota before signing."""

from __future__ import annotations

import os
import sqlite3
from contextlib import closing
from pathlib import Path

from libs.blackbox_core.encoding import parse_timestamp
from libs.blackbox_core.errors import SignerRuleError
from services.signer import state

_MAX_COUNT = 2**63 - 1
_MIN_SECOND = 86400  # date.toordinal() starts at one, not zero.
_MAX_SECOND = 315537983999  # Last second of 9999-12-31 UTC.
_SCHEMA = (
    "CREATE TABLE rate_bucket ("
    "singleton INTEGER PRIMARY KEY CHECK (singleton = 1), "
    "last_second INTEGER NOT NULL CHECK (typeof(last_second) = 'integer' "
    f"AND last_second BETWEEN {_MIN_SECOND} AND {_MAX_SECOND}), "
    "count INTEGER NOT NULL CHECK (typeof(count) = 'integer' "
    f"AND count BETWEEN 1 AND {_MAX_COUNT}))"
)


class DurableRateLimiter:
    """A file-backed singleton bucket for one signer's fixed UTC calendar second.

    The optional path names the quota database itself. Otherwise it is a sibling
    of the configured signer state, named ``<state filename>.rate.sqlite3``.
    Paths are bound at construction without touching storage. A missing database
    is initialized on first use (including creating parents); an existing empty,
    corrupt, or incompatible database is never reinitialized. Once this instance
    has seen storage, disappearance is an error. A fresh process cannot distinguish
    an externally deleted database from first deployment: preserve this file with
    the signer state. No reservation is refunded, even if later signing fails.
    """

    def __init__(self, path: Path | None = None) -> None:
        if path is None:
            configured = os.environ.get("SIGNER_STATE_PATH")
            state_path = Path(configured) if configured else state.DEFAULT_STATE_PATH
            path = state_path.with_name(f"{state_path.name}.rate.sqlite3")
        self._path = Path(path).absolute()
        self._seen_store = False

    def reserve(self, now: str, rate_cap: int) -> None:
        """Commit one reservation, or refuse without increasing the count.

        Backward calendar seconds and exhausted caps are signer rule refusals.
        Invalid inputs/accounting raise ValueError; SQLite/storage errors raise
        OSError, allowing the HTTP boundary to fail closed with an unavailable
        response. A commit or subsequent directory-fsync failure can consume a
        reservation despite reporting failure, which is intentionally conservative.
        """
        timestamp = parse_timestamp(now)
        if type(rate_cap) is not int or not 1 <= rate_cap <= _MAX_COUNT:
            raise ValueError("rate_cap must be a positive SQLite-range integer")
        second = (
            timestamp.toordinal() * 86400
            + timestamp.hour * 3600
            + timestamp.minute * 60
            + timestamp.second
        )

        created = self._prepare_file()
        try:
            # URI rw mode forbids SQLite silently recreating a vanished file and
            # ensures even a path named ':memory:' is actual file-backed storage.
            with closing(
                sqlite3.connect(self._path.as_uri() + "?mode=rw", uri=True, isolation_level=None)
            ) as connection:
                connection.execute("PRAGMA synchronous = FULL")
                if connection.execute("PRAGMA journal_mode").fetchone() != ("delete",):
                    raise ValueError("unexpected signer rate database journal mode")
                with connection:
                    connection.execute("BEGIN IMMEDIATE")
                    if created:
                        connection.execute(_SCHEMA)
                        connection.execute("PRAGMA user_version = 1")
                        connection.execute("INSERT INTO rate_bucket VALUES (1, ?, 1)", (second,))
                    else:
                        last_second, count = self._read_bucket(connection)
                        if second < last_second:
                            raise SignerRuleError("signer clock moved backwards")
                        if second == last_second and count >= rate_cap:
                            raise SignerRuleError("rate cap exceeded")
                        next_count = count + 1 if second == last_second else 1
                        connection.execute(
                            "UPDATE rate_bucket SET last_second = ?, count = ? WHERE singleton = 1",
                            (second, next_count),
                        )
            if created:
                directory_fd = os.open(self._path.parent, os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
        except sqlite3.Error as exc:
            raise OSError("signer rate database unavailable or malformed") from exc

    def _prepare_file(self) -> bool:
        """Claim a new file exclusively; never reset a preexisting store."""
        try:
            self._path.stat()
        except FileNotFoundError:
            if self._seen_store:
                raise OSError("signer rate database disappeared") from None
            self._path.parent.mkdir(parents=True, exist_ok=True)
            try:
                descriptor = os.open(self._path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError:
                # Another initializer won. Validate its store rather than reset it.
                created = False
            else:
                os.close(descriptor)
                created = True
        else:
            created = False
        self._seen_store = True
        return created

    @staticmethod
    def _read_bucket(connection: sqlite3.Connection) -> tuple[int, int]:
        schema = connection.execute("SELECT type, name, sql FROM sqlite_master").fetchall()
        if schema != [("table", "rate_bucket", _SCHEMA)]:
            raise ValueError("invalid signer rate database schema")
        if connection.execute("PRAGMA user_version").fetchone() != (1,):
            raise ValueError("invalid signer rate database version")
        rows = connection.execute(
            "SELECT singleton, last_second, count FROM rate_bucket"
        ).fetchall()
        if len(rows) != 1:
            raise ValueError("signer rate database must contain one bucket")
        singleton, last_second, count = rows[0]
        if (
            type(singleton) is not int
            or singleton != 1
            or type(last_second) is not int
            or not _MIN_SECOND <= last_second <= _MAX_SECOND
            or type(count) is not int
            or not 1 <= count <= _MAX_COUNT
        ):
            raise ValueError("invalid signer rate accounting")
        if connection.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
            raise ValueError("corrupt signer rate database")
        return last_second, count
