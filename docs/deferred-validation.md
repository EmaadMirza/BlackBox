# Deferred validation

## L2b-2 PostgreSQL/in-process boundary

The L2b-2 integration tests exercise the signer outbox, cooperative delivery
worker and an in-process FastAPI ledger app backed by the real local PostgreSQL
database `blackbox_ledger_test`. They cover at-least-once replay, exact-hash
acknowledgements, ordering, rollover delivery, equivocation, out-of-order
rejection, signer restart, append-only role checks and offline verification of
evidence exported from PostgreSQL rows.

The transport is intentionally in-process, so these tests do **not** establish
production network or deployment guarantees.

## Docker/Postgres validation still required

The following claims remain deferred to the Docker stage:

- PostgreSQL append-only triggers and `ledger_app` role behavior are covered for
  the exercised mutation paths, but broader privilege review remains deferred;
- Postgres transactions under concurrent requests and process-level connection
  failure are not fully load-tested;
- the real cross-process signer-to-ledger HTTP/network path is not exercised;
- Compose network isolation, container volume ownership, startup ordering and
  service health behavior are correct;
- power-loss behavior and recovery across the signer filesystem and Postgres are
  not demonstrated by the in-process tests.

The in-memory store is an additive test seam. It does not replace or weaken the
existing Postgres implementation; `create_app()` continues to construct the
Postgres pool when no store is injected.
