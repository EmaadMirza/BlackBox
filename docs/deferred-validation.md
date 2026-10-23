# Deferred validation

## L2b-2 in-process boundary

The L2b-2 tests exercise the signer outbox, cooperative delivery worker and an
in-process FastAPI ledger app backed by `InMemoryLedgerStore`. They cover
at-least-once replay, exact-hash acknowledgements, ordering, equivocation,
out-of-order rejection, signer restart and offline verification of exported
evidence.

They do **not** establish production storage or deployment guarantees.

## Docker/Postgres validation still required

The following claims remain deferred to the Docker stage:

- PostgreSQL append-only triggers reject update, delete and truncate;
- `ledger_app` and migration-owner roles have the intended least privilege;
- Postgres transactions preserve verify-before-insert, contiguity, idempotent
  replay and conflict recording under concurrent requests;
- the real signer-to-ledger HTTP path authenticates with the configured bearer
  token and preserves the same response/error semantics;
- Compose network isolation, container volume ownership, startup ordering and
  service health behavior are correct;
- power-loss behavior and recovery across the signer filesystem and Postgres are
  not demonstrated by the in-process tests.

The in-memory store is an additive test seam. It does not replace or weaken the
existing Postgres implementation; `create_app()` continues to construct the
Postgres pool when no store is injected.
