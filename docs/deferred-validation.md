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

## L3a Merkle frontier boundary

The ledger persists one append-only frontier snapshot per tree size in
`blackbox.merkle_frontiers`. On startup it recomputes each log from the stored
sealed entries in O(N) time and refuses checkpoint service with
`merkle_frontier_mismatch` if the frontier or root disagrees. Entry reads remain
available during that degraded state. The current stage does not yet provide a
checkpoint scheduler or witness service.

## Docker/Postgres validation still required

Docker-dependent validation is intentionally deferred; Docker was not run for L4b.
The Compose files awaiting that validation are:

- `docker-compose.yml`
- `docker-compose.provider.yml`
- `deploy/witness-host/docker-compose.yml`

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

DK2 and DK3 remain deferred. They must not be treated as passed until Docker is
available and `docker compose version` succeeds, followed by validation of the
Compose files and their real cross-process/network behavior.

W2a/W2b witness fan-out, failure, recovery, partition and high-risk evidence
tests use in-process FastAPI witness instances with real local PostgreSQL for
ledger state. They do not prove real network timeouts, process crashes,
container partitions, TLS, or separate-host behavior; those remain DK3/deferred.

The in-memory store is an additive test seam. It does not replace or weaken the
existing Postgres implementation; `create_app()` continues to construct the
Postgres pool when no store is injected.
