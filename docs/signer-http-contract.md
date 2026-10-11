# Signer HTTP contract

This authorized wire-contract decision supplements spec §§7.3 and 9 without
changing the original specification. `services/signer/http_contract.py` declares
transport models/constants and reuses the signed types in
`libs/blackbox_core/schemas.py`. The liveness route and shared bearer-auth
dependency are implemented; seal, attestation and checkpoint routes remain
unimplemented. These tests are not evidence that G3/G4 or E1–E12 pass.

## Endpoints and JSON

POST bodies and all responses use `application/json`, with the snake_case fields
and strict JSON/encoding profile in [stage1-protocol.md](stage1-protocol.md).
Unknown fields, floats, coercions, duplicate JSON keys and malformed JSON are
rejected; integers must satisfy core bounds. HTTP JSON need not already be JCS;
canonicalization and cryptography remain core responsibilities.

| Method/path | Authentication | Request body | 200 response body |
| --- | --- | --- | --- |
| `GET /health` | None | None | Exactly `{"status":"ok"}` (`HealthResponse`) |
| `POST /seal` | Bearer | Raw candidate `Entry` JSON object, discriminated by `type`; no wrapper or signature | `SealedEntry`: `{"body": <Entry>, "signature": <signature>}` |
| `POST /attest` | Bearer | Exactly `{"intent_seq": <integer>}` (`AttestRequest`) | Signed core `Attestation` |
| `POST /checkpoint` | Bearer | Unsigned core `Checkpoint`; `signature` omitted or `""` | Signed core `Checkpoint` |

`intent_seq` is a strict integer in `0..2^53−1`, not a boolean, string or float.
`/attest` accepts no caller-supplied digest, log id or idempotency key: these come
from the sealed intent. The response fields are `log_id`, `intent_seq`,
`idempotency_key`, `body_digest`, `issued_at`, `expires_at`, `signature`.

The checkpoint fields are `log_id`, `tree_size`, `root_hash`, `latest_seq`,
`epoch_id`, `signer_timestamp`, and optional empty request `signature`. A nonempty
request signature violates the unsigned request contract (422); the existing
core `Checkpoint` accepts signatures, so the future HTTP adapter must enforce
this additional precondition. Every successful signed response has a nonempty,
valid signature; empty signatures or fabricated results are never a success.
Well-formed signer-only `epoch_start`/`epoch_end` candidates are rejected by
`/seal` as a rule conflict (409), not silently accepted through the HTTP API.

`/health` is unauthenticated only for Compose liveness. It reports that the HTTP
process is alive, even if auth, keys or dependencies are unavailable; it is not
readiness, integrity, quorum or epoch-validity evidence.

## Authentication and deployment boundary

Each POST requires `Authorization: Bearer <token>`. The expected token is loaded
from the signer's `SIGNER_AUTH_TOKEN` environment variable, not JSON or a query
parameter. Use one Authorization header, one space between scheme and token,
and a nonempty ASCII token without whitespace. Header names and the scheme are
case-insensitive; token comparison is exact and case-sensitive, with no trimming
or coercion. Compare supplied and configured token bytes using constant-time
`hmac.compare_digest` (or an equivalent vetted implementation), not `==`.

- Missing, empty or invalid configuration fails closed with 503
  `auth_unavailable`; it never disables auth. Check configuration before
  authenticating requests, so this outcome also applies if the header is missing.
- With valid configuration, missing, malformed, duplicate or incorrect
  Authorization returns 401 `invalid_auth`, with `WWW-Authenticate: Bearer`.
  These failures use the same non-sensitive message.
- Authenticate before body validation or signer operations. A missing/invalid
  credential takes precedence over malformed JSON; no signing occurs on failure.

No HTTP operation accepts or returns private signing keys or provisions keys.
Key loading and custody remain inside the signer; the token is an interim
transport credential, not a signing key. Network membership is not
authentication. mTLS and directional, caller-/operation-specific authorization
(including the gateway/ledger ingress conflict) remain deployment work. This
shared token does not resolve those questions. Single-writer serialization and
exactly **one Uvicorn worker** remain required.

The current `create_app()` accepts an injected signer sealer for controlled
startup/tests. When no runtime sealer is supplied, `/seal` fails closed with
`503 signer_unavailable`; the HTTP layer never fabricates a key or epoch.

### Live clock and rate quota (Task A)

`SignerSealer` accepts `clock: Callable[[], str]`, defaulting to the signer-owned
live UTC clock. Every seal reads that clock once, validates its UTC-millisecond
timestamp using core, and uses that same sample for epoch checks, signer timestamp
matching and rate accounting. The former fixed `trusted_now`/`now` constructor
arguments are removed. Fixed-date tests inject a clock; production must not use a
fixed test clock. This does not change the candidate or signed entry format.

Quota is a fixed UTC calendar-second bucket, not a sliding one-second window.
Different milliseconds of the same second share the cap; a later second resets
it. A backward second is refused, not treated as a reset. The signer-local SQLite
database is beside `SIGNER_STATE_PATH` (or the default signer state path), named
`<state filename>.rate.sqlite3`. SQLite is used only for operational rate state;
it is not the future PostgreSQL ledger or a cryptographic integrity boundary.
The database contains only the second and reservation count, never keys or entries.

After candidate/rule validation, quota is transactionally reserved and committed
before invoking the signing operation. Quota survives sealer recreation and a new
Python process using the same storage. Signing or chain-state persistence failures
retain the reservation: conservative under-use is preferable to exceeding the cap
through retries. Invalid candidates do not consume quota. Corrupt or unavailable
quota storage fails closed before signing. These behaviors are covered by
`tests/unit/test_signer_clock_rate.py` and `tests/unit/test_signer_rate_limit.py`.

Preserve the quota database with the signer state. Complete storage deletion or
rollback detection across a fresh startup and uncertain chain-state commits remain
Task D, not guarantees of this rate fix. The quota and chain-state writes are not
one transaction. Exactly one signer writer/worker is still required; concurrent
quota reservations being safe does not authorize parallel sealing. No epoch
rollover, log binding or intent/outcome recovery is implemented by Task A.

### Configured log binding (Task B)

`SignerSealer` requires an explicit `log_id` constructor argument from trusted
signer configuration. It is validated with core's existing hash decoder; no
identity is inferred from a gateway request and no default log is supplied.
After strict candidate parsing, a candidate for another log raises a signer rule
conflict before quota reservation, signing or chain-state persistence. `/seal`
returns the existing sanitized `409 rule_conflict` envelope for that refusal.
Correct-log requests retain the existing core sealing and domain separation.
Coverage is in `tests/unit/test_signer_log_binding.py`, including a wrong-log
HTTP request followed by a successful correct-log request at a cap of one.

This binds each sealer instance to its configured identity; it does not verify
the configuration against a pinned root/epoch certificate at startup. The chain
state identity persistence and uncertain-commit recovery are covered by Task D
below. Certificate/key provisioning and persistent deployment configuration remain
separate unresolved work.

### Durable state recovery (Task D)

The signer state file now includes the configured `log_id` alongside the sequence,
hash and epoch. Loading with a different configured identity fails closed. The
state path also has a durable initialization sentinel; deleting the state after
initialization is not treated as a fresh signer. A pre-commit marker is fsynced
before replacement and remains present when the post-replacement directory fsync
fails. Startup and signing refuse while that marker exists, because the chain head
commit is uncertain. Corrupt, legacy state without `log_id`, missing initialized
state and uncertain commits all require explicit recovery rather than sequence
reuse. Tests cover the marker and missing-state boundaries. This is crash-recovery
behavior, not a claim of HSM or PostgreSQL transactional durability.

## Status and rejection contract

For the operations above, every rejection uses exactly
`{"error":{"code":<string>,"message":<string>}}` (`ErrorResponse`), without
FastAPI validation details or additional fields. Codes are stable public
identifiers; messages are fixed, non-sensitive summaries. Never expose input
values, tokens, keys, paths, stack traces or raw exception text. Representative
codes/messages below define the baseline; more specific public rule codes can
be added without changing the envelope or status meanings.

| Status | Meaning | Representative code / message |
| --- | --- | --- |
| 200 | Successful operation | Endpoint-specific response above |
| 401 | Missing/invalid auth with configured token | `invalid_auth` / `Authentication required.` |
| 409 | Well-formed request conflicts with signer rules or available state | `rule_conflict` / `Request conflicts with signer rules.` |
| 422 | Malformed JSON or schema/unsigned-request violation | `invalid_request` / `Invalid request.` |
| 503 | Dependency, key, or usable signer state unavailable | `signer_unavailable` / `Signer unavailable.`; `auth_unavailable` / `Authentication unavailable.` |
| 500 | Unexpected internal error | `internal_error` / `Internal error.` |

Sequence/previous-hash conflicts, reserved entry types and rate-cap refusals are
409. A known state inconsistent with a request is 409; unreadable/corrupt state,
unavailable storage, or no usable key/epoch after attempted recovery is 503.
Schema validation must happen before calling the sealer, rather than mapping all
`SignerRuleError` exceptions to 409 (it currently also wraps schema errors).
No response pretends a failed operation succeeded. These mappings and exception
sanitization are requirements for the future adapter, not implemented behavior.

## Attest/checkpoint prerequisites (not implemented)

- **Attest:** authenticated lookup/verification of the sealed intent; persistent
  prior-attestation/digest tracking; trusted risk classification and verified
  witnessed-checkpoint coverage for high-risk intents; attestation-key custody,
  trusted time, expiry handling and core domain-separated signing. Apply §9.4
  before issuing any attestation. A sequence alone is not sufficient evidence.
- **Checkpoint:** authenticated ledger tree-state/evidence access; durable signer
  last-sealed state and serialized epoch lifecycle; verification of claimed size
  and latest-entry hash against what the signer sealed; trusted time and a usable
  epoch signing operation. `Checkpoint` has no latest-entry-hash/proof field:
  the evidence-fetch/trust design must be implemented before this endpoint can
  sign. Echoing or blindly signing the supplied root is not verification.
- **Both:** fail-closed dependency/state handling, request serialization, runtime
  error mapping and endpoint/auth integration tests. Core models alone do not
  establish these behaviors; no attest/checkpoint implementation or gate advance
  is claimed by this contract.
