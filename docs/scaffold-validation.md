# Stage 1 validation — 2026-10-11

Environment: macOS, local CPython 3.14.4; project declares Python >=3.11.
Dependencies are resolved with `uv --frozen` in `uv.lock`. CI declares Python
3.11/3.12/3.13; those interpreters were not exercised locally.

Stage 1 implementation is present and the real G1 and G2 tests pass. Stage 2/3
service behavior remains scaffolded. No claim below means that the deployment is
production-ready or that a later stage has passed.

## Requested commands and actual results

Commands below ran with the repository `.venv` tools.

```text
$ uv sync --frozen --extra services --extra dev
Checked 62 packages in 14ms
(exit 0)

$ .venv/bin/python -c "import libs.blackbox_core"
(no output; exit 0)

$ pytest -q
284 passed, 14 xfailed
(exit 0)

$ make lint
.venv/bin/ruff check .
All checks passed!
.venv/bin/ruff format --check .
150 files already formatted
(exit 0)

$ .venv/bin/python -m compileall -q libs services tools agent baseline tests bench
(no output; exit 0)

$ make gates
204 passed, 2 xfailed
(exit 0)

$ make attack
honest: VERIFIED
edit_and_rehash: TAMPERED
delete_seq_7: MISSING
plain_hash_chain control: ACCEPTED
(exit 0)

$ make demo-bundle
Development public evidence written to artifacts
(exit 0)

$ make verify
ten entries report VERIFIED
(exit 0)
```

The nine Task 0 demo-generation tests are included in the full-suite count. The
14 xfails are strict and are not gates: 12 acceptance scenarios remain pending,
G3 remains pending, and G4 remains pending.

## Gate status

| Gate | Status | Evidence |
| --- | --- | --- |
| G1 | **PASS** | Ten-entry signed log: edit plus rehash is detected at seq 5; deletion of seq 7 is `MISSING`; bare hash-chain control accepts the edit |
| G2 | **PASS** | RFC 6962 vectors, independent reference, all inclusion/consistency proofs for sizes 1–200, and proof bit-flip rejection |
| G3 | **PENDING** | Witness service and rewrite-refusal test are not implemented |
| G4 | **PENDING** | Signer attestation endpoint and provider body-digest enforcement are not implemented |

## Stage 1 coverage now implemented

- Strict schemas reject unknown fields, floats and invalid encoded values.
- NFC preprocessing and RFC 8785 canonical JSON are tested.
- Ed25519 signatures are domain-separated by structure label and log identity.
- Entry hash-chain sealing and precise break diagnostics are tested.
- Epoch certificates, half-open validity windows and revocation handling are tested.
- RFC 6962 Merkle roots, inclusion proofs and consistency proofs are tested.
- Signed checkpoints, witness-set authentication and quorum counting are tested.
- Offline bundle loading, pinned-key identity, proof verification, verdict precedence
  and commitment openings are tested.
- The development demo generator writes only public `bundle.json` and
  `pinned-keys.json`; private keys are ephemeral and never persisted.

## Not verified in this environment

- Docker Compose configuration: the `docker` executable is not installed locally.
- PostgreSQL migration execution and append-only trigger behavior.
- Service startup, HTTP routes, healthchecks and network isolation.
- Signer, ledger, witness, gateway, provider, reconciler and agent runtime behavior.
- Acceptance scenarios E1–E12 and production key custody/HSM guarantees.
- CI's Python 3.11–3.13 matrix and its Docker-equipped runner.

These gaps are intentional stage boundaries, not passing tests. See
`limitations.md` for unresolved interface/deployment decisions, `build-log.md` for
stage history, and `../project-tree.txt` for the source tree.
