# Payload store and commitment semantics

Stage 3 sensitive request and result values are kept outside the ledger. The
payload store generates a random 32-byte salt and records the commitment

```text
SHA-256(salt || value)
```

The ledger entry contains only the commitment and a payload reference. The
payload store keeps the value and salt in its own state directory and requires
service authentication for retrieval. Error responses are sanitized and do not
include payload contents, salts, filesystem paths, or exception details.

Deleting a payload removes the stored value and salt but retains the commitment
metadata. This is crypto-shredding semantics: the commitment remains publicly
verifiable when an auditor already has the original value and salt, but the
deleted payload can no longer be opened through the service.

Offline bundles may include explicit openings. The verifier checks every
opening against the commitment in the signed entry; wrong values or salts make
the affected entry non-verified. Supplying no opening does not reveal the
payload.

The Stage 3 provider and payload-store tests use separate state directories.
They run in-process with the real PostgreSQL ledger where applicable. Container
and real-network isolation remain deferred. The provider is a same-team mock
with **reduced independence**.
