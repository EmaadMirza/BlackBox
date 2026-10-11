# Trust zones and intended access

| Zone | Components | Compose networks |
| --- | --- | --- |
| A: untrusted callers | agent | agent_net |
| B: enforcement | gateway, Redis, approval | enforce_net; gateway also joins its upstream/downstream networks |
| C: sealing | signer, ledger, ledger DB, payload store | seal_net |
| D: downstream | independently configured mock provider, its DB | downstream_net; provider_storage for its DB |
| E: independence | three witnesses | witness_net locally; separately provisioned remote hosts |
| Offline | pinned-key verifier, root ceremony | no deployed network |

`read_net` connects ledger readers (reconciler, optional anchor and alerting).
Alerting joins service zones for future alarm delivery; it is not a security proxy.
Reconciler joins downstream for the read-only event feed. All main stack networks
are internal. Agent belongs only to agent_net; its only intended egress is gateway.
Provider's database never joins a main-stack network and its credentials are separate.

The main stack creates the named `blackbox_downstream` network; start it before the
provider project. The provider declares it external. Stop provider before main.
`BLACKBOX_DOWNSTREAM_NETWORK` overrides the shared name for separate development runs.

Docker network membership permits bidirectional peer connections: it cannot prove
signer ingress is gateway-only or ledger appends are signer-only. No published
signer/database port is useful isolation, not authentication. Identity checks,
mTLS, endpoint authorization and/or directional firewall policy must be designed
and tested in Stage 2/3. No working security boundary is claimed by this scaffold.

Local witnesses simulate independence with separate key/storage volumes. Deploy
`witness-host/docker-compose.yml` independently on each host for the eventual remote
topology; replace host URLs, provision mTLS and independent keys, and provide TLS
ingress. Its localhost port is deliberately not a public HTTP service.

TODO(spec §6.2, §11.2, §29.2): validate routes and bypass behavior in E5 and document
actual witness/provider operators with every acceptance run.
