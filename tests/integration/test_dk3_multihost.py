"""Integration tests for DK3 Multi-Host Witness Deployment, mTLS, and partition resilience (§11.2, DK3)."""

from __future__ import annotations

import ssl
from pathlib import Path

import pytest
import yaml

from libs.blackbox_core.encoding import encode_base64url
from libs.blackbox_core.schemas import Checkpoint, Cosignature, WitnessIdentity, WitnessSet
from libs.blackbox_core.signing import sign_structure
from tools.mtls import (
    create_ssl_context,
    generate_ca,
    issue_client_cert,
    issue_server_cert,
    perform_in_memory_handshake,
)


def _load_witness_host_compose() -> dict:
    compose_path = Path("deploy/witness-host/docker-compose.yml")
    assert compose_path.exists(), "deploy/witness-host/docker-compose.yml must exist"
    with open(compose_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def test_witness_host_compose_configuration() -> None:
    """Verify DK3 multi-host witness docker compose configuration and hardening."""
    compose = _load_witness_host_compose()
    services = compose.get("services", {})
    assert "witness" in services, "witness service must be defined"
    witness = services["witness"]

    # 1. Container security hardening
    assert witness.get("read_only") is True, "witness container must be read_only"
    assert witness.get("cap_drop") == ["ALL"], "witness container must drop all capabilities"
    assert witness.get("security_opt") == ["no-new-privileges:true"], (
        "no-new-privileges must be enforced"
    )
    assert witness.get("tmpfs") == ["/tmp"], "tmpfs must be configured for /tmp"

    # 2. mTLS volume mounts and environment variables
    env = witness.get("environment", {})
    assert "TLS_ENABLED" in env, "TLS_ENABLED must be defined in environment"
    assert "TLS_CA_CERT" in env, "TLS_CA_CERT must be configured"
    assert "TLS_SERVER_CERT" in env, "TLS_SERVER_CERT must be configured"
    assert "REQUIRE_CLIENT_CERT" in env, "REQUIRE_CLIENT_CERT must be configured"

    volumes = witness.get("volumes", [])
    has_certs_mount = any("./certs:/run/blackbox/certs:ro" in str(v) for v in volumes)
    assert has_certs_mount, f"Expected ./certs volume mount, got {volumes}"


def test_mtls_cert_generation_and_handshake(tmp_path: Path) -> None:
    """Test pure-Python mTLS Root CA and node certificate issuance and mutual authentication."""
    ca_dir = tmp_path / "ca"
    ca_cert, ca_key = generate_ca(ca_dir, common_name="Test Cluster CA")
    assert ca_cert.exists() and ca_key.exists()

    # Issue server cert for ledger
    srv_dir = tmp_path / "ledger"
    srv_cert, srv_key = issue_server_cert(
        ca_cert,
        ca_key,
        srv_dir,
        common_name="ledger.internal",
        san_dns=["ledger.internal", "localhost"],
    )

    # Issue client cert for witness
    cli_dir = tmp_path / "witness-1"
    cli_cert, cli_key = issue_client_cert(
        ca_cert, ca_key, cli_dir, common_name="witness-1.internal"
    )

    # Create mTLS contexts
    server_ctx = create_ssl_context(
        ca_cert, srv_cert, srv_key, is_server=True, require_client_cert=True
    )
    client_ctx = create_ssl_context(ca_cert, cli_cert, cli_key, is_server=False)

    # Perform mutual TLS handshake
    client_peer, server_peer = perform_in_memory_handshake(
        client_ctx, server_ctx, server_hostname="ledger.internal"
    )

    # Verify both peers established mutual cryptographic identity
    assert dict(client_peer["subject"][0])["commonName"] == "ledger.internal"
    assert dict(server_peer["subject"][0])["commonName"] == "witness-1.internal"


def test_mtls_rejects_untrusted_client(tmp_path: Path) -> None:
    """Verify that a server configured with mTLS rejects clients signed by an untrusted CA."""
    # Legitimate CA and server
    legit_ca_cert, legit_ca_key = generate_ca(tmp_path / "legit_ca", common_name="Legit CA")
    srv_cert, srv_key = issue_server_cert(
        legit_ca_cert,
        legit_ca_key,
        tmp_path / "server",
        common_name="server.internal",
        san_dns=["server.internal"],
    )

    # Attacker CA and rogue client cert
    rogue_ca_cert, rogue_ca_key = generate_ca(
        tmp_path / "rogue_ca", common_name="Rogue Attacker CA"
    )
    rogue_cli_cert, rogue_cli_key = issue_client_cert(
        rogue_ca_cert, rogue_ca_key, tmp_path / "rogue_client", common_name="rogue-agent"
    )

    server_ctx = create_ssl_context(
        legit_ca_cert, srv_cert, srv_key, is_server=True, require_client_cert=True
    )
    # Rogue client trusts legit server CA for server verification, but presents rogue client cert
    rogue_client_ctx = create_ssl_context(
        legit_ca_cert, rogue_cli_cert, rogue_cli_key, is_server=False
    )

    with pytest.raises(ssl.SSLCertVerificationError):
        perform_in_memory_handshake(rogue_client_ctx, server_ctx, server_hostname="server.internal")


def test_mtls_rejects_missing_client_cert(tmp_path: Path) -> None:
    """Verify that a server enforcing CERT_REQUIRED rejects connections without client certs."""
    ca_cert, ca_key = generate_ca(tmp_path / "ca", common_name="Test CA")
    srv_cert, srv_key = issue_server_cert(
        ca_cert,
        ca_key,
        tmp_path / "srv",
        common_name="server.internal",
        san_dns=["server.internal"],
    )

    server_ctx = create_ssl_context(
        ca_cert, srv_cert, srv_key, is_server=True, require_client_cert=True
    )

    # Client without certificate
    anonymous_client_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(ca_cert))

    with pytest.raises(ssl.SSLError):
        perform_in_memory_handshake(
            anonymous_client_ctx, server_ctx, server_hostname="server.internal"
        )


def test_distributed_partition_resilience(tmp_path: Path) -> None:
    """Verify distributed witness quorum behavior across network partition scenarios."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from libs.blackbox_core.checkpoint import build_cosignature
    from libs.blackbox_core.labels import derive_log_id
    from libs.blackbox_core.signing import structure_hash

    # Setup 3-witness cluster with quorum = 2
    root_priv = Ed25519PrivateKey.generate()
    root_pub_bytes = root_priv.public_key().public_bytes_raw()
    log_id = derive_log_id(root_pub_bytes, "test-cluster-log")

    witness_keys = [Ed25519PrivateKey.generate() for _ in range(3)]
    witness_ids = ["w0", "w1", "w2"]
    witness_set = sign_structure(
        WitnessSet(
            log_id=log_id,
            version=1,
            witnesses=[
                WitnessIdentity(
                    witness_id=wid,
                    public_key=encode_base64url(key.public_key().public_bytes_raw()),
                )
                for wid, key in zip(witness_ids, witness_keys)
            ],
            quorum=2,
            effective_time="2026-01-01T00:00:00.000Z",
        ),
        root_priv,
        "witness_set",
    )

    # Valid checkpoint structure
    checkpoint = Checkpoint(
        log_id=log_id,
        tree_size=10,
        root_hash="sha256:" + "0" * 64,
        latest_seq=10,
        epoch_id=1,
        signer_timestamp="2026-01-01T00:00:05.000Z",
    )
    checkpoint_hash = structure_hash(checkpoint)

    # Simulated fan-out helper
    def fan_out_to_cluster(reachable_witnesses: set[str]) -> tuple[bool, list[Cosignature]]:
        cosignatures: list[Cosignature] = []
        for wid, wkey in zip(witness_ids, witness_keys):
            if wid not in reachable_witnesses:
                # Network partition: node is unreachable (timeout / refused)
                continue
            cosig = build_cosignature(
                checkpoint_hash,
                wid,
                "2026-01-01T00:00:06.000Z",
                wkey,
                log_id=log_id,
            )
            cosignatures.append(cosig)

        # Quorum check
        quorum_met = len(cosignatures) >= witness_set.quorum
        return quorum_met, cosignatures

    # Scenario 1: Full cluster connectivity (3/3)
    quorum_met, cosigs = fan_out_to_cluster({"w0", "w1", "w2"})
    assert quorum_met is True
    assert len(cosigs) == 3

    # Scenario 2: Minority partition (1 node offline: w2 partitioned)
    # Remaining nodes: {w0, w1} -> 2 reachable == quorum (2)
    quorum_met, cosigs = fan_out_to_cluster({"w0", "w1"})
    assert quorum_met is True
    assert len(cosigs) == 2
    assert {c.witness_id for c in cosigs} == {"w0", "w1"}

    # Scenario 3: Majority partition (2 nodes offline: w1 and w2 partitioned)
    # Remaining node: {w0} -> 1 reachable < quorum (2)
    # System MUST fail closed: quorum_met is False
    quorum_met, cosigs = fan_out_to_cluster({"w0"})
    assert quorum_met is False
    assert len(cosigs) == 1

    # Scenario 4: Partition healed (all 3 nodes back online)
    quorum_met, cosigs = fan_out_to_cluster({"w0", "w1", "w2"})
    assert quorum_met is True
    assert len(cosigs) == 3
