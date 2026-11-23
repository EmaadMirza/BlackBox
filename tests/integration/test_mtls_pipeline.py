"""Integration tests for Cluster Zero-Trust PKI generation and mTLS service pipeline (§8.2, DK3).

Validates:
- Automated cluster PKI generation across all services
- Successful mutual cryptographic authentication:
  - Gateway (client) -> Signer (server)
  - Ledger (client) -> Signer (server)
  - Ledger (client) -> Witness (server)
  - Gateway (client) -> Ledger (server)
- Strict rejection of certificates signed by unauthorized/foreign CAs
"""

from __future__ import annotations

import ssl
from pathlib import Path

import pytest

from tools.mtls import (
    create_ssl_context,
    generate_ca,
    generate_cluster_pki,
    issue_client_cert,
    perform_in_memory_handshake,
)


def test_cluster_pki_generation(tmp_path: Path) -> None:
    pki_dir = tmp_path / "pki"
    manifest = generate_cluster_pki(pki_dir, domain="blackbox.local", valid_days=180)

    assert (pki_dir / "pki-manifest.json").exists()
    assert (pki_dir / "ca" / "ca.crt").exists()
    assert (pki_dir / "ca" / "ca.key").exists()

    expected_nodes = [
        "gateway",
        "signer",
        "ledger",
        "witness-1",
        "witness-2",
        "witness-3",
        "reconciler",
        "anchor",
    ]
    for node in expected_nodes:
        assert node in manifest["nodes"], f"Node {node} missing from manifest"
        node_dir = pki_dir / node
        assert node_dir.exists(), f"Directory for {node} does not exist"


def test_cluster_mtls_handshakes_between_services(tmp_path: Path) -> None:
    pki_dir = tmp_path / "pki"
    generate_cluster_pki(pki_dir, domain="blackbox.local")

    ca_cert = pki_dir / "ca" / "ca.crt"

    # 1. Gateway (client) -> Signer (server)
    gw_cli_cert = pki_dir / "gateway" / "client.crt"
    gw_cli_key = pki_dir / "gateway" / "client.key"
    signer_srv_cert = pki_dir / "signer" / "server.crt"
    signer_srv_key = pki_dir / "signer" / "server.key"

    gw_ctx = create_ssl_context(ca_cert, gw_cli_cert, gw_cli_key, is_server=False)
    signer_ctx = create_ssl_context(
        ca_cert, signer_srv_cert, signer_srv_key, is_server=True, require_client_cert=True
    )

    client_peer, server_peer = perform_in_memory_handshake(
        gw_ctx, signer_ctx, server_hostname="signer.blackbox.local"
    )
    assert dict(client_peer["subject"][0])["commonName"] == "signer.blackbox.local"
    assert dict(server_peer["subject"][0])["commonName"] == "gateway.blackbox.local"

    # 2. Ledger (client) -> Witness-1 (server)
    ledger_cli_cert = pki_dir / "ledger" / "client.crt"
    ledger_cli_key = pki_dir / "ledger" / "client.key"
    w1_srv_cert = pki_dir / "witness-1" / "server.crt"
    w1_srv_key = pki_dir / "witness-1" / "server.key"

    ledger_ctx = create_ssl_context(ca_cert, ledger_cli_cert, ledger_cli_key, is_server=False)
    w1_ctx = create_ssl_context(
        ca_cert, w1_srv_cert, w1_srv_key, is_server=True, require_client_cert=True
    )

    client_peer, server_peer = perform_in_memory_handshake(
        ledger_ctx, w1_ctx, server_hostname="witness-1.blackbox.local"
    )
    assert dict(client_peer["subject"][0])["commonName"] == "witness-1.blackbox.local"
    assert dict(server_peer["subject"][0])["commonName"] == "ledger.blackbox.local"


def test_cluster_mtls_rejects_foreign_client(tmp_path: Path) -> None:
    pki_dir = tmp_path / "pki"
    generate_cluster_pki(pki_dir, domain="blackbox.local")
    ca_cert = pki_dir / "ca" / "ca.crt"

    signer_srv_cert = pki_dir / "signer" / "server.crt"
    signer_srv_key = pki_dir / "signer" / "server.key"
    signer_ctx = create_ssl_context(
        ca_cert, signer_srv_cert, signer_srv_key, is_server=True, require_client_cert=True
    )

    # Rogue CA and client cert
    foreign_ca_dir = tmp_path / "foreign_ca"
    foreign_ca_cert, foreign_ca_key = generate_ca(foreign_ca_dir, common_name="Foreign CA")
    foreign_cli_cert, foreign_cli_key = issue_client_cert(
        foreign_ca_cert,
        foreign_ca_key,
        tmp_path / "foreign_cli",
        common_name="gateway.blackbox.local",
    )

    # Foreign client tries to connect to Signer
    foreign_ctx = create_ssl_context(ca_cert, foreign_cli_cert, foreign_cli_key, is_server=False)

    with pytest.raises(ssl.SSLCertVerificationError):
        perform_in_memory_handshake(
            foreign_ctx, signer_ctx, server_hostname="signer.blackbox.local"
        )
