"""Mutual TLS (mTLS) certificate authority and node identity management (§11.2, DK3)."""

from __future__ import annotations

import argparse
import datetime
import ipaddress
import os
import ssl
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def generate_ca(
    output_dir: Path,
    common_name: str = "BlackBox Mutual Root CA",
    valid_days: int = 3650,
) -> tuple[Path, Path]:
    """Generate an air-gapped or cluster-level Root Certificate Authority."""
    output_dir.mkdir(parents=True, exist_ok=True)
    ca_key = ed25519.Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    ski = x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key())

    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=valid_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(ski, critical=False)
        .sign(ca_key, None)
    )

    cert_path = output_dir / "ca.crt"
    key_path = output_dir / "ca.key"

    cert_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    key_bytes = ca_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key_bytes)

    return cert_path, key_path


def issue_server_cert(
    ca_cert_path: Path,
    ca_key_path: Path,
    output_dir: Path,
    common_name: str,
    san_dns: list[str] | None = None,
    san_ips: list[str] | None = None,
    valid_days: int = 365,
    filename_prefix: str | None = None,
) -> tuple[Path, Path]:
    """Issue a server TLS certificate signed by the CA with SANs."""
    output_dir.mkdir(parents=True, exist_ok=True)
    ca_key = serialization.load_pem_private_key(ca_key_path.read_bytes(), password=None)
    ca_cert = x509.load_pem_x509_certificate(ca_cert_path.read_bytes())

    srv_key = ed25519.Ed25519PrivateKey.generate()
    srv_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)

    san_entries: list[x509.GeneralName] = []
    if san_dns:
        san_entries.extend(x509.DNSName(dns) for dns in san_dns)
    if san_ips:
        for ip in san_ips:
            san_entries.append(x509.IPAddress(ipaddress.ip_address(ip)))
    if not san_entries:
        san_entries.append(x509.DNSName(common_name))

    srv_cert = (
        x509.CertificateBuilder()
        .subject_name(srv_name)
        .issuer_name(ca_cert.subject)
        .public_key(srv_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=valid_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
        )
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(ca_key, None)
    )

    prefix = filename_prefix if filename_prefix is not None else common_name
    cert_path = output_dir / f"{prefix}.crt"
    key_path = output_dir / f"{prefix}.key"

    cert_path.write_bytes(srv_cert.public_bytes(serialization.Encoding.PEM))
    key_bytes = srv_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key_bytes)

    return cert_path, key_path


def issue_client_cert(
    ca_cert_path: Path,
    ca_key_path: Path,
    output_dir: Path,
    common_name: str,
    valid_days: int = 365,
    filename_prefix: str | None = None,
) -> tuple[Path, Path]:
    """Issue a client mTLS certificate signed by the CA."""
    output_dir.mkdir(parents=True, exist_ok=True)
    ca_key = serialization.load_pem_private_key(ca_key_path.read_bytes(), password=None)
    ca_cert = x509.load_pem_x509_certificate(ca_cert_path.read_bytes())

    cli_key = ed25519.Ed25519PrivateKey.generate()
    cli_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)

    cli_cert = (
        x509.CertificateBuilder()
        .subject_name(cli_name)
        .issuer_name(ca_cert.subject)
        .public_key(cli_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=valid_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .sign(ca_key, None)
    )

    prefix = filename_prefix if filename_prefix is not None else common_name
    cert_path = output_dir / f"{prefix}.crt"
    key_path = output_dir / f"{prefix}.key"

    cert_path.write_bytes(cli_cert.public_bytes(serialization.Encoding.PEM))
    key_bytes = cli_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key_bytes)

    return cert_path, key_path


def create_ssl_context(
    ca_cert_path: Path,
    cert_path: Path,
    key_path: Path,
    is_server: bool,
    require_client_cert: bool = True,
) -> ssl.SSLContext:
    """Create a configured Python ssl.SSLContext for client or server mTLS."""
    if is_server:
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.load_cert_chain(cert_path, key_path)
        ctx.load_verify_locations(ca_cert_path)
        if require_client_cert:
            ctx.verify_mode = ssl.CERT_REQUIRED
    else:
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(ca_cert_path))
        ctx.load_cert_chain(cert_path, key_path)

    return ctx


def perform_in_memory_handshake(
    client_ctx: ssl.SSLContext,
    server_ctx: ssl.SSLContext,
    server_hostname: str = "localhost",
    max_cycles: int = 15,
) -> tuple[dict, dict]:
    """Execute an in-memory mTLS handshake via MemoryBIO, returning (client_peer, server_peer)."""
    cli_in = ssl.MemoryBIO()
    cli_out = ssl.MemoryBIO()
    srv_in = ssl.MemoryBIO()
    srv_out = ssl.MemoryBIO()

    cli_ssl = client_ctx.wrap_bio(
        cli_in, cli_out, server_side=False, server_hostname=server_hostname
    )
    srv_ssl = server_ctx.wrap_bio(srv_in, srv_out, server_side=True)

    for _ in range(max_cycles):
        try:
            cli_ssl.do_handshake()
        except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
            pass
        if cli_out.pending:
            srv_in.write(cli_out.read())

        try:
            srv_ssl.do_handshake()
        except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
            pass
        if srv_out.pending:
            cli_in.write(srv_out.read())

    client_peer = cli_ssl.getpeercert()
    server_peer = srv_ssl.getpeercert()
    if not client_peer or not server_peer:
        raise ssl.SSLError("In-memory mTLS handshake failed to complete")
    return client_peer, server_peer


def generate_cluster_pki(
    output_dir: Path | str,
    domain: str = "internal",
    valid_days: int = 365,
) -> dict[str, Any]:
    """Generate complete zero-trust mTLS infrastructure for all cluster nodes (§8.2, DK3)."""
    import json

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    ca_dir = output_dir / "ca"
    ca_cert, ca_key = generate_ca(ca_dir, common_name=f"BlackBox {domain.capitalize()} Root CA")

    nodes = {
        "gateway": {
            "san_dns": [f"gateway.{domain}", "gateway", "localhost"],
            "is_server": True,
            "is_client": True,
        },
        "signer": {
            "san_dns": [f"signer.{domain}", "signer", "localhost"],
            "is_server": True,
            "is_client": False,
        },
        "ledger": {
            "san_dns": [f"ledger.{domain}", "ledger", "localhost"],
            "is_server": True,
            "is_client": True,
        },
        "witness-1": {
            "san_dns": [f"witness-1.{domain}", "witness-1", "localhost"],
            "is_server": True,
            "is_client": True,
        },
        "witness-2": {
            "san_dns": [f"witness-2.{domain}", "witness-2", "localhost"],
            "is_server": True,
            "is_client": True,
        },
        "witness-3": {
            "san_dns": [f"witness-3.{domain}", "witness-3", "localhost"],
            "is_server": True,
            "is_client": True,
        },
        "reconciler": {
            "san_dns": [f"reconciler.{domain}", "reconciler"],
            "is_server": False,
            "is_client": True,
        },
        "anchor": {
            "san_dns": [f"anchor.{domain}", "anchor"],
            "is_server": False,
            "is_client": True,
        },
    }

    manifest: dict[str, Any] = {
        "format_version": "1",
        "domain": domain,
        "ca_cert": str(ca_cert.relative_to(output_dir)),
        "nodes": {},
    }

    for name, config in nodes.items():
        node_dir = output_dir / name
        node_entry: dict[str, str] = {}
        if config["is_server"]:
            srv_cert, srv_key = issue_server_cert(
                ca_cert,
                ca_key,
                node_dir,
                common_name=f"{name}.{domain}",
                san_dns=config["san_dns"],
                valid_days=valid_days,
                filename_prefix="server",
            )
            node_entry["server_cert"] = str(srv_cert.relative_to(output_dir))
            node_entry["server_key"] = str(srv_key.relative_to(output_dir))
        if config["is_client"]:
            cli_cert, cli_key = issue_client_cert(
                ca_cert,
                ca_key,
                node_dir,
                common_name=f"{name}.{domain}",
                valid_days=valid_days,
                filename_prefix="client",
            )
            node_entry["client_cert"] = str(cli_cert.relative_to(output_dir))
            node_entry["client_key"] = str(cli_key.relative_to(output_dir))
        manifest["nodes"][name] = node_entry

    manifest_path = output_dir / "pki-manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2))
    return manifest


def verify_certificate(
    cert_source: Path | bytes | str,
    ca_cert_source: Path | bytes | str,
    *,
    expected_common_name: str | None = None,
    expected_role: str | None = None,
    now: datetime | None = None,
) -> bool:
    """Verify certificate validity, CA signature, common name/SAN, and EKU (§8.2)."""
    if isinstance(cert_source, Path):
        cert_bytes = cert_source.read_bytes()
    elif isinstance(cert_source, str):
        cert_bytes = (
            cert_source.encode("utf-8")
            if cert_source.startswith("-----BEGIN")
            else Path(cert_source).read_bytes()
        )
    else:
        cert_bytes = cert_source

    if isinstance(ca_cert_source, Path):
        ca_bytes = ca_cert_source.read_bytes()
    elif isinstance(ca_cert_source, str):
        ca_bytes = (
            ca_cert_source.encode("utf-8")
            if ca_cert_source.startswith("-----BEGIN")
            else Path(ca_cert_source).read_bytes()
        )
    else:
        ca_bytes = ca_cert_source

    cert = x509.load_pem_x509_certificate(cert_bytes)
    ca_cert = x509.load_pem_x509_certificate(ca_bytes)

    # 1. Cryptographic signature check against CA public key
    ca_cert.public_key().verify(cert.signature, cert.tbs_certificate_bytes)

    # 2. Time validity check
    check_time = now or datetime.datetime.now(datetime.timezone.utc)
    if not (cert.not_valid_before_utc <= check_time <= cert.not_valid_after_utc):
        raise ValueError("Certificate is expired or not yet valid.")

    # 3. Expected Common Name / SAN check
    if expected_common_name:
        expected_norm = expected_common_name.lower().strip()
        names: set[str] = set()
        for attr in cert.subject:
            if attr.oid == x509.NameOID.COMMON_NAME:
                names.add(str(attr.value).lower().strip())
        try:
            san_ext = cert.extensions.get_extension_for_oid(
                x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            for item in san_ext.value:  # type: ignore[attr-defined]
                names.add(str(item.value).lower().strip())
        except x509.ExtensionNotFound:
            pass

        if expected_norm not in names:
            raise ValueError(
                f"Certificate does not contain expected Common Name or SAN: {expected_common_name}"
            )

    # 4. Expected Extended Key Usage
    if expected_role:
        try:
            eku_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.EXTENDED_KEY_USAGE)
            usages = eku_ext.value  # type: ignore[attr-defined]
            if expected_role.lower() == "server" and ExtendedKeyUsageOID.SERVER_AUTH not in usages:
                raise ValueError("Certificate does not have SERVER_AUTH extended key usage.")
            if expected_role.lower() == "client" and ExtendedKeyUsageOID.CLIENT_AUTH not in usages:
                raise ValueError("Certificate does not have CLIENT_AUTH extended key usage.")
        except x509.ExtensionNotFound as exc:
            raise ValueError("Certificate lacks ExtendedKeyUsage extension.") from exc

    return True


def main() -> None:
    parser = argparse.ArgumentParser(description="Mutual TLS management tooling (§8.2, §11.2)")
    commands = parser.add_subparsers(dest="command", required=True)

    ca_cmd = commands.add_parser("generate-ca")
    ca_cmd.add_argument("--output", type=Path, required=True)
    ca_cmd.add_argument("--name", default="BlackBox Mutual Root CA")

    srv_cmd = commands.add_parser("issue-server")
    srv_cmd.add_argument("--ca-cert", type=Path, required=True)
    srv_cmd.add_argument("--ca-key", type=Path, required=True)
    srv_cmd.add_argument("--output", type=Path, required=True)
    srv_cmd.add_argument("--common-name", required=True)
    srv_cmd.add_argument("--san-dns", nargs="*", default=None)
    srv_cmd.add_argument("--san-ip", nargs="*", default=None)

    cli_cmd = commands.add_parser("issue-client")
    cli_cmd.add_argument("--ca-cert", type=Path, required=True)
    cli_cmd.add_argument("--ca-key", type=Path, required=True)
    cli_cmd.add_argument("--output", type=Path, required=True)
    cli_cmd.add_argument("--common-name", required=True)

    cluster_cmd = commands.add_parser("generate-cluster-pki")
    cluster_cmd.add_argument("--output", type=Path, required=True)
    cluster_cmd.add_argument("--domain", default="internal")
    cluster_cmd.add_argument("--days", type=int, default=365)

    verify_cmd = commands.add_parser("verify-cert")
    verify_cmd.add_argument("--cert", type=Path, required=True)
    verify_cmd.add_argument("--ca-cert", type=Path, required=True)
    verify_cmd.add_argument("--common-name", default=None)
    verify_cmd.add_argument("--role", choices=["server", "client"], default=None)

    args = parser.parse_args()
    if args.command == "generate-ca":
        cert, key = generate_ca(args.output, common_name=args.name)
        print(f"Root CA created: cert={cert}, key={key}")
    elif args.command == "issue-server":
        cert, key = issue_server_cert(
            args.ca_cert,
            args.ca_key,
            args.output,
            args.common_name,
            san_dns=args.san_dns,
            san_ips=args.san_ip,
        )
        print(f"Server certificate issued: cert={cert}, key={key}")
    elif args.command == "issue-client":
        cert, key = issue_client_cert(args.ca_cert, args.ca_key, args.output, args.common_name)
        print(f"Client certificate issued: cert={cert}, key={key}")
    elif args.command == "generate-cluster-pki":
        res = generate_cluster_pki(args.output, domain=args.domain, valid_days=args.days)
        print(f"Cluster PKI generated with {len(res['nodes'])} nodes: {args.output}")
    elif args.command == "verify-cert":
        verify_certificate(
            args.cert,
            args.ca_cert,
            expected_common_name=args.common_name,
            expected_role=args.role,
        )
        print(f"Certificate {args.cert} successfully verified against CA {args.ca_cert}.")


if __name__ == "__main__":
    main()
