"""Mutual TLS (mTLS) certificate authority and node identity management (§11.2, DK3)."""

from __future__ import annotations

import argparse
import datetime
import ipaddress
import os
import ssl
from pathlib import Path

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

    cert_path = output_dir / f"{common_name}.crt"
    key_path = output_dir / f"{common_name}.key"

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

    cert_path = output_dir / f"{common_name}.crt"
    key_path = output_dir / f"{common_name}.key"

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


def main() -> None:
    parser = argparse.ArgumentParser(description="Mutual TLS management tooling (§11.2)")
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


if __name__ == "__main__":
    main()
