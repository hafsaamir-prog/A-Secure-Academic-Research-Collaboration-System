"""
Simple PKI helper for Academic Research Collaborator.

Generates a self-signed CA certificate and a server certificate,
and saves them as PEM files in the ./certs directory:

- certs/ca_key.pem
- certs/ca_cert.pem
- certs/server_key.pem
- certs/server_cert.pem
"""

import os
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


CERT_DIR = "certs"
CA_KEY_FILE = os.path.join(CERT_DIR, "ca_key.pem")
CA_CERT_FILE = os.path.join(CERT_DIR, "ca_cert.pem")
SERVER_KEY_FILE = os.path.join(CERT_DIR, "server_key.pem")
SERVER_CERT_FILE = os.path.join(CERT_DIR, "server_cert.pem")


def _generate_ca():
    """Generate self-signed CA key and certificate."""
    os.makedirs(CERT_DIR, exist_ok=True)

    ca_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Islamabad"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Islamabad"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Research CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"Research-CA"),
    ])

    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow() - timedelta(minutes=1))
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .sign(private_key=ca_key, algorithm=hashes.SHA256(), backend=default_backend())
    )

    with open(CA_KEY_FILE, "wb") as f:
        f.write(
            ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    with open(CA_CERT_FILE, "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

    print(f"[PKI] Generated CA key:   {CA_KEY_FILE}")
    print(f"[PKI] Generated CA cert:  {CA_CERT_FILE}")

    return ca_key, ca_cert


def _generate_server_cert(ca_key, ca_cert, common_name="localhost"):
    """Generate server key and certificate signed by CA."""
    server_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Islamabad"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Islamabad"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Research Server"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    server_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow() - timedelta(minutes=1))
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(u"localhost"),
                x509.DNSName(u"127.0.0.1"),
            ]),
            critical=False,
        )
        .sign(private_key=ca_key, algorithm=hashes.SHA256(), backend=default_backend())
    )

    with open(SERVER_KEY_FILE, "wb") as f:
        f.write(
            server_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    with open(SERVER_CERT_FILE, "wb") as f:
        f.write(server_cert.public_bytes(serialization.Encoding.PEM))

    print(f"[PKI] Generated server key:  {SERVER_KEY_FILE}")
    print(f"[PKI] Generated server cert: {SERVER_CERT_FILE}")

    return server_key, server_cert


def ensure_certificates():
    """
    If PEM files do not exist, generate CA and server certificates.
    Returns paths so server/client can load them if needed.
    """
    ca_exists = os.path.exists(CA_KEY_FILE) and os.path.exists(CA_CERT_FILE)
    server_exists = os.path.exists(SERVER_KEY_FILE) and os.path.exists(SERVER_CERT_FILE)

    if ca_exists and server_exists:
        print("[PKI] Using existing CA and server certificates.")
        return {
            "ca_key": CA_KEY_FILE,
            "ca_cert": CA_CERT_FILE,
            "server_key": SERVER_KEY_FILE,
            "server_cert": SERVER_CERT_FILE,
        }

    print("[PKI] Certificates not found, generating new CA and server certs...")
    ca_key, ca_cert = _generate_ca()
    _generate_server_cert(ca_key, ca_cert, common_name="localhost")

    return {
        "ca_key": CA_KEY_FILE,
        "ca_cert": CA_CERT_FILE,
        "server_key": SERVER_KEY_FILE,
        "server_cert": SERVER_CERT_FILE,
    }
