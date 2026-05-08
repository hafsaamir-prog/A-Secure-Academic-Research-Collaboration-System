Academic Research Collaborator (ARC)
A secure, multi-threaded communication platform designed for academic researchers to exchange sensitive data using multi-layered cryptography and blockchain technology.

Security Protocols Used
Ephemeral Diffie-Hellman (DH): Used for forward secrecy and secure session key establishment.

AEAD (Authenticated Encryption with Associated Data): To ensure both data confidentiality and message integrity.

RSA PKI: Automated generation of self-signed CA and Server certificates for identity verification.

ElGamal Encryption: Asymmetric encryption supported by a centralized Key Distribution Center (KDC).

Features
Hybrid Encryption: Provides a choice between Caesar, Vigenère, XOR Stream, and Mini Block ciphers.

Blockchain Research Log: An immutable ledger that mines and stores every message to provide non-repudiation.

Secure Storage: XOR-encrypted user and key databases that are protected by SHA-256 integrity hashes.

Key Lifecycle Management: Supports manual and automated key rotation and revocation.

Steps
Socket Connection: Establishing a multi-threaded server-client link for communication.

Secure Handshake: Ephemeral DH key exchange and secure session initialization.

Authentication: Secure user login using SHA-256 salted password hashing.

Message Exchange: Handling encryption, HMAC tagging, and transmission of research data.

Blockchain Mining: Validating and appending blocks to the secure research ledger.

Tools
Python | Sockets | Cryptography (Lib) | Hashlib | HMAC | JSON | Threading
