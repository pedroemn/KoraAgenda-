

from dataclasses import dataclass
from datetime import datetime

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from app.crypto.identity import Identity, check_key_matches_certificate
from app.crypto.keys import generate_encryption_key, generate_signing_key
from app.crypto.pki import (
    CertificateAuthority,
    KeyPurpose,
    certificate_from_pem,
    certificate_to_pem,
    create_certificate_request,
    validate_identity_name,
    verify_certificate,
)


@dataclass
class EnrollmentRequest:
    """Fica no dispositivo. As chaves privadas nunca são enviadas."""

    name: str
    signing_key: ed25519.Ed25519PrivateKey
    encryption_key: rsa.RSAPrivateKey
    signing_csr: bytes
    encryption_csr: bytes

    @classmethod
    def create(cls, name: str) -> "EnrollmentRequest":
        name = validate_identity_name(name)
        signing_key = generate_signing_key()
        encryption_key = generate_encryption_key()
        return cls(
            name=name,
            signing_key=signing_key,
            encryption_key=encryption_key,
            signing_csr=create_certificate_request(name, signing_key),
            encryption_csr=create_certificate_request(name, encryption_key),
        )

    def complete(
        self,
        signing_certificate_pem: bytes,
        encryption_certificate_pem: bytes,
        ca_certificate: x509.Certificate,
        *,
        now: datetime | None = None,
    ) -> Identity:
        signing_cert = certificate_from_pem(signing_certificate_pem)
        encryption_cert = certificate_from_pem(encryption_certificate_pem)

        verify_certificate(
            signing_cert, ca_certificate, KeyPurpose.SIGNING, expected_name=self.name, now=now
        )
        verify_certificate(
            encryption_cert, ca_certificate, KeyPurpose.ENCRYPTION, expected_name=self.name, now=now
        )
        check_key_matches_certificate(self.signing_key, signing_cert, self.name)
        check_key_matches_certificate(self.encryption_key, encryption_cert, self.name)

        return Identity(
            name=self.name,
            signing_key=self.signing_key,
            encryption_key=self.encryption_key,
            signing_certificate=signing_cert,
            encryption_certificate=encryption_cert,
        )


def enroll_locally(
    name: str, ca: CertificateAuthority, *, now: datetime | None = None
) -> Identity:
    """Executa os 3 passos num único processo (testes e demonstração)."""
    request = EnrollmentRequest.create(name)
    signing_cert = ca.issue_from_request(
        request.signing_csr, KeyPurpose.SIGNING, expected_name=request.name, now=now
    )
    encryption_cert = ca.issue_from_request(
        request.encryption_csr, KeyPurpose.ENCRYPTION, expected_name=request.name, now=now
    )
    return request.complete(
        certificate_to_pem(signing_cert),
        certificate_to_pem(encryption_cert),
        ca.certificate,
        now=now,
    )
