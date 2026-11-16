

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from app.core.exceptions import CryptoError
from app.crypto.keys import PrivateKey, load_private_key, public_key_bytes, save_private_key
from app.crypto.pki import (
    CertificateAuthority,
    certificate_from_pem,
    certificate_to_pem,
    common_name,
    validate_identity_name,
)


def _paths(directory: Path, name: str) -> dict[str, Path]:
    return {
        "signing_key": directory / f"{name}.sign.key.pem",
        "encryption_key": directory / f"{name}.enc.key.pem",
        "signing_certificate": directory / f"{name}.sign.crt.pem",
        "encryption_certificate": directory / f"{name}.enc.crt.pem",
    }


def check_key_matches_certificate(
    key: PrivateKey, certificate: x509.Certificate, name: str
) -> None:
    """O certificado precisa ser da MINHA chave e do MEU nome."""
    if public_key_bytes(key.public_key()) != public_key_bytes(certificate.public_key()):
        raise CryptoError("Chave privada não corresponde ao certificado.")
    if common_name(certificate) != name:
        raise CryptoError("Certificado pertence a outra identidade.")


@dataclass
class Identity:
    name: str
    signing_key: ed25519.Ed25519PrivateKey
    encryption_key: rsa.RSAPrivateKey
    signing_certificate: x509.Certificate
    encryption_certificate: x509.Certificate

    @classmethod
    def enroll(
        cls, name: str, ca: CertificateAuthority, *, now: datetime | None = None
    ) -> "Identity":
        """Atalho: roda o fluxo CSR completo (dispositivo -> CA -> dispositivo)
        num único processo. Entre sistemas, use app.crypto.enrollment."""
        from app.crypto.enrollment import enroll_locally  # evita import circular

        return enroll_locally(name, ca, now=now)

    def save(self, directory: Path, passphrase: bytes) -> None:
        """Grava chaves privadas cifradas com a senha e certificados em claro."""
        directory.mkdir(parents=True, exist_ok=True)
        paths = _paths(directory, self.name)
        save_private_key(paths["signing_key"], self.signing_key, passphrase)
        save_private_key(paths["encryption_key"], self.encryption_key, passphrase)
        paths["signing_certificate"].write_bytes(
            certificate_to_pem(self.signing_certificate)
        )
        paths["encryption_certificate"].write_bytes(
            certificate_to_pem(self.encryption_certificate)
        )

    @classmethod
    def load(cls, name: str, directory: Path, passphrase: bytes) -> "Identity":
        name = validate_identity_name(name)
        paths = _paths(directory, name)
        signing_key = load_private_key(paths["signing_key"], passphrase)
        encryption_key = load_private_key(paths["encryption_key"], passphrase)
        signing_cert = certificate_from_pem(paths["signing_certificate"].read_bytes())
        encryption_cert = certificate_from_pem(
            paths["encryption_certificate"].read_bytes()
        )

        if not isinstance(signing_key, ed25519.Ed25519PrivateKey) or not isinstance(
            encryption_key, rsa.RSAPrivateKey
        ):
            raise CryptoError("Arquivos de chave trocados ou de tipo inesperado.")
        check_key_matches_certificate(signing_key, signing_cert, name)
        check_key_matches_certificate(encryption_key, encryption_cert, name)

        return cls(name, signing_key, encryption_key, signing_cert, encryption_cert)
