

from hashlib import sha256
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.hazmat.primitives.asymmetric.types import CertificatePublicKeyTypes

from app.core.config import RSA_KEY_SIZE
from app.core.exceptions import CryptoError

PrivateKey = ed25519.Ed25519PrivateKey | rsa.RSAPrivateKey
PublicKey = ed25519.Ed25519PublicKey | rsa.RSAPublicKey


def generate_signing_key() -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.generate()


def generate_encryption_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=RSA_KEY_SIZE)


def public_key_bytes(public_key: CertificatePublicKeyTypes) -> bytes:
    return public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def fingerprint(public_key: CertificatePublicKeyTypes) -> str:
    """Impressão digital SHA-256 da chave pública (para conferência humana)."""
    return "SHA256:" + sha256(public_key_bytes(public_key)).hexdigest()


def private_key_to_pem(key: PrivateKey, passphrase: bytes) -> bytes:
    if not passphrase:
        raise CryptoError("Uma senha é obrigatória para proteger a chave privada.")
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
    )


def private_key_from_pem(data: bytes, passphrase: bytes) -> PrivateKey:
    try:
        key = serialization.load_pem_private_key(data, password=passphrase or None)
    except (ValueError, TypeError) as exc:
        raise CryptoError(
            "Não foi possível abrir a chave privada (senha incorreta ou arquivo corrompido)."
        ) from exc
    if not isinstance(key, (ed25519.Ed25519PrivateKey, rsa.RSAPrivateKey)):
        raise CryptoError("Tipo de chave privada não suportado.")
    return key


def save_private_key(path: Path, key: PrivateKey, passphrase: bytes) -> None:
    path.write_bytes(private_key_to_pem(key, passphrase))


def load_private_key(path: Path, passphrase: bytes) -> PrivateKey:
    return private_key_from_pem(path.read_bytes(), passphrase)
