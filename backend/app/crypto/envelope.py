

import base64
import json
import os
from dataclasses import dataclass, replace
from datetime import datetime
from uuid import uuid4

from cryptography import x509
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.exceptions import CertificateError, MessageIntegrityError
from app.crypto.identity import Identity
from app.crypto.replay import ReplayGuard
from app.crypto.pki import (
    KeyPurpose,
    certificate_from_pem,
    certificate_to_pem,
    common_name,
    utc_now,
    verify_certificate,
)

ENVELOPE_VERSION = 1
ENCRYPTION_SCHEME = "RSA-OAEP-SHA256+AES-256-GCM"
SIGNATURE_SCHEME = "Ed25519"
_NONCE_BYTES = 12  
_OAEP = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)
_BINARY_FIELDS = ("sender_certificate", "wrapped_key", "nonce", "ciphertext", "signature")


def _canonical(data: dict) -> bytes:
    """Serialização determinística: os mesmos dados geram sempre os mesmos bytes."""
    return json.dumps(
        data, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


@dataclass(frozen=True)
class Envelope:
    header: dict
    sender_certificate: bytes  
    wrapped_key: bytes         
    nonce: bytes
    ciphertext: bytes          
    signature: bytes = b""

    def signed_bytes(self) -> bytes:
        """Tudo o que a assinatura cobre: o envelope inteiro, menos ela mesma."""
        data: dict[str, object] = {"header": self.header}
        for name in _BINARY_FIELDS:
            if name != "signature":
                data[name] = _b64encode(getattr(self, name))
        return _canonical(data)

    def to_json(self) -> str:
        data: dict[str, object] = {"header": self.header}
        data.update({name: _b64encode(getattr(self, name)) for name in _BINARY_FIELDS})
        return json.dumps(data, ensure_ascii=False, indent=2)

    @classmethod
    def from_json(cls, raw: str) -> "Envelope":
        try:
            data = json.loads(raw)
            header = data["header"]
            if not isinstance(header, dict):
                raise TypeError("header")
            fields = {
                name: base64.b64decode(data[name], validate=True)
                for name in _BINARY_FIELDS
            }
        except (ValueError, KeyError, TypeError) as exc:
            raise MessageIntegrityError("Envelope malformado.") from exc
        return cls(header=header, **fields)


@dataclass(frozen=True)
class OpenedMessage:
    message_id: str
    sender: str
    recipient: str
    created_at: datetime
    text: str


def seal(
    text: str,
    sender: Identity,
    recipient_certificate: x509.Certificate,
    ca_certificate: x509.Certificate,
    *,
    now: datetime | None = None,
) -> Envelope:
    now = now or utc_now()
    verify_certificate(recipient_certificate, ca_certificate, KeyPurpose.ENCRYPTION, now=now)
    recipient_key = recipient_certificate.public_key()
    if not isinstance(recipient_key, rsa.RSAPublicKey):
        raise CertificateError("Certificado do destinatário não tem chave RSA de cifragem.")

    header = {
        "version": ENVELOPE_VERSION,
        "message_id": str(uuid4()),
        "sender": sender.name,
        "recipient": common_name(recipient_certificate),
        "created_at": now.isoformat(),
        "enc_alg": ENCRYPTION_SCHEME,
        "sig_alg": SIGNATURE_SCHEME,
    }

    content_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(_NONCE_BYTES)
    ciphertext = AESGCM(content_key).encrypt(nonce, text.encode("utf-8"), _canonical(header))
    wrapped_key = recipient_key.encrypt(content_key, _OAEP)

    unsigned = Envelope(
        header=header,
        sender_certificate=certificate_to_pem(sender.signing_certificate),
        wrapped_key=wrapped_key,
        nonce=nonce,
        ciphertext=ciphertext,
    )
    return replace(unsigned, signature=sender.signing_key.sign(unsigned.signed_bytes()))


def open_envelope(
    envelope: Envelope,
    recipient: Identity,
    ca_certificate: x509.Certificate,
    replay_guard: ReplayGuard,
    *,
    now: datetime | None = None,
) -> OpenedMessage:
    """`replay_guard` é obrigatório: cada sistema receptor mantém o seu."""
    now = now or utc_now()
    header = envelope.header

    # 1) Só aceita a versão e os algoritmos conhecidos.
    if (
        header.get("version") != ENVELOPE_VERSION
        or header.get("enc_alg") != ENCRYPTION_SCHEME
        or header.get("sig_alg") != SIGNATURE_SCHEME
    ):
        raise MessageIntegrityError("Versão ou algoritmo de envelope não suportado.")

    # 2) Quem diz ter enviado tem certificado válido, emitido pela CA, no próprio nome?
    sender_certificate = certificate_from_pem(envelope.sender_certificate)
    verify_certificate(
        sender_certificate,
        ca_certificate,
        KeyPurpose.SIGNING,
        expected_name=header.get("sender"),
        now=now,
    )

    # 3) A assinatura confere com o envelope recebido?
    sender_key = sender_certificate.public_key()
    if not isinstance(sender_key, ed25519.Ed25519PublicKey):
        raise CertificateError("Certificado do remetente não tem chave Ed25519 de assinatura.")
    try:
        sender_key.verify(envelope.signature, envelope.signed_bytes())
    except (InvalidSignature, ValueError) as exc:
        raise MessageIntegrityError(
            "Assinatura inválida: a mensagem foi alterada ou não veio do remetente."
        ) from exc

    # 4) A mensagem é para mim?
    if header.get("recipient") != recipient.name:
        raise MessageIntegrityError("Esta mensagem não é destinada a você.")

    # 5 e 6) Desembrulha a chave e decifra (o GCM confere a integridade de novo).
    try:
        content_key = recipient.encryption_key.decrypt(envelope.wrapped_key, _OAEP)
        plaintext = AESGCM(content_key).decrypt(
            envelope.nonce, envelope.ciphertext, _canonical(header)
        )
        created_at = datetime.fromisoformat(header["created_at"])
        message_id = str(header["message_id"])
    except (ValueError, InvalidTag, KeyError, TypeError) as exc:
        raise MessageIntegrityError("Não foi possível decifrar a mensagem.") from exc

    # 7) Só agora (mensagem autêntica e íntegra) registra o ID.
    replay_guard.check_and_remember(message_id, created_at, now)

    return OpenedMessage(
        message_id=message_id,
        sender=header["sender"],
        recipient=header["recipient"],
        created_at=created_at,
        text=plaintext.decode("utf-8"),
    )
