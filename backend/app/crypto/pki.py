
import re
from datetime import datetime, timedelta, timezone
from enum import Enum

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.types import CertificatePublicKeyTypes
from cryptography.x509.oid import NameOID

from app.core.config import CA_VALIDITY_DAYS, CERT_VALIDITY_DAYS
from app.core.exceptions import CertificateError
from app.crypto.keys import PrivateKey, generate_signing_key

ORGANIZATION = "KoraAgenda"

# O nome do titular vira nome de arquivo e campo de certificado: restringir
# evita path traversal ("../../x") e nomes ambíguos.
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def validate_identity_name(name: str) -> str:
    if not isinstance(name, str) or not _NAME_RE.match(name):
        raise CertificateError(
            "Nome de identidade inválido (use a-z, 0-9, '.', '_' ou '-')."
        )
    return name


class KeyPurpose(Enum):
    SIGNING = "assinatura"
    ENCRYPTION = "cifragem"


_EXPECTED_KEY_TYPE = {
    KeyPurpose.SIGNING: ed25519.Ed25519PublicKey,
    KeyPurpose.ENCRYPTION: rsa.RSAPublicKey,
}

# RSA assina o CSR com PSS (o padding moderno para assinaturas RSA).
_RSA_PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH)


def _subject(name: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORGANIZATION),
            x509.NameAttribute(NameOID.COMMON_NAME, name),
        ]
    )


def _key_usage(
    *,
    digital_signature: bool = False,
    key_encipherment: bool = False,
    key_cert_sign: bool = False,
    crl_sign: bool = False,
) -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=digital_signature,
        content_commitment=False,
        key_encipherment=key_encipherment,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=key_cert_sign,
        crl_sign=crl_sign,
        encipher_only=False,
        decipher_only=False,
    )


def common_name(item: x509.Certificate | x509.CertificateSigningRequest) -> str:
    attributes = item.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if len(attributes) != 1:
        raise CertificateError("Certificado sem nome de titular válido.")
    return str(attributes[0].value)


def certificate_to_pem(certificate: x509.Certificate) -> bytes:
    return certificate.public_bytes(serialization.Encoding.PEM)


def certificate_from_pem(data: bytes) -> x509.Certificate:
    try:
        return x509.load_pem_x509_certificate(data)
    except ValueError as exc:
        raise CertificateError("Certificado malformado.") from exc


def create_certificate_request(name: str, private_key: PrivateKey) -> bytes:
    """Lado do DISPOSITIVO: gera um CSR (PEM) assinado com a própria chave privada.

    A assinatura prova à CA que quem pede o certificado possui a chave privada.
    """
    builder = x509.CertificateSigningRequestBuilder().subject_name(
        _subject(validate_identity_name(name))
    )
    if isinstance(private_key, ed25519.Ed25519PrivateKey):
        request = builder.sign(private_key, None)
    else:
        request = builder.sign(private_key, hashes.SHA256(), rsa_padding=_RSA_PSS)
    return request.public_bytes(serialization.Encoding.PEM)


class CertificateAuthority:
    """CA raiz com chave Ed25519. Em produção a chave da CA ficaria isolada
    (HSM/cofre) e offline; aqui ela vive em memória para fins didáticos."""

    def __init__(
        self, private_key: ed25519.Ed25519PrivateKey, certificate: x509.Certificate
    ) -> None:
        self.private_key = private_key
        self.certificate = certificate

    @classmethod
    def create(
        cls,
        name: str = "KoraAgenda Root CA",
        *,
        now: datetime | None = None,
        validity_days: int = CA_VALIDITY_DAYS,
    ) -> "CertificateAuthority":
        now = now or utc_now()
        key = generate_signing_key()
        subject = _subject(name)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)  # autoassinado: é a raiz de confiança
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=validity_days))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(_key_usage(key_cert_sign=True, crl_sign=True), critical=True)
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                critical=False,
            )
            .sign(key, algorithm=None)  # Ed25519 já define o próprio hash
        )
        return cls(key, certificate)

    def issue_from_request(
        self,
        request_pem: bytes,
        purpose: KeyPurpose,
        *,
        expected_name: str,
        now: datetime | None = None,
    ) -> x509.Certificate:
        """Lado da CA: emite um certificado a partir de um CSR recebido pela rede.

        `expected_name` deve vir da conta AUTENTICADA de quem pede (ex.: sessão
        de login), nunca do próprio CSR — senão qualquer um pediria em nome de outro.
        Extensões pedidas no CSR são ignoradas: quem decide o uso é a CA.
        """
        try:
            request = x509.load_pem_x509_csr(request_pem)
        except ValueError as exc:
            raise CertificateError("Pedido de certificado (CSR) malformado.") from exc

        if not request.is_signature_valid:
            raise CertificateError(
                "Pedido de certificado com assinatura inválida (sem prova de posse da chave)."
            )
        if common_name(request) != expected_name:
            raise CertificateError("Pedido de certificado em nome de outra identidade.")

        return self.issue(expected_name, request.public_key(), purpose, now=now)

    def issue(
        self,
        subject_name: str,
        public_key: CertificatePublicKeyTypes,  # o tipo exato é conferido abaixo
        purpose: KeyPurpose,
        *,
        now: datetime | None = None,
        validity_days: int = CERT_VALIDITY_DAYS,
    ) -> x509.Certificate:
        """Emite um certificado de entidade final para UM uso (assinar OU cifrar)."""
        validate_identity_name(subject_name)
        if not isinstance(public_key, _EXPECTED_KEY_TYPE[purpose]):
            raise CertificateError(
                f"Tipo de chave incompatível com o uso '{purpose.value}'."
            )
        now = now or utc_now()
        usage = _key_usage(
            digital_signature=purpose is KeyPurpose.SIGNING,
            key_encipherment=purpose is KeyPurpose.ENCRYPTION,
        )
        return (
            x509.CertificateBuilder()
            .subject_name(_subject(subject_name))
            .issuer_name(self.certificate.subject)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=validity_days))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(usage, critical=True)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    self.private_key.public_key()
                ),
                critical=False,
            )
            .sign(self.private_key, algorithm=None)
        )


def _check_validity(certificate: x509.Certificate, now: datetime, whose: str) -> None:
    if not certificate.not_valid_before_utc <= now <= certificate.not_valid_after_utc:
        raise CertificateError(f"Certificado {whose} fora do prazo de validade.")


def verify_certificate(
    certificate: x509.Certificate,
    ca_certificate: x509.Certificate,
    purpose: KeyPurpose,
    *,
    expected_name: str | None = None,
    now: datetime | None = None,
) -> None:
    """Lança CertificateError se o certificado não for confiável para `purpose`.

    Verifica: validade da CA, assinatura da CA, validade do certificado,
    que não é um certificado de CA, uso permitido (KeyUsage), tipo da chave e,
    opcionalmente, o nome do titular.
    """
    now = now or utc_now()
    _check_validity(ca_certificate, now, "da autoridade certificadora")

    try:
        certificate.verify_directly_issued_by(ca_certificate)
    except (ValueError, TypeError, InvalidSignature) as exc:
        raise CertificateError(
            "Certificado não foi emitido pela autoridade certificadora confiável."
        ) from exc

    _check_validity(certificate, now, "do titular")

    try:
        basic = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
        usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound as exc:
        raise CertificateError("Certificado sem as extensões obrigatórias.") from exc

    if basic.ca:
        raise CertificateError("Certificado de CA não pode identificar um usuário.")

    allowed = (
        usage.digital_signature
        if purpose is KeyPurpose.SIGNING
        else usage.key_encipherment
    )
    if not allowed or not isinstance(
        certificate.public_key(), _EXPECTED_KEY_TYPE[purpose]
    ):
        raise CertificateError(f"Certificado não autorizado para {purpose.value}.")

    if expected_name is not None and common_name(certificate) != expected_name:
        raise CertificateError("Certificado não pertence ao remetente informado.")
