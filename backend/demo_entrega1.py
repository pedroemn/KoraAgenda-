"""Demonstração da Entrega 1 — Proteger mensagens e entender PKI.

Uso (dentro de backend/):
    python demo_entrega1.py              # pausa entre as etapas (para apresentar)
    python demo_entrega1.py --sem-pausa  # roda tudo direto

A senha que protege as chaves privadas vem da variável KORA_KEY_PASSPHRASE
ou é pedida no terminal (nunca fica escrita no código).
"""

import os
import sys
import tempfile
from dataclasses import replace
from datetime import timedelta
from getpass import getpass
from pathlib import Path

from app.core.exceptions import CryptoError
from app.crypto.enrollment import EnrollmentRequest
from app.crypto.envelope import Envelope, open_envelope, seal
from app.crypto.identity import Identity
from app.crypto.keys import fingerprint, load_private_key
from app.crypto.pki import (
    CertificateAuthority,
    KeyPurpose,
    certificate_to_pem,
    common_name,
    utc_now,
)
from app.crypto.replay import ReplayGuard

PAUSE = "--sem-pausa" not in sys.argv
MESSAGE = "Sua reunião com Leonardo começa em 15 minutos."


def title(text: str) -> None:
    print("\n" + "=" * 72)
    print(f" {text}")
    print("=" * 72)


def pause() -> None:
    if PAUSE:
        input("\n[Enter para continuar] ")


def flip_bit(data: bytes) -> bytes:
    changed = bytearray(data)
    changed[0] ^= 0x01
    return bytes(changed)


def resign(envelope: Envelope, attacker: Identity, **changes) -> Envelope:
    """Atacante altera o envelope e assina de novo com a chave DELE."""
    tampered = replace(envelope, **changes, signature=b"")
    return replace(tampered, signature=attacker.signing_key.sign(tampered.signed_bytes()))


def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except AttributeError:
        pass

    passphrase = (
        os.environ.get("KORA_KEY_PASSPHRASE")
        or getpass("Senha para proteger as chaves privadas: ")
    ).encode()

    # ------------------------------------------------------------------
    title("ETAPA 1 — Gerar chaves e certificados (PKI)")
    ca = CertificateAuthority.create()
    print(f"[CA] Autoridade certificadora criada: '{common_name(ca.certificate)}'")
    backend = Identity.enroll("kora-backend", ca)
    print("[Backend] 2 pares de chaves gerados e certificados pela CA")

    print("\n[Celular do Lucas] gera as chaves DENTRO do aparelho e envia só os pedidos (CSR)")
    request = EnrollmentRequest.create("lucas")
    has_private = b"PRIVATE" in request.signing_csr + request.encryption_csr
    print(f"  O pedido enviado contém chave privada? {'SIM (ERRO!)' if has_private else 'NÃO'}")
    signing_cert = ca.issue_from_request(
        request.signing_csr, KeyPurpose.SIGNING, expected_name="lucas"
    )
    encryption_cert = ca.issue_from_request(
        request.encryption_csr, KeyPurpose.ENCRYPTION, expected_name="lucas"
    )
    print("[CA] conferiu a prova de posse da chave e emitiu 2 certificados")
    lucas = request.complete(
        certificate_to_pem(signing_cert), certificate_to_pem(encryption_cert), ca.certificate
    )
    print("[Celular do Lucas] conferiu os certificados recebidos (CA, nome, uso e chave)")

    print("\nChaves do Lucas (impressão digital da chave pública):")
    print(f"  Assinatura (Ed25519): {fingerprint(lucas.signing_key.public_key())[:39]}...")
    print(f"  Cifragem (RSA-3072):  {fingerprint(lucas.encryption_key.public_key())[:39]}...")

    with tempfile.TemporaryDirectory() as folder:
        lucas.save(Path(folder), passphrase)
        key_file = Path(folder) / "lucas.enc.key.pem"
        lines = key_file.read_text().splitlines()
        print("\nChave privada gravada no disco — cifrada com senha:")
        print(f"  {lines[0]}")
        print(f"  {lines[1][:40]}...  (conteúdo ilegível sem a senha)")
        try:
            load_private_key(key_file, b"senha-errada")
            print("  Senha errada abriu a chave: FALHA DE SEGURANÇA")
        except CryptoError as error:
            print(f"  Tentativa com senha errada -> REJEITADA: {error}")
    pause()

    # ------------------------------------------------------------------
    title("ETAPA 2 — Cifrar e assinar (backend -> celular do Lucas)")
    print(f"Mensagem original: {MESSAGE!r}\n")
    envelope = seal(MESSAGE, backend, lucas.encryption_certificate, ca.certificate)
    header = envelope.header
    print("Envelope gerado:")
    print(f"  cabeçalho (em claro, mas protegido): de={header['sender']} "
          f"para={header['recipient']} id={header['message_id'][:8]}...")
    print(f"  texto cifrado (AES-256-GCM):        {envelope.ciphertext.hex()[:40]}...")
    print(f"  chave AES trancada (RSA-OAEP):      {len(envelope.wrapped_key)} bytes")
    print(f"  assinatura do backend (Ed25519):    {envelope.signature.hex()[:40]}...")
    raw = envelope.to_json()
    print(f"\nO texto 'Leonardo' aparece no envelope? {'SIM (ERRO!)' if 'Leonardo' in raw else 'NÃO'}")
    print(f"Tamanho total do envelope: {len(raw.encode())} bytes (JSON)")
    pause()

    # ------------------------------------------------------------------
    title("ETAPA 3 — Lucas abre e verifica a mensagem")
    guards = {"lucas": ReplayGuard(), "ana": ReplayGuard()}
    opened = open_envelope(Envelope.from_json(raw), lucas, ca.certificate, guards["lucas"])
    for check in (
        "algoritmos permitidos",
        "certificado do remetente emitido pela CA e válido",
        "assinatura do backend confere",
        "mensagem é para o Lucas",
        "chave AES destrancada com a chave privada do Lucas",
        "texto decifrado e íntegro (AES-GCM)",
        "mensagem nova (anti-replay)",
    ):
        print(f"  [OK] {check}")
    print(f"\nMensagem lida pelo Lucas: {opened.text!r}  (de: {opened.sender})")
    pause()

    # ------------------------------------------------------------------
    title("ETAPA 4 — Testar adulteração e ataques")
    print("Preparando atacantes: Mallory (usuária com chaves válidas), Ana e uma CA falsa...")
    mallory = Identity.enroll("mallory", ca)
    ana = Identity.enroll("ana", ca)
    rogue_ca = CertificateAuthority.create()  # mesmo nome da CA verdadeira, outra chave
    fake_backend = Identity.enroll("kora-backend", rogue_ca)
    mallory_cert = certificate_to_pem(mallory.signing_certificate)

    attacks = [
        ("Alterar 1 bit do texto cifrado no caminho",
         replace(envelope, ciphertext=flip_bit(envelope.ciphertext)), lucas, {}),
        ("Alterar o horário no cabeçalho",
         replace(envelope, header={**header, "created_at": "2020-01-01T00:00:00+00:00"}), lucas, {}),
        ("Alterar a assinatura",
         replace(envelope, signature=flip_bit(envelope.signature)), lucas, {}),
        ("Alterar a chave AES trancada",
         replace(envelope, wrapped_key=flip_bit(envelope.wrapped_key)), lucas, {}),
        ("Trocar o algoritmo por um mais fraco",
         replace(envelope, header={**header, "enc_alg": "RSA-PKCS1v15+AES-CBC"}), lucas, {}),
        ("Mallory troca remetente e assina como ela mesma",
         resign(envelope, mallory, header={**header, "sender": "mallory"},
                sender_certificate=mallory_cert), lucas, {}),
        ("Mallory usa o certificado dela fingindo ser o backend",
         resign(envelope, mallory, sender_certificate=mallory_cert), lucas, {}),
        ("Backend falso com certificado de uma CA falsa",
         seal(MESSAGE, fake_backend, lucas.encryption_certificate, ca.certificate), lucas, {}),
        ("Ana tenta abrir a mensagem do Lucas", envelope, ana, {}),
        ("Abrir 400 dias depois (certificado vencido)",
         envelope, lucas, {"now": utc_now() + timedelta(days=400)}),
        ("REPLAY: reenviar a mesma mensagem já lida", envelope, lucas, {}),
    ]

    blocked = 0
    for number, (description, attack, recipient, options) in enumerate(attacks, 1):
        try:
            open_envelope(attack, recipient, ca.certificate, guards[recipient.name], **options)
            print(f"\n{number:2}. {description}\n    ACEITO -> FALHA DE SEGURANÇA")
        except CryptoError as error:
            blocked += 1
            print(f"\n{number:2}. {description}\n    REJEITADO: {error}")

    title(f"RESULTADO: {blocked} de {len(attacks)} ataques bloqueados")
    return 0 if blocked == len(attacks) else 1


if __name__ == "__main__":
    sys.exit(main())
