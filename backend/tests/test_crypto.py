import base64
import tempfile
import unittest
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from app.core.exceptions import CertificateError, CryptoError, MessageIntegrityError
from app.crypto.enrollment import EnrollmentRequest
from app.crypto.envelope import Envelope, open_envelope, seal
from app.crypto.identity import Identity
from app.crypto.keys import (
    fingerprint,
    generate_signing_key,
    private_key_from_pem,
    private_key_to_pem,
)
from app.crypto.pki import (
    CertificateAuthority,
    KeyPurpose,
    certificate_to_pem,
    utc_now,
    verify_certificate,
)
from app.crypto.replay import ReplayGuard

TEXT = "Sua reunião com Leonardo começa em 15 minutos."


def flip_bit(data: bytes, index: int = 0) -> bytes:
    changed = bytearray(data)
    changed[index] ^= 0x01
    return bytes(changed)


def resign(envelope: Envelope, signer: Identity, **changes) -> Envelope:
    """Simula um atacante que altera o envelope e assina de novo com a chave dele."""
    tampered = replace(envelope, **changes, signature=b"")
    return replace(tampered, signature=signer.signing_key.sign(tampered.signed_bytes()))


class CryptoTestBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Gerar chaves RSA-3072 é lento: cria tudo uma vez só.
        cls.ca = CertificateAuthority.create()
        cls.backend = Identity.enroll("kora-backend", cls.ca)
        cls.lucas = Identity.enroll("lucas", cls.ca)
        cls.ana = Identity.enroll("ana", cls.ca)
        cls.mallory = Identity.enroll("mallory", cls.ca)
        # CA falsa com o MESMO nome da verdadeira, mas outra chave.
        cls.rogue_ca = CertificateAuthority.create()
        cls.fake_backend = Identity.enroll("kora-backend", cls.rogue_ca)

    def seal_to_lucas(self, text=TEXT, sender=None, **kw):
        return seal(
            text,
            sender or self.backend,
            self.lucas.encryption_certificate,
            self.ca.certificate,
            **kw,
        )

    def open(self, envelope, recipient=None, guard=None, **kw):
        return open_envelope(
            envelope,
            recipient or self.lucas,
            self.ca.certificate,
            guard if guard is not None else ReplayGuard(),
            **kw,
        )

    def assert_rejected(self, envelope, exception=MessageIntegrityError, **kw):
        with self.assertRaises(exception) as ctx:
            self.open(envelope, **kw)
        return ctx.exception


class PositiveCasesTest(CryptoTestBase):
    def test_roundtrip(self):
        opened = self.open(self.seal_to_lucas())
        self.assertEqual(opened.text, TEXT)
        self.assertEqual(opened.sender, "kora-backend")
        self.assertEqual(opened.recipient, "lucas")

    def test_reverse_direction_user_to_backend(self):
        envelope = seal(
            "Adie meu compromisso das 15h para as 16h.",
            self.lucas,
            self.backend.encryption_certificate,
            self.ca.certificate,
        )
        opened = self.open(envelope, recipient=self.backend)
        self.assertEqual(opened.sender, "lucas")

    def test_json_roundtrip(self):
        raw = self.seal_to_lucas().to_json()
        self.assertEqual(self.open(Envelope.from_json(raw)).text, TEXT)

    def test_plaintext_is_not_visible_in_envelope(self):
        raw = self.seal_to_lucas().to_json()
        self.assertNotIn("Leonardo", raw)
        self.assertNotIn("reunião", raw)

    def test_each_message_uses_fresh_key_and_nonce(self):
        first, second = self.seal_to_lucas(), self.seal_to_lucas()
        self.assertNotEqual(first.wrapped_key, second.wrapped_key)
        self.assertNotEqual(first.nonce, second.nonce)
        self.assertNotEqual(first.ciphertext, second.ciphertext)

    def test_empty_and_long_messages(self):
        for text in ("", "x" * 100_000):
            with self.subTest(size=len(text)):
                self.assertEqual(self.open(self.seal_to_lucas(text)).text, text)


class TamperingTest(CryptoTestBase):
    """Qualquer alteração em qualquer campo deve ser rejeitada."""

    def setUp(self):
        self.envelope = self.seal_to_lucas()

    def test_ciphertext_changed(self):
        self.assert_rejected(replace(self.envelope, ciphertext=flip_bit(self.envelope.ciphertext)))

    def test_ciphertext_truncated(self):
        self.assert_rejected(replace(self.envelope, ciphertext=self.envelope.ciphertext[:-1]))

    def test_nonce_changed(self):
        self.assert_rejected(replace(self.envelope, nonce=flip_bit(self.envelope.nonce)))

    def test_wrapped_key_changed(self):
        self.assert_rejected(
            replace(self.envelope, wrapped_key=flip_bit(self.envelope.wrapped_key))
        )

    def test_header_changed(self):
        header = {**self.envelope.header, "created_at": "2020-01-01T00:00:00+00:00"}
        self.assert_rejected(replace(self.envelope, header=header))

    def test_signature_changed(self):
        self.assert_rejected(
            replace(self.envelope, signature=flip_bit(self.envelope.signature))
        )

    def test_signature_removed(self):
        self.assert_rejected(replace(self.envelope, signature=b""))

    def test_algorithm_downgrade(self):
        header = {**self.envelope.header, "enc_alg": "RSA-PKCS1v15+AES-CBC"}
        self.assert_rejected(replace(self.envelope, header=header))

    def test_malformed_json(self):
        broken_nonce = self.envelope.to_json().replace('"nonce": "', '"nonce": "@@')
        for raw in ("{", "[]", '{"header": {}}', broken_nonce):
            with self.subTest(raw=raw[:20]):
                with self.assertRaises(MessageIntegrityError):
                    Envelope.from_json(raw)


class ForgeryTest(CryptoTestBase):
    """Ataques de quem tem chaves válidas, mas não as do remetente."""

    def test_mallory_resigns_as_herself(self):
        # Troca remetente, certificado e assinatura pelos dela: tudo "válido",
        # mas o cabeçalho original faz parte do AAD do GCM -> decifragem falha.
        envelope = self.seal_to_lucas()
        forged = resign(
            envelope,
            self.mallory,
            header={**envelope.header, "sender": "mallory"},
            sender_certificate=certificate_to_pem(self.mallory.signing_certificate),
        )
        error = self.assert_rejected(forged)
        self.assertIn("decifrar", str(error))

    def test_mallory_certificate_with_backend_name(self):
        envelope = self.seal_to_lucas()
        forged = resign(
            envelope,
            self.mallory,
            sender_certificate=certificate_to_pem(self.mallory.signing_certificate),
        )
        self.assert_rejected(forged, CertificateError)

    def test_certificate_from_rogue_ca(self):
        self.assert_rejected(self.seal_to_lucas(sender=self.fake_backend), CertificateError)

    def test_message_opened_by_wrong_recipient(self):
        self.assert_rejected(self.seal_to_lucas(), recipient=self.ana)

    def test_recipient_field_redirected_to_attacker(self):
        # Mudar o destinatário quebra a assinatura do backend.
        envelope = self.seal_to_lucas()
        redirected = replace(envelope, header={**envelope.header, "recipient": "ana"})
        self.assert_rejected(redirected, recipient=self.ana)


class ReplayTest(CryptoTestBase):
    def test_same_message_twice_is_rejected(self):
        guard, envelope = ReplayGuard(), self.seal_to_lucas()
        self.open(envelope, guard=guard)
        error = self.assert_rejected(envelope, guard=guard)
        self.assertIn("replay", str(error))

    def test_replay_after_json_transport_is_rejected(self):
        guard, raw = ReplayGuard(), self.seal_to_lucas().to_json()
        self.open(Envelope.from_json(raw), guard=guard)
        self.assert_rejected(Envelope.from_json(raw), guard=guard)

    def test_forged_copy_does_not_burn_the_real_id(self):
        # Um envelope adulterado com o MESMO ID é recusado antes de registrar
        # o ID; a mensagem verdadeira continua sendo aceita depois.
        guard, envelope = ReplayGuard(), self.seal_to_lucas()
        self.assert_rejected(
            replace(envelope, ciphertext=flip_bit(envelope.ciphertext)), guard=guard
        )
        self.assertEqual(self.open(envelope, guard=guard).text, TEXT)

    def test_old_message_is_rejected(self):
        error = self.assert_rejected(
            self.seal_to_lucas(), now=utc_now() + timedelta(minutes=61)
        )
        self.assertIn("antiga", str(error))

    def test_future_message_is_rejected(self):
        envelope = self.seal_to_lucas(now=utc_now() + timedelta(minutes=10))
        error = self.assert_rejected(envelope)
        self.assertIn("futuro", str(error))

    def test_small_clock_skew_is_tolerated(self):
        envelope = self.seal_to_lucas(now=utc_now() + timedelta(seconds=60))
        self.assertEqual(self.open(envelope).text, TEXT)

    def test_old_ids_are_forgotten_after_window(self):
        guard, start = ReplayGuard(), utc_now()
        self.open(self.seal_to_lucas(now=start), guard=guard, now=start)
        later = start + timedelta(minutes=61)
        self.open(self.seal_to_lucas(now=later), guard=guard, now=later)
        self.assertEqual(guard.remembered_count, 1)

    def test_persistent_guard_survives_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "seen.json"
            envelope = self.seal_to_lucas()
            self.open(envelope, guard=ReplayGuard(storage_path=path))
            # "Reinicia" o sistema: novo objeto lendo o mesmo arquivo.
            self.assert_rejected(envelope, guard=ReplayGuard(storage_path=path))

    def test_corrupted_storage_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "seen.json"
            path.write_text("isto não é json", encoding="utf-8")
            with self.assertRaises(CryptoError):
                ReplayGuard(storage_path=path)


class EnrollmentTest(CryptoTestBase):
    """Fluxo CSR: chave gerada no dispositivo, só o CSR vai para a CA."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.request = EnrollmentRequest.create("joao")  # "dispositivo"

    def issue(self, csr, purpose, name="joao", ca=None):
        return certificate_to_pem((ca or self.ca).issue_from_request(csr, purpose, expected_name=name))

    def test_full_flow_between_device_and_ca(self):
        self.assertNotIn(b"PRIVATE", self.request.signing_csr + self.request.encryption_csr)
        joao = self.request.complete(
            self.issue(self.request.signing_csr, KeyPurpose.SIGNING),
            self.issue(self.request.encryption_csr, KeyPurpose.ENCRYPTION),
            self.ca.certificate,
        )
        envelope = seal(TEXT, self.backend, joao.encryption_certificate, self.ca.certificate)
        self.assertEqual(self.open(envelope, recipient=joao).text, TEXT)

    def test_ca_rejects_csr_without_proof_of_possession(self):
        der = bytearray(
            x509.load_pem_x509_csr(self.request.signing_csr).public_bytes(
                serialization.Encoding.DER
            )
        )
        der[-1] ^= 0x01  # o final do DER é a assinatura do CSR
        tampered = (
            b"-----BEGIN CERTIFICATE REQUEST-----\n"
            + base64.encodebytes(bytes(der))
            + b"-----END CERTIFICATE REQUEST-----\n"
        )
        with self.assertRaises(CertificateError):
            self.issue(tampered, KeyPurpose.SIGNING)

    def test_ca_rejects_csr_in_another_name(self):
        # O nome esperado vem da conta logada ("ana"), não do CSR ("joao").
        with self.assertRaises(CertificateError):
            self.issue(self.request.signing_csr, KeyPurpose.SIGNING, name="ana")

    def test_ca_rejects_key_for_wrong_purpose(self):
        with self.assertRaises(CertificateError):
            self.issue(self.request.signing_csr, KeyPurpose.ENCRYPTION)

    def test_ca_rejects_malformed_csr(self):
        with self.assertRaises(CertificateError):
            self.issue(b"lixo", KeyPurpose.SIGNING)

    def test_device_rejects_certificate_for_another_key(self):
        # Backend malicioso devolve um certificado "do joao" com a chave do Mallory.
        swapped = certificate_to_pem(
            self.ca.issue("joao", self.mallory.signing_key.public_key(), KeyPurpose.SIGNING)
        )
        with self.assertRaises(CryptoError):
            self.request.complete(
                swapped,
                self.issue(self.request.encryption_csr, KeyPurpose.ENCRYPTION),
                self.ca.certificate,
            )

    def test_device_rejects_certificates_from_rogue_ca(self):
        with self.assertRaises(CertificateError):
            self.request.complete(
                self.issue(self.request.signing_csr, KeyPurpose.SIGNING, ca=self.rogue_ca),
                self.issue(self.request.encryption_csr, KeyPurpose.ENCRYPTION, ca=self.rogue_ca),
                self.ca.certificate,
            )


class CertificateTest(CryptoTestBase):
    def test_valid_certificates(self):
        verify_certificate(self.lucas.signing_certificate, self.ca.certificate, KeyPurpose.SIGNING)
        verify_certificate(
            self.lucas.encryption_certificate, self.ca.certificate, KeyPurpose.ENCRYPTION
        )

    def test_expired_sender_certificate(self):
        self.assert_rejected(
            self.seal_to_lucas(), CertificateError, now=utc_now() + timedelta(days=400)
        )

    def test_not_yet_valid_certificate(self):
        self.assert_rejected(
            self.seal_to_lucas(), CertificateError, now=utc_now() - timedelta(days=1)
        )

    def test_wrong_key_usage(self):
        # Certificado de assinatura não pode ser usado para cifrar, e vice-versa.
        with self.assertRaises(CertificateError):
            seal(TEXT, self.backend, self.lucas.signing_certificate, self.ca.certificate)
        with self.assertRaises(CertificateError):
            verify_certificate(
                self.lucas.encryption_certificate, self.ca.certificate, KeyPurpose.SIGNING
            )

    def test_seal_refuses_untrusted_recipient(self):
        with self.assertRaises(CertificateError):
            seal(
                TEXT, self.backend, self.fake_backend.encryption_certificate, self.ca.certificate
            )

    def test_ca_certificate_cannot_identify_user(self):
        with self.assertRaises(CertificateError):
            verify_certificate(self.ca.certificate, self.ca.certificate, KeyPurpose.SIGNING)

    def test_ca_refuses_wrong_key_type(self):
        with self.assertRaises(CertificateError):
            self.ca.issue("x", generate_signing_key().public_key(), KeyPurpose.ENCRYPTION)


class KeyStorageTest(CryptoTestBase):
    def test_private_key_is_encrypted_on_disk(self):
        pem = private_key_to_pem(self.lucas.signing_key, b"senha-forte-123")
        self.assertIn(b"BEGIN ENCRYPTED PRIVATE KEY", pem)
        loaded = private_key_from_pem(pem, b"senha-forte-123")
        self.assertEqual(
            fingerprint(loaded.public_key()), fingerprint(self.lucas.signing_key.public_key())
        )

    def test_wrong_or_missing_passphrase(self):
        pem = private_key_to_pem(self.lucas.signing_key, b"senha-forte-123")
        for passphrase in (b"senha-errada", b""):
            with self.subTest(passphrase=passphrase):
                with self.assertRaises(CryptoError):
                    private_key_from_pem(pem, passphrase)
        with self.assertRaises(CryptoError):
            private_key_to_pem(self.lucas.signing_key, b"")

    def test_identity_save_and_load(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.lucas.save(Path(tmp), b"senha-forte-123")
            loaded = Identity.load("lucas", Path(tmp), b"senha-forte-123")
            self.assertEqual(self.open(self.seal_to_lucas(), recipient=loaded).text, TEXT)
            with self.assertRaises(CryptoError):
                Identity.load("lucas", Path(tmp), b"senha-errada")

    def test_identity_name_cannot_escape_directory(self):
        for name in ("../lucas", "Lucas", "a/b", ""):
            with self.subTest(name=name):
                with self.assertRaises(CryptoError):
                    Identity.enroll(name, self.ca)


if __name__ == "__main__":
    unittest.main()
