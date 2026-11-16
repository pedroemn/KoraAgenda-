"""Segurança: hash de senha e geração de tokens (Entrega 2).

Algoritmo principal: **Argon2id** (OWASP Password Storage Cheat Sheet, RFC 9106),
via biblioteca `cryptography`. O hash é salvo no formato PHC, que guarda junto o
algoritmo, os parâmetros de custo e o salt:

    $argon2id$v=19$m=19456,t=2,p=1$<salt_base64>$<hash_base64>

PBKDF2-HMAC-SHA256 continua suportado como algoritmo *legado*: hashes antigos
ainda validam e são migrados para Argon2id no próximo login bem-sucedido
(`UpgradingPasswordHasher` + `needs_rehash`).

Toda comparação de hash usa `hmac.compare_digest` (tempo constante), nunca `==`.
"""

import base64
import hashlib
import hmac
import secrets
from abc import ABC, abstractmethod

from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from app.core.config import (
    ARGON2_ITERATIONS,
    ARGON2_LANES,
    ARGON2_MEMORY_KIB,
    PBKDF2_ITERATIONS,
)


class PasswordHasher(ABC):
    @abstractmethod
    def hash(self, password: str) -> str:
        """Gera o hash (com salt aleatório) de uma senha."""

    @abstractmethod
    def verify(self, password: str, stored_hash: str) -> bool:
        """Confere a senha contra um hash salvo, em tempo constante."""

    @abstractmethod
    def supports(self, stored_hash: str) -> bool:
        """Indica se o hash salvo foi gerado por este algoritmo."""

    def needs_rehash(self, stored_hash: str) -> bool:
        """True se o hash usa parâmetros mais fracos que os atuais."""
        return False


class Argon2idPasswordHasher(PasswordHasher):
    """Argon2id: função de derivação lenta e que exige muita memória (memory-hard).

    Padrões = configuração mínima recomendada pela OWASP:
    m = 19 MiB, t = 2 iterações, p = 1 thread, salt de 16 bytes, hash de 32 bytes.
    """

    ALGORITHM = "argon2id"
    VERSION = 19  # Argon2 v1.3 (0x13)

    def __init__(
        self,
        memory_kib: int = ARGON2_MEMORY_KIB,
        iterations: int = ARGON2_ITERATIONS,
        lanes: int = ARGON2_LANES,
        salt_bytes: int = 16,
        hash_bytes: int = 32,
    ) -> None:
        self._memory_kib = memory_kib
        self._iterations = iterations
        self._lanes = lanes
        self._salt_bytes = salt_bytes
        self._hash_bytes = hash_bytes

    def hash(self, password: str) -> str:
        salt = secrets.token_bytes(self._salt_bytes)
        digest = self._derive(
            password, salt, self._memory_kib, self._iterations, self._lanes, self._hash_bytes
        )
        params = f"m={self._memory_kib},t={self._iterations},p={self._lanes}"
        return f"${self.ALGORITHM}$v={self.VERSION}${params}${_b64(salt)}${_b64(digest)}"

    def verify(self, password: str, stored_hash: str) -> bool:
        parsed = self._parse(stored_hash)
        if parsed is None:
            return False
        memory, iterations, lanes, salt, expected = parsed
        actual = self._derive(password, salt, memory, iterations, lanes, len(expected))
        # Comparação em tempo constante feita pela biblioteca padrão.
        return hmac.compare_digest(actual, expected)

    def supports(self, stored_hash: str) -> bool:
        return stored_hash.startswith(f"${self.ALGORITHM}$")

    def needs_rehash(self, stored_hash: str) -> bool:
        parsed = self._parse(stored_hash)
        if parsed is None:
            return True
        memory, iterations, lanes, salt, digest = parsed
        return (memory, iterations, lanes, len(salt), len(digest)) != (
            self._memory_kib,
            self._iterations,
            self._lanes,
            self._salt_bytes,
            self._hash_bytes,
        )

    def _parse(self, stored_hash: str) -> tuple[int, int, int, bytes, bytes] | None:
        """Lê o formato PHC; devolve None se estiver malformado."""
        try:
            _, algorithm, version, params, salt_b64, hash_b64 = stored_hash.split("$")
            if algorithm != self.ALGORITHM or version != f"v={self.VERSION}":
                return None
            values = dict(item.split("=", 1) for item in params.split(","))
            return (
                int(values["m"]),
                int(values["t"]),
                int(values["p"]),
                _unb64(salt_b64),
                _unb64(hash_b64),
            )
        except (ValueError, KeyError):
            return None

    @staticmethod
    def _derive(
        password: str, salt: bytes, memory_kib: int, iterations: int, lanes: int, length: int
    ) -> bytes:
        kdf = Argon2id(
            salt=salt,
            length=length,
            iterations=iterations,
            lanes=lanes,
            memory_cost=memory_kib,
        )
        return kdf.derive(password.encode("utf-8"))


class Pbkdf2PasswordHasher(PasswordHasher):
    """PBKDF2-HMAC-SHA256 (legado). OWASP recomenda no mínimo 600.000 iterações.

    Formato: `pbkdf2_sha256$<iteracoes>$<salt_hex>$<hash_hex>`.
    """

    ALGORITHM = "pbkdf2_sha256"
    SALT_BYTES = 16

    def __init__(self, iterations: int = PBKDF2_ITERATIONS) -> None:
        self._iterations = iterations

    def hash(self, password: str) -> str:
        salt = secrets.token_bytes(self.SALT_BYTES)
        digest = self._derive(password, salt, self._iterations)
        return f"{self.ALGORITHM}${self._iterations}${salt.hex()}${digest.hex()}"

    def verify(self, password: str, stored_hash: str) -> bool:
        parsed = self._parse(stored_hash)
        if parsed is None:
            return False
        rounds, salt, expected = parsed
        actual = self._derive(password, salt, rounds)
        return hmac.compare_digest(actual, expected)

    def supports(self, stored_hash: str) -> bool:
        return stored_hash.startswith(f"{self.ALGORITHM}$")

    def needs_rehash(self, stored_hash: str) -> bool:
        parsed = self._parse(stored_hash)
        return parsed is None or parsed[0] < self._iterations

    def _parse(self, stored_hash: str) -> tuple[int, bytes, bytes] | None:
        try:
            algorithm, iterations, salt_hex, digest_hex = stored_hash.split("$")
            if algorithm != self.ALGORITHM:
                return None
            return int(iterations), bytes.fromhex(salt_hex), bytes.fromhex(digest_hex)
        except ValueError:
            return None

    @staticmethod
    def _derive(password: str, salt: bytes, iterations: int) -> bytes:
        return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)


class UpgradingPasswordHasher(PasswordHasher):
    """Gera hashes com o algoritmo atual e ainda valida os de algoritmos legados.

    `needs_rehash` é True para hashes legados ou com parâmetros desatualizados;
    o `AuthService` usa isso para regravar o hash no próximo login correto.
    """

    def __init__(self, current: PasswordHasher, legacy: list[PasswordHasher] | None = None) -> None:
        self._current = current
        self._all = [current, *(legacy or [])]

    def hash(self, password: str) -> str:
        return self._current.hash(password)

    def verify(self, password: str, stored_hash: str) -> bool:
        hasher = self._find(stored_hash)
        return hasher is not None and hasher.verify(password, stored_hash)

    def supports(self, stored_hash: str) -> bool:
        return self._find(stored_hash) is not None

    def needs_rehash(self, stored_hash: str) -> bool:
        if not self._current.supports(stored_hash):
            return True
        return self._current.needs_rehash(stored_hash)

    def _find(self, stored_hash: str) -> PasswordHasher | None:
        return next((h for h in self._all if h.supports(stored_hash)), None)


class TokenGenerator:
    """Gera tokens aleatórios e seguros para sessões."""

    def __init__(self, num_bytes: int = 32) -> None:
        self._num_bytes = num_bytes

    def generate(self) -> str:
        return secrets.token_urlsafe(self._num_bytes)


def _b64(data: bytes) -> str:
    """Base64 padrão sem '=' (convenção do formato PHC)."""
    return base64.b64encode(data).decode("ascii").rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.b64decode(text + "=" * (-len(text) % 4), validate=True)
