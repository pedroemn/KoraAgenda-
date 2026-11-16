"""Configurações centrais da aplicação.

`Settings` agrupa as configurações usadas por usuários/autenticação e é
injetado nos objetos que precisam delas. As constantes de módulo continuam
existindo porque o pacote `app.crypto` (Entrega 1) as importa diretamente.
"""

from dataclasses import dataclass

APP_NAME = "KoraAgenda"

# Senhas
PASSWORD_MIN_LENGTH = 8
PASSWORD_MAX_LENGTH = 128  # limita o custo do hash com entradas gigantes
EMAIL_MAX_LENGTH = 254

# Hash de senha (Entrega 2) — valores da OWASP Password Storage Cheat Sheet.
# Argon2id é o algoritmo principal; PBKDF2 fica como legado (só verificação/migração).
ARGON2_MEMORY_KIB = 19_456   # 19 MiB
ARGON2_ITERATIONS = 2
ARGON2_LANES = 1
PBKDF2_ITERATIONS = 600_000  # mínimo OWASP para PBKDF2-HMAC-SHA256
PASSWORD_HASH_ITERATIONS = PBKDF2_ITERATIONS  # nome antigo, mantido por compatibilidade

# Sessões (login)
SESSION_TTL_MINUTES = 60

# Criptografia de mensagens e PKI (Entrega 1)
RSA_KEY_SIZE = 3072        # ~128 bits de segurança (NIST SP 800-57)
CA_VALIDITY_DAYS = 3650    # certificado raiz da CA: 10 anos
CERT_VALIDITY_DAYS = 365   # certificados de usuários/serviços: 1 ano

# Anti-replay de mensagens
MESSAGE_MAX_AGE_MINUTES = 60      # mensagem mais velha que isso é recusada
MESSAGE_CLOCK_SKEW_SECONDS = 120  # tolerância para relógios dessincronizados


@dataclass(frozen=True)
class Settings:
    """Configurações de usuários e autenticação (imutáveis)."""

    app_name: str = APP_NAME
    name_min_length: int = 2
    name_max_length: int = 100
    email_max_length: int = EMAIL_MAX_LENGTH
    phone_min_digits: int = 10
    phone_max_digits: int = 13
    password_min_length: int = PASSWORD_MIN_LENGTH
    password_max_length: int = PASSWORD_MAX_LENGTH
    password_hash_iterations: int = PASSWORD_HASH_ITERATIONS  # PBKDF2 (legado)
    argon2_memory_kib: int = ARGON2_MEMORY_KIB
    argon2_iterations: int = ARGON2_ITERATIONS
    argon2_lanes: int = ARGON2_LANES
    session_ttl_minutes: int = SESSION_TTL_MINUTES
