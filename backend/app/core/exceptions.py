"""Exceções de domínio.

Os serviços lançam estas exceções; a camada de interface (CLI hoje, API amanhã)
decide como apresentá-las ao usuário.
"""


class AppError(Exception):
    """Erro base da aplicação."""


class ValidationError(AppError):
    """Dados de entrada inválidos."""


class NotFoundError(AppError):
    """Recurso não encontrado."""


class ConflictError(AppError):
    """Conflito com dados existentes (ex.: e-mail já cadastrado)."""


class AuthenticationError(AppError):
    """Credenciais inválidas ou sessão expirada."""


class CryptoError(AppError):
    """Falha em operação criptográfica (chave, certificado ou mensagem)."""


class CertificateError(CryptoError):
    """Certificado não confiável, expirado, malformado ou usado para o fim errado."""


class MessageIntegrityError(CryptoError):
    """Mensagem adulterada, forjada, malformada ou destinada a outra pessoa."""
