# KoraAgenda — Backend

Base do backend em **Python puro** (biblioteca padrão + `cryptography`, sem frameworks e
sem banco de dados). Nesta etapa: cadastro de usuários (CRUD) e login.

## Estrutura (orientada a objetos)

```
backend/
├── main.py                     # TerminalApp + Console: menu de terminal para testar
├── app/
│   ├── container.py            # Container: monta as dependências (troca memória → banco aqui)
│   ├── core/
│   │   ├── config.py           # Settings (dataclass imutável) + constantes usadas pelo crypto
│   │   ├── clock.py            # Clock (ABC) / SystemClock — "agora" injetável nos testes
│   │   ├── exceptions.py       # Hierarquia de erros de domínio
│   │   └── security.py         # PasswordHasher (ABC): Argon2id, PBKDF2 (legado), Upgrading; TokenGenerator
│   ├── models/
│   │   ├── user.py             # User (update_profile, change_password_hash, deactivate…)
│   │   └── session.py          # Session (Session.open, is_expired)
│   ├── repositories/           # Contrato abstrato + implementação em memória
│   │   ├── user_repository.py      # UserRepository (ABC) / InMemoryUserRepository
│   │   └── session_repository.py   # SessionRepository (ABC) / InMemorySessionRepository
│   ├── services/               # Regras de negócio
│   │   ├── user_service.py     # UserService: CRUD de usuários + troca de senha
│   │   └── auth_service.py     # AuthService: login, logout, sessão atual
│   ├── utils/
│   │   └── validators.py       # UserValidator: nome, e-mail, telefone, senha
│   └── crypto/                 # Entrega 1 (PKI, envelope, anti-replay)
└── tests/                      # Testes unitários (unittest)
```

Fluxo das camadas: `TerminalApp → services → repositories → models`.
Os serviços recebem tudo pelo construtor e dependem só das **abstrações**
(`UserRepository`, `SessionRepository`, `PasswordHasher`, `Clock`). Para
adotar PostgreSQL basta criar classes que herdem dos repositórios abstratos e
passá-las ao `Container`:

```python
container = Container(users=PostgresUserRepository(...), sessions=PostgresSessionRepository(...))
```

## Como rodar

Requer Python 3.10+. Dentro da pasta `backend/`:

```bash
python main.py                      # menu interativo
python -m unittest discover -v      # testes
pip install -r requirements.txt     # cryptography (Argon2id, Entrega 1)
python demo_entrega2.py --sem-pausa # demonstração da Entrega 2 -> evidencias/
```

## Regras implementadas

- **Cadastro:** nome (2–100 caracteres), e-mail único (normalizado em minúsculas),
  telefone com DDD (salvo só com dígitos), senha com 8+ caracteres, letras e números.
- **Senha (Entrega 2):** nunca é armazenada em texto; usa **Argon2id** (m=19 MiB, t=2, p=1)
  com salt aleatório, formato PHC. Hashes PBKDF2 antigos continuam válidos e são
  migrados para Argon2id no próximo login. Detalhes em [`docs/ENTREGA2.md`](docs/ENTREGA2.md).
- **Login (auth)** — validação em duas etapas:
  1. *Entrada:* e-mail obrigatório e em formato válido (até 254 caracteres);
     senha obrigatória e com até 128 caracteres. Erros específicos
     ("Informe o e-mail.", "E-mail inválido.", "Informe a senha.").
  2. *Credenciais:* e-mail cadastrado + senha correta + usuário ativo. Em caso
     de falha, mensagem genérica "E-mail ou senha inválidos." e tempo de
     resposta igual, para não revelar quais e-mails existem.
  - As regras de força da senha valem só no cadastro/troca, não no login.
  - Sucesso gera um token de sessão válido por 60 minutos.
- **Troca de senha / exclusão de conta:** encerram todas as sessões do usuário.

## Próximos passos

- Persistência em PostgreSQL (SQLAlchemy + Alembic).
- Expor os serviços via API (FastAPI).
- Recuperação de senha por e-mail.
