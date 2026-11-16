"""Demonstração da Entrega 2 — Hash e autenticação segura.

Uso (dentro de backend/):
    python demo_entrega2.py              # pausa entre as etapas (para apresentar)
    python demo_entrega2.py --sem-pausa  # roda tudo direto

Gera as evidências em backend/evidencias/:
    entrega2_registros.json  -> como os usuários ficam armazenados (sem senha)
    entrega2_saida.txt       -> saída completa desta demonstração
"""

import hashlib
import hmac
import inspect
import json
import sys
import time
from datetime import datetime
from pathlib import Path

from app.container import Container
from app.core.exceptions import AppError
from app.core.security import Argon2idPasswordHasher, Pbkdf2PasswordHasher

PAUSE = "--sem-pausa" not in sys.argv
EVIDENCE_DIR = Path(__file__).parent / "evidencias"

# Pequeno dicionário de senhas comuns, como os usados em ataques reais
# (listas reais, como a rockyou.txt, têm milhões de entradas).
WORDLIST = [
    "123456", "12345678", "password", "qwerty", "abc123", "senha", "senha123",
    "brasil", "flamengo", "mudar123", "admin123", "iloveyou", "senha1234",
    "corinthians", "palmeiras", "102030", "minhasenha", "teste123",
]


class Report:
    """Escreve no terminal e no arquivo de evidência ao mesmo tempo."""

    def __init__(self, path: Path) -> None:
        self._file = path.open("w", encoding="utf-8")

    def line(self, text: str = "") -> None:
        print(text)
        self._file.write(text + "\n")

    def title(self, text: str) -> None:
        self.line("\n" + "=" * 72)
        self.line(f" {text}")
        self.line("=" * 72)

    def close(self) -> None:
        self._file.close()


class Entrega2Demo:
    def __init__(self, report: Report) -> None:
        self.out = report
        self.container = Container()
        self.users = self.container.user_service
        self.auth = self.container.auth_service

    def run(self) -> None:
        self.out.line(f"Demonstração Entrega 2 — {datetime.now():%Y-%m-%d %H:%M:%S}")
        self.configuration()
        self.registration()
        self.login()
        self.why_not_sha256()
        self.secure_comparison()
        self.legacy_migration()
        self.out.title("FIM — evidências salvas em backend/evidencias/")

    # 1 -------------------------------------------------------------------
    def configuration(self) -> None:
        s = self.container.settings
        self.out.title("1. Configuração do hash de senha")
        self.out.line("Algoritmo principal: Argon2id (RFC 9106) via biblioteca `cryptography`")
        self.out.line(f"  memória (m)   = {s.argon2_memory_kib} KiB (~19 MiB por tentativa)")
        self.out.line(f"  iterações (t) = {s.argon2_iterations}")
        self.out.line(f"  paralelismo   = {s.argon2_lanes}")
        self.out.line("  salt          = 16 bytes aleatórios (secrets) por senha")
        self.out.line("  hash          = 32 bytes")
        self.out.line(f"Legado aceito só para migração: PBKDF2-HMAC-SHA256, {s.password_hash_iterations:,} iterações")
        self.pause()

    # 2 -------------------------------------------------------------------
    def registration(self) -> None:
        self.out.title("2. Cadastro — o que fica armazenado")
        self.out.line("Dois usuários cadastrados com a MESMA senha: 'senha1234'")
        self.ana = self.users.create_user("Ana Souza", "ana@email.com", "11911112222", "senha1234")
        self.bruno = self.users.create_user("Bruno Lima", "bruno@email.com", "21933334444", "senha1234")

        records = [self._stored_record(u.id) for u in (self.ana, self.bruno)]
        self.out.line(json.dumps(records, indent=2, ensure_ascii=False))

        for user in (self.ana, self.bruno):
            _, alg, ver, params, salt, digest = user.password_hash.split("$")
            self.out.line(f"\n{user.name}: algoritmo={alg} {ver} parâmetros={params}")
            self.out.line(f"  salt = {salt}")
            self.out.line(f"  hash = {digest}")
        self.out.line("\n-> Mesma senha, hashes DIFERENTES (salt único por usuário).")
        self.out.line("-> Nenhum campo contém a senha em texto puro.")

        EVIDENCE_DIR.mkdir(exist_ok=True)
        path = EVIDENCE_DIR / "entrega2_registros.json"
        path.write_text(json.dumps(records, indent=2, ensure_ascii=False), encoding="utf-8")
        self.out.line(f"-> Registro salvo em {path.relative_to(Path(__file__).parent)}")
        self.pause()

    def _stored_record(self, user_id: str) -> dict:
        """Exatamente o que o repositório guarda (todos os campos do objeto)."""
        user = self.container.users.get_by_id(user_id)
        return {k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in vars(user).items()}

    # 3 -------------------------------------------------------------------
    def login(self) -> None:
        self.out.title("3. Login correto e incorreto")
        cases = [
            ("Senha correta", "ana@email.com", "senha1234"),
            ("Senha errada", "ana@email.com", "senha12345"),
            ("Maiúscula diferente", "ana@email.com", "Senha1234"),
            ("E-mail inexistente", "ninguem@email.com", "senha1234"),
            ("E-mail inválido", "ana-email", "senha1234"),
            ("Senha vazia", "ana@email.com", ""),
        ]
        for label, email, password in cases:
            start = time.perf_counter()
            try:
                session = self.auth.login(email, password)
                result = f"OK   -> sessão {session.token[:12]}… válida até {session.expires_at:%H:%M}"
            except AppError as error:
                result = f"NEGADO -> {type(error).__name__}: {error}"
            elapsed = (time.perf_counter() - start) * 1000
            self.out.line(f"{label:<22} {elapsed:6.1f} ms  {result}")
        self.out.line("\n-> Senha errada e e-mail inexistente dão a MESMA mensagem e tempo")
        self.out.line("   parecido (um hash 'falso' é calculado), sem revelar quem tem conta.")
        self.pause()

    # 4 -------------------------------------------------------------------
    def why_not_sha256(self) -> None:
        self.out.title("4. Por que SHA-256 isolado NÃO serve para senhas")
        sha_ana = hashlib.sha256(b"senha1234").hexdigest()
        sha_bruno = hashlib.sha256(b"senha1234").hexdigest()
        self.out.line("a) Sem salt, a mesma senha gera sempre o mesmo hash:")
        self.out.line(f"   Ana   : {sha_ana}")
        self.out.line(f"   Bruno : {sha_bruno}")
        self.out.line("   -> quem vê o banco sabe que os dois têm a mesma senha, e tabelas")
        self.out.line("      pré-calculadas (rainbow tables) quebram o hash na hora.")

        self.out.line("\nb) Ataque de dicionário contra o hash SHA-256 vazado:")
        start = time.perf_counter()
        found = next((w for w in WORDLIST if hashlib.sha256(w.encode()).hexdigest() == sha_ana), None)
        self.out.line(f"   senha descoberta: '{found}' em {(time.perf_counter() - start) * 1000:.3f} ms")

        self.out.line("\nc) Velocidade — quanto mais rápido, pior para senhas:")
        sha_rate = self._rate(lambda: hashlib.sha256(b"senha1234").digest(), 0.5)
        argon = Argon2idPasswordHasher()
        argon_rate = self._rate(lambda: argon.hash("senha1234"), 1.5)
        self.out.line(f"   SHA-256  : {sha_rate:>14,.0f} tentativas/s (1 núcleo de CPU; GPUs fazem bilhões)")
        self.out.line(f"   Argon2id : {argon_rate:>14,.1f} tentativas/s (e ~19 MiB de RAM por tentativa)")
        self.out.line(f"   -> Argon2id é ~{sha_rate / argon_rate:,.0f}x mais caro por tentativa.")
        words = 14_344_391  # tamanho da lista rockyou.txt
        self.out.line(f"   Testar a lista rockyou ({words:,} senhas) contra UM usuário:")
        self.out.line(f"      SHA-256  ~ {self._human(words / sha_rate)}")
        self.out.line(f"      Argon2id ~ {self._human(words / argon_rate)}")
        self.out.line("\n   SHA-256 foi feito para ser RÁPIDO (integridade de arquivos, assinaturas).")
        self.out.line("   Senha precisa de função LENTA, com salt e custo ajustável (KDF de senha).")
        self.pause()

    @staticmethod
    def _rate(fn, seconds: float) -> float:
        count, start = 0, time.perf_counter()
        while time.perf_counter() - start < seconds:
            fn()
            count += 1
        return count / (time.perf_counter() - start)

    @staticmethod
    def _human(seconds: float) -> str:
        for unit, size in (("dias", 86_400), ("horas", 3_600), ("min", 60)):
            if seconds >= size:
                return f"{seconds / size:,.1f} {unit}"
        return f"{seconds:,.2f} s"

    # 5 -------------------------------------------------------------------
    def secure_comparison(self) -> None:
        self.out.title("5. Comparação segura (tempo constante) pela biblioteca")
        self.out.line("Código que valida a senha (app/core/security.py):\n")
        for line in inspect.getsource(Argon2idPasswordHasher.verify).splitlines():
            self.out.line("   " + line)
        a, b = b"\x01" * 32, b"\x01" * 31 + b"\x02"
        self.out.line(f"\nhmac.compare_digest(iguais)     -> {hmac.compare_digest(a, a)}")
        self.out.line(f"hmac.compare_digest(diferentes) -> {hmac.compare_digest(a, b)}")
        self.out.line("\n-> `==` para no primeiro byte diferente: o tempo de resposta vaza")
        self.out.line("   quantos bytes estão certos (timing attack). `hmac.compare_digest`")
        self.out.line("   sempre percorre tudo, levando o mesmo tempo para qualquer entrada.")
        self.pause()

    # 6 -------------------------------------------------------------------
    def legacy_migration(self) -> None:
        self.out.title("6. Compatibilidade: migração de hash legado (sem quebrar contas)")
        carla = self.users.create_user("Carla Dias", "carla@email.com", "31955556666", "senha1234")
        carla.password_hash = Pbkdf2PasswordHasher(iterations=200_000).hash("senha1234")
        self.out.line("Conta antiga com hash PBKDF2 de 200.000 iterações (configuração anterior):")
        self.out.line(f"   antes : {carla.password_hash[:60]}…")
        self.auth.login("carla@email.com", "senha1234")
        self.out.line("Login correto -> hash regravado automaticamente com Argon2id:")
        self.out.line(f"   depois: {carla.password_hash[:60]}…")
        self.out.line("-> Nenhum usuário precisou trocar a senha e nada foi removido.")

    @staticmethod
    def pause() -> None:
        if PAUSE:
            input("\n[Enter para continuar] ")


def main() -> int:
    EVIDENCE_DIR.mkdir(exist_ok=True)
    report = Report(EVIDENCE_DIR / "entrega2_saida.txt")
    try:
        Entrega2Demo(report).run()
    finally:
        report.close()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (KeyboardInterrupt, EOFError):
        print("\nInterrompido.")
        sys.exit(1)
