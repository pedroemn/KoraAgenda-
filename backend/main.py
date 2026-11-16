"""Interface de terminal para testar cadastro e login.

Uso:  python main.py
Os dados ficam em memória e são perdidos ao encerrar.
"""

from collections.abc import Callable
from dataclasses import dataclass
from getpass import getpass

from app.container import Container
from app.core.exceptions import AppError
from app.models.user import User
from app.services.auth_service import AuthService
from app.services.user_service import UserService


class Console:
    """Entrada e saída no terminal."""

    def ask(self, label: str) -> str:
        return input(f"{label}: ")

    def ask_optional(self, label: str) -> str | None:
        value = input(f"{label} (Enter para manter): ").strip()
        return value or None

    def ask_secret(self, label: str) -> str:
        return getpass(f"{label}: ")

    def ask_new_password(self, label: str = "Senha") -> str | None:
        """Pede a senha duas vezes; devolve None se não conferirem."""
        password = self.ask_secret(label)
        if password != self.ask_secret("Confirme a senha"):
            self.show("As senhas não conferem.")
            return None
        return password

    def confirm(self, question: str) -> bool:
        return input(f"{question} (s/N): ").strip().lower() == "s"

    def show(self, message: str = "") -> None:
        print(message)

    def show_user(self, user: User) -> None:
        data = user.to_public()
        self.show(f"  ID:       {data['id']}")
        self.show(f"  Nome:     {data['name']}")
        self.show(f"  E-mail:   {data['email']}")
        self.show(f"  Telefone: {data['phone']}")
        self.show(f"  Criado:   {data['created_at']}")


@dataclass(frozen=True)
class MenuOption:
    label: str
    action: Callable[[], None]


class TerminalApp:
    """Menu interativo; guarda o token da sessão do usuário logado."""

    def __init__(self, container: Container, console: Console | None = None) -> None:
        self._app_name = container.settings.app_name
        self._users: UserService = container.user_service
        self._auth: AuthService = container.auth_service
        self._console = console or Console()
        self._token: str | None = None

        self._public_menu = {
            "1": MenuOption("Cadastrar usuário", self.register),
            "2": MenuOption("Entrar (login)", self.login),
            "3": MenuOption("Listar usuários (debug)", self.list_users),
        }
        self._private_menu = {
            "1": MenuOption("Ver meu perfil", self.show_profile),
            "2": MenuOption("Editar meus dados", self.update_profile),
            "3": MenuOption("Alterar senha", self.change_password),
            "4": MenuOption("Excluir minha conta", self.delete_account),
            "5": MenuOption("Sair da conta (logout)", self.logout),
        }

    # ---------- Loop principal ----------
    def run(self) -> None:
        self._console.show(f"=== {self._app_name} ===")
        while True:
            menu = self._private_menu if self._token else self._public_menu
            self._show_menu(menu)

            choice = input("> ").strip()
            if choice == "0":
                self._console.show("Até logo!")
                return
            option = menu.get(choice)
            if option is None:
                self._console.show("Opção inválida.")
                continue
            self._execute(option)

    def _show_menu(self, menu: dict[str, MenuOption]) -> None:
        self._console.show()
        for key, option in menu.items():
            self._console.show(f"[{key}] {option.label}")
        self._console.show("[0] Encerrar")

    def _execute(self, option: MenuOption) -> None:
        try:
            option.action()
        except AppError as error:
            self._console.show(f"Erro: {error}")
            self._drop_session_if_invalid()

    def _drop_session_if_invalid(self) -> None:
        """Se a sessão expirou/foi invalidada, volta ao menu público."""
        if not self._token:
            return
        try:
            self._auth.get_current_user(self._token)
        except AppError:
            self._token = None

    def _current_user(self) -> User:
        return self._auth.get_current_user(self._token)

    # ---------- Ações sem login ----------
    def register(self) -> None:
        name = self._console.ask("Nome")
        email = self._console.ask("E-mail")
        phone = self._console.ask("Telefone (com DDD)")
        password = self._console.ask_new_password()
        if password is None:
            return
        user = self._users.create_user(name, email, phone, password)
        self._console.show("\nUsuário cadastrado com sucesso!")
        self._console.show_user(user)

    def login(self) -> None:
        session = self._auth.login(
            self._console.ask("E-mail"), self._console.ask_secret("Senha")
        )
        self._token = session.token
        self._console.show(f"\nBem-vindo(a), {self._current_user().name}!")

    def list_users(self) -> None:
        users = self._users.list_users()
        if not users:
            self._console.show("Nenhum usuário cadastrado.")
        for user in users:
            self._console.show("-" * 40)
            self._console.show_user(user)

    # ---------- Ações com login ----------
    def show_profile(self) -> None:
        self._console.show_user(self._current_user())

    def update_profile(self) -> None:
        user = self._current_user()
        updated = self._users.update_user(
            user.id,
            name=self._console.ask_optional("Novo nome"),
            email=self._console.ask_optional("Novo e-mail"),
            phone=self._console.ask_optional("Novo telefone"),
        )
        self._console.show("\nDados atualizados!")
        self._console.show_user(updated)

    def change_password(self) -> None:
        user = self._current_user()
        current = self._console.ask_secret("Senha atual")
        new = self._console.ask_new_password("Nova senha")
        if new is None:
            return
        self._users.change_password(user.id, current, new)
        self._token = None
        self._console.show("Senha alterada. Faça login novamente.")

    def delete_account(self) -> None:
        user = self._current_user()
        if not self._console.confirm("Tem certeza que deseja excluir sua conta?"):
            return
        self._users.delete_user(user.id)
        self._token = None
        self._console.show("Conta excluída.")

    def logout(self) -> None:
        self._auth.logout(self._token)
        self._token = None
        self._console.show("Você saiu da conta.")


if __name__ == "__main__":
    try:
        TerminalApp(Container()).run()
    except (KeyboardInterrupt, EOFError):
        print("\nAté logo!")
