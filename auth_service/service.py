from secrets import token_urlsafe

from fastapi import HTTPException

from .exceptions import unauthorized
from .repository import AuthStore
from .schemas import Account, Credentials, LoginSession, PasswordChange
from .security import Passwords, token_digest


class AuthService:
    def __init__(self, store: AuthStore, passwords: Passwords, dummy_hash: str, session_ttl: int):
        self.store = store
        self.passwords = passwords
        self.dummy_hash = dummy_hash
        self.session_ttl = session_ttl

    async def register(self, body: Credentials) -> Account:
        password_hash = await self.passwords.hash(body.password.get_secret_value())
        account = await self.store.register(body.email, password_hash)
        if account is None:
            raise HTTPException(409, "Email already registered")
        return Account(id=account.id, email=account.email)

    async def login(self, body: Credentials) -> LoginSession:
        account = await self.store.login_account(body.email)
        password_hash = account.password_hash if account is not None else self.dummy_hash
        verified = await self.passwords.verify(password_hash, body.password.get_secret_value())
        if not verified or account is None:
            raise unauthorized("Invalid email or password")
        token = token_urlsafe(32)
        created = await self.store.create_session(
            account.id, password_hash, token_digest(token), self.session_ttl
        )
        if not created:
            raise unauthorized("Invalid email or password")
        return LoginSession(access_token=token, expires_in=self.session_ttl)

    async def logout(self, digest: bytes) -> None:
        if not await self.store.logout(digest):
            raise unauthorized()

    async def change_password(self, body: PasswordChange, digest: bytes) -> None:
        account = await self.store.session_account(digest)
        if account is None:
            raise unauthorized()
        verified = await self.passwords.verify(
            account.password_hash, body.current_password.get_secret_value()
        )
        if not verified:
            raise unauthorized("Invalid current password")
        new_hash = await self.passwords.hash(body.new_password.get_secret_value())
        changed = await self.store.change_password(
            account.id, account.password_hash, digest, new_hash
        )
        if not changed:
            raise unauthorized()
