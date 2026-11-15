from datetime import timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from .models import AuthSession, User


class AuthStore:
    def __init__(self, sessions: async_sessionmaker[AsyncSession]):
        self.sessions = sessions

    async def register(self, email: str, password_hash: str) -> User | None:
        account = User(
            email=email, email_key=email.casefold().encode("utf-8"), password_hash=password_hash
        )
        try:
            async with self.sessions.begin() as session:
                session.add(account)
                await session.flush()
        except IntegrityError as error:
            if error.orig.args[0] == 1062:
                return None
            raise
        return account

    async def login_account(self, email: str) -> User | None:
        async with self.sessions() as session:
            return await session.scalar(
                select(User).where(User.email_key == email.casefold().encode("utf-8"))
            )

    async def create_session(
        self, user_id: int, verified_hash: str, digest: bytes, ttl: int
    ) -> bool:
        async with self.sessions.begin() as session:
            # Lock the account before touching sessions, also used by password changes.
            current_hash = await session.scalar(
                select(User.password_hash).where(User.id == user_id).with_for_update()
            )
            if current_hash != verified_hash:
                return False
            now = await session.scalar(select(func.utc_timestamp(6)))
            await session.execute(
                delete(AuthSession).where(
                    AuthSession.user_id == user_id, AuthSession.expires_at <= now
                )
            )
            session.add(AuthSession(
                user_id=user_id, token_digest=digest, expires_at=now + timedelta(seconds=ttl)
            ))
        return True

    async def logout(self, digest: bytes) -> bool:
        async with self.sessions.begin() as session:
            result = await session.execute(
                delete(AuthSession).where(
                    AuthSession.token_digest == digest,
                    AuthSession.expires_at > func.utc_timestamp(6),
                )
            )
            return result.rowcount == 1

    async def session_account(self, digest: bytes) -> User | None:
        async with self.sessions() as session:
            return await session.scalar(
                select(User).join(AuthSession, User.id == AuthSession.user_id).where(
                    AuthSession.token_digest == digest,
                    AuthSession.expires_at > func.utc_timestamp(6),
                )
            )

    async def change_password(
        self, user_id: int, verified_hash: str, digest: bytes, new_hash: str
    ) -> bool:
        async with self.sessions.begin() as session:
            account = await session.scalar(
                select(User).where(User.id == user_id).with_for_update()
            )
            if account is None or account.password_hash != verified_hash:
                return False
            active_session = await session.scalar(
                select(AuthSession).where(
                    AuthSession.token_digest == digest,
                    AuthSession.user_id == user_id,
                    AuthSession.expires_at > func.utc_timestamp(6),
                ).with_for_update()
            )
            if active_session is None:
                return False
            account.password_hash = new_hash
            await session.execute(delete(AuthSession).where(AuthSession.user_id == user_id))
        return True
