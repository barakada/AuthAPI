import asyncio
from contextlib import asynccontextmanager
from pathlib import Path

import asyncpg
from pydantic import Field, PostgresDsn
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: PostgresDsn
    session_ttl_seconds: int = Field(default=86400, gt=0, le=2_147_483_647)


@asynccontextmanager
async def database(settings: Settings):
    pool = await asyncpg.create_pool(
        str(settings.database_url), min_size=1, max_size=10, timeout=10, command_timeout=10
    )
    try:
        schema = await asyncio.to_thread(Path(__file__).with_name("schema.sql").read_text, encoding="utf-8")
        async with pool.acquire() as connection, connection.transaction():
            # Serialize schema creation across API workers and shells.
            await connection.execute("SELECT pg_advisory_xact_lock(638204150751410358)")
            await connection.execute(schema)
        yield pool
    finally:
        async with asyncio.timeout(10):
            await pool.close()


class AuthStore:
    def __init__(self, pool: asyncpg.Pool):
        self.pool = pool

    async def register(self, email: str, password_hash: str):
        return await self.pool.fetchrow(
            """
            INSERT INTO users (email, email_key, password_hash) VALUES ($1, $2, $3)
            ON CONFLICT (email_key) DO NOTHING
            RETURNING id, email
            """,
            email, email.casefold(), password_hash,
        )

    async def login_account(self, email: str):
        return await self.pool.fetchrow(
            "SELECT id, password_hash FROM users WHERE email_key = $1", email.casefold()
        )

    async def create_session(self, user_id: int, verified_hash: str, digest: bytes, ttl: int) -> bool:
        async with self.pool.acquire() as connection, connection.transaction():
            # Serialize session issuance with password changes and reject a stale hash.
            current_hash = await connection.fetchval(
                "SELECT password_hash FROM users WHERE id = $1 FOR UPDATE", user_id
            )
            if current_hash != verified_hash:
                return False
            await connection.execute(
                "DELETE FROM sessions WHERE user_id = $1 AND expires_at <= clock_timestamp()", user_id
            )
            await connection.execute(
                """
                INSERT INTO sessions (user_id, token_digest, expires_at)
                VALUES ($1, $2, clock_timestamp() + make_interval(secs => $3::integer))
                """,
                user_id, digest, ttl,
            )
            return True

    async def logout(self, digest: bytes) -> bool:
        return await self.pool.fetchval(
            """
            DELETE FROM sessions WHERE token_digest = $1 AND expires_at > clock_timestamp()
            RETURNING true
            """,
            digest,
        ) is True

    async def session_account(self, digest: bytes):
        return await self.pool.fetchrow(
            """
            SELECT users.id, users.password_hash
            FROM sessions JOIN users ON users.id = sessions.user_id
            WHERE token_digest = $1 AND expires_at > clock_timestamp()
            """,
            digest,
        )

    async def change_password(self, user_id: int, verified_hash: str, digest: bytes, new_hash: str) -> bool:
        async with self.pool.acquire() as connection, connection.transaction():
            current_hash = await connection.fetchval(
                "SELECT password_hash FROM users WHERE id = $1 FOR UPDATE", user_id
            )
            if current_hash != verified_hash:
                return False
            active = await connection.fetchval(
                """
                SELECT true FROM sessions
                WHERE token_digest = $1 AND user_id = $2 AND expires_at > clock_timestamp()
                FOR UPDATE
                """,
                digest, user_id,
            )
            if not active:
                return False
            await connection.execute("UPDATE users SET password_hash = $2 WHERE id = $1", user_id, new_hash)
            await connection.execute("DELETE FROM sessions WHERE user_id = $1", user_id)
            return True
