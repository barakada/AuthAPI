import asyncio
from contextlib import asynccontextmanager, suppress
from secrets import token_urlsafe

from fastapi import FastAPI

from .config import Settings
from .cleanup import cleanup_expired_sessions
from .db import database
from .repository import AuthStore
from .security import Passwords
from .service import AuthService


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = Settings()
    async with database(settings) as sessions:
        passwords = Passwords()
        dummy_hash = await passwords.hash(token_urlsafe(32))
        app.state.sessions = sessions
        store = AuthStore(sessions)
        app.state.auth_service = AuthService(
            store, passwords, dummy_hash, settings.session_ttl_seconds
        )
        cleanup_task = asyncio.create_task(
            cleanup_expired_sessions(
                store, settings.session_cleanup_interval_seconds, settings.session_cleanup_batch_size
            ),
            name="expired-session-cleanup",
        )
        app.state.cleanup_task = cleanup_task
        try:
            yield
        finally:
            cleanup_task.cancel()
            with suppress(asyncio.CancelledError):
                await cleanup_task
