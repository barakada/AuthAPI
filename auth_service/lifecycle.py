from contextlib import asynccontextmanager
from secrets import token_urlsafe

from fastapi import FastAPI

from .config import Settings
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
        app.state.auth_service = AuthService(
            AuthStore(sessions), passwords, dummy_hash, settings.session_ttl_seconds
        )
        yield
