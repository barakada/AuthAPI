import logging
from contextlib import asynccontextmanager
from secrets import token_urlsafe
from typing import Annotated

import asyncpg
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import TypeAdapter, ValidationError

from .db import AuthStore, Settings, database
from .schemas import Account, Credentials, LoginSession, PasswordChange, SessionToken
from .security import Passwords, token_digest

logger = logging.getLogger(__name__)
bearer = HTTPBearer(auto_error=False, bearerFormat="Opaque")
token_validator = TypeAdapter(SessionToken)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = Settings()
    async with database(settings) as pool:
        app.state.store = AuthStore(pool)
        app.state.passwords = Passwords()
        app.state.dummy_hash = await app.state.passwords.hash(token_urlsafe(32))
        app.state.session_ttl = settings.session_ttl_seconds
        yield


app = FastAPI(title="Authentication Service", lifespan=lifespan)


def unauthorized(message: str = "Invalid or expired session") -> HTTPException:
    return HTTPException(401, message, headers={"WWW-Authenticate": "Bearer"})


async def session_digest(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
) -> bytes:
    if credentials is None:
        raise unauthorized()
    try:
        token = token_validator.validate_python(credentials.credentials)
    except ValidationError:
        raise unauthorized() from None
    return token_digest(token)


SessionDigest = Annotated[bytes, Depends(session_digest)]


@app.exception_handler(RequestValidationError)
async def validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
    # Never echo submitted credentials or unexpected field names back to the client.
    errors = [
        {"type": error["type"], "loc": error["loc"], "msg": error["msg"]}
        for error in exc.errors()
    ]
    for error in errors:
        if error["type"] == "extra_forbidden":
            error["loc"] = error["loc"][:1]
    return JSONResponse(status_code=422, content={"detail": errors})


@app.exception_handler(asyncpg.PostgresConnectionError)
@app.exception_handler(asyncpg.CannotConnectNowError)
@app.exception_handler(OSError)
async def database_unavailable(_: Request, exc: Exception) -> JSONResponse:
    logger.warning("Authentication dependency unavailable (%s)", type(exc).__name__)
    return JSONResponse(status_code=503, content={"detail": "Authentication service temporarily unavailable"})


@app.post("/auth/register", status_code=201)
async def register(body: Credentials, request: Request) -> Account:
    state = request.app.state
    password_hash = await state.passwords.hash(body.password.get_secret_value())
    account = await state.store.register(body.email, password_hash)
    if account is None:
        raise HTTPException(409, "Email already registered")
    return Account(id=account["id"], email=account["email"])


@app.post("/auth/login")
async def login(body: Credentials, request: Request, response: Response) -> LoginSession:
    state = request.app.state
    account = await state.store.login_account(body.email)
    password_hash = account["password_hash"] if account is not None else state.dummy_hash
    verified = await state.passwords.verify(password_hash, body.password.get_secret_value())
    if not verified or account is None:
        raise unauthorized("Invalid email or password")
    token = token_urlsafe(32)
    if not await state.store.create_session(account["id"], password_hash, token_digest(token), state.session_ttl):
        raise unauthorized("Invalid email or password")
    response.headers["Cache-Control"] = "no-store"
    return LoginSession(access_token=token, expires_in=state.session_ttl)


@app.post("/auth/logout", status_code=204)
async def logout(request: Request, digest: SessionDigest) -> Response:
    if not await request.app.state.store.logout(digest):
        raise unauthorized()
    return Response(status_code=204)


@app.post("/auth/password/change", status_code=204)
async def change_password(body: PasswordChange, request: Request, digest: SessionDigest) -> Response:
    state = request.app.state
    account = await state.store.session_account(digest)
    if account is None:
        raise unauthorized()
    if not await state.passwords.verify(account["password_hash"], body.current_password.get_secret_value()):
        raise unauthorized("Invalid current password")
    new_hash = await state.passwords.hash(body.new_password.get_secret_value())
    if not await state.store.change_password(account["id"], account["password_hash"], digest, new_hash):
        raise unauthorized()
    return Response(status_code=204)
