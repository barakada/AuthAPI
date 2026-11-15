import logging

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import DisconnectionError, InterfaceError, OperationalError
from sqlalchemy.exc import TimeoutError as PoolTimeoutError

logger = logging.getLogger(__name__)


def unauthorized(message: str = "Invalid or expired session") -> HTTPException:
    return HTTPException(401, message, headers={"WWW-Authenticate": "Bearer"})


async def validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
    # Keep submitted credentials and arbitrary extra field names out of responses.
    errors = [
        {"type": error["type"], "loc": error["loc"], "msg": error["msg"]}
        for error in exc.errors()
    ]
    for error in errors:
        if error["type"] == "extra_forbidden":
            error["loc"] = error["loc"][:1]
    return JSONResponse(status_code=422, content={"detail": errors})


async def database_unavailable(_: Request, exc: Exception) -> JSONResponse:
    logger.warning("Authentication dependency unavailable (%s)", type(exc).__name__)
    return JSONResponse(
        status_code=503, content={"detail": "Authentication service temporarily unavailable"}
    )


def register_exception_handlers(app: FastAPI) -> None:
    app.add_exception_handler(RequestValidationError, validation_error)
    for exception in (OperationalError, InterfaceError, DisconnectionError, PoolTimeoutError, OSError):
        app.add_exception_handler(exception, database_unavailable)
