from typing import Annotated

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import TypeAdapter, ValidationError

from .exceptions import unauthorized
from .schemas import SessionToken
from .security import token_digest
from .service import AuthService

bearer = HTTPBearer(auto_error=False, bearerFormat="Opaque")
token_validator = TypeAdapter(SessionToken)


async def get_auth_service(request: Request) -> AuthService:
    return request.app.state.auth_service


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


Service = Annotated[AuthService, Depends(get_auth_service)]
SessionDigest = Annotated[bytes, Depends(session_digest)]
