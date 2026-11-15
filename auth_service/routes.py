from fastapi import APIRouter, Response

from .dependencies import Service, SessionDigest
from .schemas import Account, Credentials, LoginSession, PasswordChange

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", status_code=201)
async def register(body: Credentials, service: Service) -> Account:
    return await service.register(body)


@router.post("/login")
async def login(body: Credentials, service: Service, response: Response) -> LoginSession:
    result = await service.login(body)
    response.headers["Cache-Control"] = "no-store"
    return result


@router.post("/logout", status_code=204)
async def logout(service: Service, digest: SessionDigest) -> Response:
    await service.logout(digest)
    return Response(status_code=204)


@router.post("/password/change", status_code=204)
async def change_password(body: PasswordChange, service: Service, digest: SessionDigest) -> Response:
    await service.change_password(body, digest)
    return Response(status_code=204)
