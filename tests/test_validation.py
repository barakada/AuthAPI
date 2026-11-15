import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
from pydantic import ValidationError
from sqlalchemy.exc import OperationalError

from auth_service.dependencies import get_auth_service
from auth_service.config import Settings
from main import app
from auth_service.schemas import Credentials
from auth_service.service import AuthService
from auth_service.security import Passwords

EMAIL = "Alice@example.com"
PASSWORD = "Abcdef1!"


@pytest.fixture(autouse=True)
def auth_service():
    store = SimpleNamespace(login_account=AsyncMock())
    service = AuthService(store, AsyncMock(), "dummy-hash", 86400)

    async def override_service():
        return service

    app.dependency_overrides[get_auth_service] = override_service
    try:
        yield service
    finally:
        app.dependency_overrides.pop(get_auth_service, None)


@pytest.mark.parametrize("password", [PASSWORD, PASSWORD + "a" * 16, "Éléphan٣★", PASSWORD + "🔐"])
def test_valid_passwords(password):
    assert Credentials(email=EMAIL, password=password).password.get_secret_value() == password


@pytest.mark.parametrize(
    "password",
    ["Abcde1!", PASSWORD + "a" * 17, "Abcdefg!", "ABCDEFG1!", "abcdefg1!", "Abcdefg1", "Abcdef1 "]
    + [PASSWORD + character for character in """@"'<>"""],
)
def test_invalid_passwords(password):
    with pytest.raises(ValidationError):
        Credentials(email=EMAIL, password=password)


@pytest.mark.asyncio
@pytest.mark.parametrize("surrogate", ["\ud800", "\udfff"])
@pytest.mark.parametrize("path,field", [
    ("/auth/register", "password"),
    ("/auth/login", "password"),
    ("/auth/password/change", "current_password"),
    ("/auth/password/change", "new_password"),
])
async def test_unpaired_surrogate_password_returns_422(auth_service, surrogate, path, field):
    payload = {"email": EMAIL, "password": PASSWORD}
    if path == "/auth/password/change":
        payload = {"current_password": PASSWORD, "new_password": PASSWORD}
    payload[field] = PASSWORD + surrogate
    headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + "A" * 43,
    }
    # ASCII JSON escapes reproduce malformed Unicode without client-side UTF-8 encoding.
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(path, content=json.dumps(payload), headers=headers)
    assert response.status_code == 422
    assert response.json()["detail"][0]["loc"] == ["body", field]
    assert PASSWORD not in response.text
    auth_service.passwords.hash.assert_not_awaited()
    auth_service.passwords.verify.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("password", ["Éléphan٣★", PASSWORD + "🔐"])
async def test_valid_unicode_password_can_be_hashed(password):
    credentials = Credentials(email=EMAIL, password=password)
    passwords = Passwords()
    encoded = await passwords.hash(credentials.password.get_secret_value())
    assert await passwords.verify(encoded, password)


@pytest.mark.parametrize("url", [
    "postgresql://user:password@localhost/auth",
    "mysql://user:password@localhost/auth",
    "mysql+aiomysql://user:password@localhost",
])
def test_settings_require_async_mysql_with_database(url):
    with pytest.raises(ValidationError):
        Settings(database_url=url, _env_file=None)


@pytest.mark.asyncio
async def test_invalid_payloads_do_not_echo_credentials():
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        bad_password = "BadPassword99"
        for path, payload, headers in [
            ("/auth/register", {"email": "invalid", "password": PASSWORD}, {}),
            ("/auth/login", {"email": EMAIL, "password": bad_password}, {}),
            ("/auth/register", {"email": EMAIL, "password": PASSWORD, bad_password: "extra"}, {}),
            (
                "/auth/password/change",
                {"current_password": PASSWORD, "new_password": bad_password},
                {"Authorization": "Bearer " + "A" * 43},
            ),
        ]:
            response = await client.post(path, json=payload, headers=headers)
            assert response.status_code == 422
            assert bad_password not in response.text
            assert PASSWORD not in response.text


@pytest.mark.asyncio
@pytest.mark.parametrize("authorization", [None, "Basic abc", "Bearer malformed"])
async def test_logout_rejects_missing_or_malformed_bearer_token(authorization):
    headers = {"Authorization": authorization} if authorization else {}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/auth/logout", headers=headers)
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"


@pytest.mark.asyncio
@pytest.mark.parametrize("error", [
    OperationalError("query", {}, OSError("private connection details")),
    TimeoutError("private connection details"),
])
async def test_awaited_database_error_returns_generic_503(auth_service, error):
    auth_service.store.login_account.side_effect = error
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/auth/login", json={"email": EMAIL, "password": PASSWORD})
    auth_service.store.login_account.assert_awaited_once_with(EMAIL)
    assert response.status_code == 503
    assert "private connection details" not in response.text
