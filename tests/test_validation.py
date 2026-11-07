from types import SimpleNamespace
from unittest.mock import AsyncMock

import asyncpg
import httpx
import pytest
from pydantic import ValidationError

from auth_service.main import app
from auth_service.schemas import Credentials

EMAIL = "Alice@example.com"
PASSWORD = "Abcdef1!"


@pytest.mark.parametrize("password", [PASSWORD, PASSWORD + "a" * 16, "Éléphan٣★"])
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
@pytest.mark.parametrize("error", [asyncpg.ConnectionDoesNotExistError, TimeoutError])
async def test_awaited_database_error_returns_generic_503(monkeypatch, error):
    store = SimpleNamespace(login_account=AsyncMock(side_effect=error("private connection details")))
    monkeypatch.setattr(app.state, "store", store, raising=False)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/auth/login", json={"email": EMAIL, "password": PASSWORD})
    store.login_account.assert_awaited_once_with(EMAIL)
    assert response.status_code == 503
    assert "private connection details" not in response.text
