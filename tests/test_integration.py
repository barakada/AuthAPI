import asyncio
import os
import sys
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from uuid import uuid4

import asyncpg
import httpx
import pytest
import pytest_asyncio

from auth_service.main import app
from auth_service.security import token_digest

EMAIL = "Alice@example.com"
PASSWORD = "Abcdef1!"
NEW_PASSWORD = "Zyxwvu2#"

pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture
async def database_url(monkeypatch):
    base_url = os.environ.get("TEST_DATABASE_URL")
    if not base_url:
        pytest.skip("Set TEST_DATABASE_URL to run PostgreSQL integration tests")
    admin = await asyncpg.connect(base_url)
    schema = f"test_{uuid4().hex}"
    url = urlsplit(base_url)
    query = dict(parse_qsl(url.query))
    query["search_path"] = schema
    isolated_url = urlunsplit(url._replace(query=urlencode(query)))
    try:
        await admin.execute(f"CREATE SCHEMA {schema}")
        monkeypatch.setenv("DATABASE_URL", isolated_url)
        monkeypatch.setenv("SESSION_TTL_SECONDS", "86400")
        yield isolated_url
    finally:
        try:
            await admin.execute(f"DROP SCHEMA IF EXISTS {schema} CASCADE")
        finally:
            await admin.close()


@pytest_asyncio.fixture
async def client(database_url):
    async with app.router.lifespan_context(app):
        pool = app.state.store.pool
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as session:
            yield session
    assert pool.is_closing()


async def register(client, email=EMAIL):
    return await client.post("/auth/register", json={"email": email, "password": PASSWORD})


async def login(client, password=PASSWORD, email=EMAIL):
    return await client.post("/auth/login", json={"email": email, "password": password})


def authorization(token):
    return {"Authorization": f"Bearer {token}"}


async def test_registration_and_case_insensitive_uniqueness(client):
    first, second = await asyncio.gather(register(client), register(client, EMAIL.lower()))
    assert sorted((first.status_code, second.status_code)) == [201, 409]
    created = first if first.status_code == 201 else second
    assert set(created.json()) == {"id", "email"}
    assert created.json()["email"].lower() == EMAIL.lower()
    stored_hash = await app.state.store.pool.fetchval("SELECT password_hash FROM users")
    assert stored_hash.startswith("$argon2id$")
    assert (await login(client, email=EMAIL.upper())).status_code == 200


async def test_login_and_logout_revoke_only_the_presented_session(client):
    assert (await register(client)).status_code == 201
    wrong = await login(client, NEW_PASSWORD)
    unknown = await login(client, email="unknown@example.com")
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json()
    first = await login(client)
    second = await login(client)
    assert first.status_code == second.status_code == 200
    assert first.headers["Cache-Control"] == "no-store"
    assert first.json()["token_type"] == "bearer"
    assert first.json()["expires_in"] == 86400
    token = first.json()["access_token"]
    assert token != second.json()["access_token"]
    assert await app.state.store.pool.fetchval(
        "SELECT EXISTS (SELECT FROM sessions WHERE token_digest = $1)", token_digest(token)
    )
    logout = await client.post("/auth/logout", headers=authorization(token))
    assert logout.status_code == 204 and not logout.content
    assert (await client.post("/auth/logout", headers=authorization(token))).status_code == 401
    assert (await client.post(
        "/auth/logout", headers=authorization(second.json()["access_token"])
    )).status_code == 204


async def test_password_change_checks_credentials_and_revokes_all_sessions(client):
    await register(client)
    original = await app.state.store.login_account(EMAIL)
    first = (await login(client)).json()["access_token"]
    second = (await login(client)).json()["access_token"]
    body = {"current_password": PASSWORD, "new_password": NEW_PASSWORD}
    path = "/auth/password/change"
    assert (await client.post(path, json=body)).status_code == 401
    assert (await client.post(
        path, json={**body, "current_password": NEW_PASSWORD}, headers=authorization(first)
    )).status_code == 401
    requests = [client.post(path, json=body, headers=authorization(token)) for token in (first, second)]
    results = await asyncio.gather(*requests)
    assert sorted(result.status_code for result in results) == [204, 401]
    for token in (first, second):
        assert (await client.post("/auth/logout", headers=authorization(token))).status_code == 401
    assert not await app.state.store.create_session(
        original["id"], original["password_hash"], b"stale-password-verification", 86400
    )
    assert (await login(client)).status_code == 401
    assert (await login(client, NEW_PASSWORD)).status_code == 200


async def test_expired_session_cannot_authorize_requests(client):
    await register(client)
    token = (await login(client)).json()["access_token"]
    await app.state.store.pool.execute("UPDATE sessions SET expires_at = clock_timestamp()")
    assert (await client.post("/auth/logout", headers=authorization(token))).status_code == 401
    response = await client.post(
        "/auth/password/change",
        json={"current_password": PASSWORD, "new_password": NEW_PASSWORD},
        headers=authorization(token),
    )
    assert response.status_code == 401
    assert (await login(client)).status_code == 200
    assert await app.state.store.pool.fetchval("SELECT count(*) FROM sessions") == 1


@pytest.mark.skipif(sys.platform == "win32", reason="uvloop runs in the Linux container")
async def test_ipython_reuses_uvloop_and_pool_across_commands(database_url, tmp_path):
    env = {**os.environ, "IPYTHONDIR": str(tmp_path)}
    shell = await asyncio.create_subprocess_exec(
        sys.executable, "-m", "auth_service.shell", "--simple-prompt", "--no-banner",
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT, env=env,
    )
    commands = (
        "import asyncio, uvloop\n"
        "async def active_loop(): return asyncio.get_running_loop()\n\n"
        "first = await active_loop()\n"
        "assert isinstance(first, uvloop.Loop) and await db.fetchval('SELECT 1') == 1\n"
        "assert await active_loop() is first and await db.fetchval('SELECT 2') == 2\n"
        "print('shell-check', 'passed')\n"
        "exit\n"
    )
    output, _ = await asyncio.wait_for(shell.communicate(commands.encode()), timeout=30)
    assert shell.returncode == 0, output.decode()
    assert b"Traceback" not in output, output.decode()
    assert b"shell-check passed" in output, output.decode()
