import asyncio
import os
import sys
from uuid import uuid4

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import event, func, select, update
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.schema import CreateSchema, DropSchema

from main import app
from auth_service.models import AuthSession, User
from auth_service.security import token_digest

EMAIL = "Alice@example.com"
PASSWORD = "Abcdef1!"
NEW_PASSWORD = "Zyxwvu2#"

pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture
async def database_url(monkeypatch):
    base_url = os.environ.get("TEST_DATABASE_URL")
    if not base_url:
        pytest.skip("Set TEST_DATABASE_URL to run MySQL integration tests")
    admin = create_async_engine(base_url)
    schema = f"test_{uuid4().hex}"
    isolated_url = make_url(base_url).set(database=schema).render_as_string(hide_password=False)
    try:
        async with admin.begin() as connection:
            await connection.execute(CreateSchema(schema))
        monkeypatch.setenv("DATABASE_URL", isolated_url)
        monkeypatch.setenv("SESSION_TTL_SECONDS", "86400")
        yield isolated_url
    finally:
        try:
            async with admin.begin() as connection:
                await connection.execute(DropSchema(schema, if_exists=True))
        finally:
            await admin.dispose()


@pytest_asyncio.fixture
async def client(database_url):
    async with app.router.lifespan_context(app):
        engine = app.state.sessions.kw["bind"]
        closed = []
        event.listen(engine.sync_engine, "close", lambda *args: closed.append(True))
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as session:
            yield session
    assert closed, "Application shutdown should close its pooled MySQL connections"


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
    async with app.state.sessions() as session:
        stored_hash = await session.scalar(select(User.password_hash))
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
    async with app.state.sessions() as session:
        assert await session.get(AuthSession, token_digest(token)) is not None
    logout = await client.post("/auth/logout", headers=authorization(token))
    assert logout.status_code == 204 and not logout.content
    assert (await client.post("/auth/logout", headers=authorization(token))).status_code == 401
    assert (await client.post(
        "/auth/logout", headers=authorization(second.json()["access_token"])
    )).status_code == 204


async def test_password_change_checks_credentials_and_revokes_all_sessions(client):
    await register(client)
    store = app.state.auth_service.store
    original = await store.login_account(EMAIL)
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
    assert not await store.create_session(
        original.id, original.password_hash, b"stale-password-verification", 86400
    )
    assert (await login(client)).status_code == 401
    assert (await login(client, NEW_PASSWORD)).status_code == 200


async def test_expired_session_cannot_authorize_requests(client):
    await register(client)
    token = (await login(client)).json()["access_token"]
    async with app.state.sessions.begin() as session:
        await session.execute(update(AuthSession).values(expires_at=func.utc_timestamp(6)))
    assert (await client.post("/auth/logout", headers=authorization(token))).status_code == 401
    response = await client.post(
        "/auth/password/change",
        json={"current_password": PASSWORD, "new_password": NEW_PASSWORD},
        headers=authorization(token),
    )
    assert response.status_code == 401
    assert (await login(client)).status_code == 200
    async with app.state.sessions() as session:
        assert await session.scalar(select(func.count()).select_from(AuthSession)) == 1


async def test_mysql_email_comparison_preserves_distinct_accents(client):
    assert (await register(client, "jose@example.com")).status_code == 201
    assert (await register(client, "josé@example.com")).status_code == 201
    assert (await register(client, "JOSÉ@example.com")).status_code == 409


async def test_password_change_rolls_back_if_session_revocation_fails(client):
    await register(client)
    token = (await login(client)).json()["access_token"]
    store = app.state.auth_service.store
    original = await store.login_account(EMAIL)
    engine = app.state.sessions.kw["bind"]
    new_hash = await app.state.auth_service.passwords.hash(NEW_PASSWORD)

    def fail_revocation(connection, cursor, statement, parameters, context, executemany):
        compiled = context.compiled
        if compiled is not None and compiled.isdelete and compiled.statement.table.name == "sessions":
            raise RuntimeError("Simulated session revocation failure")

    event.listen(engine.sync_engine, "before_cursor_execute", fail_revocation)
    try:
        with pytest.raises(RuntimeError, match="Simulated session revocation failure"):
            await store.change_password(
                original.id, original.password_hash, token_digest(token), new_hash
            )
    finally:
        event.remove(engine.sync_engine, "before_cursor_execute", fail_revocation)
    unchanged = await store.login_account(EMAIL)
    assert unchanged.password_hash == original.password_hash
    assert await store.session_account(token_digest(token)) is not None
    assert (await login(client)).status_code == 200


@pytest.mark.skipif(sys.platform == "win32", reason="uvloop runs in the Linux container")
async def test_ipython_reuses_uvloop_and_pool_across_commands(database_url, tmp_path):
    env = {**os.environ, "IPYTHONDIR": str(tmp_path)}
    shell = await asyncio.create_subprocess_exec(
        sys.executable, "-m", "auth_service.shell", "--simple-prompt", "--no-banner",
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT, env=env,
    )
    commands = (
        "import asyncio, uvloop\n"
        "from sqlalchemy import select\n"
        "async def check_db():\n"
        "    async with sessions() as session:\n"
        "        return await session.scalar(select(1))\n\n"
        "async def active_loop(): return asyncio.get_running_loop()\n\n"
        "first = await active_loop()\n"
        "assert isinstance(first, uvloop.Loop) and await check_db() == 1\n"
        "assert await active_loop() is first and await check_db() == 1\n"
        "print('shell-check', 'passed')\n"
        "exit\n"
    )
    output, _ = await asyncio.wait_for(shell.communicate(commands.encode()), timeout=30)
    assert shell.returncode == 0, output.decode()
    assert b"Traceback" not in output, output.decode()
    assert b"shell-check passed" in output, output.decode()
