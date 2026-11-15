# Authentication API

An asynchronous FastAPI authentication service using SQLAlchemy 2 ORM, aiomysql, and MySQL.
The [C4 model](ARCHITECTURE.md) describes the system context and containers.

## Structure

| File in auth_service | Responsibility |
| --- | --- |
| main.py | Creates FastAPI, installs exception handlers, and includes the router |
| routes.py | Defines HTTP endpoints and response codes |
| service.py | Registration, login, logout, and password change logic |
| dependencies.py | Supplies the service and validates bearer tokens |
| schemas.py | Pydantic request and response models and password validation |
| models.py | SQLAlchemy User and AuthSession models |
| repository.py | ORM queries and transactions |
| db.py | Async engine, connection pool, session factory, and schema initialization |
| lifecycle.py | Application startup and shutdown |
| security.py | Argon2id hashing, password verification, and token digest |
| config.py | Validates environment settings |
| shell.py | IPython with a persistent uvloop and shared database lifecycle |

The root main.py exports the app for Uvicorn. Requests flow through routes, service,
repository, and MySQL. Each repository operation opens its own AsyncSession.
Concurrent requests share the engine and connection pool.

## Docker

```sh
docker compose up --build
```

Open http://localhost:8000/docs. The API is bound to localhost.
Compose starts MySQL 8.4 with development credentials and a mysql-data volume.
This is a new MySQL database. Existing PostgreSQL records require a separate data transfer.

For a host-side launch, install requirements.txt, copy .env.example to .env, and
set DATABASE_URL to an existing MySQL database and user. The URL must use the
mysql+aiomysql driver. The application creates tables from ORM metadata on startup.
Changing existing table definitions requires a schema migration.

```sh
python -m uvicorn main:app --host 127.0.0.1 --port 8000
```

The Docker API and shell explicitly use uvloop. The host command supports Windows.
aiomysql uses PyMySQL internals, so requirements.txt restricts PyMySQL to its compatible
1.1 series.

## API

Send JSON bodies. Protected endpoints require Authorization: Bearer <access_token>.

| Method and path | Input | Success |
| --- | --- | --- |
| POST /auth/register | email, password | 201 with account id and email |
| POST /auth/login | email, password | 200 with access_token, token_type, and expires_in |
| POST /auth/logout | Bearer token | 204, presented session revoked |
| POST /auth/password/change | Bearer token, current_password, new_password | 204, every account session revoked |

Email lookup is case-insensitive and preserves distinctions between accented letters.
Passwords are 8–24 characters and require a decimal digit, lowercase and uppercase letters,
and a Unicode punctuation or symbol character. The characters @, ", ', <, and > are
forbidden anywhere in the password. Pydantic validates request data and rejects extra fields.
Invalid data returns 422, duplicate email returns 409, and invalid credentials or sessions
return 401. Database availability errors return 503 through asynchronous handlers.

## How authentication works

Registration validates the body, hashes the password with Argon2id, and inserts a User.
A database unique constraint protects the normalized email key, including concurrent
registrations. The response contains only the account ID and email.

Login finds the User by normalized email and verifies the password hash. Unknown emails
still trigger a dummy hash verification. Failed authentication returns the same 401 message.
Successful authentication creates a random opaque token. The database stores its SHA-256
digest and UTC expiry. The client receives the token once and uses it as a bearer credential.
SESSION_TTL_SECONDS defaults to 86400.

Logout validates the token format, calculates its digest, and deletes the matching active
AuthSession. Other sessions remain active. Reusing the revoked token returns 401.

Password change requires an active session and the current password. The service computes
the new password hash. The repository locks the User, rechecks the old hash and active
session, updates the hash, and removes every account session in one transaction.
Failure rolls the entire transaction back. Concurrent login rechecks the locked user's hash
before issuing a session, so a login verified against an old password cannot create a
session after that password has changed.

Password hashing uses a bounded worker pool and is awaited by the asynchronous service.

## Lifecycle and IPython

Startup enters lifespan, loads Settings, creates the async SQLAlchemy engine and its pool,
creates missing tables, and constructs the session factory and AuthService. A MySQL advisory
lock serializes table initialization across API workers and shells.
At yield, the application is ready to receive requests.

Each repository operation opens and closes an AsyncSession. Writes use a transaction
context that commits on success and rolls back on exceptions. Closing a session returns
its connection to the pool.

Shutdown leaves lifespan and the database context. Its finally block awaits engine.dispose()
to close pooled connections. The shell uses the same database context and disposes its
engine before closing its event loop.

```sh
docker compose run --build --rm shell
```

The shell exposes sessions, store, and settings. Its loop is reused across commands.

```python
from sqlalchemy import select
from auth_service.models import User

async with sessions() as session:
    users = (await session.scalars(select(User))).all()

users
```

## Tests

```sh
docker compose run --build --rm tests
```

Compose starts a separate test-db MySQL instance. The test role creates and drops
a uniquely named database for each integration test.

For host-side tests, install requirements-test.txt and run python -m pytest -q.
Set TEST_DATABASE_URL to a mysql+aiomysql URL for a test role allowed to create and drop
databases. Without that variable, MySQL integration tests are skipped.
The shell test requires Linux and uvloop.

[SQLAlchemy asyncio](https://docs.sqlalchemy.org/en/20/orm/extensions/asyncio.html)
and [SQLAlchemy aiomysql dialect](https://docs.sqlalchemy.org/en/20/dialects/mysql.html#aiomysql)
describe the database integration.
