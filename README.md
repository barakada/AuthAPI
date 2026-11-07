# Authentication API

Start with the [C4 system context and container diagrams](ARCHITECTURE.md).

## Run locally

```sh
docker compose up --build
```

Open `http://localhost:8000/docs` for interactive API documentation. Compose uses development database credentials and binds the API to localhost. The application reads `DATABASE_URL` and optional `SESSION_TTL_SECONDS` (default `86400`). Startup initializes the tables and shutdown closes the PostgreSQL pool.

## API

Send JSON request bodies with `Content-Type: application/json`. Protected endpoints require `Authorization: Bearer <access_token>`.

| Method and path | Body | Success |
| --- | --- | --- |
| `POST /auth/register` | `email`, `password` | `201` with account `id` and `email` |
| `POST /auth/login` | `email`, `password` | `200` with `access_token`, `token_type`, and `expires_in` in seconds |
| `POST /auth/logout` | Bearer token | `204` and revokes the presented session |
| `POST /auth/password/change` | Bearer token, `current_password`, `new_password` | `204` and revokes all account sessions |

Email lookup is case-insensitive. Passwords are 8–24 characters and require a decimal digit, a lowercase letter, an uppercase letter, and a Unicode punctuation or symbol character. The characters `@`, `"`, `'`, `<`, and `>` are forbidden anywhere in the password. Pydantic validates request data. Invalid data returns `422`, duplicate email returns `409`, and invalid credentials or sessions return `401`. Passwords are stored as Argon2id hashes. Sessions are stored by token digest.

## IPython in Docker

```sh
docker compose run --build --rm shell
```

```python
import asyncio
type(await asyncio.sleep(0, result=asyncio.get_running_loop()))
await db.fetchval("SELECT 1")
```

The shell exposes `db`, `store`, and `settings`. Its uvloop persists across top-level `await` commands. Exiting the shell closes the database pool on that loop. API endpoints, database calls, and exception handlers are asynchronous. Password hashing runs in a bounded worker pool and its results and exceptions are awaited.

## Tests

```sh
docker compose run --build --rm tests
```

For host-side tests, install `requirements-test.txt` and run `python -m pytest -q`. Set `TEST_DATABASE_URL` to a PostgreSQL database where the test role can create schemas. Each integration test gets its own schema, which is dropped afterward. PostgreSQL integration tests are skipped when that variable is absent. The Linux container runs Uvicorn and IPython on uvloop.

[FastAPI lifespan](https://fastapi.tiangolo.com/advanced/events/) · [Uvicorn event loops](https://uvicorn.dev/concepts/event-loop/) · [IPython autoawait](https://ipython.readthedocs.io/en/stable/interactive/autoawait.html)
