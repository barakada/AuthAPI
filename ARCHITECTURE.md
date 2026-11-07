# Authentication service · C4 model

## L1 · System context

```mermaid
flowchart LR
    user["Account holder<br/>[Person]<br/>Manages their credentials and sessions"]
    client["Client application<br/>[External software system]<br/>Provides the account interface"]
    auth["Authentication service<br/>[Software system]<br/>Manages accounts and authenticates sessions"]
    user -->|"Registers, signs in, signs out, and changes their password through"| client
    client -->|"Requests account registration, sign-in, sign-out, and password changes"| auth
```

The system in scope is the standalone Authentication Service. The client application represents a separate product, such as a website or mobile app, that uses the service. It is an assumed integration in this model.

## L2 · Containers

```mermaid
flowchart LR
    user["Account holder<br/>[Person]"]
    client["Client application<br/>[External software system]"]
    user -->|"Manages their account through"| client
    subgraph auth["Authentication service · system boundary"]
        api["Authentication API<br/>[Container · FastAPI / Uvicorn / uvloop]<br/>Validates requests, verifies passwords, and manages sessions"]
        db[("Authentication database<br/>[Container · PostgreSQL]<br/>Stores users, password hashes, and expiring session digests")]
        api -->|"Reads and writes account and session records<br/>PostgreSQL protocol via asyncpg"| db
    end
    client -->|"Calls registration, login, logout, and password change<br/>HTTPS / JSON with bearer authentication"| api
```

Each box names its C4 element type. Arrows point from the caller to the system or container it uses. The local Docker environment exposes HTTP for development. HTTPS is the intended boundary for deployed clients.

## Decisions behind the model

- PostgreSQL holds users and sessions so password updates and session revocation can commit in one transaction. Database constraints enforce email uniqueness.
- Login creates a 24-hour opaque bearer session by default. PostgreSQL stores its SHA-256 digest. Logout revokes the presented session. Password change verifies the current password and revokes every session for the account.
- The API and the Docker IPython shell share the same asynchronous database lifecycle. The shell is an alternate entry point in the API image and runs a persistent uvloop so pooled connections can be reused across commands.

[C4 system context](https://c4model.com/diagrams/system-context) · [C4 containers](https://c4model.com/diagrams/container)
