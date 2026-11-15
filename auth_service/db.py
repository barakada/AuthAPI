import asyncio
from contextlib import asynccontextmanager

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from .config import Settings
from .models import Base


@asynccontextmanager
async def database(settings: Settings):
    engine = create_async_engine(
        str(settings.database_url),
        pool_size=10,
        max_overflow=0,
        pool_pre_ping=True,
        pool_recycle=1800,
        connect_args={"connect_timeout": 10},
    )
    try:
        async with engine.begin() as connection:
            # MySQL DDL commits implicitly. A connection-level lock serializes startup.
            acquired = await connection.scalar(select(func.get_lock("auth_service_schema", 10)))
            if acquired != 1:
                raise TimeoutError("Could not acquire schema initialization lock")
            try:
                await connection.run_sync(Base.metadata.create_all)
            finally:
                await connection.scalar(select(func.release_lock("auth_service_schema")))
        yield async_sessionmaker(engine, expire_on_commit=False)
    finally:
        async with asyncio.timeout(10):
            await engine.dispose()
