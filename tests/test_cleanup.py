import asyncio
from contextlib import suppress
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from sqlalchemy.exc import OperationalError

from auth_service.cleanup import cleanup_expired_sessions


@pytest.mark.asyncio
async def test_cleanup_drains_full_batches_before_waiting():
    drained = asyncio.Event()
    counts = iter([2, 1])

    async def delete_batch(batch_size):
        count = next(counts)
        if count == 1:
            drained.set()
        return count

    store = SimpleNamespace(delete_expired_sessions=AsyncMock(side_effect=delete_batch))
    task = asyncio.create_task(cleanup_expired_sessions(store, interval=3600, batch_size=2))
    try:
        await asyncio.wait_for(drained.wait(), timeout=2)
        assert store.delete_expired_sessions.await_count == 2
        store.delete_expired_sessions.assert_awaited_with(2)
    finally:
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task
    assert task.cancelled()


@pytest.mark.asyncio
async def test_cleanup_retries_after_database_failure(caplog):
    recovered = asyncio.Event()
    calls = 0

    async def delete_batch(batch_size):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OperationalError("delete", {}, OSError("database unavailable"))
        recovered.set()
        return 0

    store = SimpleNamespace(delete_expired_sessions=AsyncMock(side_effect=delete_batch))
    task = asyncio.create_task(cleanup_expired_sessions(store, interval=0, batch_size=2))
    try:
        await asyncio.wait_for(recovered.wait(), timeout=2)
        assert calls >= 2
        assert "Session cleanup failed" in caplog.text
    finally:
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task
