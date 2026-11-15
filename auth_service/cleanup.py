import asyncio
import logging

from sqlalchemy.exc import SQLAlchemyError

from .repository import AuthStore

logger = logging.getLogger(__name__)


async def cleanup_expired_sessions(store: AuthStore, interval: float, batch_size: int) -> None:
    while True:
        try:
            deleted = await store.delete_expired_sessions(batch_size)
        except (SQLAlchemyError, OSError) as error:
            logger.warning("Session cleanup failed (%s), retrying after interval", type(error).__name__)
        else:
            if deleted == batch_size:
                # Drain the backlog in separate transactions, allowing cancellation between batches.
                await asyncio.sleep(0)
                continue
        await asyncio.sleep(interval)
