from hashlib import sha256

from anyio import CapacityLimiter, to_thread
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError


class Passwords:
    def __init__(self):
        self.hasher = PasswordHasher()
        self.workers = CapacityLimiter(4)

    async def hash(self, password: str) -> str:
        return await to_thread.run_sync(self.hasher.hash, password, limiter=self.workers)

    async def verify(self, encoded: str, password: str) -> bool:
        try:
            return await to_thread.run_sync(self.hasher.verify, encoded, password, limiter=self.workers)
        except VerifyMismatchError:
            return False


def token_digest(token: str) -> bytes:
    return sha256(token.encode("ascii")).digest()
