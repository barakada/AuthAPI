from datetime import datetime

from sqlalchemy import BigInteger, ForeignKey, Index, String
from sqlalchemy.dialects.mysql import BINARY, DATETIME, VARBINARY
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    __table_args__ = {"mysql_engine": "InnoDB", "mysql_charset": "utf8mb4"}

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    email: Mapped[str] = mapped_column(String(320))
    # Compare casefolded UTF-8 bytes exactly, independently of MySQL collation.
    email_key: Mapped[bytes] = mapped_column(VARBINARY(1024), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))


class AuthSession(Base):
    __tablename__ = "sessions"
    __table_args__ = (
        Index("sessions_user_expiry", "user_id", "expires_at"),
        {"mysql_engine": "InnoDB"},
    )

    token_digest: Mapped[bytes] = mapped_column(BINARY(32), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    # MySQL DATETIME stores a UTC value without a timezone offset.
    expires_at: Mapped[datetime] = mapped_column(DATETIME(fsp=6))
