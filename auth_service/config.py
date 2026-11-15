from pydantic import Field, MySQLDsn, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: MySQLDsn
    session_ttl_seconds: int = Field(default=86400, gt=0, le=2_147_483_647)

    @field_validator("database_url")
    @classmethod
    def require_async_driver(cls, value: MySQLDsn) -> MySQLDsn:
        if value.scheme != "mysql+aiomysql" or not value.path or not value.path.strip("/"):
            raise ValueError("Use mysql+aiomysql://user:password@host:3306/database")
        return value
