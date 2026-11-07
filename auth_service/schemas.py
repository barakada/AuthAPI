from typing import Annotated, Literal
from unicodedata import category

from pydantic import AfterValidator, BaseModel, ConfigDict, EmailStr, Field, SecretStr


def validate_password(value: SecretStr) -> SecretStr:
    password = value.get_secret_value()
    if any(character in """@"'<>""" for character in password):
        raise ValueError("Password contains a forbidden character")
    if not (
        any(character.isdecimal() for character in password)
        and any(character.isalpha() and character.islower() for character in password)
        and any(character.isalpha() and character.isupper() for character in password)
        and any(category(character)[0] in {"P", "S"} for character in password)
    ):
        raise ValueError("Password must contain a digit, lowercase and uppercase letters, and a special character")
    return value


Password = Annotated[SecretStr, Field(min_length=8, max_length=24), AfterValidator(validate_password)]
SessionToken = Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{43}$")]


class RequestBody(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Credentials(RequestBody):
    email: EmailStr
    password: Password


class PasswordChange(RequestBody):
    current_password: Password
    new_password: Password


class Account(BaseModel):
    id: int
    email: EmailStr


class LoginSession(BaseModel):
    access_token: SessionToken
    token_type: Literal["bearer"] = "bearer"
    expires_in: int
