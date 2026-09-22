import secrets

from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


DUMMY_HASH = pwd_context.hash(secrets.token_urlsafe(32))


def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)
