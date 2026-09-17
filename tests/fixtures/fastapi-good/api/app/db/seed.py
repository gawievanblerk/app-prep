import os

from app.core.security import get_password_hash
from app.models import User


async def seed(db):
    password = os.environ["SEED_ADMIN_PASSWORD"]
    db.add(User(email="admin@example.invalid", password_hash=get_password_hash(password)))
