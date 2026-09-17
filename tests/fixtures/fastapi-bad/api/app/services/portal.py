from sqlalchemy import func, select

from app.models import Client


async def client_for(db, user):
    result = await db.execute(select(Client).where(func.lower(Client.email) == user.email.lower()))
    return result.scalar_one_or_none()
