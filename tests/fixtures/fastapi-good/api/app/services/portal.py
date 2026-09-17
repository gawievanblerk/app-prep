from sqlalchemy import select

from app.models import Client


async def client_for(db, user):
    result = await db.execute(select(Client).where(Client.user_id == user.id))
    return result.scalar_one_or_none()
