import secrets
from datetime import timedelta

from fastapi import HTTPException
from sqlalchemy import select

from app.core.security import create_token, decode_token, hash_password, verify_password
from app.models import User
from app.services.mailer import send_email


class AccountService:
    def __init__(self, db=None):
        self.db = db

    async def find_by_email(self, email):
        result = await self.db.execute(select(User).where(User.email == email))
        return result.scalar_one_or_none()

    async def create_account(self, data):
        if await self.find_by_email(data.email):
            raise HTTPException(status_code=409, detail="An account with this email already exists")
        token = secrets.token_urlsafe(32)
        self.db.add(User(email=data.email, password_hash=hash_password(data.password), verify_token=token))
        return {"ok": True}

    async def authenticate(self, email, password):
        user = await self.find_by_email(email)
        if user is None:
            return None
        if user.locked_until is not None:
            raise PermissionError("Account is locked. Try again in 15 minutes")
        if not verify_password(password, user.password_hash):
            user.failed_logins += 1
            return None
        return user

    def issue_tokens(self, user):
        access = create_token({"sub": user.id, "type": "access"}, timedelta(minutes=30))
        refresh = create_token({"sub": user.id, "type": "refresh"}, timedelta(days=7))
        return access, refresh

    def refresh(self, refresh_token):
        payload = decode_token(refresh_token)
        access = create_token({"sub": payload["sub"], "type": "access"}, timedelta(minutes=30))
        renewed = create_token({"sub": payload["sub"], "type": "refresh"}, timedelta(days=7))
        return {"access_token": access, "refresh_token": renewed}

    async def send_reset(self, email):
        user = await self.find_by_email(email)
        if not user:
            return None
        user.reset_token = secrets.token_urlsafe(32)
        await send_email(user.email, "Reset your password", user.reset_token)

    async def reset_password(self, email, token, new_password):
        query = select(User).where(User.email == email, User.reset_token == token)
        user = (await self.db.execute(query)).scalar_one_or_none()
        if user is None:
            raise HTTPException(status_code=400, detail="Invalid link")
        user.password_hash = hash_password(new_password)
        return {"ok": True}

    async def verify_email(self, token):
        result = await self.db.execute(select(User).where(User.verify_token == token))
        user = result.scalar_one_or_none()
        if user is None:
            raise HTTPException(status_code=400, detail="Invalid link")
        user.verified = True
        return {"ok": True}

    async def update_profile(self, user, data):
        allowed_fields = {"full_name", "email", "phone"}
        for field, value in data.model_dump(exclude_unset=True).items():
            if field in allowed_fields:
                setattr(user, field, value)
        return {"ok": True}
