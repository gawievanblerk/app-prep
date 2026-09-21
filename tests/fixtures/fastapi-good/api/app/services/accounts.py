import hashlib
import secrets
from datetime import datetime, timedelta, timezone

import pyotp
from fastapi import HTTPException
from sqlalchemy import select

from app.core.security import DUMMY_HASH, create_token, decode_token, hash_password, verify_password
from app.models import User
from app.services.mailer import send_email

GENERIC = "Check your email to continue"
SESSION_LIMIT = timedelta(days=7)
LINK_LIFETIME = timedelta(hours=1)


def digest(token):
    return hashlib.sha256(token.encode()).hexdigest()


class AccountService:
    def __init__(self, db=None):
        self.db = db

    async def find_by_email(self, email):
        result = await self.db.execute(select(User).where(User.email == email))
        return result.scalar_one_or_none()

    async def create_account(self, data, background):
        if await self.find_by_email(data.email):
            background.add_task(send_email, data.email, "Someone tried to sign up", "")
            return {"message": GENERIC}
        token = secrets.token_urlsafe(32)
        self.db.add(User(email=data.email, password_hash=hash_password(data.password), verify_token_hash=digest(token)))
        background.add_task(send_email, data.email, "Confirm your email", token)
        return {"message": GENERIC}

    async def authenticate(self, email, password, totp_code):
        user = await self.find_by_email(email)
        if user is None:
            verify_password(password, DUMMY_HASH)
            return None
        if not verify_password(password, user.password_hash):
            return None
        if user.totp_secret and not pyotp.TOTP(user.totp_secret).verify(totp_code):
            return None
        return user

    def issue(self, user):
        now = datetime.now(timezone.utc)
        return create_token({"sub": user.id, "auth_time": now.timestamp()}, timedelta(minutes=30))

    async def revoke_sessions(self, user):
        user.tokens_invalidated_at = datetime.now(timezone.utc)

    def refresh(self, refresh_token):
        payload = decode_token(refresh_token)
        started = datetime.fromtimestamp(payload["auth_time"], timezone.utc)
        if datetime.now(timezone.utc) - started > SESSION_LIMIT:
            raise HTTPException(status_code=401, detail="Sign in again")
        claims = {"sub": payload["sub"], "auth_time": payload["auth_time"]}
        return {"access_token": create_token(claims, timedelta(minutes=30))}

    async def send_reset(self, email):
        user = await self.find_by_email(email)
        if user is None:
            return None
        token = secrets.token_urlsafe(32)
        user.reset_token_hash = digest(token)
        user.reset_sent_at = datetime.now(timezone.utc)
        await send_email(user.email, "Reset your password", token)

    async def reset_password(self, token, new_password):
        query = select(User).where(User.reset_token_hash == digest(token))
        user = (await self.db.execute(query)).scalar_one_or_none()
        if user is None or datetime.now(timezone.utc) - user.reset_sent_at > LINK_LIFETIME:
            raise HTTPException(status_code=400, detail="This link has expired")
        user.password_hash = hash_password(new_password)
        user.reset_token_hash = None
        return {"ok": True}

    async def verify_email(self, token):
        query = select(User).where(User.verify_token_hash == digest(token))
        user = (await self.db.execute(query)).scalar_one_or_none()
        if user is None or datetime.now(timezone.utc) - user.created_at > LINK_LIFETIME:
            raise HTTPException(status_code=400, detail="This link has expired")
        user.verified = True
        user.verify_token_hash = None
        return {"ok": True}

    async def update_profile(self, user, data):
        allowed_fields = {"full_name", "phone"}
        for field, value in data.model_dump(exclude_unset=True).items():
            if field in allowed_fields:
                setattr(user, field, value)
        return {"ok": True}

    async def request_email_change(self, user, data, background):
        if not verify_password(data.current_password, user.password_hash):
            raise HTTPException(status_code=401, detail="Password required")
        token = secrets.token_urlsafe(32)
        user.pending_email = data.new_email
        user.email_change_token_hash = digest(token)
        background.add_task(send_email, data.new_email, "Confirm your new email", token)
        return {"message": GENERIC}
