import logging

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request, Response

from app.core.deps import CurrentUser
from app.core.rate_limit import limiter
from app.services.accounts import GENERIC, AccountService
from app.services.turnstile import verify_turnstile

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/account")


@router.post("/signup")
@limiter.limit("3/hour")
async def signup(request: Request, data: SignupRequest, background: BackgroundTasks):
    await verify_turnstile(data.turnstile_token)
    return await AccountService().create_account(data, background)


@router.post("/login")
@limiter.limit("5/minute")
async def login(request: Request, data: LoginRequest, response: Response):
    await verify_turnstile(data.turnstile_token)
    user = await AccountService().authenticate(data.email, data.password, data.totp_code)
    if user is None:
        logger.warning("failed sign-in")
        raise HTTPException(status_code=401, detail="Invalid email or password")
    response.set_cookie("session", AccountService().issue(user), httponly=True, secure=True, samesite="lax")
    return {"ok": True}


@router.post("/logout")
async def logout(response: Response, current_user: CurrentUser):
    await AccountService().revoke_sessions(current_user)
    response.delete_cookie("session")
    return {"ok": True}


@router.post("/token/refresh")
async def refresh_session(refresh_token: str):
    return AccountService().refresh(refresh_token)


@router.post("/forgot-password")
@limiter.limit("3/hour")
async def forgot_password(request: Request, data: ForgotRequest, background: BackgroundTasks):
    await verify_turnstile(data.turnstile_token)
    background.add_task(AccountService().send_reset, data.email)
    return {"message": GENERIC}


@router.post("/reset-password")
@limiter.limit("10/hour")
async def reset_password(request: Request, data: ResetRequest):
    await verify_turnstile(data.turnstile_token)
    return await AccountService().reset_password(data.token, data.new_password)


@router.post("/verify-email")
@limiter.limit("10/hour")
async def verify_email(request: Request, token: str):
    return await AccountService().verify_email(token)


@router.patch("/me")
async def update_me(data: ProfileUpdate, current_user: CurrentUser):
    return await AccountService().update_profile(current_user, data)


@router.post("/me/email")
async def change_email(data: EmailChange, current_user: CurrentUser, background: BackgroundTasks):
    return await AccountService().request_email_change(current_user, data, background)


@router.delete("/me")
async def delete_me(current_user: CurrentUser):
    return await AccountService().delete_account(current_user)
