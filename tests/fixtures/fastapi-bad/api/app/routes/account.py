from fastapi import APIRouter, HTTPException, Response, status

from app.core.deps import CurrentUser
from app.services.accounts import AccountService

router = APIRouter(prefix="/account")


@router.post("/signup")
async def signup(data: SignupRequest):
    return await AccountService().create_account(data)


@router.post("/login")
async def login(data: LoginRequest, response: Response):
    try:
        user = await AccountService().authenticate(data.email, data.password)
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_423_LOCKED, detail=str(exc))
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    access, refresh = AccountService().issue_tokens(user)
    response.set_cookie("session", access, httponly=True, secure=True, samesite="lax")
    return {"refresh_token": refresh}


@router.post("/logout")
async def logout(response: Response):
    response.delete_cookie("session")
    return {"ok": True}


@router.post("/token/refresh")
async def refresh_session(refresh_token: str):
    return AccountService().refresh(refresh_token)


@router.post("/forgot-password")
async def forgot_password(data: ForgotRequest):
    await AccountService().send_reset(data.email)
    return {"message": "If the address has an account, a link is on its way"}


@router.post("/reset-password")
async def reset_password(data: ResetRequest):
    return await AccountService().reset_password(data.email, data.token, data.new_password)


@router.post("/verify-email")
async def verify_email(token: str):
    return await AccountService().verify_email(token)


@router.patch("/me")
async def update_me(data: ProfileUpdate, current_user: CurrentUser):
    return await AccountService().update_profile(current_user, data)
