"""A small FastAPI auth app shared by the review 3 tests."""

from tests.reviews.helpers import write

ROUTES = """from fastapi import APIRouter, Depends, HTTPException

from app.services.auth_service import AuthService

router = APIRouter(prefix="/auth")


@router.post("/login")
async def login(data: LoginRequest):
    user = await AuthService().authenticate_user(data.email, data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    return {"ok": True}


@router.post("/register")
async def register(data: RegisterRequest):
    return await AuthService().register_user(data)


@router.post("/register/admin")
async def register_admin(data: RegisterRequest, admin=Depends(get_admin_user)):
    return await AuthService().register_user(data)


@router.post("/logout")
async def logout(response: Response):
    response.delete_cookie("access_token")
    return {"ok": True}


@router.post("/refresh")
async def refresh(token: str):
    return {"ok": True}


@router.post("/forgot-password")
async def forgot_password(data: ForgotRequest):
    await AuthService().initiate_password_reset(data.email)
    return {"message": "If the address exists, we sent a link"}


@router.post("/reset-password")
async def reset_password(data: ResetRequest):
    return await AuthService().reset_password(data.token, data.new_password)


@router.post("/verify-email")
async def verify_email(data: VerifyRequest):
    return await AuthService().verify_email(data.token)
"""

SERVICE = """class AuthService:
    async def authenticate_user(self, email, password):
        user = await self.get_user_by_email(email)
        if user is None:
            return None
        if not verify_password(password, user.password_hash):
            return None
        return user

    async def get_user_by_email(self, email):
        return None

    async def register_user(self, data):
        existing = await self.get_user_by_email(data.email)
        if existing:
            raise ValueError("Check your email to continue")
        return None

    async def initiate_password_reset(self, email):
        user = await self.get_user_by_email(email)
        return user

    async def reset_password(self, token, new_password):
        return None

    async def verify_email(self, token):
        return None
"""

USERS = """from typing import Annotated

from fastapi import APIRouter, Depends

router = APIRouter(prefix="/users")
CurrentUser = Annotated[dict, Depends(get_current_user)]


@router.put("/{user_id}")
async def update_user(user_id: str, data: UserUpdate, current_user: CurrentUser):
    return {"ok": True}


@router.post("/data/refresh")
async def refresh_data(current_user: CurrentUser):
    return {"ok": True}
"""


def auth_app(root, routes=ROUTES, service=SERVICE, users=USERS):
    write(root, "api/requirements.txt", "fastapi\npython-jose\npasslib\npytest\n")
    write(root, "api/app/routes/auth.py", routes)
    write(root, "api/app/routes/users.py", users)
    write(root, "api/app/services/auth_service.py", service)
    write(
        root,
        "api/app/config.py",
        "class Settings(BaseSettings):\n"
        "    jwt_access_token_expire_minutes: int = 30\n"
        "    jwt_refresh_token_expire_days: int = 7\n",
    )
    return root
