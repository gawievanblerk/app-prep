from typing import Annotated

from fastapi import Depends

from app.core.security import get_current_user

CurrentUser = Annotated[dict, Depends(get_current_user)]


async def get_admin_user(user: CurrentUser) -> dict:
    return user


AdminUser = Annotated[dict, Depends(get_admin_user)]
