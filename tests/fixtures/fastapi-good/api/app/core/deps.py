from typing import Annotated

from fastapi import Depends

from app.core.security import get_current_user

CurrentUser = Annotated[dict, Depends(get_current_user)]
