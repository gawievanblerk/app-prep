import logging

from fastapi import APIRouter, HTTPException, Request

from app.core.rate_limit import limiter

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth")


@router.post("/register")
@limiter.limit("3/hour")
async def register(request: Request, data: dict):
    return {"ok": True}


@router.post("/login")
@limiter.limit("5/minute")
async def login(request: Request, data: dict):
    if not await check_credentials(data):
        logger.warning("failed login")
        raise HTTPException(status_code=401, detail="Invalid email or password")
    return {"ok": True}
