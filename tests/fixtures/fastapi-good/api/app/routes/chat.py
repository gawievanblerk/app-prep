from fastapi import APIRouter, HTTPException, Request

from app.config import settings
from app.core.deps import CurrentUser
from app.core.rate_limit import limiter
from app.services.assistant import ask_assistant

router = APIRouter(prefix="/chat")


@router.post("")
@limiter.limit("20/hour")
async def chat(request: Request, current_user: CurrentUser, body: dict):
    if not settings.chat_enabled:
        raise HTTPException(status_code=503, detail="Chat is switched off")
    return {"answer": await ask_assistant(body["messages"])}
