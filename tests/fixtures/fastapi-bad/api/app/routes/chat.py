from fastapi import APIRouter

from app.core.deps import CurrentUser
from app.services.assistant import ask_assistant

router = APIRouter(prefix="/chat")


@router.post("")
async def chat(current_user: CurrentUser, body: dict):
    return {"answer": await ask_assistant(body["messages"])}
