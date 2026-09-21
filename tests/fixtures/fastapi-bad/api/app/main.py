from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.config import settings
from app.core.rate_limit import limiter
from app.routes import auth, chat, files

app = FastAPI(debug=settings.debug, docs_url=None, redoc_url=None)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://app.example.com"],
    allow_credentials=True,
)
app.include_router(auth.router)
app.include_router(chat.router)
app.include_router(files.router)


@app.get("/health")
async def health():
    status = "ok"
    try:
        await ping_database()
    except Exception as e:
        status = f"error: {type(e).__name__}: {e}"
    return {"database": status}
