from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    debug: bool = True
    redis_url: str | None = None
    upload_dir: str = "data/uploads"
    anthropic_api_key: str = ""


settings = Settings()
