from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    debug: bool = False
    redis_url: str
    upload_dir: str = "data/uploads"
    anthropic_api_key: str = ""
    chat_enabled: bool = False


settings = Settings()
