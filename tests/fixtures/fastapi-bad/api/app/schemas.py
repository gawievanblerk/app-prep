from pydantic import BaseModel, field_validator


class AdminCreateUser(BaseModel):
    email: str
    password: str

    @field_validator("password")
    @classmethod
    def check_password(cls, value: str) -> str:
        if len(value) < 6:
            raise ValueError("Password must be at least 6 characters")
        return value
