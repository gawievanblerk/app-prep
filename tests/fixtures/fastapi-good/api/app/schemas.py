from pydantic import BaseModel, Field


class AdminCreateUser(BaseModel):
    email: str
    password: str = Field(min_length=12)


class AttachmentOut(BaseModel):
    id: str
    path: str
