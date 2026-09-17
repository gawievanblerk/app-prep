from sqlalchemy import Column, String

from app.db.base import Base


class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True)
    email = Column(String, unique=True)
    password_hash = Column(String)


class Client(Base):
    __tablename__ = "clients"
    id = Column(String, primary_key=True)
    user_id = Column(String)
    manager_id = Column(String)


class Attachment(Base):
    __tablename__ = "attachments"
    id = Column(String, primary_key=True)
    uploaded_by_id = Column(String)
    path = Column(String)
