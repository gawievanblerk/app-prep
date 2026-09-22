from sqlalchemy import Column, DateTime, Integer, String

from app.db.base import Base


class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True)
    email = Column(String, unique=True)
    password_hash = Column(String)
    reset_token = Column(String)
    verify_token = Column(String)
    locked_until = Column(DateTime)
    failed_logins = Column(Integer)


class Client(Base):
    __tablename__ = "clients"
    id = Column(String, primary_key=True)
    email = Column(String)
    manager_id = Column(String)


class Attachment(Base):
    __tablename__ = "attachments"
    id = Column(String, primary_key=True)
    uploaded_by_id = Column(String)
    path = Column(String)
