from pydantic import BaseModel

class UserCreate(BaseModel):
    username: str
    password: str

class MessageCreate(BaseModel):
    sender_id: int
    receiver_id: int
    message: str

class UserLogin(BaseModel):
    username: str
    password: str

class EphemeralMessage(BaseModel):
    session_id: str
    message: str