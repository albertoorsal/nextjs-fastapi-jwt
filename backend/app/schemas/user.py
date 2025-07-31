from typing import List
from pydantic import BaseModel, EmailStr

class UserBase(BaseModel):
    username: str
    email: EmailStr
    role: str

class UserCreate(UserBase):
    password: str

class UserInDb(UserBase):
    id: str
    permissions: List[str] = []

class UserWithPasswordInDb(UserInDb):
    hashed_password: str



