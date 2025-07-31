from fastapi import APIRouter
from app.schemas.user import UserInDb, UserCreate
from app.services import user_service

user_router = APIRouter(prefix="/api/v1/users", tags=["users"])

@user_router.post("/", response_model=UserInDb)
async def register(user: UserCreate):
    return user_service.create_user(user)


