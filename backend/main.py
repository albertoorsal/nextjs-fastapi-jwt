from fastapi import FastAPI
from app.routes.auth_routes import auth_router
from app.routes.users_routes import user_router

app = FastAPI()

app.include_router(user_router)
app.include_router(auth_router)

