from datetime import datetime
from typing import List, Optional
from app.database import mongo_db
from app.schemas.user import UserCreate, UserInDb, UserWithPasswordInDb
from app.utils.security import get_password_hash

users_collection = mongo_db["users"]
roles_collection = mongo_db["roles"]
revoked_tokens_collection = mongo_db["revoked_tokens"]

def revoke_token(token: str):
    revoked_tokens_collection.insert_one({
        "token": token,
        "revoked_at": datetime.now()
    })

def is_token_revoked(token: str) -> bool:
    return revoked_tokens_collection.find_one({"token": token}) is not None

def delete_refresh_token(username: str):
    users_collection.update_one(
        {"username": username},
        {"$unset": {"refresh_token": ""}}
    )

def create_user(user: UserCreate) -> dict:
    user_dict = user.model_dump()

    # Encrypt password
    user_dict["password"] = get_password_hash(user_dict["password"])

    result = users_collection.insert_one(user_dict)
    new_user =  users_collection.find_one({"_id": result.inserted_id})
    return serialize_user(new_user)

def get_user_by_username(username: str) -> Optional[dict]:
    user = users_collection.find_one({"username": username})

    role = roles_collection.find_one({"name": user["role"]})
    permissions = role.get("permissions", []) if role else []

    if user:
        return UserWithPasswordInDb(
            id=str(user["_id"]),
            username=user["username"],
            email=user["email"],
            role=user["role"],
            hashed_password=user["password"],
            permissions=permissions,
        )
    return None

def save_refresh_token(username: str, refresh_token: str):
    users_collection.update_one(
        {"username": username},
        {"$set": {"refresh_token": refresh_token}}
    )

def get_refresh_token(username: str) -> Optional[str]:
    user = users_collection.find_one({"username": username})
    return user.get("refresh_token") if user else None


def serialize_user(user) -> dict:
    return {
        "id": str(user["_id"]),
        "username": user["username"],
        "email": user["email"],
        "role": user["role"],
    }