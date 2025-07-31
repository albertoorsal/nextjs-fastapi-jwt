from typing import List
from app.database import mongo_db

roles_collection = mongo_db["roles"]

def get_permissions_by_role(role_name: str) -> List[str]:
    role_doc = roles_collection.find_one({"name": role_name})
    if not role_doc:
        return []
    return role_doc.get("permissions", [])