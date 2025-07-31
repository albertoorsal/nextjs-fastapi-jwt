from fastapi import HTTPException, status
from fastapi.params import Depends
from app.services.auth_service import get_current_user
from app.services.role_service import get_permissions_by_role

def require_permission(permission: str):
    async def permission_checker(current_user=Depends(get_current_user)):
        permissions = get_permissions_by_role(current_user.role)
        if permission not in permissions:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission '{permission}' denied for role '{current_user.role}'"
            )
        return current_user
    return permission_checker