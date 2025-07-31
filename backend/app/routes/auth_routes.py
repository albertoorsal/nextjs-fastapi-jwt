from datetime import timedelta
from fastapi import Request
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from app.middleware.rbac_permissions import require_permission
from app.schemas.token import Token
from app.schemas.user import UserInDb
from app.services.auth_service import create_access_token, get_current_user, create_refresh_token, SECRET_KEY, ALGORITHM
from app.services.user_service import get_user_by_username, save_refresh_token, delete_refresh_token, get_refresh_token, \
    revoke_token
from app.utils.security import verify_password
from jwt import decode, exceptions as jwt_exceptions

auth_router = APIRouter(prefix="/api/v1/auth", tags=["auth"])

@auth_router.post("/login/", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = get_user_by_username(form_data.username)

    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )

    access_token = create_access_token({"sub": user.username}, timedelta(minutes=15))
    refresh_token = create_refresh_token({"sub": user.username})

    from app.services.user_service import save_refresh_token
    save_refresh_token(user.username, refresh_token)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }


@auth_router.post("/logout")
async def logout(
    request: Request,
    current_user: UserInDb = Depends(get_current_user)
):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if token:
        revoke_token(token)

    delete_refresh_token(current_user.username)

    return {"detail": "Successfully logged out"}

@auth_router.post("/refresh", response_model=Token)
async def refresh_token(request: Request):
    body = await request.json()
    token = body.get("refresh_token")

    if not token:
        raise HTTPException(status_code=400, detail="Refresh token required")

    try:
        payload = decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid refresh token")

        # Verify token matches one stored
        stored_token = get_refresh_token(username)
        if stored_token != token:
            raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

    except jwt_exceptions.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Refresh token expired")
    except jwt_exceptions.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

    new_access_token = create_access_token({"sub": username}, timedelta(minutes=15))
    new_refresh_token = create_refresh_token({"sub": username})

    # Save new refresh token
    save_refresh_token(username, new_refresh_token)

    return {
        "access_token": new_access_token,
        "refresh_token": new_refresh_token,
        "token_type": "bearer",
    }


@auth_router.post("/me", response_model=UserInDb)
async def me(current_user: UserInDb = Depends(get_current_user)):
    return current_user

@auth_router.get("/profile", response_model=UserInDb)
async def get_profile(current_user: UserInDb = Depends(get_current_user)):
    return {"message": f"Hello {current_user.username}"}

@auth_router.get("/reports")
async def reports(current_user: UserInDb = Depends(require_permission("view_reports"))):
    return {"message": f"Welcome, admin {current_user.username}!"}

