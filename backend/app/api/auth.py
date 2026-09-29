from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.app.api.dependencies import DbSession, current_user
from backend.app.models.user import User
from backend.app.schemas.auth import LoginRequest, RegisterRequest, TokenResponse
from backend.app.services.auth_service import DuplicateUserError, authenticate, register_user

router = APIRouter(prefix="/api/v1/auth", tags=["authentication"])


@router.post("/register", status_code=status.HTTP_201_CREATED)
def register(payload: RegisterRequest, db: DbSession) -> dict[str, str]:
    try:
        user = register_user(db, payload.username, str(payload.email).lower(), payload.password)
        db.commit()
    except DuplicateUserError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"id": user.id, "username": user.username, "role": user.role.value}


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, db: DbSession) -> TokenResponse:
    result = authenticate(db, payload.username, payload.password)
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user, token = result
    return TokenResponse(access_token=token, role=user.role.value)


@router.get("/me")
def me(user: Annotated[User, Depends(current_user)]) -> dict[str, str]:
    return {"id": user.id, "username": user.username, "role": user.role.value}
