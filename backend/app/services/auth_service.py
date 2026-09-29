from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.core.security import create_access_token, hash_password, verify_password
from backend.app.models.user import User, UserRole


class DuplicateUserError(ValueError):
    pass


def register_user(db: Session, username: str, email: str, password: str) -> User:
    existing = db.scalar(select(User).where((User.username == username) | (User.email == email)))
    if existing:
        raise DuplicateUserError("Username or email is already registered")
    user = User(
        username=username,
        email=email,
        password_hash=hash_password(password),
        role=UserRole.SECURITY_ANALYST,
    )
    db.add(user)
    db.flush()
    return user


def authenticate(db: Session, username: str, password: str) -> tuple[User, str] | None:
    user = db.scalar(select(User).where(User.username == username))
    if user is None or not user.is_active or not verify_password(password, user.password_hash):
        return None
    return user, create_access_token(user.id, user.role.value)
