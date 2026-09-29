from collections.abc import Callable
from enum import StrEnum
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import InvalidTokenError
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.core.security import decode_access_token
from backend.app.models.user import User, UserRole

bearer_scheme = HTTPBearer(auto_error=False)
DbSession = Annotated[Session, Depends(get_db)]


class Permission(StrEnum):
    USER_ADMIN = "user:admin"
    INCIDENT_READ = "incident:read"
    INCIDENT_CREATE = "incident:create"
    INCIDENT_TRIAGE = "incident:triage"
    INCIDENT_STATUS_UPDATE = "incident:status:update"
    REMEDIATION_APPROVE = "remediation:approve"
    REMEDIATION_REQUEST = "remediation:request"
    REMEDIATION_EXECUTE = "remediation:execute"
    REMEDIATION_VERIFY = "remediation:verify"
    AUDIT_READ = "audit:read"
    REPORT_READ = "report:read"


ROLE_PERMISSIONS: dict[UserRole, frozenset[Permission]] = {
    UserRole.ADMINISTRATOR: frozenset(Permission),
    UserRole.SECURITY_ANALYST: frozenset(
        {
            Permission.INCIDENT_READ,
            Permission.INCIDENT_CREATE,
            Permission.INCIDENT_TRIAGE,
            Permission.INCIDENT_STATUS_UPDATE,
            Permission.REMEDIATION_REQUEST,
            Permission.AUDIT_READ,
            Permission.REPORT_READ,
        }
    ),
    UserRole.OPERATOR: frozenset(
        {
            Permission.INCIDENT_READ,
            Permission.INCIDENT_CREATE,
            Permission.INCIDENT_STATUS_UPDATE,
            Permission.REMEDIATION_APPROVE,
            Permission.REMEDIATION_REQUEST,
            Permission.REMEDIATION_EXECUTE,
            Permission.REMEDIATION_VERIFY,
            Permission.AUDIT_READ,
            Permission.REPORT_READ,
        }
    ),
}


def current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
    db: DbSession,
) -> User:
    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired access token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise unauthorized
    try:
        subject = decode_access_token(credentials.credentials).get("sub")
        if not isinstance(subject, str):
            raise unauthorized
    except (InvalidTokenError, RuntimeError) as exc:
        raise unauthorized from exc
    user = db.scalar(select(User).where(User.id == subject))
    if user is None or not user.is_active:
        raise unauthorized
    return user


def require_roles(*roles: UserRole) -> Callable[..., User]:
    def check(user: Annotated[User, Depends(current_user)]) -> User:
        if user.role not in roles:
            raise HTTPException(status_code=403, detail="Insufficient role")
        return user

    return check


def require_permission(permission: Permission) -> Callable[..., User]:
    def check(user: Annotated[User, Depends(current_user)]) -> User:
        if permission not in ROLE_PERMISSIONS[user.role]:
            raise HTTPException(status_code=403, detail="Insufficient permission")
        return user

    return check
