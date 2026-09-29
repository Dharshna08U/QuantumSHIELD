import getpass

from sqlalchemy import select

from backend.app.core.database import Base, SessionLocal, engine
from backend.app.core.security import hash_password
from backend.app.models import User
from backend.app.models.user import UserRole


def provision_admin() -> None:
    """Provision the initial administrator interactively, never via public registration."""
    Base.metadata.create_all(engine)
    username = input("Administrator username: ").strip()
    email = input("Administrator email: ").strip().lower()
    password = getpass.getpass("Administrator password (12+ characters): ")
    confirmation = getpass.getpass("Confirm password: ")
    if len(password) < 12 or password != confirmation:
        raise SystemExit("Password must be at least 12 characters and match confirmation")
    with SessionLocal.begin() as db:
        if db.scalar(select(User).where((User.username == username) | (User.email == email))):
            raise SystemExit("Username or email is already in use")
        db.add(
            User(
                username=username,
                email=email,
                password_hash=hash_password(password),
                role=UserRole.ADMINISTRATOR,
            )
        )


if __name__ == "__main__":
    provision_admin()
