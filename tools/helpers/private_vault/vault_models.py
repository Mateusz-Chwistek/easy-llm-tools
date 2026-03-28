import os
from typing import Final
from private_vault import db
from flask_login import UserMixin
from sqlalchemy.orm import Mapped, mapped_column, relationship
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import Boolean, String, Text, LargeBinary, ForeignKey, CheckConstraint

# -----------------------------------------------------------------------------
# User configuration
# -----------------------------------------------------------------------------

# Werkzeug password hashing method (scrypt with matching KDF parameters).
_HASH_METHOD: Final[str] = "scrypt:65536:8:2"

# Salt length in bytes for werkzeug password hashing.
_HASH_SALT_LENGTH: Final[int] = 16

# Salt length in bytes for encryption key derivation (stored per-user).
ENCRYPTION_SALT_LENGTH: Final[int] = 32

# -----------------------------------------------------------------------------
# Models
# -----------------------------------------------------------------------------


class User(UserMixin, db.Model):
    """
    Registered vault user.
    """

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    login: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    salt: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    level_salt: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    is_admin: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    entries: Mapped[list["Entry"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )

    __table_args__ = (
        CheckConstraint("length(login) >= 2", name="login_min_length"),
        CheckConstraint("length(login) <= 255", name="login_max_length"),
    )

    def register(self, login: str, password: str) -> None:
        """
        Create a new user with a hashed password and random encryption salt.

        Does not commit to the database - the caller is responsible for
        adding the user to the session and committing.

        :param login: Username (2-255 characters).
        :type login: str

        :param password: Plaintext password.
        :type password: str

        :return: New User instance ready to be added to the database.
        :rtype: User
        """

        self.login = login
        self.password_hash = generate_password_hash(
            password, method=_HASH_METHOD, salt_length=_HASH_SALT_LENGTH
        )
        self.salt = os.urandom(ENCRYPTION_SALT_LENGTH)
        self.level_salt = os.urandom(ENCRYPTION_SALT_LENGTH)

    def check_password(self, password: str) -> bool:
        """
        Verify the password against the stored hash.

        :param password: Plaintext password to verify.
        :type password: str

        :return: True if the password matches, False otherwise.
        :rtype: bool
        """

        return check_password_hash(self.password_hash, password)

    def get_id(self) -> str:
        return str(self.id)


class Entry(db.Model):
    """
    Encrypted vault entry belonging to a user.
    """

    __tablename__ = "entries"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    secrecy_level: Mapped[int] = mapped_column(nullable=False, default=0)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    meta: Mapped[str | None] = mapped_column(Text, nullable=True)
    entry: Mapped[str] = mapped_column(Text, nullable=False)

    user: Mapped["User"] = relationship(back_populates="entries")

    __table_args__ = (
        CheckConstraint(
            "secrecy_level >= 0 AND secrecy_level <= 3", name="valid_secrecy_level"
        ),
    )


class Settings(db.Model):
    """
    Single-row application settings table.
    """

    __tablename__ = "settings"

    id: Mapped[int] = mapped_column(primary_key=True, default=1)
    registration_locked: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True
    )

    __table_args__ = (
        CheckConstraint("id = 1", name="single_row"),
    )
