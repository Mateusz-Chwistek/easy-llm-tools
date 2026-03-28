import re
from http import HTTPStatus
from threading import Lock
from typing import Final, Optional, Dict, List
from sqlalchemy.exc import IntegrityError
from private_vault import db, key_vault, limiter
from private_vault.vault_models import User, Settings
from flask import Blueprint, jsonify, request, render_template, redirect, url_for
from flask_login import current_user, login_user, logout_user, login_required
from private_vault.audit import log as audit_log

_admin_creation_lock: Lock = Lock()

# Minimum number of characters required for a password.
PASSWORD_MIN_LENGTH: Final[int] = 8

# Maximum number of characters allowed for a password.
PASSWORD_MAX_LENGTH: Final[int] = 128

# Whether the password must contain at least one uppercase letter.
PASSWORD_REQUIRE_UPPERCASE: Final[bool] = True

# Whether the password must contain at least one lowercase letter.
PASSWORD_REQUIRE_LOWERCASE: Final[bool] = True

# Whether the password must contain at least one digit.
PASSWORD_REQUIRE_DIGIT: Final[bool] = True

# Whether the password must contain at least one special character.
PASSWORD_REQUIRE_SPECIAL: Final[bool] = True

# Regex character class body listing allowed special characters.
PASSWORD_SPECIAL_CHARS: Final[str] = r"!@#$%^&*()_+\-=\[\]{}|;':\",./<>?`~"


def validate_password(password: str) -> List[str]:
    """
    Check a password against the configured policy.

    :param password: Plaintext password to validate.
    :type password: str

    :return: List of human-readable violation messages (empty if valid).
    :rtype: list[str]
    """

    errors: List[str] = []

    if len(password) < PASSWORD_MIN_LENGTH or len(password) > PASSWORD_MAX_LENGTH:
        errors.append(
            f"Password must be {PASSWORD_MIN_LENGTH}-{PASSWORD_MAX_LENGTH} characters"
        )

    if PASSWORD_REQUIRE_UPPERCASE and not re.search(r"[A-Z]", password):
        errors.append("Password must contain at least one uppercase letter")

    if PASSWORD_REQUIRE_LOWERCASE and not re.search(r"[a-z]", password):
        errors.append("Password must contain at least one lowercase letter")

    if PASSWORD_REQUIRE_DIGIT and not re.search(r"[0-9]", password):
        errors.append("Password must contain at least one digit")

    if PASSWORD_REQUIRE_SPECIAL and not re.search(
        f"[{PASSWORD_SPECIAL_CHARS}]", password
    ):
        errors.append("Password must contain at least one special character")

    return errors


auth_bp: Blueprint = Blueprint("auth", __name__, url_prefix="/auth")

def _is_registration_locked() -> bool:
    """
    Check if registration is currently locked.

    Returns False when the settings row does not exist yet (fresh database
    with no users), so the first user can always register.

    :return: True if registration is locked.
    :rtype: bool
    """

    settings: Optional[Settings] = db.session.get(Settings, 1)
    if settings is None:
        return False
    return settings.registration_locked


@auth_bp.route("/register", methods=["POST"])
@limiter.limit("3 per minute")
def register():
    """
    Register a new user account.

    Validates the JSON body, enforces login length and password policy,
    then creates the user. Rejects the request if registration is locked.
    The first registered user becomes the admin and registration is
    locked automatically.

    Expected JSON body:
        - login (str): Desired username (2-255 characters).
        - password (str): Desired password (must pass validate_password).
    """

    if current_user.is_authenticated:
        return jsonify({"error": "Already logged in"}), HTTPStatus.FORBIDDEN

    if _is_registration_locked():
        return (
            jsonify({"error": "Registration is locked. Contact the administrator."}),
            HTTPStatus.FORBIDDEN,
        )

    request_data: Optional[Dict[str, str]] = request.get_json(silent=True) or {}
    if not isinstance(request_data, dict):
        return jsonify({"error": "Invalid request format"}), HTTPStatus.BAD_REQUEST

    login: Optional[str] = request_data.get("login")
    password: Optional[str] = request_data.get("password")

    if not isinstance(login, str) or not isinstance(password, str):
        return (
            jsonify({"error": "Login and password must be strings"}),
            HTTPStatus.BAD_REQUEST,
        )

    normalized_login: str = login.strip()

    if len(normalized_login) < 2 or len(normalized_login) > 255:
        return (
            jsonify({"error": f"Login must be {2}-{255} characters"}),
            HTTPStatus.BAD_REQUEST,
        )

    password_errors: List[str] = validate_password(password)
    if password_errors:
        return jsonify({"errors": password_errors}), HTTPStatus.BAD_REQUEST

    existing_user = db.session.execute(
        db.select(User).filter_by(login=normalized_login)
    ).scalar_one_or_none()

    if existing_user is not None:
        return jsonify({"error": "User already exists"}), HTTPStatus.CONFLICT

    new_user: User = User()
    new_user.register(normalized_login, password)

    is_first_user: bool = (
        db.session.execute(db.select(db.func.count(User.id))).scalar() == 0
    )

    if is_first_user:
        with _admin_creation_lock:
            is_still_first: bool = (
                db.session.execute(db.select(db.func.count(User.id))).scalar() == 0
            )
            if is_still_first:
                new_user.is_admin = True
                db.session.add(new_user)
                db.session.add(Settings(id=1, registration_locked=True))
                try:
                    db.session.commit()
                except IntegrityError:
                    db.session.rollback()
                    audit_log("register", ip=request.remote_addr, success=False, detail="conflict")
                    return (
                        jsonify({"error": "User already exists"}),
                        HTTPStatus.CONFLICT,
                    )
                audit_log("register", ip=request.remote_addr, user_id=new_user.id, detail="admin")
                return (
                    jsonify({"message": "Registration successful"}),
                    HTTPStatus.CREATED,
                )

    if _is_registration_locked():
        return (
            jsonify({"error": "Registration is locked. Contact the administrator."}),
            HTTPStatus.FORBIDDEN,
        )

    try:
        db.session.add(new_user)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        audit_log("register", ip=request.remote_addr, success=False, detail="conflict")
        return jsonify({"error": "User already exists"}), HTTPStatus.CONFLICT

    audit_log("register", ip=request.remote_addr, user_id=new_user.id)
    return jsonify({"message": "Registration successful"}), HTTPStatus.CREATED


@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    """
    Serve the login page (GET) or authenticate a user (POST).

    GET: renders the auth page. Redirects to vault if already logged in.
    POST: verifies credentials, derives the master key via KeyVault, and
    starts a Flask-Login session.

    Expected JSON body (POST):
        - login (str): Username.
        - password (str): Password.
    """

    if request.method == "GET":
        if current_user.is_authenticated:
            return redirect(url_for("vault.list_entries"))
        return render_template(
            "auth.html", registration_locked=_is_registration_locked()
        )

    if current_user.is_authenticated:
        return jsonify({"error": "Already logged in"}), HTTPStatus.FORBIDDEN

    request_data: Optional[Dict[str, str]] = request.get_json(silent=True) or {}
    if not isinstance(request_data, dict):
        return jsonify({"error": "Invalid request format"}), HTTPStatus.BAD_REQUEST

    login_value: Optional[str] = request_data.get("login")
    password: Optional[str] = request_data.get("password")

    if not isinstance(login_value, str) or not isinstance(password, str):
        return (
            jsonify({"error": "Login and password must be strings"}),
            HTTPStatus.BAD_REQUEST,
        )

    normalized_login: str = login_value.strip()

    user: Optional[User] = db.session.execute(
        db.select(User).filter_by(login=normalized_login)
    ).scalar_one_or_none()

    if user is None or not user.check_password(password):
        audit_log("login", ip=request.remote_addr, success=False)
        return jsonify({"error": "Invalid login or password"}), HTTPStatus.UNAUTHORIZED

    key_vault.set_master_key(
        user_id=user.id,
        raw_password=password,
        user_key_salt=user.salt,
        level_salt=user.level_salt,
    )

    login_user(user, remember=False)
    audit_log("login", ip=request.remote_addr, user_id=user.id)
    return jsonify({"message": "Login successful"}), HTTPStatus.OK


@auth_bp.route("/logout", methods=["POST"])
@login_required
@limiter.limit("3 per minute")
def logout():
    """
    Log out the current user.

    Removes the master key from the in-memory store and ends the
    Flask-Login session. The LLM session key (if any) is left intact.
    """

    user_id: int = current_user.id
    key_vault.delete_key(user_id, master=True)
    logout_user()
    audit_log("logout", ip=request.remote_addr, user_id=user_id)
    return jsonify({"message": "Logged out"}), HTTPStatus.OK


@auth_bp.route("/registration-lock", methods=["POST"])
@login_required
@limiter.limit("3 per minute")
def toggle_registration():
    """
    Toggle the registration lock state. Admin-only.

    Flips the ``registration_locked`` flag in the settings table and
    returns the new state.
    """

    if not current_user.is_admin:
        return jsonify({"error": "Admin access required"}), HTTPStatus.FORBIDDEN

    settings: Optional[Settings] = db.session.get(Settings, 1)
    if settings is None:
        return (
            jsonify({"error": "Settings not initialized"}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )

    settings.registration_locked = not settings.registration_locked
    db.session.commit()

    audit_log(
        "registration_lock",
        ip=request.remote_addr,
        user_id=current_user.id,
        detail=f"locked={settings.registration_locked}",
    )
    return (
        jsonify({"registration_locked": settings.registration_locked}),
        HTTPStatus.OK,
    )
