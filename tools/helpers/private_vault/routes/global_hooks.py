from http import HTTPStatus
from typing import Optional
from private_vault import db, login_manager, key_vault
from private_vault.vault_models import User, Settings
from flask import Blueprint, Response, session, redirect, url_for, jsonify, request
from flask_login import current_user, logout_user

global_bp: Blueprint = Blueprint("global_hooks", __name__)

login_manager.login_view = "auth.login"


@global_bp.route("/")
def index():
    """
    Redirect root to vault if logged in, otherwise to login.
    """

    if current_user.is_authenticated:
        return redirect(url_for("vault.list_entries"))
    return redirect(url_for("auth.login"))


@global_bp.after_app_request
def set_security_headers(response: Response) -> Response:
    """
    Add standard browser security headers to every response.
    """

    response.headers["Strict-Transport-Security"] = "max-age=31536000"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self'; "
        "frame-ancestors 'none'"
    )
    return response


@global_bp.before_app_request
def invalidate_session_without_runtime_key() -> None:
    """
    Force logout when the authenticated Flask session no longer has
    a matching in-memory master key (expired or lost on restart).
    """

    if not current_user.is_authenticated:
        return

    user_id: Optional[int] = getattr(current_user, "id", None)

    if not isinstance(user_id, int):
        logout_user()
        session.clear()
        return

    if key_vault.has_key(user_id=user_id):
        return

    logout_user()
    session.clear()


@login_manager.unauthorized_handler
def unauthorized():
    """
    Return 401 JSON for API requests, redirect to login for page requests.
    """

    if request.is_json:
        return (
            jsonify({"error": "Authentication required"}),
            HTTPStatus.UNAUTHORIZED,
        )
    return redirect(url_for("auth.login"))


@login_manager.user_loader
def load_user(user_id: str) -> Optional[User]:
    """
    Restore the authenticated user from the session.

    Called by Flask-Login on every request. Returns None if the
    user ID is missing, malformed, or does not exist in the database.

    :param user_id: User identifier stored in the session by Flask-Login.
    :type user_id: str

    :return: Matching User object, or None.
    :rtype: User | None
    """

    if not isinstance(user_id, str) or not user_id.isdigit():
        return None
    return db.session.get(User, int(user_id))


@global_bp.app_context_processor
def inject_admin_context() -> dict:
    """
    Inject ``registration_locked`` into every template context so the
    navbar can show the admin toggle button with the current state.
    """

    if not current_user.is_authenticated or not current_user.is_admin:
        return {}

    settings: Optional[Settings] = db.session.get(Settings, 1)
    registration_locked: bool = settings.registration_locked if settings else False
    return {"registration_locked": registration_locked}
