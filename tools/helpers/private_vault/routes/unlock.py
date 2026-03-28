from http import HTTPStatus
from typing import Optional, Dict
from private_vault import db, key_vault, limiter
from private_vault.vault_models import User
from private_vault.key_vault import SecrecyLevel
from flask import Blueprint, jsonify, request, render_template
from flask_login import current_user, login_required
from private_vault.helpers import user_rate_key
from private_vault.audit import log as audit_log

unlock_bp: Blueprint = Blueprint("unlock", __name__, url_prefix="/unlock")


@unlock_bp.route("", methods=["GET", "POST"])
@login_required
@limiter.limit("10 per minute")
@limiter.limit("3 per minute", methods=["POST"], key_func=user_rate_key)
def unlock():
    """
    Serve the unlock page (GET) or generate a session key (POST).

    GET: renders the unlock page.
    POST: user re-enters password and selects secrecy scope,
    returns a random request token for LLM access.

    Expected JSON body (POST):
        - password (str): User's password (verified before key derivation).
        - secrecy_level (int): Maximum secrecy level for this session (0-3).
    """

    if request.method == "GET":
        return render_template("unlock.html")

    request_data: Optional[Dict[str, str]] = request.get_json(silent=True) or {}
    if not isinstance(request_data, dict):
        return jsonify({"error": "Invalid request format"}), HTTPStatus.BAD_REQUEST

    password: Optional[str] = request_data.get("password")
    raw_secrecy_level = request_data.get("secrecy_level")

    if not isinstance(password, str):
        return jsonify({"error": "Password must be a string"}), HTTPStatus.BAD_REQUEST

    if not isinstance(raw_secrecy_level, int):
        return (
            jsonify({"error": "Secrecy level must be an integer"}),
            HTTPStatus.BAD_REQUEST,
        )

    try:
        secrecy_level: SecrecyLevel = SecrecyLevel(raw_secrecy_level)
    except ValueError:
        valid_levels: str = ", ".join(
            f"{level.value} ({level.name.lower()})" for level in SecrecyLevel
        )
        return (
            jsonify({"error": f"Invalid secrecy level. Valid: {valid_levels}"}),
            HTTPStatus.BAD_REQUEST,
        )

    user: Optional[User] = db.session.get(User, current_user.id)
    if user is None:
        return jsonify({"error": "User not found"}), HTTPStatus.NOT_FOUND

    if not user.check_password(password):
        audit_log("unlock", ip=request.remote_addr, user_id=user.id, success=False)
        return jsonify({"error": "Invalid password"}), HTTPStatus.UNAUTHORIZED

    request_key: str = key_vault.set_session_key(
        user_id=user.id,
        raw_password=password,
        secrecy_level=secrecy_level,
        user_key_salt=user.salt,
        level_salt=user.level_salt,
    )

    audit_log(
        "unlock",
        ip=request.remote_addr,
        user_id=user.id,
        detail=f"secrecy_level={secrecy_level.value}",
    )
    return (
        jsonify(
            {
                "message": "Session key created",
                "request_key": request_key,
                "secrecy_level": secrecy_level.value,
                "secrecy_label": secrecy_level.name.lower(),
            }
        ),
        HTTPStatus.CREATED,
    )
