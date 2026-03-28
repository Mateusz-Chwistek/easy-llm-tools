from datetime import datetime
from http import HTTPStatus
from typing import Final, Optional, Dict, Any, List
from private_vault import db, key_vault, limiter
from private_vault.vault_models import Entry
from private_vault.key_vault import KeyInstance, SecrecyLevel
from private_vault.helpers import build_meta, update_meta, parse_meta, validate_tags
from flask import Blueprint, jsonify, request, render_template, redirect, url_for
from flask_login import current_user, login_required
from private_vault.helpers import user_rate_key
from private_vault.audit import log as audit_log

# Whether to encrypt entry titles before storing them.
# Encrypted titles require the master key to list or view.
ENCRYPT_TITLES: Final[bool] = True

# Whether to encrypt entry metadata before storing it.
# Encrypted metadata requires the master key to list or view.
ENCRYPT_META: Final[bool] = True

vault_bp: Blueprint = Blueprint("vault", __name__, url_prefix="/vault")


def _get_master_key() -> Optional[KeyInstance]:
    """
    Retrieve the current user's master key from the in-memory store.

    :return: The master KeyInstance, or None if missing/expired.
    :rtype: Optional[KeyInstance]
    """

    return key_vault.get_key(user_id=current_user.id)


@vault_bp.route("", methods=["GET"])
@login_required
def list_entries():
    """
    List all vault entries for the current user.

    Returns entry metadata (id, title, meta, secrecy level).
    Decrypts title and meta if ENCRYPT_TITLES / ENCRYPT_META are enabled.
    """

    master_key: Optional[KeyInstance] = _get_master_key()
    if master_key is None and (ENCRYPT_TITLES or ENCRYPT_META):
        return redirect(url_for("auth.login"))

    entries: List[Entry] = (
        db.session.execute(
            db.select(Entry)
            .filter_by(user_id=current_user.id)
            .order_by(Entry.id.desc())
        )
        .scalars()
        .all()
    )

    result: List[Dict[str, Any]] = []
    for entry in entries:
        entry_level: SecrecyLevel = SecrecyLevel(entry.secrecy_level)
        title: str = master_key.decrypt(entry.title, entry_level) if ENCRYPT_TITLES else entry.title

        tags: List[str] = []
        created_at: str = ""
        modified_at: str = ""

        if entry.meta is not None:
            raw_meta: str = (
                master_key.decrypt(entry.meta, entry_level) if ENCRYPT_META else entry.meta
            )
            parsed_meta: Dict[str, Any] = parse_meta(raw_meta)
            tags = parsed_meta["tags"]
            created_at = parsed_meta["created_at"]
            modified_at = parsed_meta["modified_at"]

        secrecy_label: str = (
            SecrecyLevel(entry.secrecy_level).name.replace("_", " ").title()
        )

        result.append(
            {
                "id": entry.id,
                "title": title,
                "tags": tags,
                "created_at": created_at,
                "modified_at": modified_at,
                "secrecy_level": entry.secrecy_level,
                "secrecy_label": secrecy_label,
            }
        )

    return render_template("vault.html", entries=result)


@vault_bp.route("/add", methods=["POST"])
@login_required
@limiter.limit("5 per minute", methods=["POST"], key_func=user_rate_key)
def add_entry():
    """
    Create a new encrypted vault entry.

    Encrypts the content with the user's master key and stores it.

    Expected JSON body:
        - title (str): Plaintext title for the entry.
        - content (str): Secret content to encrypt.
        - secrecy_level (int): Secrecy level (0-3).
        - tags (list[str], optional): User-assigned tags for LLM search.
    """

    request_data: Optional[Dict[str, Any]] = request.get_json(silent=True) or {}
    if not isinstance(request_data, dict):
        return jsonify({"error": "Invalid request format"}), HTTPStatus.BAD_REQUEST

    title: Optional[str] = request_data.get("title")
    content: Optional[str] = request_data.get("content")
    raw_secrecy_level = request_data.get("secrecy_level")
    raw_tags = request_data.get("tags", [])

    if not isinstance(title, str):
        return (
            jsonify({"error": "Title must be a non-empty string"}),
            HTTPStatus.BAD_REQUEST,
        )

    title = title.strip()
    if len(title) < 1:
        return (
            jsonify({"error": "Title must be a non-empty string"}),
            HTTPStatus.BAD_REQUEST,
        )

    if not isinstance(content, str):
        return (
            jsonify({"error": "Content must be a non-empty string"}),
            HTTPStatus.BAD_REQUEST,
        )

    content = content.strip()
    if len(content) < 1:
        return (
            jsonify({"error": "Content must be a non-empty string"}),
            HTTPStatus.BAD_REQUEST,
        )

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

    if not isinstance(raw_tags, list):
        return (
            jsonify({"error": "Tags must be a list of strings"}),
            HTTPStatus.BAD_REQUEST,
        )

    tag_error: Optional[str] = validate_tags(raw_tags)
    if tag_error is not None:
        return jsonify({"error": tag_error}), HTTPStatus.BAD_REQUEST

    tags: List[str] = [tag.strip() for tag in raw_tags]

    master_key: Optional[KeyInstance] = _get_master_key()
    if master_key is None:
        return (
            jsonify({"error": "Master key unavailable, please log in again"}),
            HTTPStatus.UNAUTHORIZED,
        )

    now: datetime = datetime.now()
    meta: str = build_meta(tags, now)

    stored_title: str = master_key.encrypt(title, secrecy_level) if ENCRYPT_TITLES else title
    stored_meta: str = master_key.encrypt(meta, secrecy_level) if ENCRYPT_META else meta
    stored_content: str = master_key.encrypt(content, secrecy_level)

    entry: Entry = Entry(
        user_id=current_user.id,
        title=stored_title,
        meta=stored_meta,
        entry=stored_content,
        secrecy_level=secrecy_level.value,
    )

    db.session.add(entry)
    db.session.commit()

    audit_log(
        "vault.add",
        ip=request.remote_addr,
        user_id=current_user.id,
        detail=f"entry_id={entry.id} secrecy_level={secrecy_level.value}",
    )
    return jsonify({"message": "Entry created", "id": entry.id}), HTTPStatus.CREATED


@vault_bp.route("/<int:entry_id>", methods=["GET"])
@login_required
def view_entry(entry_id: int):
    """
    View a single vault entry with decrypted content.

    :param entry_id: Database ID of the entry.
    :type entry_id: int
    """

    master_key: Optional[KeyInstance] = _get_master_key()
    if master_key is None:
        return redirect(url_for("auth.login"))

    entry: Optional[Entry] = db.session.execute(
        db.select(Entry).filter_by(id=entry_id, user_id=current_user.id)
    ).scalar_one_or_none()

    if entry is None:
        return redirect(url_for("vault.list_entries"))

    entry_level: SecrecyLevel = SecrecyLevel(entry.secrecy_level)
    title: str = master_key.decrypt(entry.title, entry_level) if ENCRYPT_TITLES else entry.title
    content: str = master_key.decrypt(entry.entry, entry_level)

    tags: List[str] = []
    created_at: str = ""
    modified_at: str = ""

    if entry.meta is not None:
        raw_meta: str = master_key.decrypt(entry.meta, entry_level) if ENCRYPT_META else entry.meta
        parsed_meta: Dict[str, Any] = parse_meta(raw_meta)
        tags = parsed_meta["tags"]
        created_at = parsed_meta["created_at"]
        modified_at = parsed_meta["modified_at"]

    secrecy_label: str = (
        SecrecyLevel(entry.secrecy_level).name.replace("_", " ").title()
    )

    entry_data: Dict[str, Any] = {
        "id": entry.id,
        "title": title,
        "tags": tags,
        "created_at": created_at,
        "modified_at": modified_at,
        "content": content,
        "secrecy_level": entry.secrecy_level,
        "secrecy_label": secrecy_label,
    }

    return render_template("entry.html", entry=entry_data)


@vault_bp.route("/<int:entry_id>/edit", methods=["POST"])
@login_required
@limiter.limit("5 per minute", methods=["POST"], key_func=user_rate_key)
def edit_entry(entry_id: int):
    """
    Edit an existing vault entry.

    All fields are optional. Only provided fields are updated.
    If content is provided, it is re-encrypted with the master key.

    :param entry_id: Database ID of the entry.
    :type entry_id: int

    Expected JSON body (all optional):
        - title (str): New plaintext title.
        - content (str): New secret content (will be encrypted).
        - secrecy_level (int): New secrecy level (0-3).
        - tags (list[str]): New tags to replace existing ones.
    """

    request_data: Optional[Dict[str, Any]] = request.get_json(silent=True) or {}
    if not isinstance(request_data, dict):
        return jsonify({"error": "Invalid request format"}), HTTPStatus.BAD_REQUEST

    new_title: Optional[str] = None
    new_content: Optional[str] = None
    new_secrecy_level: Optional[SecrecyLevel] = None
    new_tags: Optional[List[str]] = None

    if "title" in request_data:
        title = request_data["title"]
        if not isinstance(title, str):
            return (
                jsonify({"error": "Title must be a non-empty string"}),
                HTTPStatus.BAD_REQUEST,
            )

        title = title.strip()
        if len(title) < 1:
            return (
                jsonify({"error": "Title must be a non-empty string"}),
                HTTPStatus.BAD_REQUEST,
            )
        new_title = title

    if "content" in request_data:
        content = request_data["content"]
        if not isinstance(content, str):
            return (
                jsonify({"error": "Content must be a non-empty string"}),
                HTTPStatus.BAD_REQUEST,
            )

        content = content.strip()
        if len(content) < 1:
            return (
                jsonify({"error": "Content must be a non-empty string"}),
                HTTPStatus.BAD_REQUEST,
            )
        new_content = content

    if "secrecy_level" in request_data:
        raw_secrecy_level = request_data["secrecy_level"]
        if not isinstance(raw_secrecy_level, int):
            return (
                jsonify({"error": "Secrecy level must be an integer"}),
                HTTPStatus.BAD_REQUEST,
            )
        try:
            new_secrecy_level = SecrecyLevel(raw_secrecy_level)
        except ValueError:
            valid_levels: str = ", ".join(
                f"{level.value} ({level.name.lower()})" for level in SecrecyLevel
            )
            return (
                jsonify({"error": f"Invalid secrecy level. Valid: {valid_levels}"}),
                HTTPStatus.BAD_REQUEST,
            )

    if "tags" in request_data:
        raw_tags = request_data["tags"]
        if not isinstance(raw_tags, list):
            return (
                jsonify({"error": "Tags must be a list of strings"}),
                HTTPStatus.BAD_REQUEST,
            )

        tag_error: Optional[str] = validate_tags(raw_tags)
        if tag_error is not None:
            return jsonify({"error": tag_error}), HTTPStatus.BAD_REQUEST

        new_tags = [tag.strip() for tag in raw_tags]

    master_key: Optional[KeyInstance] = _get_master_key()
    if master_key is None:
        return (
            jsonify({"error": "Master key unavailable, please log in again"}),
            HTTPStatus.UNAUTHORIZED,
        )

    entry: Optional[Entry] = db.session.execute(
        db.select(Entry).filter_by(id=entry_id, user_id=current_user.id)
    ).scalar_one_or_none()

    if entry is None:
        return jsonify({"error": "Entry not found"}), HTTPStatus.NOT_FOUND

    old_level: SecrecyLevel = SecrecyLevel(entry.secrecy_level)
    target_level: SecrecyLevel = new_secrecy_level if new_secrecy_level is not None else old_level
    level_changed: bool = target_level != old_level

    # If the secrecy level changed, re-encrypt existing fields with the new level key.
    if level_changed:
        if ENCRYPT_TITLES and new_title is None:
            plain_title: str = master_key.decrypt(entry.title, old_level)
            entry.title = master_key.encrypt(plain_title, target_level)
        if new_content is None:
            plain_content: str = master_key.decrypt(entry.entry, old_level)
            entry.entry = master_key.encrypt(plain_content, target_level)
        entry.secrecy_level = target_level.value

    if new_title is not None:
        entry.title = master_key.encrypt(new_title, target_level) if ENCRYPT_TITLES else new_title

    if new_content is not None:
        entry.entry = master_key.encrypt(new_content, target_level)

    now: datetime = datetime.now()
    if entry.meta is not None:
        raw_meta: str = master_key.decrypt(entry.meta, old_level) if ENCRYPT_META else entry.meta
        updated_meta: str = update_meta(raw_meta, new_tags, now)
        entry.meta = master_key.encrypt(updated_meta, target_level) if ENCRYPT_META else updated_meta

    db.session.commit()

    edit_detail: str = f"entry_id={entry_id}"
    if level_changed:
        edit_detail += f" level_change={old_level.value}->{target_level.value}"
    audit_log(
        "vault.edit",
        ip=request.remote_addr,
        user_id=current_user.id,
        detail=edit_detail,
    )
    return jsonify({"message": "Entry updated"}), HTTPStatus.OK


@vault_bp.route("/<int:entry_id>/delete", methods=["POST"])
@login_required
@limiter.limit("5 per minute", methods=["POST"], key_func=user_rate_key)
def delete_entry(entry_id: int):
    """
    Delete a vault entry.

    :param entry_id: Database ID of the entry.
    :type entry_id: int
    """

    entry: Optional[Entry] = db.session.execute(
        db.select(Entry).filter_by(id=entry_id, user_id=current_user.id)
    ).scalar_one_or_none()

    if entry is None:
        return jsonify({"error": "Entry not found"}), HTTPStatus.NOT_FOUND

    db.session.delete(entry)
    db.session.commit()

    audit_log(
        "vault.delete",
        ip=request.remote_addr,
        user_id=current_user.id,
        detail=f"entry_id={entry_id}",
    )
    return jsonify({"message": "Entry deleted"}), HTTPStatus.OK
