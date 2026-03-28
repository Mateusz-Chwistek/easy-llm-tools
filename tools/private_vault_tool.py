import json
from typing import Final, Optional, List, Dict, Any
from helpers.vault_service import start_vault_service, VAULT_PORT
from private_vault import app as vault_app
from private_vault import db as vault_db
from private_vault import key_vault
from private_vault.vault_models import Entry
from private_vault.key_vault import KeyInstance, SecrecyLevel
from private_vault.helpers import parse_meta
from private_vault.routes.vault import ENCRYPT_TITLES, ENCRYPT_META
from private_vault.audit import log as audit_log

# -----------------------------------------------------------------------------
# User configuration
# -----------------------------------------------------------------------------

# URL shown to the LLM when no request_key is provided, so the user
# knows where to generate one.
UNLOCK_URL: Final[str] = f"https://localhost:{VAULT_PORT}/unlock"

# -----------------------------------------------------------------------------
# Internal helpers
# -----------------------------------------------------------------------------


def _build_response(
    *,
    action: str = "",
    success: bool = False,
    error: str = "",
    data: Optional[Any] = None,
) -> str:
    """
    Build the public JSON response returned by the tool.

    :param action: Action that was performed.
    :type action: str

    :param success: True when the action completed successfully.
    :type success: bool

    :param error: Diagnostic text returned to the caller.
    :type error: str

    :param data: Action-specific payload.
    :type data: Optional[Any]

    :return: JSON string with the tool response.
    :rtype: str
    """

    payload: Dict[str, Any] = {
        "action": action,
        "success": success,
        "error": error,
        "data": data,
    }

    return json.dumps(payload, ensure_ascii=False)


def _get_session_key(request_key: str) -> Optional[KeyInstance]:
    """
    Look up a session key by its request token.

    :param request_key: Token returned by /unlock.
    :type request_key: str

    :return: Matching KeyInstance, or None if not found or expired.
    :rtype: Optional[KeyInstance]
    """

    return key_vault.get_key(request_key=request_key)


# -----------------------------------------------------------------------------
# Actions
# -----------------------------------------------------------------------------


def _action_help() -> str:
    """
    Return a short user guide for the private vault tool.

    :return: JSON response with the user guide text.
    :rtype: str
    """

    guide: str = (
        "# Private Vault - User Guide\n"
        "\n"
        "Private Vault gives you read-only access to your encrypted notes.\n"
        "\n"
        "## First-time setup\n"
        "\n"
        f"1. Open {UNLOCK_URL.rsplit('/unlock', 1)[0]} in your browser.\n"
        "2. Register a user account. The first registered user becomes the admin\n"
        "   and registration locks automatically.\n"
        "3. Log in and create entries (title, content, tags, secrecy level).\n"
        "\n"
        "## Getting a request key\n"
        "\n"
        f"1. Open {UNLOCK_URL} in your browser.\n"
        "2. Enter your password and choose a secrecy level.\n"
        "3. Copy the generated request key and give it to the model.\n"
        "\n"
        "Key behavior:\n"
        "- Keys expire after some time.\n"
        "- Generating a new key invalidates the previous one.\n"
        "- The key's secrecy level determines which entries are accessible.\n"
        "\n"
        "## Secrecy levels\n"
        "\n"
        "Each entry and each key has a secrecy level:\n"
        "- 0: unclassified\n"
        "- 1: confidential\n"
        "- 2: secret\n"
        "- 3: top secret\n"
        "\n"
        "A key can only access entries at or below its own level.\n"
        "This is enforced both by access control and by encryption:\n"
        "a level-1 key physically cannot decrypt level-2 or level-3 data.\n"
        "\n"
        "## Available tool actions\n"
        "\n"
        "- help: show this guide (no request key needed).\n"
        "- list: return all entries visible at the key's secrecy level\n"
        "  (id, title, tags, dates, secrecy level). Requires request_key.\n"
        "- read: return the full decrypted content of a single entry by id.\n"
        "  Requires request_key and entry_id.\n"
    )

    return _build_response(action="help", success=True, data=guide)


def _action_list(session_key: KeyInstance) -> str:
    """
    List vault entries accessible at the session key's secrecy level.

    Returns entry id, title, tags, and timestamps for each entry whose
    secrecy level is at or below the session key's level.

    :param session_key: Authenticated session key.
    :type session_key: KeyInstance

    :return: JSON response with entry list.
    :rtype: str
    """

    with vault_app.app_context():
        entries: List[Entry] = (
            vault_db.session.execute(
                vault_db.select(Entry)
                .filter_by(user_id=session_key.user_id)
                .filter(Entry.secrecy_level <= session_key.secrecy_level.value)
                .order_by(Entry.id.desc())
            )
            .scalars()
            .all()
        )

        result: List[Dict[str, Any]] = []
        for entry in entries:
            entry_level: SecrecyLevel = SecrecyLevel(entry.secrecy_level)
            title: str = (
                session_key.decrypt(entry.title, entry_level) if ENCRYPT_TITLES else entry.title
            )

            tags: List[str] = []
            created_at: str = ""
            modified_at: str = ""

            if entry.meta is not None:
                raw_meta: str = (
                    session_key.decrypt(entry.meta, entry_level) if ENCRYPT_META else entry.meta
                )
                parsed_meta: Dict[str, Any] = parse_meta(raw_meta)
                tags = parsed_meta["tags"]
                created_at = parsed_meta["created_at"]
                modified_at = parsed_meta["modified_at"]

            secrecy_label: str = (
                SecrecyLevel(entry.secrecy_level).name.replace("_", " ").lower()
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

    audit_log("tool.list", user_id=session_key.user_id, detail=f"count={len(result)}")
    return _build_response(action="list", success=True, data=result)


def _action_read(session_key: KeyInstance, entry_id: int) -> str:
    """
    Read a single vault entry by ID.

    Verifies that the entry belongs to the session key's user and that
    the session key's secrecy level is sufficient.

    :param session_key: Authenticated session key.
    :type session_key: KeyInstance

    :param entry_id: Database ID of the entry to read.
    :type entry_id: int

    :return: JSON response with decrypted entry data.
    :rtype: str
    """

    with vault_app.app_context():
        entry: Optional[Entry] = vault_db.session.execute(
            vault_db.select(Entry).filter_by(id=entry_id, user_id=session_key.user_id)
        ).scalar_one_or_none()

        if entry is None:
            return _build_response(
                action="read", success=False, error="Entry not found"
            )

        if not session_key.secrecy_level.is_allowed(SecrecyLevel(entry.secrecy_level)):
            audit_log(
                "tool.read",
                user_id=session_key.user_id,
                success=False,
                detail=f"entry_id={entry_id} insufficient_level",
            )
            return _build_response(
                action="read",
                success=False,
                error="Insufficient secrecy level for this entry",
            )

        entry_level: SecrecyLevel = SecrecyLevel(entry.secrecy_level)
        title: str = session_key.decrypt(entry.title, entry_level) if ENCRYPT_TITLES else entry.title
        content: str = session_key.decrypt(entry.entry, entry_level)

        tags: List[str] = []
        created_at: str = ""
        modified_at: str = ""

        if entry.meta is not None:
            raw_meta: str = (
                session_key.decrypt(entry.meta, entry_level) if ENCRYPT_META else entry.meta
            )
            parsed_meta: Dict[str, Any] = parse_meta(raw_meta)
            tags = parsed_meta["tags"]
            created_at = parsed_meta["created_at"]
            modified_at = parsed_meta["modified_at"]

        secrecy_label: str = (
            SecrecyLevel(entry.secrecy_level).name.replace("_", " ").lower()
        )

        data: Dict[str, Any] = {
            "id": entry.id,
            "title": title,
            "content": content,
            "tags": tags,
            "created_at": created_at,
            "modified_at": modified_at,
            "secrecy_level": entry.secrecy_level,
            "secrecy_label": secrecy_label,
        }

    audit_log("tool.read", user_id=session_key.user_id, detail=f"entry_id={entry_id}")
    return _build_response(action="read", success=True, data=data)


# -----------------------------------------------------------------------------
# Public API
# -----------------------------------------------------------------------------


def tool_run(action: str, request_key: Optional[str] = "", entry_id: Optional[int] = None) -> str:
    """
    Execute a vault action using a session key.

    :param action: Action to perform ("list" or "read").
    :type action: str

    :param request_key: Session token from /unlock.
    :type request_key: str

    :param entry_id: Entry ID (required for "read" action).
    :type entry_id: Optional[int]

    :return: JSON string with the action result.
    :rtype: str
    """

    try:
        if not isinstance(action, str):
            return _build_response(error="Action must be a string")

        action = action.strip().lower()
        if action not in ("help", "list", "read"):
            return _build_response(error="Action must be 'help', 'list', or 'read'")

        if action == "help":
            return _action_help()

        if not isinstance(request_key, str):
            return _build_response(
                error=f"No request_key provided. Generate one at: {UNLOCK_URL}"
            )

        request_key = request_key.strip()
        if len(request_key) < 1:
            return _build_response(
                error=f"No request_key provided. Generate one at: {UNLOCK_URL}"
            )

        session_key: Optional[KeyInstance] = _get_session_key(request_key)
        if session_key is None:
            return _build_response(
                error=f"Invalid or expired request_key. Generate a new one at: {UNLOCK_URL}"
            )

        if action == "list":
            return _action_list(session_key)

        if action == "read":
            if isinstance(entry_id, bool) or not isinstance(entry_id, int):
                return _build_response(
                    action="read", error="entry_id must be an integer"
                )

            if entry_id < 1:
                return _build_response(
                    action="read", error="entry_id must be greater than 0"
                )

            return _action_read(session_key, entry_id)

        return _build_response(error="Unknown action")

    except Exception:
        return _build_response(error="An internal error occurred")


TOOL_DEFINITION = json.dumps(
    {
        "type": "function",
        "function": {
            "name": "private_vault",
            "description": (
                "Read entries from the user's encrypted private vault. "
                f"Requires a request_key obtained by the user at the {UNLOCK_URL} page. "
                "Ask the user for the request_key if you don't have one. "
                "If you are unsure how to use this tool or the user needs help, call with action 'help' first."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["help", "list", "read"],
                        "description": (
                            "'help': return a user guide explaining setup and usage (no request_key needed). "
                            "'list': return all entries at or below the session's secrecy level "
                            "(id, title, tags, dates, secrecy level). "
                            "Entries with secrecy levels above the key level are not included in results. "
                            "'read': return full decrypted content of a single entry by entry_id."
                        ),
                    },
                    "request_key": {
                        "type": "string",
                        "description": f"Session token from {UNLOCK_URL}.",
                        "minLength": 1,
                    },
                    "entry_id": {
                        "type": "integer",
                        "description": "Entry ID to read. Required for 'read', omit for 'list'.",
                        "minimum": 1,
                    },
                },
                "required": ["action", "request_key"],
                "additionalProperties": False,
            },
        },
    },
    ensure_ascii=False,
)

start_vault_service()
