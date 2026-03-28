import logging
from pathlib import Path
from typing import Final, Optional
from logging.handlers import RotatingFileHandler

# Log file lives alongside the database in permanent/vault/.
# Resolves to <repo>/permanent/vault/ locally or /app/permanent/vault/ in Docker.
_LOG_DIR: Final[Path] = Path(__file__).resolve().parent.parent.parent / "permanent" / "vault"
_LOG_FILE: Final[Path] = _LOG_DIR / "audit.log"

# Maximum size per log file (5 MB) and number of backup files to keep.
_MAX_BYTES: Final[int] = 5 * 1024 * 1024
_BACKUP_COUNT: Final[int] = 3

_logger: logging.Logger = logging.getLogger("vault.audit")
_logger.setLevel(logging.INFO)
_logger.propagate = False

_LOG_DIR.mkdir(parents=True, exist_ok=True)
_handler: RotatingFileHandler = RotatingFileHandler(
    _LOG_FILE, maxBytes=_MAX_BYTES, backupCount=_BACKUP_COUNT
)
_handler.setFormatter(
    logging.Formatter("%(asctime)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
)
_logger.addHandler(_handler)


def log(
    action: str,
    *,
    ip: Optional[str] = None,
    user_id: Optional[int] = None,
    success: bool = True,
    detail: str = "",
) -> None:
    """
    Write a structured audit log entry.

    No personal information (usernames, passwords, content) is logged.
    Only action, IP, user_id, outcome, and optional detail.

    :param action: Short action label (e.g. "login", "register", "vault.add").
    :type action: str

    :param ip: Client IP address.
    :type ip: Optional[str]

    :param user_id: Database ID of the user involved.
    :type user_id: Optional[int]

    :param success: Whether the action succeeded.
    :type success: bool

    :param detail: Extra context (e.g. entry_id, secrecy_level change).
    :type detail: str
    """

    outcome: str = "OK" if success else "FAIL"
    parts: list[str] = [f"action={action}", f"outcome={outcome}"]

    if ip is not None:
        parts.append(f"ip={ip}")
    if user_id is not None:
        parts.append(f"user_id={user_id}")
    if detail:
        parts.append(f"detail={detail}")

    _logger.info(" ".join(parts))
