import os
import sys
import fcntl
import ssl
import time
import logging
from ipaddress import IPv4Address
from pathlib import Path
from threading import Thread
from typing import Final
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from werkzeug.serving import BaseWSGIServer, make_server

# Ensure private_vault is importable as a top-level package.
# The tool finder adds tools/ to sys.path, but private_vault lives
# under tools/helpers/, so we need helpers/ on the path too.
_helpers_dir: str = str(Path(__file__).resolve().parent)
if _helpers_dir not in sys.path:
    sys.path.insert(0, _helpers_dir)

from private_vault import app, db, login_manager, csrf, limiter, key_vault
from private_vault.routes import auth_bp, global_bp, unlock_bp, vault_bp

logger: logging.Logger = logging.getLogger(__name__)

# -----------------------------------------------------------------------------
# User configuration
# -----------------------------------------------------------------------------

VAULT_PORT: Final[int] = 8000  # HTTPS port for the vault server
VAULT_HOST: Final[str] = "127.0.0.1"  # Bind address; use 0.0.0.0 only inside a container (not bare metal)
CERT_VALIDITY_DAYS: Final[int] = 365  # Self-signed certificate validity period

# -----------------------------------------------------------------------------
# Static paths (derived, not configurable)
# -----------------------------------------------------------------------------

# Base directory for all persistent vault data (DB, certs, lock).
# Resolves to <repo>/permanent/vault/ locally or /app/permanent/vault/ in Docker.
_PERMANENT_DIR: Final[Path] = Path(__file__).resolve().parent.parent.parent / "permanent"
VAULT_DATA_DIR: Final[Path] = _PERMANENT_DIR / "vault"

CERT_DIR: Final[Path] = VAULT_DATA_DIR / "certs"
CERT_FILE: Final[Path] = CERT_DIR / "vault.crt"
KEY_FILE: Final[Path] = CERT_DIR / "vault.key"
DB_PATH: Final[Path] = VAULT_DATA_DIR / "vault.db"
LOCK_FILE: Final[Path] = VAULT_DATA_DIR / "vault.lock"

# -----------------------------------------------------------------------------
# Internal helpers
# -----------------------------------------------------------------------------




def _atomic_write(path: Path, data: bytes) -> bool:
    """
    Atomically create a file and write data to it.

    Uses O_CREAT | O_EXCL to fail if the file already exists, and
    O_NOFOLLOW to reject symlinks. File is created with mode 0600.

    :param path: Target file path.
    :type path: Path

    :param data: Bytes to write.
    :type data: bytes

    :return: True if the file was created, False if it already existed.
    :rtype: bool
    """

    flags: int = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    try:
        fd: int = os.open(path, flags, 0o600)
    except FileExistsError:
        return False

    try:
        os.write(fd, data)
    finally:
        os.close(fd)

    return True


def _ensure_cert() -> None:
    """
    Generate a self-signed TLS certificate and key if they don't already exist.

    Uses atomic file creation (O_CREAT | O_EXCL | O_NOFOLLOW) to avoid
    TOCTOU races and symlink attacks. If only one of the two files exists
    (partial state from a previous crash), both are removed and regenerated.

    Uses ECDSA P-256 for a compact, fast certificate. Stored in CERT_DIR.
    """

    key_exists: bool = KEY_FILE.exists()
    cert_exists: bool = CERT_FILE.exists()

    if key_exists and cert_exists:
        return

    # Clean up partial state from a previous crash.
    if key_exists != cert_exists:
        if key_exists:
            KEY_FILE.unlink()
        if cert_exists:
            CERT_FILE.unlink()

    CERT_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(CERT_DIR, 0o700)

    private_key: ec.EllipticCurvePrivateKey = ec.generate_private_key(ec.SECP256R1())

    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Private Vault")]
    )

    now: datetime = datetime.now(timezone.utc)
    cert: x509.Certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=CERT_VALIDITY_DAYS))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(IPv4Address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )

    key_bytes: bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_bytes: bytes = cert.public_bytes(serialization.Encoding.PEM)

    if not _atomic_write(KEY_FILE, key_bytes):
        return
    if not _atomic_write(CERT_FILE, cert_bytes):
        return

    logger.info("Generated self-signed TLS certificate at %s", CERT_FILE)


def _configure_app() -> None:
    """
    Apply Flask config, register blueprints, and create DB tables.
    """

    app.config["SECRET_KEY"] = key_vault._flask_secret
    VAULT_DATA_DIR.mkdir(parents=True, exist_ok=True)
    app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DB_PATH}"
    app.config["SESSION_COOKIE_SECURE"] = True
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Strict"

    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    app.register_blueprint(global_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(unlock_bp)
    app.register_blueprint(vault_bp)

    with app.app_context():
        db.create_all()

    limiter.exempt(app.view_functions["static"])


def _verify_lock_owner() -> None:
    """
    Check that the lock file is owned by the current user or root.

    If it is owned by another user, it is deleted so a fresh one can
    be created. This prevents a local attacker from pre-creating the
    lock file and holding it to block vault startup.

    :raises RuntimeError: If the foreign lock file cannot be removed.
    """

    try:
        lock_stat: os.stat_result = LOCK_FILE.stat()
    except OSError:
        return

    current_uid: int = os.getuid()
    if lock_stat.st_uid == current_uid or lock_stat.st_uid == 0:
        return

    logger.warning(
        "Lock file owned by uid %d, expected %d or 0 -- removing",
        lock_stat.st_uid,
        current_uid,
    )
    try:
        LOCK_FILE.unlink()
    except OSError as ex:
        raise RuntimeError(f"Cannot remove foreign lock file: {ex}") from ex


def _is_vault_locked() -> bool:
    """
    Check if another process holds the vault lock file, meaning the
    vault is either running or being started.

    :return: True if the lock is held by another process.
    :rtype: bool
    """

    _verify_lock_owner()

    try:
        probe_fd: int = os.open(LOCK_FILE, os.O_RDWR)
    except OSError:
        return False

    try:
        fcntl.flock(probe_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        # Lock acquired -- no one else holds it.
        fcntl.flock(probe_fd, fcntl.LOCK_UN)
        return False
    except OSError:
        # Could not acquire -- another process holds it.
        return True
    finally:
        os.close(probe_fd)


_LOCK_WAIT_INTERVAL: Final[float] = 0.5  # Seconds between lock probe retries
_LOCK_WAIT_TIMEOUT: Final[float] = 30.0  # Maximum seconds to wait for another process to finish startup


def start_vault_service() -> None:
    """
    Start the vault Flask server in a daemon thread if not already running.

    The lock file is held for the lifetime of the server process (not just
    during startup). Other callers detect a running vault by probing the
    lock, so no network-based health check is needed.

    Safe to call multiple times -- subsequent calls are no-ops if the
    lock is already held by this or another process.
    """

    VAULT_DATA_DIR.mkdir(parents=True, exist_ok=True)
    _verify_lock_owner()

    lock_fd: int = os.open(LOCK_FILE, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        # Another process holds the lock -- vault is already running or starting.
        os.close(lock_fd)
        logger.info("Another process is starting the vault, waiting...")
        elapsed: float = 0.0
        while elapsed < _LOCK_WAIT_TIMEOUT:
            time.sleep(_LOCK_WAIT_INTERVAL)
            elapsed += _LOCK_WAIT_INTERVAL
            if _is_vault_locked():
                logger.info("Vault service started by another process")
                return
        raise RuntimeError("Timed out waiting for vault service to start")

    # We hold the lock. It stays held until the process exits (daemon thread
    # keeps the fd open; the OS releases the flock on process termination).
    _ensure_cert()
    _configure_app()

    ssl_context: ssl.SSLContext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    # Open cert/key with O_NOFOLLOW so the kernel rejects symlinks at
    # open time, then load via /proc/self/fd/ to avoid any TOCTOU gap
    # between a symlink check and the actual file read. Linux-specific.
    cert_fd: int = os.open(CERT_FILE, os.O_RDONLY | os.O_NOFOLLOW)
    key_fd: int = os.open(KEY_FILE, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        ssl_context.load_cert_chain(
            f"/proc/self/fd/{cert_fd}", f"/proc/self/fd/{key_fd}"
        )
    finally:
        os.close(cert_fd)
        os.close(key_fd)

    server: BaseWSGIServer = make_server(
        VAULT_HOST,
        VAULT_PORT,
        app,
        threaded=True,
        ssl_context=ssl_context,
    )

    thread: Thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    logger.info("Vault service started on %s:%d (HTTPS)", VAULT_HOST, VAULT_PORT)
