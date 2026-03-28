import os
import stat
import hmac
import base64
from gc import collect
from pathlib import Path
from enum import IntEnum
from threading import RLock
from secrets import token_hex
from dotenv import dotenv_values
from dataclasses import dataclass, field
from typing import Dict, Final, Optional, List
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# -----------------------------------------------------------------------------
# User configuration
# -----------------------------------------------------------------------------

# scrypt CPU/memory cost parameter (N). Higher values increase resistance
# to brute-force but also increase key derivation time.
SCRYPT_N: Final[int] = 65536

# scrypt block size (r) and parallelization (p) parameters.
SCRYPT_R: Final[int] = 8
SCRYPT_P: Final[int] = 2

# Derived key length in bytes (256-bit AES key).
KEY_LENGTH: Final[int] = 32

# Master key lifetime in minutes (web UI session, created at login).
MASTER_KEY_EXPIRATION_MINUTES: Final[int] = 120

# Session key lifetime in minutes (LLM access, created at /unlock).
SESSION_KEY_EXPIRATION_MINUTES: Final[int] = 30

# AES-GCM nonce length in bytes (96-bit, recommended by NIST).
NONCE_LENGTH: Final[int] = 12

# Path to .env file containing VAULT_SECRET, FLASK_SECRET, and VAULT_LEVEL_SECRET_0..3.
# Resolves to tools/.env (three levels up: private_vault -> helpers -> tools).
ENV_PATH: Final[str] = str(Path(__file__).resolve().parent.parent.parent / ".env")

# -----------------------------------------------------------------------------
# Public API
# -----------------------------------------------------------------------------


class SecrecyLevel(IntEnum):
    """
    Predefined secrecy levels with increasing sensitivity.
    """

    UNCLASSIFIED = 0
    CONFIDENTIAL = 1
    SECRET = 2
    TOP_SECRET = 3

    def is_allowed(self, required_level: "SecrecyLevel") -> bool:
        """
        Check if this secrecy level is sufficient to access data at the required level.

        :param required_level: Secrecy level of the data we want to access.
        :type required_level: SecrecyLevel

        :return: True if this level >= required_level.
        :rtype: bool

        :raises TypeError: If required_level is not a SecrecyLevel.
        """

        if not isinstance(required_level, SecrecyLevel):
            raise TypeError("required_level must be of `SecrecyLevel` type")

        return self >= required_level


@dataclass
class KeyInstance:
    """
    Encryption keys bound to a user, scoped to a secrecy level and with a fixed expiration.
    Mutable to allow in-place updates on re-authentication.

    Holds two kinds of keys:
        - user_key: per-user AES key derived from password + vault secret + user salt.
        - level_keys: per-level AES keys derived from password + level secret + level salt.
          Only levels up to secrecy_level are present.

    Encryption is two-layer: first encrypt with the level key, then encrypt the
    result with the user key (with associated_data binding the secrecy level).

    Two variants:
        - Master key (request_key is None): created at login for the web UI,
          full TOP_SECRET access, longer TTL. Not retrievable by request_key.
        - Session key (request_key is set): created at /unlock for LLM access,
          user-chosen secrecy scope, shorter TTL. Retrieved by request_key.
    """

    request_key: Optional[str]
    user_id: int
    secrecy_level: SecrecyLevel
    user_key: bytes
    level_keys: Dict[SecrecyLevel, bytes] = field(default_factory=dict)
    expires_at: datetime = field(default_factory=datetime.now)

    @property
    def is_master(self) -> bool:
        return self.request_key is None

    def _level_aad(self, secrecy_level: SecrecyLevel) -> bytes:
        """
        Build the associated data bytes for the user-key encryption layer.

        :param secrecy_level: The secrecy level to encode.
        :type secrecy_level: SecrecyLevel

        :return: UTF-8 encoded level identifier.
        :rtype: bytes
        """

        return f"level:{int(secrecy_level)}".encode("utf-8")

    def encrypt(self, text: str, secrecy_level: SecrecyLevel) -> str:
        """
        Two-layer AES-GCM encryption: level key then user key.

        Layer 1 (level key): encrypts plaintext with the level-specific key.
        Layer 2 (user key): encrypts the layer-1 blob with the user key,
        binding the secrecy level via associated_data.

        Each layer prepends its own random nonce. The final result is
        returned as a URL-safe base64 string for DB storage.

        :param text: Plaintext to encrypt.
        :type text: str

        :param secrecy_level: Secrecy level of the entry being encrypted.
        :type secrecy_level: SecrecyLevel

        :return: Base64-encoded token containing the two-layer ciphertext.
        :rtype: str

        :raises RuntimeError: If the key has expired.
        :raises KeyError: If level_keys does not contain the required level.
        """

        if self.expires_at <= datetime.now():
            raise RuntimeError("Session key has expired")

        level_key: bytes = self.level_keys[secrecy_level]

        # Layer 1: encrypt plaintext with level key
        level_aesgcm: AESGCM = AESGCM(level_key)
        level_nonce: bytes = os.urandom(NONCE_LENGTH)
        level_ciphertext: bytes = level_aesgcm.encrypt(
            level_nonce, text.encode("utf-8"), associated_data=None
        )
        level_blob: bytes = level_nonce + level_ciphertext

        # Layer 2: encrypt level blob with user key, binding secrecy level
        user_aesgcm: AESGCM = AESGCM(self.user_key)
        user_nonce: bytes = os.urandom(NONCE_LENGTH)
        user_ciphertext: bytes = user_aesgcm.encrypt(
            user_nonce, level_blob, associated_data=self._level_aad(secrecy_level)
        )
        token: bytes = user_nonce + user_ciphertext

        return base64.urlsafe_b64encode(token).decode("ascii")

    def decrypt(self, token: str, secrecy_level: SecrecyLevel) -> str:
        """
        Two-layer AES-GCM decryption: user key then level key.

        Layer 1 (user key): decrypts the outer blob, verifying the secrecy
        level via associated_data.
        Layer 2 (level key): decrypts the inner blob to recover plaintext.

        :param token: Base64-encoded token from encrypt().
        :type token: str

        :param secrecy_level: Secrecy level of the entry being decrypted.
        :type secrecy_level: SecrecyLevel

        :return: Decrypted plaintext.
        :rtype: str

        :raises InvalidTag: If decryption fails (wrong key, wrong level, or corrupted data).
        :raises RuntimeError: If the key has expired.
        :raises KeyError: If level_keys does not contain the required level.
        """

        if self.expires_at <= datetime.now():
            raise RuntimeError("Session key has expired")

        level_key: bytes = self.level_keys[secrecy_level]

        # Layer 1: decrypt outer blob with user key
        raw: bytes = base64.urlsafe_b64decode(token.encode("ascii"))
        user_nonce: bytes = raw[:NONCE_LENGTH]
        user_ciphertext: bytes = raw[NONCE_LENGTH:]
        user_aesgcm: AESGCM = AESGCM(self.user_key)
        level_blob: bytes = user_aesgcm.decrypt(
            user_nonce, user_ciphertext, associated_data=self._level_aad(secrecy_level)
        )

        # Layer 2: decrypt inner blob with level key
        level_nonce: bytes = level_blob[:NONCE_LENGTH]
        level_ciphertext: bytes = level_blob[NONCE_LENGTH:]
        level_aesgcm: AESGCM = AESGCM(level_key)
        plaintext: bytes = level_aesgcm.decrypt(
            level_nonce, level_ciphertext, associated_data=None
        )

        return plaintext.decode("utf-8")


class KeyVault:
    """
    In-memory store for active session keys. Thread-safe via RLock.

    Keys are held only in memory and lost on process restart.
    Expired keys are cleaned up lazily when accessed.
    """

    # Environment variable names for per-level secrets, indexed by SecrecyLevel value.
    _LEVEL_SECRET_VARS: Final[Dict[SecrecyLevel, str]] = {
        SecrecyLevel.UNCLASSIFIED: "VAULT_LEVEL_SECRET_0",
        SecrecyLevel.CONFIDENTIAL: "VAULT_LEVEL_SECRET_1",
        SecrecyLevel.SECRET: "VAULT_LEVEL_SECRET_2",
        SecrecyLevel.TOP_SECRET: "VAULT_LEVEL_SECRET_3",
    }

    def __init__(self) -> None:
        """
        Load VAULT_SECRET and VAULT_LEVEL_SECRET_0..3 from the .env file
        and initialize the key store.

        :raises FileNotFoundError: If the .env file does not exist or has wrong extension.
        :raises ValueError: If any required secret is missing or empty in the .env file.
        """

        env_path: Path = Path(ENV_PATH).expanduser().resolve()
        if not env_path.is_file() or env_path.name != ".env":
            raise FileNotFoundError(f"Expected .env file at '{env_path}'")

        env_stat: os.stat_result = env_path.stat()

        # Owner must be root or the current user.
        current_uid: int = os.getuid()
        if env_stat.st_uid != current_uid and env_stat.st_uid != 0:
            raise PermissionError(
                f".env file is owned by uid {env_stat.st_uid}, "
                f"expected uid {current_uid} or 0 (root)"
            )

        # Reject group/other access (anything beyond owner-only).
        if env_stat.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise PermissionError(
                ".env file is accessible by group or others, "
                "expected owner-only permissions (0600)"
            )

        env: dict[str, Optional[str]] = dotenv_values(env_path)
        vault_secret: Optional[str] = env.get("VAULT_SECRET")

        if not vault_secret:
            raise ValueError("VAULT_SECRET is missing or empty in the .env file")

        self._vault_secret: str = vault_secret

        flask_secret: Optional[str] = env.get("FLASK_SECRET")
        if not flask_secret:
            raise ValueError("FLASK_SECRET is missing or empty in the .env file")
        self._flask_secret: str = flask_secret

        self._level_secrets: Dict[SecrecyLevel, str] = {}
        for level, var_name in self._LEVEL_SECRET_VARS.items():
            value: Optional[str] = env.get(var_name)
            if not value:
                raise ValueError(f"{var_name} is missing or empty in the .env file")
            self._level_secrets[level] = value

        self._keys: List[KeyInstance] = []
        self._lock: RLock = RLock()

    def _derive_user_key(self, raw_password: str, user_key_salt: bytes) -> bytes:
        """
        Derive the per-user AES encryption key from the user's password.

        The password is first peppered with HMAC-SHA256 using the vault secret,
        then fed into scrypt with the user's salt to produce the AES key.

        :param raw_password: User's plaintext password (used only for derivation, not stored).
        :type raw_password: str

        :param user_key_salt: Per-user salt from the database.
        :type user_key_salt: bytes

        :return: Derived AES-256 key.
        :rtype: bytes
        """

        peppered_password: bytes = hmac.digest(
            self._vault_secret.encode("utf-8"),
            raw_password.encode("utf-8"),
            "sha256",
        )

        kdf: Scrypt = Scrypt(
            salt=user_key_salt,
            length=KEY_LENGTH,
            n=SCRYPT_N,
            r=SCRYPT_R,
            p=SCRYPT_P,
        )

        return kdf.derive(peppered_password)

    def _derive_level_key(
        self,
        level: SecrecyLevel,
        raw_password: str,
        level_salt: bytes,
    ) -> bytes:
        """
        Derive a per-level AES encryption key from the user's password.

        The password is peppered with HMAC-SHA256 using the level-specific
        secret, then fed into scrypt with the user's level salt.

        :param level: Secrecy level to derive the key for.
        :type level: SecrecyLevel

        :param raw_password: User's plaintext password (used only for derivation, not stored).
        :type raw_password: str

        :param level_salt: Per-user level salt from the database.
        :type level_salt: bytes

        :return: Derived AES-256 key.
        :rtype: bytes
        """

        peppered_password: bytes = hmac.digest(
            self._level_secrets[level].encode("utf-8"),
            raw_password.encode("utf-8"),
            "sha256",
        )

        kdf: Scrypt = Scrypt(
            salt=level_salt,
            length=KEY_LENGTH,
            n=SCRYPT_N,
            r=SCRYPT_R,
            p=SCRYPT_P,
        )

        return kdf.derive(peppered_password)

    def _derive_level_keys(
        self,
        max_level: SecrecyLevel,
        raw_password: str,
        level_salt: bytes,
    ) -> Dict[SecrecyLevel, bytes]:
        """
        Derive level keys for all levels up to and including max_level.

        :param max_level: Highest secrecy level to derive a key for.
        :type max_level: SecrecyLevel

        :param raw_password: User's plaintext password.
        :type raw_password: str

        :param level_salt: Per-user level salt from the database.
        :type level_salt: bytes

        :return: Mapping from SecrecyLevel to derived AES-256 key.
        :rtype: Dict[SecrecyLevel, bytes]
        """

        level_keys: Dict[SecrecyLevel, bytes] = {}
        for level in SecrecyLevel:
            if level > max_level:
                break
            level_keys[level] = self._derive_level_key(level, raw_password, level_salt)
        return level_keys

    def _validate_set_key_args(
        self,
        user_id: int,
        raw_password: str,
        user_key_salt: bytes,
        level_salt: bytes,
    ) -> None:
        """
        Validate common arguments for set_master_key and set_session_key.

        :param user_id: Database ID of the user.
        :type user_id: int

        :param raw_password: User's plaintext password.
        :type raw_password: str

        :param user_key_salt: Per-user salt from the database.
        :type user_key_salt: bytes

        :param level_salt: Per-user level salt from the database.
        :type level_salt: bytes

        :raises TypeError: If any argument has an invalid type.
        :raises ValueError: If user_id is less than 1.
        """

        if not isinstance(user_id, int):
            raise TypeError("user_id must be an integer")

        if user_id < 1:
            raise ValueError("user_id must be greater than 0")

        if not isinstance(raw_password, str):
            raise TypeError("raw_password must be a string")

        if not isinstance(user_key_salt, bytes):
            raise TypeError("user_key_salt must be bytes")

        if not isinstance(level_salt, bytes):
            raise TypeError("level_salt must be bytes")

    def set_master_key(
        self,
        user_id: int,
        raw_password: str,
        user_key_salt: bytes,
        level_salt: bytes,
    ) -> None:
        """
        Create or update the master key for the web UI session.

        The master key has TOP_SECRET access and no request_key, so it
        cannot be retrieved by the LLM via get_key(request_key=...).
        Derives the user key and all 4 level keys.

        :param user_id: Database ID of the user.
        :type user_id: int

        :param raw_password: User's plaintext password (used only for key derivation, not stored).
        :type raw_password: str

        :param user_key_salt: Per-user salt from the database, used in scrypt derivation.
        :type user_key_salt: bytes

        :param level_salt: Per-user level salt from the database, used in level key derivation.
        :type level_salt: bytes

        :raises TypeError: If any argument has an invalid type.
        :raises ValueError: If user_id is less than 1.
        """

        self._validate_set_key_args(user_id, raw_password, user_key_salt, level_salt)

        user_key: bytes = self._derive_user_key(raw_password, user_key_salt)
        level_keys: Dict[SecrecyLevel, bytes] = self._derive_level_keys(
            SecrecyLevel.TOP_SECRET, raw_password, level_salt
        )
        expires_at: datetime = datetime.now() + timedelta(
            minutes=MASTER_KEY_EXPIRATION_MINUTES
        )

        with self._lock:
            for key in self._keys:
                if key.user_id == user_id and key.is_master:
                    key.user_key = user_key
                    key.level_keys = level_keys
                    key.expires_at = expires_at
                    return

            self._keys.append(
                KeyInstance(
                    request_key=None,
                    user_id=user_id,
                    secrecy_level=SecrecyLevel.TOP_SECRET,
                    user_key=user_key,
                    level_keys=level_keys,
                    expires_at=expires_at,
                )
            )

    def set_session_key(
        self,
        user_id: int,
        raw_password: str,
        secrecy_level: SecrecyLevel,
        user_key_salt: bytes,
        level_salt: bytes,
    ) -> str:
        """
        Create or update a session key for LLM access via /unlock.

        If the user already has a session key, it is updated in place with a new
        request token, secrecy level, keys, and expiration. Derives the user key
        and level keys for levels 0 through secrecy_level.

        :param user_id: Database ID of the user.
        :type user_id: int

        :param raw_password: User's plaintext password (used only for key derivation, not stored).
        :type raw_password: str

        :param secrecy_level: Maximum secrecy level this session key grants access to.
        :type secrecy_level: SecrecyLevel

        :param user_key_salt: Per-user salt from the database, used in scrypt derivation.
        :type user_key_salt: bytes

        :param level_salt: Per-user level salt from the database, used in level key derivation.
        :type level_salt: bytes

        :return: Random request token (64-char hex) for the LLM to authenticate with.
        :rtype: str

        :raises TypeError: If any argument has an invalid type.
        :raises ValueError: If user_id is less than 1.
        """

        self._validate_set_key_args(user_id, raw_password, user_key_salt, level_salt)

        if not isinstance(secrecy_level, SecrecyLevel):
            raise TypeError("secrecy_level must be of `SecrecyLevel` type")

        user_key: bytes = self._derive_user_key(raw_password, user_key_salt)
        level_keys: Dict[SecrecyLevel, bytes] = self._derive_level_keys(
            secrecy_level, raw_password, level_salt
        )
        expires_at: datetime = datetime.now() + timedelta(
            minutes=SESSION_KEY_EXPIRATION_MINUTES
        )

        with self._lock:
            request_key: str = token_hex(32)
            all_request_keys: List[str] = [
                key.request_key for key in self._keys if key.request_key is not None
            ]
            while request_key in all_request_keys:
                request_key = token_hex(32)

            for key in self._keys:
                if key.user_id == user_id and not key.is_master:
                    key.request_key = request_key
                    key.secrecy_level = secrecy_level
                    key.user_key = user_key
                    key.level_keys = level_keys
                    key.expires_at = expires_at
                    return request_key

            self._keys.append(
                KeyInstance(
                    request_key=request_key,
                    user_id=user_id,
                    secrecy_level=secrecy_level,
                    user_key=user_key,
                    level_keys=level_keys,
                    expires_at=expires_at,
                )
            )

        return request_key

    def get_key(
        self,
        *,
        user_id: Optional[int] = None,
        request_key: Optional[str] = None,
    ) -> Optional[KeyInstance]:
        """
        Look up a key by request_key or user_id. At least one must be provided.

        By request_key: returns the matching session key (master keys are skipped).
        By user_id: returns the master key for that user.
        Expired keys are removed on access and None is returned.

        :param user_id: Database ID of the user. Returns the master key.
        :type user_id: Optional[int]

        :param request_key: Random session token returned by set_session_key.
        :type request_key: Optional[str]

        :return: Matching KeyInstance, or None if not found or expired.
        :rtype: Optional[KeyInstance]

        :raises ValueError: If neither user_id nor request_key is provided.
        """

        if user_id is None and request_key is None:
            raise ValueError("At least one of user_id or request_key must be provided")

        expired: List[KeyInstance] = []
        result: Optional[KeyInstance] = None

        try:
            now: datetime = datetime.now()
            with self._lock:
                for key in self._keys:
                    if key.expires_at <= now:
                        expired.append(key)
                    elif result is None:
                        if request_key is not None:
                            if not key.is_master and hmac.compare_digest(key.request_key, request_key):
                                result = key
                        elif key.user_id == user_id and key.is_master:
                            result = key

                for key in expired:
                    self._keys.remove(key)

            return result
        finally:
            if expired:
                collect()

    def delete_key(self, user_id: int, *, master: Optional[bool] = None) -> None:
        """
        Remove keys for a given user.

        :param user_id: Database ID of the user.
        :type user_id: int

        :param master: If True, delete only the master key. If False, delete only
            the session key. If None, delete all keys for the user.
        :type master: Optional[bool]

        :raises TypeError: If user_id is not an integer.
        """

        if not isinstance(user_id, int):
            raise TypeError("user_id must be an integer")

        with self._lock:
            if master is None:
                self._keys = [k for k in self._keys if k.user_id != user_id]
            else:
                self._keys = [
                    k
                    for k in self._keys
                    if not (k.user_id == user_id and k.is_master == master)
                ]

        collect()

    def has_key(
        self,
        *,
        user_id: Optional[int] = None,
        request_key: Optional[str] = None,
    ) -> bool:
        """
        Check if a key exists. At least one of user_id or request_key must be provided.

        By user_id: checks for the master key. By request_key: checks for a session key.

        :param user_id: Database ID of the user. Checks for the master key.
        :type user_id: Optional[int]

        :param request_key: Random session token returned by set_session_key.
        :type request_key: Optional[str]

        :return: True if a matching key exists.
        :rtype: bool

        :raises ValueError: If neither user_id nor request_key is provided.
        """

        return self.get_key(user_id=user_id, request_key=request_key) is not None
