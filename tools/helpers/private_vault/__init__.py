from flask_login import LoginManager
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from .key_vault import KeyVault
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from .audit import log

app: Flask = Flask(__name__)
db: SQLAlchemy = SQLAlchemy()
login_manager: LoginManager = LoginManager()
csrf: CSRFProtect = CSRFProtect()
limiter: Limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["10 per minute"],
    storage_uri="memory://",
    headers_enabled=True,
)
key_vault: KeyVault = KeyVault()

__all__ = [
    "db",
    "app",
    "login_manager",
    "csrf",
    "key_vault",
    "limiter",
    "log",
]
