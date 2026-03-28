from flask_login import current_user
from flask_limiter.util import get_remote_address

def user_rate_key() -> str:
    user_id = getattr(current_user, "id", None)
    if isinstance(user_id, int):
        return f"user:{user_id}"
    return get_remote_address()