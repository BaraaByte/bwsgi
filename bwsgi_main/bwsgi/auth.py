"""Password hashing and session token management. Stdlib only."""
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone


PBKDF2_ITERATIONS = 260_000
SESSION_DAYS = 7


def hash_password(password: str, salt=None):
    """Return (hash_hex, salt_hex). PBKDF2-HMAC-SHA256."""
    if salt is None:
        salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes.fromhex(salt),
        PBKDF2_ITERATIONS,
    )
    return dk.hex(), salt


def verify_password(password: str, stored_hash: str, salt: str) -> bool:
    """Constant-time comparison."""
    computed, _ = hash_password(password, salt)
    return hmac.compare_digest(computed, stored_hash)


def new_session_token() -> str:
    return secrets.token_urlsafe(32)


def session_expiry(days: int = SESSION_DAYS) -> str:
    dt = datetime.now(timezone.utc) + timedelta(days=days)
    return dt.strftime("%Y-%m-%d %H:%M:%S")
