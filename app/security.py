import hashlib
import secrets


def hash_password(password: str, salt: str | None = None) -> str:
    selected_salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), selected_salt.encode('utf-8'), 390000)
    return f'{selected_salt}${digest.hex()}'


def verify_password(password: str, hashed: str) -> bool:
    try:
        salt, stored_hash = hashed.split('$', 1)
    except ValueError:
        return False
    comparison_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 390000).hex()
    return secrets.compare_digest(comparison_hash, stored_hash)
