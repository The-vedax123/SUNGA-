import hashlib
import secrets
from datetime import datetime, UTC


def utc_now_iso() -> str:
    return datetime.now(UTC).replace(tzinfo=None).isoformat()


def generate_wallet_address() -> str:
    return f"SW-{secrets.token_hex(6).upper()}"


def generate_otp() -> str:
    return f"{secrets.randbelow(900000) + 100000}"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
