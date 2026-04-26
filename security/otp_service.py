import secrets
import time
from datetime import UTC, datetime, timedelta


OTP_EXPIRY_SECONDS = 300
OTP_MAX_ATTEMPTS = 3
OTP_RATE_LIMIT_COUNT = 3
OTP_RATE_LIMIT_WINDOW_SECONDS = 300


def generate_otp() -> str:
    return f"{secrets.randbelow(900000) + 100000}"


def now_epoch() -> int:
    return int(time.time())


def expiry_iso() -> str:
    return (datetime.now(UTC) + timedelta(seconds=OTP_EXPIRY_SECONDS)).replace(tzinfo=None).isoformat()


def is_expired(expiry_iso_value: str) -> bool:
    return datetime.now(UTC).replace(tzinfo=None) > datetime.fromisoformat(expiry_iso_value)


def build_otp_session_payload(*, username: str, role: str, email: str, next_url: str, purpose: str) -> dict:
    return {
        "otp_username": username,
        "otp_role": role,
        "otp_email": email,
        "otp_next": next_url,
        "otp_purpose": purpose,
        "otp_code": generate_otp(),
        "otp_expiry": expiry_iso(),
        "otp_attempts": 0,
        "otp_status": "sent",
    }


def parse_request_log(raw_value) -> list[int]:
    if not raw_value:
        return []
    now = now_epoch()
    cleaned = []
    for token in str(raw_value).split(","):
        token = token.strip()
        if not token.isdigit():
            continue
        stamp = int(token)
        if now - stamp <= OTP_RATE_LIMIT_WINDOW_SECONDS:
            cleaned.append(stamp)
    return cleaned
