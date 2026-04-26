import re


USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9]{3,20}$")
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
PHONE_PATTERN = re.compile(r"^[0-9+\-\s]{7,20}$")
PASSWORD_UPPER = re.compile(r"[A-Z]")
PASSWORD_LOWER = re.compile(r"[a-z]")
PASSWORD_DIGIT = re.compile(r"\d")
PASSWORD_SPECIAL = re.compile(r"[^A-Za-z0-9]")
WALLET_PATTERN = re.compile(r"^SW-[A-F0-9]{12}$")


def validate_username(username: str) -> tuple[bool, str]:
    if not username:
        return False, "Username is required."
    if not USERNAME_PATTERN.fullmatch(username):
        return False, "Username must be 3-20 characters and letters/numbers only."
    return True, ""


def validate_password(password: str) -> tuple[bool, str]:
    if not password:
        return False, "Password is required."
    if len(password) < 8:
        return False, "Password must be at least 8 characters."
    if not PASSWORD_UPPER.search(password):
        return False, "Password must include at least one uppercase letter."
    if not PASSWORD_LOWER.search(password):
        return False, "Password must include at least one lowercase letter."
    if not PASSWORD_DIGIT.search(password):
        return False, "Password must include at least one number."
    if not PASSWORD_SPECIAL.search(password):
        return False, "Password must include at least one special character."
    return True, ""


def validate_email(email: str) -> tuple[bool, str]:
    if not email:
        return False, "Email is required."
    if not EMAIL_PATTERN.fullmatch(email):
        return False, "Invalid email format."
    return True, ""


def validate_phone(phone: str) -> tuple[bool, str]:
    if not phone:
        return False, "Phone is required."
    if not PHONE_PATTERN.fullmatch(phone):
        return False, "Phone must be 7-20 characters and may include +, -, and spaces."
    return True, ""


def validate_amount(amount_raw: str, available_balance: float) -> tuple[bool, str, float]:
    if not amount_raw:
        return False, "Amount is required.", 0.0
    try:
        amount = round(float(amount_raw), 2)
    except ValueError:
        return False, "Amount must be numeric.", 0.0
    if amount <= 0:
        return False, "Amount must be greater than 0.", 0.0
    if amount > round(float(available_balance), 2):
        return False, "Amount exceeds available balance.", 0.0
    return True, "", amount


def validate_wallet_address(address: str) -> tuple[bool, str]:
    if not address:
        return False, "Wallet address is required."
    if not WALLET_PATTERN.fullmatch(address):
        return False, "Invalid wallet address format."
    return True, ""
