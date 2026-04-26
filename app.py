import io
import os
import re
import sqlite3
import traceback
from datetime import datetime, timedelta
from functools import wraps

import bcrypt
from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken
from flask import Flask, flash, g, jsonify, make_response, redirect, render_template, request, session, url_for
import qrcode
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
try:
    import psycopg2
    import psycopg2.extras
except ImportError:
    psycopg2 = None

from blockchain import Blockchain
from backup import create_encrypted_backup, recover_encrypted_backup
from security import generate_wallet_address, utc_now_iso
from security.email_service import EmailDeliveryError, send_security_otp_email
from security.otp_service import (
    OTP_EXPIRY_SECONDS,
    OTP_MAX_ATTEMPTS,
    OTP_RATE_LIMIT_COUNT,
    OTP_RATE_LIMIT_WINDOW_SECONDS,
    build_otp_session_payload,
    generate_otp as generate_secure_otp,
    is_expired,
    now_epoch,
    parse_request_log,
)
from validation import (
    validate_amount,
    validate_email,
    validate_password,
    validate_phone,
    validate_username as validate_username_input,
    validate_wallet_address as validate_wallet_input,
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
IS_VERCEL = os.environ.get("VERCEL") == "1"
DATA_DIR = os.environ.get("DATA_DIR", "/tmp" if IS_VERCEL else BASE_DIR)
DATABASE_PATH = os.path.join(DATA_DIR, "database.db")
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
USE_POSTGRES = DATABASE_URL.startswith("postgres://") or DATABASE_URL.startswith("postgresql://")
if USE_POSTGRES and psycopg2 is None:
    raise RuntimeError("DATABASE_URL points to Postgres but psycopg2 is not installed.")
FERNET_KEY_PATH = os.path.join(DATA_DIR, "fernet.key")
BACKUP_DIR = os.path.join(DATA_DIR, "backups")
SESSION_TIMEOUT_MINUTES = 5
OTP_EXPIRY_MINUTES = OTP_EXPIRY_SECONDS // 60
DEFAULT_STARTING_BALANCE = 100.0
FRAUD_THRESHOLD = 200.0
LOCKOUT_THRESHOLD = 3
LOCKOUT_MINUTES = 5
FEE_RATE = 0.01

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-change-this-secret-key")
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=SESSION_TIMEOUT_MINUTES)
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0

def get_or_create_fernet_key() -> str:
    env_key = os.environ.get("FERNET_KEY")
    if env_key:
        return env_key
    os.makedirs(DATA_DIR, exist_ok=True)
    if os.path.exists(FERNET_KEY_PATH):
        with open(FERNET_KEY_PATH, "r", encoding="utf-8") as key_file:
            return key_file.read().strip()
    new_key = Fernet.generate_key().decode("utf-8")
    with open(FERNET_KEY_PATH, "w", encoding="utf-8") as key_file:
        key_file.write(new_key)
    return new_key


fernet_key = get_or_create_fernet_key()
fernet = Fernet(fernet_key.encode("utf-8"))
blockchain = Blockchain()
BOOTSTRAPPED = False


def _qmark_to_pyformat(query: str) -> str:
    if "?" not in query:
        return query
    parts = query.split("?")
    return "%s".join(parts)


class PostgresCompatDB:
    def __init__(self, conn):
        self._conn = conn

    def execute(self, query, params=()):
        cursor = self._conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cursor.execute(_qmark_to_pyformat(query), params)
        return cursor

    def commit(self):
        self._conn.commit()

    def close(self):
        self._conn.close()


def get_db():
    if "db" not in g:
        if USE_POSTGRES:
            conn = psycopg2.connect(DATABASE_URL)
            g.db = PostgresCompatDB(conn)
        else:
            g.db = sqlite3.connect(DATABASE_PATH)
            g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


@app.after_request
def disable_browser_cache(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


def get_columns(table_name: str) -> set:
    db = get_db()
    if USE_POSTGRES:
        rows = db.execute(
            """
            SELECT column_name AS name
            FROM information_schema.columns
            WHERE table_schema = 'public' AND table_name = ?
            """,
            (table_name,),
        ).fetchall()
    else:
        rows = db.execute(f"PRAGMA table_info({table_name})").fetchall()
    return {row["name"] for row in rows}


def wallet_address() -> str:
    return generate_wallet_address()


def generate_unique_wallet_address() -> str:
    db = get_db()
    for _ in range(20):
        candidate = wallet_address()
        exists = db.execute("SELECT id FROM users WHERE wallet_address = ?", (candidate,)).fetchone()
        if not exists:
            return candidate
    raise RuntimeError("Unable to generate a unique wallet address.")


def migrate_db():
    if USE_POSTGRES:
        return
    db = get_db()
    user_cols = get_columns("users")
    if "wallet_address" not in user_cols:
        db.execute("ALTER TABLE users ADD COLUMN wallet_address TEXT")
    if "locked_until" not in user_cols:
        db.execute("ALTER TABLE users ADD COLUMN locked_until TEXT")
    if "full_name" not in user_cols:
        db.execute("ALTER TABLE users ADD COLUMN full_name TEXT")
    if "email" not in user_cols:
        db.execute("ALTER TABLE users ADD COLUMN email TEXT")
    if "phone" not in user_cols:
        db.execute("ALTER TABLE users ADD COLUMN phone TEXT")
    if "status" not in user_cols:
        db.execute("ALTER TABLE users ADD COLUMN status TEXT DEFAULT 'Active'")
    tx_cols = get_columns("transactions")
    if "amount" in tx_cols:
        try:
            db.execute("ALTER TABLE transactions RENAME COLUMN amount TO amount_enc")
        except sqlite3.OperationalError:
            pass
    tx_cols = get_columns("transactions")
    if "sender_enc" not in tx_cols:
        db.execute("ALTER TABLE transactions ADD COLUMN sender_enc TEXT")
    if "receiver_enc" not in tx_cols:
        db.execute("ALTER TABLE transactions ADD COLUMN receiver_enc TEXT")
    if "fee_amount" not in tx_cols:
        db.execute("ALTER TABLE transactions ADD COLUMN fee_amount REAL DEFAULT 0")
    if "status" not in tx_cols:
        db.execute("ALTER TABLE transactions ADD COLUMN status TEXT DEFAULT 'completed'")
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user TEXT NOT NULL,
            amount REAL NOT NULL,
            reason TEXT NOT NULL,
            severity TEXT,
            timestamp TEXT NOT NULL
        )
        """
    )
    alert_cols = get_columns("alerts")
    if "severity" not in alert_cols:
        db.execute("ALTER TABLE alerts ADD COLUMN severity TEXT")
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS error_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user TEXT NOT NULL,
            route TEXT NOT NULL,
            error_message TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            message TEXT NOT NULL,
            is_read INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS failed_logins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            ip_address TEXT NOT NULL
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS locked_funds (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            amount DECIMAL(10,2),
            release_date DATETIME,
            status TEXT DEFAULT 'locked',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS otp_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_email TEXT NOT NULL,
            otp_code TEXT NOT NULL,
            status TEXT NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            verified_at TEXT
        )
        """
    )
    db.commit()


def init_db():
    db = get_db()
    if USE_POSTGRES:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('admin', 'student')),
                balance DOUBLE PRECISION NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                wallet_address TEXT,
                full_name TEXT,
                email TEXT,
                phone TEXT,
                status TEXT DEFAULT 'Active',
                locked_until TEXT
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS transactions (
                id SERIAL PRIMARY KEY,
                sender TEXT,
                receiver TEXT,
                amount_enc TEXT,
                sender_enc TEXT,
                receiver_enc TEXT,
                fee_amount DOUBLE PRECISION DEFAULT 0,
                hash TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                status TEXT DEFAULT 'completed'
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS logs (
                id SERIAL PRIMARY KEY,
                user TEXT NOT NULL,
                action TEXT NOT NULL,
                timestamp TEXT NOT NULL
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id SERIAL PRIMARY KEY,
                user TEXT NOT NULL,
                amount DOUBLE PRECISION NOT NULL,
                reason TEXT NOT NULL,
                severity TEXT,
                timestamp TEXT NOT NULL
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS error_logs (
                id SERIAL PRIMARY KEY,
                user TEXT NOT NULL,
                route TEXT NOT NULL,
                error_message TEXT NOT NULL,
                timestamp TEXT NOT NULL
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS failed_logins (
                id SERIAL PRIMARY KEY,
                username TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                ip_address TEXT NOT NULL
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS locked_funds (
                id SERIAL PRIMARY KEY,
                user_id INTEGER,
                amount DECIMAL(10,2),
                release_date TEXT,
                status TEXT DEFAULT 'locked',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS notifications (
                id SERIAL PRIMARY KEY,
                username TEXT NOT NULL,
                message TEXT NOT NULL,
                is_read INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS otp_logs (
                id SERIAL PRIMARY KEY,
                user_email TEXT NOT NULL,
                otp_code TEXT NOT NULL,
                status TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                verified_at TEXT
            )
            """
        )
        db.commit()
        seed_admin()
        backfill_wallet_addresses()
        migrate_transaction_encryption()
        return
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin', 'student')),
            balance REAL NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            full_name TEXT,
            email TEXT,
            phone TEXT,
            status TEXT DEFAULT 'Active',
            locked_until TEXT
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT,
            receiver TEXT,
            amount_enc TEXT,
            fee_amount REAL DEFAULT 0,
            hash TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            status TEXT DEFAULT 'completed'
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user TEXT NOT NULL,
            action TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS otp_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_email TEXT NOT NULL,
            otp_code TEXT NOT NULL,
            status TEXT NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            verified_at TEXT
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS locked_funds (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            amount DECIMAL(10,2),
            release_date DATETIME,
            status TEXT DEFAULT 'locked',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    db.commit()
    migrate_db()
    seed_admin()
    backfill_wallet_addresses()
    migrate_transaction_encryption()


def seed_admin():
    db = get_db()
    existing = db.execute("SELECT id FROM users WHERE username = ?", ("admin",)).fetchone()
    if existing:
        return
    created_at = datetime.utcnow().isoformat()
    password_hash = bcrypt.hashpw("admin123!".encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    db.execute(
        "INSERT INTO users (username, password_hash, role, balance, created_at, wallet_address) VALUES (?, ?, ?, ?, ?, ?)",
        ("admin", password_hash, "admin", 1000.0, created_at, generate_unique_wallet_address()),
    )
    db.commit()
    log_action("system", "Seeded default admin account.")


def backfill_wallet_addresses():
    db = get_db()
    users = db.execute("SELECT id FROM users WHERE wallet_address IS NULL OR wallet_address = ''").fetchall()
    for user in users:
        db.execute("UPDATE users SET wallet_address = ? WHERE id = ?", (generate_unique_wallet_address(), user["id"]))
    db.commit()


def log_action(user: str, action: str):
    db = get_db()
    timestamp = utc_now_iso()
    db.execute("INSERT INTO logs (user, action, timestamp) VALUES (?, ?, ?)", (user, action, timestamp))
    db.commit()


def log_error(route_name: str, error_message: str):
    if getattr(g, "error_logged", False):
        return
    db = get_db()
    user = session.get("username", "anonymous")
    timestamp = datetime.utcnow().isoformat()
    normalized_route = route_name[:120] if route_name else "unknown"
    normalized_message = (error_message or "Unknown error").replace("\n", " ")[:500]
    db.execute(
        "INSERT INTO error_logs (user, route, error_message, timestamp) VALUES (?, ?, ?, ?)",
        (user, normalized_route, normalized_message, timestamp),
    )
    db.commit()
    g.error_logged = True
    log_action(user, f"Exception at {normalized_route}: {normalized_message[:120]}")


def create_notification(username: str, message: str):
    if not username or not message:
        return
    db = get_db()
    timestamp = datetime.utcnow().isoformat()
    db.execute(
        "INSERT INTO notifications (username, message, is_read, created_at) VALUES (?, ?, 0, ?)",
        (username, message[:180], timestamp),
    )
    db.commit()


def fetch_unread_notifications(username: str, limit: int = 5):
    if not username:
        return []
    db = get_db()
    rows = db.execute(
        """
        SELECT id, message, created_at
        FROM notifications
        WHERE username = ? AND is_read = 0
        ORDER BY id DESC
        LIMIT ?
        """,
        (username, limit),
    ).fetchall()
    if not rows:
        return []
    ids = [str(row["id"]) for row in rows]
    db.execute(f"UPDATE notifications SET is_read = 1 WHERE id IN ({','.join(['?'] * len(ids))})", ids)
    db.commit()
    return [{"message": row["message"], "created_at": row["created_at"]} for row in rows]


@app.context_processor
def inject_unread_notifications():
    if "username" not in session:
        return {"unread_notifications": []}
    return {"unread_notifications": fetch_unread_notifications(session.get("username"))}


def validate_username(username: str) -> bool:
    valid, _ = validate_username_input(username)
    return valid


def validate_wallet_address(address: str) -> bool:
    valid, _ = validate_wallet_input(address)
    return valid


def encrypt_value(raw: str) -> str:
    return fernet.encrypt(raw.encode("utf-8")).decode("utf-8")


def decrypt_value(cipher: str) -> str:
    return fernet.decrypt(cipher.encode("utf-8")).decode("utf-8")


def try_decrypt_value(cipher: str):
    try:
        return decrypt_value(cipher)
    except (InvalidToken, AttributeError, TypeError, ValueError):
        return None


def encrypt_transaction_fields(sender: str, receiver: str, amount: float) -> tuple:
    return encrypt_value(sender), encrypt_value(receiver), encrypt_value(f"{amount:.8f}")


def decrypt_row(row) -> dict:
    sender_enc = row["sender_enc"] if "sender_enc" in row.keys() and row["sender_enc"] else row["sender"]
    receiver_enc = row["receiver_enc"] if "receiver_enc" in row.keys() and row["receiver_enc"] else row["receiver"]
    amount_enc = row["amount_enc"] if "amount_enc" in row.keys() and row["amount_enc"] else row["amount"]
    sender = try_decrypt_value(sender_enc)
    receiver = try_decrypt_value(receiver_enc)
    amount_plain = try_decrypt_value(amount_enc)
    if sender is None or receiver is None or amount_plain is None:
        return None
    try:
        amount = float(amount_plain)
    except ValueError:
        return None
    return {
        "id": row["id"] if "id" in row.keys() else None,
        "sender": sender,
        "receiver": receiver,
        "amount": amount,
        "hash": row["hash"],
        "timestamp": row["timestamp"],
        "status": row["status"] if "status" in row.keys() else "completed",
    }


def migrate_transaction_encryption():
    db = get_db()
    cols = get_columns("transactions")
    if "sender" not in cols or "receiver" not in cols:
        return
    rows = db.execute(
        "SELECT id, sender, receiver, amount_enc, hash, timestamp, sender_enc, receiver_enc FROM transactions ORDER BY id ASC"
    ).fetchall()
    for row in rows:
        if row["sender_enc"] and row["receiver_enc"] and row["amount_enc"]:
            continue
        if row["sender"] is None or row["receiver"] is None or row["amount_enc"] is None:
            continue
        try:
            amount_plain = float(row["amount_enc"])
        except ValueError:
            continue
        sender_enc, receiver_enc, amount_enc = encrypt_transaction_fields(row["sender"], row["receiver"], amount_plain)
        db.execute(
            "UPDATE transactions SET sender_enc = ?, receiver_enc = ?, amount_enc = ?, sender = ?, receiver = ? WHERE id = ?",
            (sender_enc, receiver_enc, amount_enc, row["sender"], row["receiver"], row["id"]),
        )
    db.commit()


def track_failed_login(username: str):
    db = get_db()
    ip_address = request.remote_addr or "unknown"
    timestamp = datetime.utcnow().isoformat()
    db.execute(
        "INSERT INTO failed_logins (username, timestamp, ip_address) VALUES (?, ?, ?)",
        (username, timestamp, ip_address),
    )
    db.commit()

    if username:
        window_start = (datetime.utcnow() - timedelta(minutes=LOCKOUT_MINUTES)).isoformat()
        recent_failures = db.execute(
            """
            SELECT COUNT(*) AS count
            FROM failed_logins
            WHERE username = ? AND timestamp >= ?
            """,
            (username, window_start),
        ).fetchone()["count"]
        if recent_failures >= LOCKOUT_THRESHOLD:
            locked_until = (datetime.utcnow() + timedelta(minutes=LOCKOUT_MINUTES)).isoformat()
            db.execute("UPDATE users SET locked_until = ? WHERE username = ?", (locked_until, username))
            db.commit()
            log_action(username, "Account lockout triggered")


def is_account_locked(user_row) -> bool:
    locked_until = user_row["locked_until"] if "locked_until" in user_row.keys() else None
    if not locked_until:
        return False
    try:
        return datetime.utcnow() < datetime.fromisoformat(locked_until)
    except ValueError:
        return False


def risk_level(amount: float) -> str:
    return "LOW" if amount <= FRAUD_THRESHOLD else "HIGH"


def calculate_fee(amount: float) -> float:
    return round(amount * FEE_RATE, 2)


def get_user_locked_balance(user_id: int) -> float:
    db = get_db()
    row = db.execute(
        "SELECT COALESCE(SUM(amount), 0) AS total FROM locked_funds WHERE user_id = ? AND status = 'locked'",
        (user_id,),
    ).fetchone()
    return float(row["total"] or 0.0)


def get_user_available_balance(username: str) -> float:
    db = get_db()
    user = db.execute("SELECT id, balance FROM users WHERE username = ?", (username,)).fetchone()
    if not user:
        return 0.0
    locked_balance = get_user_locked_balance(user["id"])
    return round(float(user["balance"]) - locked_balance, 2)


def releaseExpiredFunds(user_id: int = None):
    db = get_db()
    now_iso = datetime.utcnow().isoformat()
    if user_id is None:
        rows = db.execute(
            """
            SELECT id, user_id, amount
            FROM locked_funds
            WHERE status = 'locked' AND release_date <= ?
            """,
            (now_iso,),
        ).fetchall()
    else:
        rows = db.execute(
            """
            SELECT id, user_id, amount
            FROM locked_funds
            WHERE status = 'locked' AND release_date <= ? AND user_id = ?
            """,
            (now_iso, user_id),
        ).fetchall()
    if not rows:
        return 0
    for row in rows:
        db.execute("UPDATE locked_funds SET status = 'released' WHERE id = ?", (row["id"],))
    db.commit()
    return len(rows)


def perform_transaction(sender: str, receiver_wallet: str, amount: float, *, is_demo: bool = False):
    db = get_db()
    receiver_user = db.execute("SELECT username, wallet_address FROM users WHERE wallet_address = ?", (receiver_wallet,)).fetchone()
    sender_user = db.execute("SELECT id, balance, wallet_address FROM users WHERE username = ?", (sender,)).fetchone()
    if not receiver_user:
        return False, "Receiver account was not found."
    if sender_user["wallet_address"] == receiver_wallet:
        return False, "You cannot send to your own wallet."
    releaseExpiredFunds(sender_user["id"])
    fee = calculate_fee(amount)
    total = amount + fee
    locked_balance = get_user_locked_balance(sender_user["id"])
    available_balance = round(float(sender_user["balance"]) - locked_balance, 2)
    log_action(sender, f"Transaction fee calculated: {fee:.2f}")
    if not sender_user or available_balance < total:
        return False, "Insufficient available funds"
    timestamp = datetime.utcnow().isoformat()
    tx_block = blockchain.add_block(sender, receiver_user["username"], amount, timestamp)
    if not blockchain.verify_chain():
        log_action(sender, "Transaction blocked due to blockchain integrity failure.")
        return False, "Blockchain integrity check failed. Transaction cancelled."
    sender_enc, receiver_enc, amount_enc = encrypt_transaction_fields(sender, receiver_user["username"], amount)
    try:
        db.execute("UPDATE users SET balance = balance - ? WHERE username = ?", (total, sender))
        db.execute("UPDATE users SET balance = balance + ? WHERE username = ?", (amount, receiver_user["username"]))
        db.execute(
            "INSERT INTO transactions (sender, receiver, sender_enc, receiver_enc, amount_enc, fee_amount, hash, timestamp, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (sender, receiver_user["username"], sender_enc, receiver_enc, amount_enc, fee, tx_block.block_hash, timestamp, "completed"),
        )
        db.commit()
    except sqlite3.Error:
        log_action(sender, "Transaction failed due to database error.")
        return False, "Could not complete transaction safely."
    level = risk_level(amount)
    log_action(sender, f"Transaction risk level calculated: {level}")
    log_action(sender, f"Sent {amount:.2f} tokens to wallet {receiver_wallet}.")
    log_action(receiver_user["username"], f"Received {amount:.2f} tokens from {sender}.")
    create_notification(receiver_user["username"], f"You received {amount:.2f} SCT from {sender}.")
    evaluate_fraud(sender, amount)
    if is_demo:
        log_action("system", f"Demo transaction: {sender} -> {receiver_wallet}, amount={amount:.2f}")
    return True, "Transaction completed successfully."


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "username" not in session:
            flash("Please login first.", "error")
            return redirect(url_for("login"))
        last_active = session.get("last_active")
        if last_active:
            last_active_dt = datetime.fromisoformat(last_active)
            if datetime.utcnow() - last_active_dt > timedelta(minutes=SESSION_TIMEOUT_MINUTES):
                user = session.get("username", "unknown")
                session.clear()
                flash("Session expired due to inactivity.", "error")
                log_action(user, "Session timeout due to inactivity.")
                return redirect(url_for("login"))
        session["last_active"] = datetime.utcnow().isoformat()
        return view(*args, **kwargs)

    return wrapped


def role_required(role: str):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if session.get("role") != role:
                flash("Unauthorized access.", "error")
                log_action(session.get("username", "anonymous"), f"Unauthorized access to {request.path}")
                return redirect(url_for("dashboard"))
            return view(*args, **kwargs)

        return wrapped

    return decorator


def load_blockchain_from_db():
    db = get_db()
    rows = db.execute("SELECT sender_enc, receiver_enc, amount_enc, timestamp FROM transactions ORDER BY id ASC").fetchall()
    decrypted = []
    skipped_count = 0
    for row in rows:
        sender = try_decrypt_value(row["sender_enc"])
        receiver = try_decrypt_value(row["receiver_enc"])
        amount_plain = try_decrypt_value(row["amount_enc"])
        if sender is None or receiver is None or amount_plain is None:
            skipped_count += 1
            continue
        try:
            amount = float(amount_plain)
        except ValueError:
            skipped_count += 1
            continue
        decrypted.append({"sender": sender, "receiver": receiver, "amount": amount, "timestamp": row["timestamp"]})
    blockchain.rebuild_from_transactions(decrypted)
    if skipped_count:
        log_action("system", f"Skipped {skipped_count} transactions due to invalid encryption key/data.")


def evaluate_fraud(sender: str, amount: float):
    if amount <= FRAUD_THRESHOLD:
        return
    db = get_db()
    timestamp = datetime.utcnow().isoformat()
    reason = f"Transaction above threshold {FRAUD_THRESHOLD:.2f}"
    db.execute(
        "INSERT INTO alerts (user, amount, reason, severity, timestamp) VALUES (?, ?, ?, ?, ?)",
        (sender, amount, reason, "HIGH", timestamp),
    )
    db.commit()
    log_action(sender, f"Fraud alert triggered: amount={amount:.2f}")
    flash("Warning: Transaction flagged as suspicious and reported to admin.", "error")


def generate_otp() -> str:
    return generate_secure_otp()


def clear_otp_session():
    for key in (
        "otp_code",
        "otp_expiry",
        "otp_username",
        "otp_role",
        "otp_email",
        "otp_notice",
        "otp_next",
        "otp_attempts",
        "otp_status",
        "otp_purpose",
    ):
        session.pop(key, None)


def log_otp_event(user_email: str, otp_code: str, status: str, attempts: int = 0, verified: bool = False):
    db = get_db()
    verified_at = utc_now_iso() if verified else None
    db.execute(
        """
        INSERT INTO otp_logs (user_email, otp_code, status, attempts, created_at, verified_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (user_email or "unknown", otp_code or "000000", status, attempts, utc_now_iso(), verified_at),
    )
    db.commit()
    ip_address = request.remote_addr or "unknown"
    log_action(session.get("otp_username") or user_email or "unknown", f"OTP {status} from IP {ip_address}")


def otp_rate_limited() -> bool:
    history = parse_request_log(session.get("otp_request_log"))
    if len(history) >= OTP_RATE_LIMIT_COUNT:
        return True
    history.append(now_epoch())
    session["otp_request_log"] = ",".join(str(x) for x in history)
    return False


def issue_otp_challenge(*, user_row, next_url: str, purpose: str):
    if not user_row.get("email"):
        flash("No email is registered on this account for OTP.", "error")
        return False
    if otp_rate_limited():
        flash("Too many OTP requests. Try again later.", "error")
        return False
    payload = build_otp_session_payload(
        username=user_row["username"],
        role=user_row["role"],
        email=user_row["email"],
        next_url=next_url,
        purpose=purpose,
    )
    for key, value in payload.items():
        session[key] = value
    try:
        send_security_otp_email(user_row["email"], payload["otp_code"])
    except EmailDeliveryError as error:
        clear_otp_session()
        log_error("/send-otp", f"email-send-failed: {error}")
        flash("Unable to send OTP email. Check SMTP configuration.", "error")
        return False
    log_otp_event(user_row["email"], payload["otp_code"], "sent", attempts=0)
    flash("OTP sent to your registered email.", "success")
    return True


def finalize_login(username: str, role: str):
    session.clear()
    session["username"] = username
    session["role"] = role
    session["last_active"] = datetime.utcnow().isoformat()
    session.permanent = True


def fetch_user_transactions(username: str):
    db = get_db()
    rows = db.execute(
        """
        SELECT id, sender, receiver, sender_enc, receiver_enc, amount_enc, hash, timestamp, status
        FROM transactions
        WHERE sender = ? OR receiver = ?
        ORDER BY timestamp DESC
        """,
        (username, username),
    ).fetchall()
    txs = []
    for row in rows:
        tx = decrypt_row(row)
        if tx is None:
            continue
        tx["risk_level"] = risk_level(tx["amount"])
        txs.append(tx)
    return txs


@app.route("/")
def index():
    if "username" in session:
        return redirect(url_for("dashboard"))
    return render_template("landing.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        if not full_name or not username or not email or not phone or not password or not confirm_password:
            flash("All fields are required.", "error")
            return render_template("register.html")
        username_ok, username_error = validate_username_input(username)
        if not username_ok:
            flash(username_error, "error")
            return render_template("register.html")
        email_ok, email_error = validate_email(email)
        if not email_ok:
            flash(email_error, "error")
            return render_template("register.html")
        phone_ok, phone_error = validate_phone(phone)
        if not phone_ok:
            flash(phone_error, "error")
            return render_template("register.html")
        password_ok, password_error = validate_password(password)
        if not password_ok:
            flash(password_error, "error")
            return render_template("register.html")
        if password != confirm_password:
            flash("Password confirmation does not match.", "error")
            return render_template("register.html")
        db = get_db()
        exists = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if exists:
            flash("Username already exists.", "error")
            return render_template("register.html")
        password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        db.execute(
            "INSERT INTO users (full_name, username, email, phone, status, password_hash, role, balance, created_at, wallet_address, locked_until) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                full_name,
                username,
                email,
                phone,
                "Active",
                password_hash,
                "student",
                DEFAULT_STARTING_BALANCE,
                datetime.utcnow().isoformat(),
                generate_unique_wallet_address(),
                None,
            ),
        )
        db.commit()
        log_action(username, "Registered account.")
        flash("Registration successful. Please login.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        db = get_db()
        user = db.execute(
            "SELECT username, password_hash, role, locked_until, status, email FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        if not user:
            track_failed_login(username or "unknown")
            log_action(username or "unknown", "Login failure: unknown username.")
            flash("Invalid username or password.", "error")
            return render_template("login.html")
        if is_account_locked(user):
            flash("Account temporarily locked due to multiple failed login attempts.", "error")
            return render_template("login.html")
        if user["status"] != "Active":
            flash("Account is currently suspended. Contact admin.", "error")
            return render_template("login.html")
        valid_password = bcrypt.checkpw(password.encode("utf-8"), user["password_hash"].encode("utf-8"))
        if not valid_password:
            track_failed_login(username)
            log_action(username, "Login failure: wrong password.")
            flash("Invalid username or password.", "error")
            return render_template("login.html")
        db.execute("UPDATE users SET locked_until = NULL WHERE username = ?", (username,))
        db.commit()
        if not issue_otp_challenge(user_row=user, next_url=url_for("dashboard"), purpose="login"):
            return render_template("login.html")
        return redirect(url_for("verify_otp"))
    return render_template("login.html")


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        db = get_db()
        user = db.execute(
            "SELECT username, password_hash, role, locked_until, status, email FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        if not user or user["role"] != "admin":
            track_failed_login(username or "unknown")
            log_action(username or "unknown", "Admin login failure: invalid account.")
            flash("Invalid admin credentials.", "error")
            return render_template("admin_login.html")
        if user["status"] != "Active":
            flash("Admin account is not active.", "error")
            return render_template("admin_login.html")
        if is_account_locked(user):
            flash("Account temporarily locked due to multiple failed login attempts.", "error")
            return render_template("admin_login.html")
        valid_password = bcrypt.checkpw(password.encode("utf-8"), user["password_hash"].encode("utf-8"))
        if not valid_password:
            track_failed_login(username)
            log_action(username, "Admin login failure: wrong password.")
            flash("Invalid admin credentials.", "error")
            return render_template("admin_login.html")
        db.execute("UPDATE users SET locked_until = NULL WHERE username = ?", (username,))
        db.commit()
        if not issue_otp_challenge(user_row=user, next_url=url_for("admin_dashboard"), purpose="admin_login"):
            return render_template("admin_login.html")
        return redirect(url_for("verify_otp"))
    return render_template("admin_login.html")


@app.route("/send-otp", methods=["POST"])
def send_otp():
    username = request.form.get("username", "").strip()
    if not username:
        flash("Username is required.", "error")
        return redirect(url_for("login"))
    db = get_db()
    user = db.execute("SELECT username, role, email, status FROM users WHERE username = ?", (username,)).fetchone()
    if not user or user["status"] != "Active":
        flash("Unable to send OTP for this account.", "error")
        return redirect(url_for("login"))
    next_url = url_for("admin_dashboard") if user["role"] == "admin" else url_for("dashboard")
    if issue_otp_challenge(user_row=user, next_url=next_url, purpose="manual_send"):
        return redirect(url_for("verify_otp"))
    return redirect(url_for("login"))


@app.route("/resend-otp", methods=["POST"])
def resend_otp():
    if "otp_username" not in session:
        flash("OTP session not found. Please login again.", "error")
        return redirect(url_for("login"))
    db = get_db()
    user = db.execute(
        "SELECT username, role, email, status FROM users WHERE username = ?",
        (session["otp_username"],),
    ).fetchone()
    if not user or user["status"] != "Active":
        clear_otp_session()
        flash("Unable to resend OTP for this account.", "error")
        return redirect(url_for("login"))
    if issue_otp_challenge(
        user_row=user,
        next_url=session.get("otp_next", url_for("dashboard")),
        purpose=session.get("otp_purpose", "login"),
    ):
        log_otp_event(user["email"], session.get("otp_code"), "resent", attempts=0)
    return redirect(url_for("verify_otp"))


@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    if "otp_code" not in session:
        flash("OTP session not found. Please login again.", "error")
        return redirect(url_for("login"))
    if request.method == "POST":
        otp_input = request.form.get("otp", "").strip()
        if not otp_input.isdigit() or len(otp_input) != 6:
            session["otp_attempts"] = int(session.get("otp_attempts", 0)) + 1
            log_otp_event(session.get("otp_email"), otp_input, "failed", attempts=session["otp_attempts"])
            flash("OTP must be a 6-digit code.", "error")
            return render_template("verify_otp.html", otp_notice=session.get("otp_notice"))
        if is_expired(session["otp_expiry"]):
            log_otp_event(session.get("otp_email"), session.get("otp_code"), "expired", attempts=session.get("otp_attempts", 0))
            clear_otp_session()
            flash("OTP expired. Please login again.", "error")
            return redirect(url_for("login"))
        if int(session.get("otp_attempts", 0)) >= OTP_MAX_ATTEMPTS:
            log_otp_event(session.get("otp_email"), session.get("otp_code"), "failed", attempts=session.get("otp_attempts", 0))
            clear_otp_session()
            flash("Too many OTP attempts. Please login again.", "error")
            return redirect(url_for("login"))
        if otp_input != session["otp_code"]:
            session["otp_attempts"] = int(session.get("otp_attempts", 0)) + 1
            log_otp_event(session.get("otp_email"), otp_input, "failed", attempts=session["otp_attempts"])
            flash("Incorrect OTP. Please try again.", "error")
            return render_template("verify_otp.html", otp_notice=session.get("otp_notice"))

        username = session["otp_username"]
        role = session["otp_role"]
        email = session.get("otp_email")
        next_url = session.get("otp_next", url_for("dashboard"))
        log_otp_event(email, otp_input, "verified", attempts=0, verified=True)
        purpose = session.get("otp_purpose", "login")
        if purpose in ("login", "admin_login", "manual_send"):
            finalize_login(username, role)
            log_action(username, "Successful login with OTP.")
            flash("Login successful.", "success")
        else:
            session["otp_transfer_verified_at"] = utc_now_iso()
            clear_otp_session()
            flash("OTP verified successfully.", "success")
        return redirect(next_url)
    return render_template("verify_otp.html", otp_notice=session.get("otp_notice"))


@app.route("/logout")
@login_required
def logout():
    username = session.get("username", "unknown")
    session.clear()
    log_action(username, "Logged out.")
    flash("You are logged out.", "success")
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    releaseExpiredFunds()
    user = db.execute(
        "SELECT id, username, role, balance, created_at, wallet_address FROM users WHERE username = ?",
        (session["username"],),
    ).fetchone()
    locked_balance = get_user_locked_balance(user["id"])
    available_balance = round(float(user["balance"]) - locked_balance, 2)
    next_release_row = db.execute(
        """
        SELECT release_date
        FROM locked_funds
        WHERE user_id = ? AND status = 'locked'
        ORDER BY release_date ASC
        LIMIT 1
        """,
        (user["id"],),
    ).fetchone()
    transactions = fetch_user_transactions(session["username"])[:5]
    chain_status = "VALID" if blockchain.verify_chain() else "TAMPERED"
    security_status = {
        "blockchain": chain_status,
        "session": "ACTIVE",
        "encryption": "ENABLED",
        "fraud_detection": "ACTIVE",
        "system_health": "SECURE" if chain_status == "VALID" else "WARNING",
    }
    log_action(session["username"], "Security status check")
    return render_template(
        "dashboard.html",
        user=user,
        available_balance=available_balance,
        locked_balance=locked_balance,
        next_release_date=next_release_row["release_date"] if next_release_row else None,
        transactions=transactions,
        chain_status=chain_status,
        security_status=security_status,
    )


@app.route("/send", methods=["GET", "POST"])
@login_required
@role_required("student")
def send_tokens():
    releaseExpiredFunds()
    db = get_db()
    sender_row = db.execute("SELECT id, wallet_address FROM users WHERE username = ?", (session["username"],)).fetchone()
    if request.method == "POST":
        recipient_wallet_address = request.form.get("recipient_wallet_address", "").strip()
        amount_raw = request.form.get("amount", "").strip()
        wallet_ok, wallet_error = validate_wallet_input(recipient_wallet_address)
        if not wallet_ok:
            flash(wallet_error, "error")
            return render_template("send.html", sender_wallet=sender_row["wallet_address"])
        receiver_exists = db.execute("SELECT id FROM users WHERE wallet_address = ?", (recipient_wallet_address,)).fetchone()
        if not receiver_exists:
            flash("Receiver wallet address does not exist.", "error")
            return render_template("send.html", sender_wallet=sender_row["wallet_address"])
        available_balance = get_user_available_balance(session["username"])
        amount_ok, amount_error, amount = validate_amount(amount_raw, available_balance)
        if not amount_ok:
            flash(amount_error, "error")
            return render_template("send.html", sender_wallet=sender_row["wallet_address"])
        if sender_row["wallet_address"] == recipient_wallet_address:
            flash("You cannot send to your own wallet.", "error")
            return render_template("send.html", sender_wallet=sender_row["wallet_address"])
        fee = calculate_fee(amount)
        pending = {
            "sender": session["username"],
            "sender_wallet": sender_row["wallet_address"],
            "recipient_wallet_address": recipient_wallet_address,
            "amount": amount,
            "fee": fee,
            "total": amount + fee,
        }
        session["pending_transfer"] = pending
        return redirect(url_for("confirm_transfer"))
    return render_template("send.html", sender_wallet=sender_row["wallet_address"])


@app.route("/send/confirm", methods=["GET", "POST"])
@login_required
@role_required("student")
def confirm_transfer():
    releaseExpiredFunds()
    pending = session.get("pending_transfer")
    if not pending:
        flash("No pending transaction to confirm.", "error")
        return redirect(url_for("send_tokens"))
    if request.method == "POST":
        action = request.form.get("action")
        if action == "cancel":
            session.pop("pending_transfer", None)
            session.pop("otp_transfer_verified_at", None)
            log_action(session["username"], "Transfer confirmation cancelled.")
            return redirect(url_for("send_tokens"))
        if float(pending["amount"]) >= FRAUD_THRESHOLD and not session.get("otp_transfer_verified_at"):
            db = get_db()
            user_row = db.execute(
                "SELECT username, role, email, status FROM users WHERE username = ?",
                (session["username"],),
            ).fetchone()
            if not user_row:
                flash("User account not found.", "error")
                return redirect(url_for("send_tokens"))
            if not issue_otp_challenge(
                user_row=user_row,
                next_url=url_for("confirm_transfer"),
                purpose="transfer_approval",
            ):
                return redirect(url_for("confirm_transfer"))
            flash("OTP required to approve high-value transaction.", "error")
            return redirect(url_for("verify_otp"))
        success, message = perform_transaction(
            pending["sender"],
            pending["recipient_wallet_address"],
            float(pending["amount"]),
        )
        session.pop("pending_transfer", None)
        session.pop("otp_transfer_verified_at", None)
        log_action(session["username"], "Transfer confirmation submitted.")
        flash(message, "success" if success else "error")
        return redirect(url_for("transactions") if success else url_for("send_tokens"))
    return render_template("transfer_confirm.html", pending=pending)


@app.route("/transactions")
@login_required
def transactions():
    txs = fetch_user_transactions(session["username"])
    return render_template("transactions.html", transactions=txs)


@app.route("/demo-transaction", methods=["POST"])
@login_required
def demo_transaction():
    db = get_db()
    for demo_user, demo_password in (("alice", "AlicePass1!"), ("bob", "BobPass1!")):
        existing = db.execute("SELECT id FROM users WHERE username = ?", (demo_user,)).fetchone()
        if not existing:
            password_hash = bcrypt.hashpw(demo_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
            db.execute(
                "INSERT INTO users (username, password_hash, role, balance, created_at, wallet_address, locked_until) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    demo_user,
                    password_hash,
                    "student",
                    DEFAULT_STARTING_BALANCE,
                    datetime.utcnow().isoformat(),
                    generate_unique_wallet_address(),
                    None,
                ),
            )
    db.execute("UPDATE users SET balance = CASE WHEN balance < 10 THEN 100 ELSE balance END WHERE username = 'alice'")
    db.commit()
    bob_row = db.execute("SELECT wallet_address FROM users WHERE username = 'bob'").fetchone()
    success, _ = perform_transaction("alice", bob_row["wallet_address"], 10.0, is_demo=True)
    if success:
        flash("Demo transaction completed successfully", "success")
    else:
        flash("Demo transaction failed. Check balances and user setup.", "error")
    return redirect(url_for("dashboard"))


@app.route("/verify-blockchain")
@login_required
def verify_blockchain():
    valid = blockchain.verify_chain()
    status = "VALID" if valid else "TAMPERED"
    log_action(session["username"], f"Blockchain verification result: {status}")
    return render_template(
        "verify_blockchain.html",
        status=status,
        chain_valid=valid,
        chain_length=len(blockchain.chain),
        verified_at=datetime.utcnow().isoformat(),
    )


def build_pdf(rows, requested_by: str):
    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4
    y = height - 40
    pdf.setTitle("transactions_report.pdf")
    pdf.drawString(40, y, f"SecureChain Transaction Report - Generated by {requested_by}")
    y -= 24
    pdf.drawString(40, y, "User | Amount | Date | Hash")
    y -= 18
    for row in rows:
        line = f"{row['sender']}->{row['receiver']} | {row['amount']:.2f} | {row['timestamp'][:19]} | {row['hash'][:14]}"
        pdf.drawString(40, y, line)
        y -= 16
        if y < 60:
            pdf.showPage()
            y = height - 40
    pdf.save()
    buffer.seek(0)
    return buffer


@app.route("/reports")
@login_required
def reports():
    rows = fetch_user_transactions(session["username"])
    log_action(session["username"], "Downloaded own PDF transaction report.")
    pdf_data = build_pdf(rows, session["username"])
    response = make_response(pdf_data.read())
    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] = "attachment; filename=transactions_report.pdf"
    return response


@app.route("/admin/reports")
@login_required
@role_required("admin")
def admin_reports():
    db = get_db()
    rows = db.execute("SELECT id, sender_enc, receiver_enc, amount_enc, hash, timestamp, status FROM transactions ORDER BY id DESC").fetchall()
    txs = [tx for tx in (decrypt_row(r) for r in rows) if tx is not None]
    log_action(session["username"], "Downloaded admin PDF transaction report.")
    pdf_data = build_pdf(txs, session["username"])
    response = make_response(pdf_data.read())
    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] = "attachment; filename=transactions_report.pdf"
    return response


@app.route("/admin")
@login_required
@role_required("admin")
def admin_dashboard():
    db = get_db()
    users = db.execute(
        "SELECT username, role, status, balance, wallet_address, created_at FROM users ORDER BY created_at ASC"
    ).fetchall()
    rows = db.execute("SELECT id, sender_enc, receiver_enc, amount_enc, hash, timestamp, status FROM transactions ORDER BY id DESC").fetchall()
    transactions_data = [tx for tx in (decrypt_row(r) for r in rows) if tx is not None]
    alerts = db.execute(
        "SELECT user, amount, reason, COALESCE(severity, 'MEDIUM') AS severity, timestamp FROM alerts ORDER BY id DESC LIMIT 100"
    ).fetchall()
    logs = db.execute("SELECT user, action, timestamp FROM logs ORDER BY id DESC LIMIT 200").fetchall()
    timeline = db.execute("SELECT user, action, timestamp FROM logs ORDER BY id DESC LIMIT 50").fetchall()
    total_users = len(users)
    total_transactions = len(transactions_data)
    total_volume = round(sum(float(tx["amount"]) for tx in transactions_data), 2)
    total_balance = round(sum(float(user["balance"]) for user in users), 2)
    student_count = sum(1 for user in users if user["role"] == "student")
    admin_count = sum(1 for user in users if user["role"] == "admin")
    failed_count = db.execute("SELECT COUNT(*) AS count FROM failed_logins").fetchone()["count"]
    suspicious_count = db.execute("SELECT COUNT(*) AS count FROM alerts").fetchone()["count"]
    chain_valid = blockchain.verify_chain()
    return render_template(
        "admin.html",
        users=users,
        transactions=transactions_data,
        alerts=alerts,
        suspicious_count=suspicious_count,
        failed_count=failed_count,
        logs=logs,
        timeline=timeline,
        chain_valid=chain_valid,
        chain_length=len(blockchain.chain),
        total_users=total_users,
        total_transactions=total_transactions,
        total_volume=total_volume,
        total_balance=total_balance,
        student_count=student_count,
        admin_count=admin_count,
    )


@app.route("/admin/security")
@login_required
@role_required("admin")
def admin_security():
    db = get_db()
    total_users = db.execute("SELECT COUNT(*) AS count FROM users").fetchone()["count"]
    total_transactions = db.execute("SELECT COUNT(*) AS count FROM transactions").fetchone()["count"]
    failed_logins = db.execute("SELECT COUNT(*) AS count FROM failed_logins").fetchone()["count"]
    suspicious = db.execute("SELECT COUNT(*) AS count FROM alerts").fetchone()["count"]
    recent_failed = db.execute(
        "SELECT username, timestamp, ip_address FROM failed_logins ORDER BY id DESC LIMIT 20"
    ).fetchall()
    recent_alerts = db.execute(
        "SELECT user, amount, reason, COALESCE(severity, 'MEDIUM') AS severity, timestamp FROM alerts ORDER BY id DESC LIMIT 20"
    ).fetchall()
    recent_timeline = db.execute("SELECT user, action, timestamp FROM logs ORDER BY id DESC LIMIT 50").fetchall()
    chain_valid = blockchain.verify_chain()
    blockchain_length = len(blockchain.chain)
    system_health = "Secure" if chain_valid else "Warning"
    os.makedirs(BACKUP_DIR, exist_ok=True)
    backup_files = sorted([name for name in os.listdir(BACKUP_DIR) if name.endswith(".enc")], reverse=True)[:30]
    return render_template(
        "admin_security.html",
        total_users=total_users,
        total_transactions=total_transactions,
        failed_logins=failed_logins,
        suspicious=suspicious,
        chain_valid=chain_valid,
        blockchain_length=blockchain_length,
        system_health=system_health,
        recent_failed=recent_failed,
        recent_alerts=recent_alerts,
        recent_timeline=recent_timeline,
        backup_files=backup_files,
    )


@app.route("/admin/users/<username>/suspend", methods=["POST"])
@login_required
@role_required("admin")
def suspend_user(username):
    if username == session.get("username"):
        flash("You cannot suspend your own admin account.", "error")
        return redirect(url_for("admin_dashboard"))
    db = get_db()
    db.execute("UPDATE users SET status = 'Suspended' WHERE username = ?", (username,))
    db.commit()
    log_action(session["username"], f"Suspended user: {username}")
    flash(f"User {username} suspended.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/users/<username>/activate", methods=["POST"])
@login_required
@role_required("admin")
def activate_user(username):
    db = get_db()
    db.execute("UPDATE users SET status = 'Active' WHERE username = ?", (username,))
    db.commit()
    log_action(session["username"], f"Activated user: {username}")
    flash(f"User {username} activated.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/backup", methods=["POST"])
@login_required
@role_required("admin")
def backup_database():
    try:
        backup_meta = create_encrypted_backup(DATABASE_PATH, BACKUP_DIR, fernet)
        log_action(session["username"], f"Created backup: {os.path.basename(backup_meta['backup_file'])}")
        flash(f"Backup created: {os.path.basename(backup_meta['backup_file'])}", "success")
    except Exception as error:
        log_error("/backup", str(error))
        flash("Backup creation failed.", "error")
    return redirect(url_for("admin_security"))


@app.route("/recover", methods=["POST"])
@login_required
@role_required("admin")
def recover_database():
    backup_file = request.form.get("backup_file", "").strip()
    if not backup_file:
        flash("Backup filename is required.", "error")
        return redirect(url_for("admin_security"))
    backup_path = os.path.join(BACKUP_DIR, backup_file)
    digest_path = f"{backup_path[:-4]}.sha256" if backup_path.endswith(".enc") else f"{backup_path}.sha256"
    try:
        close_db(None)
        recover_encrypted_backup(backup_path, digest_path, DATABASE_PATH, fernet)
        log_action(session["username"], f"Recovered backup: {backup_file}")
        flash(f"Recovery completed from {backup_file}.", "success")
    except Exception as error:
        log_error("/recover", str(error))
        flash("Recovery failed. Verify backup filename and integrity.", "error")
    return redirect(url_for("admin_security"))


@app.route("/system-architecture")
@login_required
def system_architecture():
    log_action(session["username"], "System architecture page access")
    return render_template("system_architecture.html")


@app.route("/receive")
@login_required
@role_required("student")
def receive():
    db = get_db()
    user = db.execute("SELECT wallet_address FROM users WHERE username = ?", (session["username"],)).fetchone()
    qr = qrcode.make(user["wallet_address"])
    qr_buffer = io.BytesIO()
    qr.save(qr_buffer, format="PNG")
    import base64

    qr_data = base64.b64encode(qr_buffer.getvalue()).decode("utf-8")
    return render_template("receive.html", wallet_address=user["wallet_address"], qr_data=qr_data)


@app.route("/hold-funds", methods=["GET", "POST"])
@login_required
def hold_funds():
    db = get_db()
    user = db.execute("SELECT id, balance, wallet_address FROM users WHERE username = ?", (session["username"],)).fetchone()
    releaseExpiredFunds(user["id"])
    if request.method == "POST":
        amount_raw = request.form.get("amount", "").strip()
        release_date_raw = request.form.get("release_date", "").strip()
        try:
            amount = round(float(amount_raw), 2)
        except ValueError:
            flash("Amount must be a valid number.", "error")
            return redirect(url_for("hold_funds"))
        if amount <= 0:
            flash("Amount must be greater than 0.", "error")
            return redirect(url_for("hold_funds"))
        try:
            release_dt = datetime.fromisoformat(release_date_raw)
        except ValueError:
            flash("Release date is invalid.", "error")
            return redirect(url_for("hold_funds"))
        if release_dt <= datetime.utcnow():
            flash("Release date must be in the future.", "error")
            return redirect(url_for("hold_funds"))
        available_balance = get_user_available_balance(session["username"])
        if amount > available_balance:
            flash("Insufficient available funds.", "error")
            return redirect(url_for("hold_funds"))
        db.execute(
            """
            INSERT INTO locked_funds (user_id, amount, release_date, status)
            VALUES (?, ?, ?, 'locked')
            """,
            (user["id"], amount, release_dt.isoformat()),
        )
        db.commit()
        log_action(session["username"], f"Locked {amount:.2f} funds until {release_dt.isoformat()}")
        flash("Funds locked successfully.", "success")
        return redirect(url_for("hold_funds"))
    locks = db.execute(
        """
        SELECT id, amount, release_date, status, created_at
        FROM locked_funds
        WHERE user_id = ?
        ORDER BY id DESC
        """,
        (user["id"],),
    ).fetchall()
    locked_balance = get_user_locked_balance(user["id"])
    available_balance = round(float(user["balance"]) - locked_balance, 2)
    next_release_row = db.execute(
        """
        SELECT release_date
        FROM locked_funds
        WHERE user_id = ? AND status = 'locked'
        ORDER BY release_date ASC
        LIMIT 1
        """,
        (user["id"],),
    ).fetchone()
    return render_template(
        "hold_funds.html",
        user=user,
        locks=locks,
        locked_balance=locked_balance,
        available_balance=available_balance,
        next_release_date=next_release_row["release_date"] if next_release_row else None,
    )


@app.route("/api/lock-funds", methods=["POST"])
@login_required
def api_lock_funds():
    db = get_db()
    user = db.execute("SELECT id FROM users WHERE username = ?", (session["username"],)).fetchone()
    releaseExpiredFunds(user["id"])
    payload = request.get_json(silent=True) or {}
    amount_raw = payload.get("amount")
    release_date_raw = payload.get("release_date")
    try:
        amount = round(float(amount_raw), 2)
    except (TypeError, ValueError):
        return jsonify({"success": False, "message": "Amount must be a valid number."}), 400
    if amount <= 0:
        return jsonify({"success": False, "message": "Amount must be greater than zero."}), 400
    try:
        release_dt = datetime.fromisoformat(str(release_date_raw))
    except (TypeError, ValueError):
        return jsonify({"success": False, "message": "Release date is invalid."}), 400
    if release_dt <= datetime.utcnow():
        return jsonify({"success": False, "message": "Release date must be in the future."}), 400
    available_balance = get_user_available_balance(session["username"])
    if amount > available_balance:
        return jsonify({"success": False, "message": "Insufficient available funds."}), 400
    db.execute(
        """
        INSERT INTO locked_funds (user_id, amount, release_date, status)
        VALUES (?, ?, ?, 'locked')
        """,
        (user["id"], amount, release_dt.isoformat()),
    )
    db.commit()
    log_action(session["username"], f"Locked {amount:.2f} funds via API until {release_dt.isoformat()}")
    return jsonify(
        {
            "success": True,
            "message": "Funds locked successfully.",
            "amount": amount,
            "release_date": release_dt.isoformat(),
            "available_balance": round(available_balance - amount, 2),
        }
    )


@app.route("/api/locked-funds", methods=["GET"])
@login_required
def api_locked_funds():
    db = get_db()
    user = db.execute("SELECT id FROM users WHERE username = ?", (session["username"],)).fetchone()
    releaseExpiredFunds(user["id"])
    rows = db.execute(
        """
        SELECT amount, release_date, status, created_at
        FROM locked_funds
        WHERE user_id = ?
        ORDER BY id DESC
        """,
        (user["id"],),
    ).fetchall()
    data = [
        {
            "amount": float(row["amount"]),
            "release_date": row["release_date"],
            "status": row["status"],
            "created_at": row["created_at"],
        }
        for row in rows
    ]
    return jsonify({"success": True, "locked_funds": data})


@app.errorhandler(404)
def not_found(error):
    return render_template("login.html"), 404


@app.errorhandler(500)
def internal_error(error):
    log_error(request.path, str(error))
    if not getattr(g, "error_flashed", False):
        flash("Unexpected error occurred. Please try again.", "error")
        g.error_flashed = True
    if session.get("username"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.errorhandler(Exception)
def handle_exception(error):
    log_error(request.path, f"{error} | {traceback.format_exc()[:1000]}")
    if not getattr(g, "error_flashed", False):
        flash("Unexpected error occurred. Please try again.", "error")
        g.error_flashed = True
    if session.get("username"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


def bootstrap():
    global BOOTSTRAPPED
    if BOOTSTRAPPED:
        return
    with app.app_context():
        init_db()
        releaseExpiredFunds()
        load_blockchain_from_db()
        if not blockchain.verify_chain():
            log_action("system", "WARNING: Blockchain integrity check failed during startup.")
    BOOTSTRAPPED = True


if __name__ == "__main__":
    bootstrap()
    app.run(debug=True)
