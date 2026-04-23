import io
import os
import random
import re
import sqlite3
import traceback
import uuid
from datetime import datetime, timedelta
from functools import wraps

import bcrypt
from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken
from flask import Flask, flash, g, jsonify, make_response, redirect, render_template, request, session, url_for
import qrcode
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

from blockchain import Blockchain

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
IS_VERCEL = os.environ.get("VERCEL") == "1"
DATA_DIR = os.environ.get("DATA_DIR", "/tmp" if IS_VERCEL else BASE_DIR)
DATABASE_PATH = os.path.join(DATA_DIR, "database.db")
FERNET_KEY_PATH = os.path.join(DATA_DIR, "fernet.key")
SESSION_TIMEOUT_MINUTES = 5
OTP_EXPIRY_MINUTES = 2
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


def get_db():
    if "db" not in g:
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
    rows = db.execute(f"PRAGMA table_info({table_name})").fetchall()
    return {row["name"] for row in rows}


def wallet_address() -> str:
    return f"0x{uuid.uuid4().hex[:10].upper()}"


def migrate_db():
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
    db.commit()


def init_db():
    db = get_db()
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
            timestamp TEXT NOT NULL
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
        ("admin", password_hash, "admin", 1000.0, created_at, wallet_address()),
    )
    db.commit()
    log_action("system", "Seeded default admin account.")


def backfill_wallet_addresses():
    db = get_db()
    users = db.execute("SELECT id FROM users WHERE wallet_address IS NULL OR wallet_address = ''").fetchall()
    for user in users:
        db.execute("UPDATE users SET wallet_address = ? WHERE id = ?", (wallet_address(), user["id"]))
    db.commit()


def log_action(user: str, action: str):
    db = get_db()
    timestamp = datetime.utcnow().isoformat()
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
    if not username:
        return False
    if len(username) < 3 or len(username) > 30:
        return False
    return username.replace("_", "").isalnum()


def validate_wallet_address(address: str) -> bool:
    return bool(address) and address.startswith("0x") and 10 <= len(address) <= 20 and re.fullmatch(r"0x[A-Za-z0-9]+", address)


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
        "sender": sender,
        "receiver": receiver,
        "amount": amount,
        "hash": row["hash"],
        "timestamp": row["timestamp"],
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
            (sender_enc, receiver_enc, amount_enc, sender_enc, receiver_enc, row["id"]),
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
            "INSERT INTO transactions (sender, receiver, sender_enc, receiver_enc, amount_enc, fee_amount, hash, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (sender_enc, receiver_enc, sender_enc, receiver_enc, amount_enc, fee, tx_block.block_hash, timestamp),
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
    return f"{random.randint(100000, 999999)}"


def finalize_login(username: str, role: str):
    session.clear()
    session["username"] = username
    session["role"] = role
    session["last_active"] = datetime.utcnow().isoformat()
    session.permanent = True


def fetch_user_transactions(username: str):
    db = get_db()
    rows = db.execute(
        "SELECT sender_enc, receiver_enc, amount_enc, hash, timestamp FROM transactions ORDER BY id DESC"
    ).fetchall()
    txs = []
    for row in rows:
        tx = decrypt_row(row)
        if tx is None:
            continue
        tx["risk_level"] = risk_level(tx["amount"])
        if tx["sender"] == username or tx["receiver"] == username:
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
        if not validate_username(username):
            flash("Username must be 3-30 chars and alphanumeric/underscore only.", "error")
            return render_template("register.html")
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            flash("Invalid email format.", "error")
            return render_template("register.html")
        if not re.fullmatch(r"[0-9+\-\s]{7,20}", phone):
            flash("Phone must be 7-20 digits and may include + or -.", "error")
            return render_template("register.html")
        if len(password) < 8:
            flash("Password must be at least 8 characters.", "error")
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
                wallet_address(),
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
        user = db.execute("SELECT username, password_hash, role, locked_until FROM users WHERE username = ?", (username,)).fetchone()
        if not user:
            track_failed_login(username or "unknown")
            log_action(username or "unknown", "Login failure: unknown username.")
            flash("Invalid username or password.", "error")
            return render_template("login.html")
        if is_account_locked(user):
            flash("Account temporarily locked due to multiple failed login attempts.", "error")
            return render_template("login.html")
        valid_password = bcrypt.checkpw(password.encode("utf-8"), user["password_hash"].encode("utf-8"))
        if not valid_password:
            track_failed_login(username)
            log_action(username, "Login failure: wrong password.")
            flash("Invalid username or password.", "error")
            return render_template("login.html")

        otp = generate_otp()
        db.execute("UPDATE users SET locked_until = NULL WHERE username = ?", (username,))
        db.commit()
        session["otp_code"] = otp
        session["otp_expiry"] = (datetime.utcnow() + timedelta(minutes=OTP_EXPIRY_MINUTES)).isoformat()
        session["otp_username"] = user["username"]
        session["otp_role"] = user["role"]
        session["otp_notice"] = f"Mock email OTP sent: {otp}"
        log_action(username, "OTP generated for login.")
        return redirect(url_for("verify_otp"))
    return render_template("login.html")


@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    if "otp_code" not in session:
        flash("OTP session not found. Please login again.", "error")
        return redirect(url_for("login"))
    if request.method == "POST":
        otp_input = request.form.get("otp", "").strip()
        if not otp_input.isdigit() or len(otp_input) != 6:
            track_failed_login(session.get("otp_username", "unknown"))
            log_action(session.get("otp_username", "unknown"), "OTP verification failed: invalid format.")
            flash("OTP must be a 6-digit code.", "error")
            return render_template("verify_otp.html", otp_notice=session.get("otp_notice"))
        if datetime.utcnow() > datetime.fromisoformat(session["otp_expiry"]):
            track_failed_login(session.get("otp_username", "unknown"))
            log_action(session.get("otp_username", "unknown"), "OTP verification failed: code expired.")
            session.pop("otp_code", None)
            session.pop("otp_expiry", None)
            session.pop("otp_notice", None)
            flash("OTP expired. Please login again.", "error")
            return redirect(url_for("login"))
        if otp_input != session["otp_code"]:
            track_failed_login(session.get("otp_username", "unknown"))
            log_action(session.get("otp_username", "unknown"), "OTP verification failed: wrong code.")
            flash("Incorrect OTP. Please try again.", "error")
            return render_template("verify_otp.html", otp_notice=session.get("otp_notice"))

        username = session["otp_username"]
        role = session["otp_role"]
        finalize_login(username, role)
        log_action(username, "Successful login with OTP.")
        flash("Login successful.", "success")
        return redirect(url_for("dashboard"))
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
def send_tokens():
    releaseExpiredFunds()
    sender_row = get_db().execute("SELECT wallet_address FROM users WHERE username = ?", (session["username"],)).fetchone()
    if request.method == "POST":
        recipient_wallet_address = request.form.get("recipient_wallet_address", "").strip()
        amount_raw = request.form.get("amount", "").strip()
        if not validate_wallet_address(recipient_wallet_address):
            flash("Invalid wallet address", "error")
            return render_template("send.html", sender_wallet=sender_row["wallet_address"])
        try:
            amount = float(amount_raw)
        except ValueError:
            flash("Amount must be a valid number.", "error")
            return render_template("send.html", sender_wallet=sender_row["wallet_address"])
        if amount <= 0:
            flash("Amount must be greater than 0.", "error")
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
            log_action(session["username"], "Transfer confirmation cancelled.")
            return redirect(url_for("send_tokens"))
        success, message = perform_transaction(
            pending["sender"],
            pending["recipient_wallet_address"],
            float(pending["amount"]),
        )
        session.pop("pending_transfer", None)
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
                (demo_user, password_hash, "student", DEFAULT_STARTING_BALANCE, datetime.utcnow().isoformat(), wallet_address(), None),
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
    rows = db.execute("SELECT sender_enc, receiver_enc, amount_enc, hash, timestamp FROM transactions ORDER BY id DESC").fetchall()
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
    users = db.execute("SELECT username, role, balance, wallet_address, created_at FROM users ORDER BY created_at ASC").fetchall()
    rows = db.execute("SELECT sender_enc, receiver_enc, amount_enc, hash, timestamp FROM transactions ORDER BY id DESC").fetchall()
    transactions_data = [tx for tx in (decrypt_row(r) for r in rows) if tx is not None]
    alerts = db.execute(
        "SELECT user, amount, reason, COALESCE(severity, 'MEDIUM') AS severity, timestamp FROM alerts ORDER BY id DESC LIMIT 100"
    ).fetchall()
    logs = db.execute("SELECT user, action, timestamp FROM logs ORDER BY id DESC LIMIT 200").fetchall()
    timeline = db.execute("SELECT user, action, timestamp FROM logs ORDER BY id DESC LIMIT 50").fetchall()
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
    )


@app.route("/system-architecture")
@login_required
def system_architecture():
    log_action(session["username"], "System architecture page access")
    return render_template("system_architecture.html")


@app.route("/receive")
@login_required
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
