"""One-off: clear login lockout fields for admin (run from blockchain_wallet folder)."""
import os
import sqlite3

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
db_path = os.path.join(BASE, "database.db")

def main():
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    before = conn.execute(
        "SELECT username, login_attempts, lock_until, locked_until FROM users WHERE username = ?",
        ("admin",),
    ).fetchone()
    print("before:", dict(before) if before else None)
    conn.execute(
        "UPDATE users SET login_attempts = 0, lock_until = NULL, locked_until = NULL WHERE username = ?",
        ("admin",),
    )
    conn.commit()
    after = conn.execute(
        "SELECT username, login_attempts, lock_until, locked_until FROM users WHERE username = ?",
        ("admin",),
    ).fetchone()
    print("after:", dict(after) if after else None)
    conn.close()


if __name__ == "__main__":
    main()
