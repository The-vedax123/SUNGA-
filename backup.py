import os
import shutil
import threading
import time
from datetime import datetime

from cryptography.fernet import Fernet
import schedule

from security import sha256_hex


def create_encrypted_backup(database_path: str, backup_dir: str, fernet: Fernet) -> dict:
    os.makedirs(backup_dir, exist_ok=True)
    date_stamp = datetime.utcnow().strftime("%Y_%m_%d")
    backup_basename = f"backup_{date_stamp}_{datetime.utcnow().strftime('%H%M%S')}.db"
    backup_path = os.path.join(backup_dir, f"{backup_basename}.enc")
    digest_path = os.path.join(backup_dir, f"{backup_basename}.sha256")

    with open(database_path, "rb") as db_file:
        raw_db = db_file.read()
    digest = sha256_hex(raw_db)
    encrypted = fernet.encrypt(raw_db)

    with open(backup_path, "wb") as backup_file:
        backup_file.write(encrypted)
    with open(digest_path, "w", encoding="utf-8") as digest_file:
        digest_file.write(digest)

    return {"backup_file": backup_path, "digest_file": digest_path, "digest": digest}


def recover_encrypted_backup(
    backup_path: str,
    digest_path: str,
    database_path: str,
    fernet: Fernet,
) -> dict:
    if not os.path.exists(backup_path):
        raise FileNotFoundError("Backup file not found.")
    if not os.path.exists(digest_path):
        raise FileNotFoundError("Digest file not found.")

    with open(backup_path, "rb") as backup_file:
        encrypted_data = backup_file.read()
    decrypted_data = fernet.decrypt(encrypted_data)

    with open(digest_path, "r", encoding="utf-8") as digest_file:
        expected_digest = digest_file.read().strip()

    actual_digest = sha256_hex(decrypted_data)
    if actual_digest != expected_digest:
        raise ValueError("Backup integrity verification failed.")

    with open(database_path, "wb") as db_file:
        db_file.write(decrypted_data)

    return {"restored": True, "digest": actual_digest}


def create_daily_backup(database_path: str, backup_dir: str) -> str:
    os.makedirs(backup_dir, exist_ok=True)
    filename = f"backup_{datetime.utcnow().strftime('%Y%m%d')}.db"
    backup_path = os.path.join(backup_dir, filename)
    shutil.copy2(database_path, backup_path)
    return backup_path


def start_backup_scheduler(database_path: str, backup_dir: str) -> threading.Thread:
    def _worker():
        schedule.clear("sunga-backup")
        schedule.every().day.at("02:00").do(create_daily_backup, database_path=database_path, backup_dir=backup_dir).tag(
            "sunga-backup"
        )
        while True:
            schedule.run_pending()
            time.sleep(60)

    thread = threading.Thread(target=_worker, daemon=True, name="sunga-backup-scheduler")
    thread.start()
    return thread
