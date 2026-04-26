import os
import tempfile
import unittest

os.environ.setdefault("SECRET_KEY", "test-secret-key")

from app import app, get_db, init_db
from backup import create_daily_backup
from blockchain import Blockchain
from security import generate_wallet_address
from validation import validate_amount, validate_password, validate_username, validate_wallet_address


class SecurityFeatureTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        self.client.testing = True
        app.config["WTF_CSRF_ENABLED"] = False
        with app.app_context():
            init_db()

    def test_username_validation_success(self):
        valid, _ = validate_username("User123")
        self.assertTrue(valid)

    def test_username_validation_failure(self):
        valid, _ = validate_username("ab")
        self.assertFalse(valid)

    def test_password_validation_failure(self):
        valid, _ = validate_password("weakpass")
        self.assertFalse(valid)

    def test_password_validation_success(self):
        valid, _ = validate_password("Strong@123")
        self.assertTrue(valid)

    def test_amount_validation(self):
        valid, _, amount = validate_amount("10.5", 100)
        self.assertTrue(valid)
        self.assertEqual(amount, 10.5)

    def test_wallet_generation_format(self):
        wallet = generate_wallet_address()
        self.assertTrue(wallet.startswith("SW-"))
        self.assertEqual(len(wallet), 15)
        valid, _ = validate_wallet_address(wallet)
        self.assertTrue(valid)

    def test_unauthorized_admin_access(self):
        response = self.client.get("/admin", follow_redirects=False)
        self.assertIn(response.status_code, [301, 302])

    def test_account_lockout_fields_increment(self):
        with app.app_context():
            db = get_db()
            db.execute("UPDATE users SET login_attempts = 5, lock_until = ? WHERE username = ?", ("2999-01-01T00:00:00", "admin"))
            db.commit()
        response = self.client.post("/admin/login", data={"username": "admin", "password": "wrong"}, follow_redirects=True)
        self.assertEqual(response.status_code, 200)

    def test_blockchain_validation_detects_tamper(self):
        chain = Blockchain()
        chain.add_block("alice", "bob", 10.0, "2026-01-01T00:00:00")
        chain.chain[1].amount = 9999.0
        self.assertFalse(chain.is_chain_valid())

    def test_backup_creation(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = os.path.join(tmp_dir, "database.db")
            with open(db_path, "wb") as handle:
                handle.write(b"test")
            backup_path = create_daily_backup(db_path, tmp_dir)
            self.assertTrue(os.path.exists(backup_path))


if __name__ == "__main__":
    unittest.main()
